package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// —— 公开端点（loginRateLimit 由路由注册挂载，同 /auth/login）——

// MFAVerifyLogin POST /auth/mfa/verify — 登录第二步：挑战令牌 + 验证码 → JWT。
func (h *Handlers) MFAVerifyLogin(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	var req struct {
		MFAToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	var userID int
	var passwordVersion int64
	var user models.User
	err := db.DB.QueryRow(`SELECT u.id, u.password_version, u.username, u.role, u.display_name, u.is_enabled, u.created_at, u.last_login
		FROM mfa_challenges ch JOIN users u ON u.id = ch.user_id
		WHERE ch.token=? AND ch.consumed=0 AND ch.expires_at > datetime('now')`, req.MFAToken).
		Scan(&userID, &passwordVersion, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin)
	if err != nil || !user.IsEnabled {
		// 挑战无效不泄露具体原因
		services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战令牌无效或已过期"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战无效或已过期，请重新登录"})
		return
	}
	user.ID = userID

	// 登录失败锁定（2026-09 用户裁定）：MFA 验证码失败与密码失败同计一个
	// 账户级计数（login_*），受「登录失败锁定」开关控制；锁定期间验证步直接
	// 429，不再消耗挑战次数。
	var loginLockedUntil sql.NullString
	if err := db.DB.QueryRow("SELECT login_locked_until FROM users WHERE id=?", userID).Scan(&loginLockedUntil); err == nil && loginLockedNow(loginLockedUntil) {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("用户 %d", userID), "账户已锁定"), c.ClientIP())
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "账户已锁定，请 10 分钟后重试"})
		return
	}

	if ok, verr := services.MFAVerifyCode(userID, req.Code, time.Now()); !ok {
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证码错误"), c.ClientIP())
		// R72 B-I-4：挑战级失败计数——分布式 IP 限流绕过下对单挑战的爆破收敛
		//（10 次作废，需重新走密码步取新挑战）。
		_ = services.MFARecordChallengeFailure(req.MFAToken)
		// 统一登录失败计数（开关语义见 recordLoginFailure）。
		recordLoginFailure(userID)
		msg := "验证码错误"
		if verr != nil {
			msg = verr.Error()
		}
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: msg})
		return
	}
	if !services.MFAConsumeChallenge(req.MFAToken, userID) {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战已被使用，请重新登录"})
		return
	}
	// 完整登录成功：清零登录失败计数与锁定（密码步未清零，见 Login 注释）。
	_, _ = db.DB.Exec("UPDATE users SET login_failed_attempts=0, login_locked_until=NULL WHERE id=?", userID)
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix(), true)
}

// —— 自助端点（JWT）——

// MFAStatus GET /auth/mfa/status
func (h *Handlers) MFAStatus(c *gin.Context) {
	userID := getContextUserIDInt(c)
	st, err := services.MFAGetStatus(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 MFA 状态失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: st})
}

// MFASetup POST /auth/mfa/setup — 生成 pending secret + otpauth URI（未启用）。
// R72 F-1：已启用 MFA 的用户重新 setup 需密码+当前有效验证码双重确认——
// 此前无任何门：持被劫持会话即可静默轮换第二因子（setup 响应明文返回新 secret
// + URI，攻击者配好自己的 authenticator 后 activate 即夺取 MFA；受害者未启用
// 场景则被强开攻击者控制的 MFA = 永久登录 DoS）。未启用用户保持无门（首次
// 绑定的可用性优先，会话本身已过密码认证）。
func (h *Handlers) MFASetup(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := getContextUserIDInt(c)
	var mfaEnabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&mfaEnabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 MFA 状态失败"})
		return
	}
	if mfaEnabled {
		var req struct {
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
			return
		}
		// B5 I-A：重新绑定确认段与 disable/verify-step 同门——连续失败 10 次冷却 10 分钟。
		if mfaEndpointHardGate(c, userID) {
			return
		}
		// H3：密码预检走共享门计数（密码失败与验码失败同计同冷却），但成功不在
		// 此清零——后续验码失败仍需跨请求累计；双重确认整体通过由 MFAVerifyCode
		// 成功路径清零（先清会把「对密码错码」尝试的验码计数抹掉，硬门永不触发）。
		if mfaGateCheckPassword(c, userID, req.Password) {
			return
		}
		if ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now()); !ok {
			msg := "验证码错误"
			if verr != nil {
				msg = verr.Error()
			}
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: msg})
			return
		}
	}
	// D5-S1：otpauth 账号位用用户名（services/mfa.go 约定 accountName 即用户名；
	// jwtAuth/apiKeyAuth 均注入 c username）——此前用数字 ID，所有用户的
	// Authenticator 条目都显示「LazyBalancer:1」不可区分。空值回退数字 ID 保可用。
	username := c.GetString("username")
	if username == "" {
		username = getContextUserID(c)
	}
	secret, uri, err := services.MFAGenerateSecret(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 MFA 密钥失败"})
		return
	}
	// D5-S4：单条 UPDATE 原子落库（新密钥 + 失败计数清零同生共死）——此前
	// 两段写（先清后设）在首成次败时已返回 200+secret 而 pending 为空，用户
	// 扫码后 activate 必报「没有待激活的 MFA 密钥」，且两语句间存在瞬时空窗。
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=?, mfa_pending_fails=0 WHERE id=?", secret, userID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 MFA 密钥失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"secret": secret, "uri": uri}})
}

// MFAActivate POST /auth/mfa/activate — 验证当前码 → 启用 + 恢复码（仅此一次明文）。
func (h *Handlers) MFAActivate(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := getContextUserIDInt(c)
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if ok, _ := services.MFAVerifyPending(userID, req.Code, time.Now()); !ok {
		// R72 A-F-2：pending 码失败计数——VerifyPending 无锁定无限流（loginRateLimit
		// 只挂公开路由），持会话者可对 10^6 码空间暴力；5 次失败作废 pending（重新
		// setup 才能再试），与挑战级计数同为与全局开关无关的硬闸。
		if invalidated := services.MFARecordPendingFailure(userID); invalidated {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误次数过多，绑定已作废，请重新开始绑定"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "验证码错误，请确认 Authenticator 时间同步后重试"})
		return
	}
	services.MFAClearPendingFailures(userID)
	codes, err := services.MFAActivate(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "启用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "MFA 已启用", Data: gin.H{"recovery_codes": codes}})
}

// MFADisable POST /auth/mfa/disable — 双重确认（密码 + 有效验证码）。
func (h *Handlers) MFADisable(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := getContextUserIDInt(c)
	var req struct {
		Password string `json:"password" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// B5 I-A：disable 与 verify-step 同门——连续失败 10 次冷却 10 分钟。
	if mfaEndpointHardGate(c, userID) {
		return
	}
	// H3：密码预检走共享门计数（同 MFASetup 重绑——成功不清零，验码成功才清）。
	if mfaGateCheckPassword(c, userID, req.Password) {
		return
	}
	if ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now()); !ok {
		// B5 I-A：高敏动作的失败尝试与成功同等可审计（对齐 MFAResetByAdmin 前置验码失败留痕）。
		recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("禁用 MFA 前验证失败", services.AuditResultPart("failure")))
		msg := "验证码错误"
		if verr != nil {
			msg = verr.Error()
		}
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: msg})
		return
	}
	if err := services.MFAResetForUser(userID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "禁用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "MFA 已禁用"})
}

// MFARecoveryCodes POST /auth/mfa/recovery-codes — 密码确认后重生成。
func (h *Handlers) MFARecoveryCodes(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := getContextUserIDInt(c)
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// H3：并入共享密码确认门——此前仅 bcrypt 比对、无任何失败上限，劫持会话可
	// 在线爆破密码重生成恢复码；密码失败与 MFA 验码失败同计同冷却。不要求 TOTP
	// 双确认：恢复码是 TOTP 丢失后的唯一取回入口，强制「密码+码」会把本端点变成
	// 死锁（用户裁决：恢复码端点只验密码）。
	if err := confirmPasswordWithGate(c, userID, req.Password); err != nil {
		return
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&enabled); err != nil || !enabled {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MFA 未启用"})
		return
	}
	// 原地重写（旧码全部作废）
	codes, err := services.MFARegenerateRecoveryCodes(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "恢复码已重新生成（旧码全部作废）", Data: gin.H{"recovery_codes": codes}})
}

// R74 verify-step 硬门阈值/冷却（审计 B3 I-5）。
const (
	mfaVerifyStepMaxAttempts = 10
	mfaVerifyStepCooldown    = 10 * time.Minute
)

// errMfaGateRejected 共享密码确认门拒绝（401/429/500 响应已由门写入，调用方 return 即可）。
var errMfaGateRejected = errors.New("mfa password gate rejected")

// mfaGateRecordPasswordFailure 密码确认失败的单条条件 UPDATE 原子递增（审计 H3）
// ——达阈值同语句置锁并清零（避免锁满后再计延长冷却），阈值/冷却复用 R74 常量。
func mfaGateRecordPasswordFailure(userID int) {
	now := time.Now()
	_, _ = db.DB.Exec(`UPDATE users SET
		mfa_failed_attempts=CASE WHEN COALESCE(mfa_failed_attempts,0)+1>=? THEN 0 ELSE COALESCE(mfa_failed_attempts,0)+1 END,
		mfa_locked_until=CASE WHEN COALESCE(mfa_failed_attempts,0)+1>=? THEN ? ELSE mfa_locked_until END
		WHERE id=?`,
		mfaVerifyStepMaxAttempts, mfaVerifyStepMaxAttempts,
		now.Add(mfaVerifyStepCooldown).UTC().Format("2006-01-02 15:04:05"), userID)
}

// mfaEndpointHardGate R74 端点级硬门（verify-step / disable / setup 重新绑定共用）——
// 与登录 challenge 10 次/激活 pending 5 次同族的端点级失败上限（独立于
// mfa_lockout_enabled 全局锁定开关）：连续失败 ≥10 触发 10 分钟冷却（429）；
// 劫持会话的在线爆破成本从小时级拉到不可用。机制：复用
// users.mfa_failed_attempts（MFAVerifyCode 每次验码失败已 +1，开关关闭时亦然；
// 审计 H3 起密码确认失败经 mfaGateCheckPassword 同计）与 mfa_locked_until。
// 审计 H3：达阈值的置锁+清零改为单条条件 UPDATE 原子完成——原「先读计数、再
// 另条置锁」的读改写在并发失败下可基于过期快照互相覆盖。冷却过期后正常用户凭
// 有效码即可恢复；冷却期内一律 429 不再验码。门在端点内、不读 auth_type，对 JWT
// 与机器身份同效；读库失败时不阻断既有验码路径（MFAVerifyCode 自会报错）。
// 返回 true = 已拦截（429 响应已写入）。
func mfaEndpointHardGate(c *gin.Context, userID int) bool {
	var attempts int
	var lockedUntil *time.Time
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_failed_attempts,0), mfa_locked_until FROM users WHERE id=?", userID).
		Scan(&attempts, &lockedUntil); err == nil {
		now := time.Now()
		if lockedUntil != nil && now.Before(*lockedUntil) {
			c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "连续失败过多，请 10 分钟后重试"})
			return true
		}
		if attempts >= mfaVerifyStepMaxAttempts {
			// 单条条件 UPDATE 原子置锁+清零（已锁时条件不满足零命中，并发下最多一次生效）。
			_, _ = db.DB.Exec("UPDATE users SET mfa_failed_attempts=0, mfa_locked_until=? WHERE id=? AND (mfa_locked_until IS NULL OR mfa_locked_until<=?)",
				now.Add(mfaVerifyStepCooldown).UTC().Format("2006-01-02 15:04:05"), userID, now.UTC().Format("2006-01-02 15:04:05"))
			c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "连续失败过多，请 10 分钟后重试"})
			return true
		}
	}
	return false
}

// mfaGateCheckPassword 共享门密码段核心：锁定检查 + bcrypt 比对，失败单条原子
// 递增并写 401。成功不在此清零失败计数——密码+验码双重确认端点（disable /
// setup 重绑）的验码失败仍需跨请求累计，清零统一交双重确认整体成功
// （MFAVerifyCode 成功路径）。返回 true = 已拦截（响应已写入）。
func mfaGateCheckPassword(c *gin.Context, userID int, password string) bool {
	if mfaEndpointHardGate(c, userID) {
		return true
	}
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", userID).Scan(&hash); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return true
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		// H3：密码失败同计（此前 recovery-codes 完全无门、disable/setup 密码段不计数）。
		mfaGateRecordPasswordFailure(userID)
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "密码错误"})
		return true
	}
	return false
}

// confirmPasswordWithGate 审计 H3 共享密码确认门：「密码即全部确认」的端点共用
// （recovery-codes 重生成 / PATCH /users/me 改密 / 特权 API Key 创建），成功即清零
// 失败计数。密码失败与 MFA 验码失败共享 users.mfa_failed_attempts /
// mfa_locked_until（同一操作者身份确认的失败同源收敛），递增为单条条件 UPDATE
// 原子完成。失败路径响应已写入（401 密码错误 / 429 冷却 / 500 读库），调用方
// err != nil 直接 return。
func confirmPasswordWithGate(c *gin.Context, userID int, password string) error {
	if mfaGateCheckPassword(c, userID, password) {
		return errMfaGateRejected
	}
	_, _ = db.DB.Exec("UPDATE users SET mfa_failed_attempts=0 WHERE id=?", userID)
	return nil
}

// MFAVerifyStep POST /auth/mfa/verify-step — step-up：验证码 → 新 JWT（mfa_ts 刷新）。
func (h *Handlers) MFAVerifyStep(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := getContextUserIDInt(c)
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// R74 verify-step 硬门（B5 I-A 起与 disable/setup 重新绑定共用 mfaEndpointHardGate）。
	if mfaEndpointHardGate(c, userID) {
		return
	}
	if ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now()); !ok {
		recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "step-up 验证失败"))
		msg := "验证码错误"
		if verr != nil {
			msg = verr.Error()
		}
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: msg})
		return
	}
	// 重签 JWT：保留原身份声明，仅刷新 mfa_ts（与 respondLogin 同构；node_mode 重读）
	var user models.User
	var passwordVersion int64
	if err := db.DB.QueryRow(`SELECT id, username, role, display_name, is_enabled, created_at, last_login, password_version FROM users WHERE id=?`, userID).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &passwordVersion); err != nil || !user.IsEnabled {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不可用"})
		return
	}
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix(), false)
}

// —— Admin 端点 ——

// MFAResetByAdmin POST /users/:id/mfa/reset — 重置指定用户（含自己）。
// R72 二次（用户裁决）：重置需确认 + 校验——操作者自己启用了 MFA 时须提供有效
// 验证码（防会话劫持后一键拆第二因子）；操作者是管理员（admin 组路由门）或
// 目标即本人（self-service）。请求体可选 {code}。
func (h *Handlers) MFAResetByAdmin(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的用户 ID"})
		return
	}
	operatorID := getContextUserIDInt(c)
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 操作者自己启用 MFA → 必须验码（本人重置自己的 MFA 也一样——与
	// MFADisable 的双重确认同语义；无密码项：admin 路由已过 JWT + 用户管理
	// 确认弹框承担意图确认）。
	// R73（用户裁决）：写操作守卫（mfaStepUpGuard）开启时第一层豁免——守卫已对
	// 本写操作完成验码（60 秒窗内静默放行或 428→verify-step 刷新 mfa_ts），再验
	// 一次会在 TOTP 重放保护下同片互斥：verify-step 消费时间片后第一层无码可用，
	// 必 401（验证码错误→踢出登录→连续失败触发 10 分钟锁定）。
	// R73 补正（审计 IMPORTANT-3）：守卫真正验过码的只有 JWT 路径——mfaStepUpGuard
	// 按设计豁免 auth_type != "jwt"，API Key/MCP 机器身份不被守卫验码，豁免理由
	// 不成立，故不免第一层（R72 二次防劫持语义对机器身份同样保持）。守卫关闭
	// 或请求为机器身份时才走本层验码——此时守卫均不参与、无双重消费，重放保护
	// 照旧。
	if operatorMfa, err := services.MFAUserEnabled(operatorID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取操作者 MFA 状态失败"})
		return
	} else if operatorMfa && !(c.GetString("auth_type") == "jwt" && services.MFAWriteGuardEnabled()) {
		if ok, verr := services.MFAVerifyCode(operatorID, req.Code, time.Now()); !ok {
			// R72 七次：重置前置验码失败留痕——高敏动作的失败尝试与成功同等
			// 可审计（含 brute 尝试面）。
			recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("重置 MFA 前验证失败", services.AuditResultPart("failure")))
			msg := "验证码错误"
			if verr != nil {
				msg = verr.Error()
			}
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: msg})
			return
		}
	}
	var target string
	if err := db.DB.QueryRow("SELECT username FROM users WHERE id=?", id).Scan(&target); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if err := services.MFAResetForUser(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// R72：detail 同时写目标用户与操作者（username 列即操作者；本人重置时两者相同，
	// 跨用户重置时 detail 可区分——此前仅「用户 X」在列表中无法判断是自重置还是
	// 管理员代重置）。
	detail := fmt.Sprintf("目标用户 %s", target)
	if operatorName := c.GetString("username"); operatorName != target {
		detail = fmt.Sprintf("目标用户 %s（由 %s 操作）", target, operatorName)
	}
	recordAudit(c, "重置", "用户认证", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已重置用户 MFA（用户需重新绑定）"})
}
