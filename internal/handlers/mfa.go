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
		// 2026-09 用户裁定：登录后不再有密码输入要求——重绑仅验当前有效验证码
		//（R72 F-1 的验码确认保留；验码失败只提示不计数，全系统唯一锁定为
		// 登录阶段 5 次/10 分钟、受「登录失败锁定」开关控制）。
		var req struct {
			Code string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
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

// MFADisable POST /auth/mfa/disable — 确认有效验证码后禁用（2026-09 用户裁定：
// 登录后无密码输入；验码失败只提示不计数，唯一锁定在登录阶段）。
func (h *Handlers) MFADisable(c *gin.Context) {
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

// MFARecoveryCodes POST /auth/mfa/recovery-codes — 重生成恢复码（2026-09 用户
// 裁定：登录后不再有密码输入要求，JWT 会话即确认；会话安全为信任边界）。
func (h *Handlers) MFARecoveryCodes(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := getContextUserIDInt(c)
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
