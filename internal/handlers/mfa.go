package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// —— 公开端点（loginRateLimit 由路由注册挂载，同 /auth/login）——

// rejectMFAChallengeLogin 「挑战无效」统一拒绝（MFAVerifyLogin 四出口单源）：
// 无效/过期/禁用/密码版本失配/行消失同形 401 + 同文案审计——不泄露具体原因。
func rejectMFAChallengeLogin(c *gin.Context) {
	// 挑战无效不泄露具体原因
	services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战令牌无效或已过期"), c.ClientIP())
	c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战无效或已过期，请重新登录"})
}

// mfaLoginInflight 同一挑战令牌的验码串行化。先消费后验码使「同一 token 的
// 两笔并发请求」互斥：A 消费成功后 B 立即在「已被使用」上落败，而 A 若验码失败
// 会归还挑战——B 本可成功却被劝退，且其 401 被审计为「挑战已被使用」，使该
// 审计不再是可靠的重放信号。此表只登记正在验码的令牌（TryLock 失败即 409，
// 不阻塞 goroutine），请求结束即删除，无长期驻留。
var (
	mfaLoginInflightMu sync.Mutex
	mfaLoginInflight   = map[string]struct{}{}
)

// tryLockMFAChallengeToken 标记令牌正在验码；false=已有请求在验码。
func tryLockMFAChallengeToken(token string) bool {
	mfaLoginInflightMu.Lock()
	defer mfaLoginInflightMu.Unlock()
	if _, busy := mfaLoginInflight[token]; busy {
		return false
	}
	mfaLoginInflight[token] = struct{}{}
	return true
}

// unlockMFAChallengeToken 解除标记（必须与成功的 tryLock 成对调用）。
func unlockMFAChallengeToken(token string) {
	mfaLoginInflightMu.Lock()
	delete(mfaLoginInflight, token)
	mfaLoginInflightMu.Unlock()
}

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
	var meta db.UserRowMeta
	var challengeVersion int64
	// 用户列清单单源（含 is_setup_admin 与 mfa_enabled），挑战表只追加
	// password_version 供版本绑定比对。
	user, err := db.ScanUserRow(db.DB.QueryRow(`SELECT `+db.UserRowColumns("u")+`, ch.password_version
		FROM mfa_challenges ch JOIN users u ON u.id = ch.user_id
		WHERE ch.token=? AND ch.expires_at > datetime('now')`, req.MFAToken), &meta, &challengeVersion)
	if err != nil {
		// DB 故障与无效挑战分判——基础设施错误 500，
		// 不再伪装成 401（挑战无效不泄露具体原因的口径仅适用于 ErrNoRows）。
		if !errors.Is(err, sql.ErrNoRows) {
			// 基础设施故障必须可观测：本端点 AuditPolicyExplicit，中间件不补
			// 审计——此前三处 500 分支零留痕，与 Login 的同型 internal_error
			// 口径不一致。
			services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战查询失败"), c.ClientIP())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
			return
		}
		rejectMFAChallengeLogin(c)
		return
	}
	if !user.IsEnabled {
		rejectMFAChallengeLogin(c)
		return
	}
	// 后续服务调用与响应构造共用单源扫描结果（user.ID 由查询载入，
	// passwordVersion 取自同一次扫描）。
	userID := user.ID
	passwordVersion := meta.PasswordVersion

	// 挑战绑定签发时的密码版本——签发后密码被改（自助/管理员重置），
	// 旧挑战即使持有有效第二因子也不得换取携带新 pwd_ver 的 JWT；顺带删除。
	if challengeVersion != passwordVersion {
		_, _ = db.DB.Exec("DELETE FROM mfa_challenges WHERE token=?", req.MFAToken)
		rejectMFAChallengeLogin(c)
		return
	}

	// 登录失败锁定（2026-09 用户裁定）：MFA 验证码失败与密码失败同计一个
	// 账户级计数（login_*），受「登录失败锁定」开关控制；锁定期间验证步直接
	// 429，不再消耗挑战次数。
	// 锁定状态/开关读取失败必须 （500，不消费挑战）——
	// 旧实现把 DB 错误静默当作「未锁定」。
	var loginLockedUntil sql.NullString
	if err := db.DB.QueryRow("SELECT login_locked_until FROM users WHERE id=?", userID).Scan(&loginLockedUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			rejectMFAChallengeLogin(c)
			return
		}
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "锁定状态读取失败"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	locked, lockErr := loginLockedNow(loginLockedUntil)
	if lockErr != nil {
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "锁定开关读取失败"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	if locked {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.FormatAuditDetail(services.AuditUserPart(userID, user.Username), "账户已锁定"), c.ClientIP())
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: fmt.Sprintf("账户已锁定，请 %d 分钟后重试", loginLockRemainingMinutes(loginLockedUntil, time.Now().UTC()))})
		return
	}

	// 同一挑战的并发验码互斥（见 mfaLoginInflight）：落败方既不能断言「挑战
	// 已被使用」（对方可能验码失败并归还），也不得重复验码（恢复码/时间片双
	// 花）。提示稍后重试，且不写「挑战已被使用」审计以保持重放信号纯粹。
	// 注意：此标记在消费之前、全部身份/锁定/版本门之后获取。
	if !tryLockMFAChallengeToken(req.MFAToken) {
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证进行中（并发请求）"), c.ClientIP())
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "验证进行中，请稍后重试"})
		return
	}
	defer unlockMFAChallengeToken(req.MFAToken)

	// 先消费挑战、后验码——消费判定是挑战状态的唯一权威（已消费/并发
	// 落败/过期窗口在此 401，不触碰凭证）；旧顺序先验码，恢复码「提交即消费」
	// 会在「挑战已被使用」路径白烧。验码失败归还挑战（错误码不烧挑战，同 token
	// 可重试；失败计数由 MFARecordChallengeFailure 负责，达阈值仍作废）。
	consumed, consumeErr := services.MFAConsumeChallenge(req.MFAToken, userID)
	if consumeErr != nil {
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战消费服务故障"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
		return
	}
	if !consumed {
		// 并发登录落败/挑战达阈值作废后的重放是爆破与
		// 外部竞态的观测面——与同函数其余拒绝分支同密度留痕（此前这是唯一
		// 无审计的拒绝分支，事后无法区分「客户端重试」与「重放已消费挑战」）。
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战已被使用"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战已被使用，请重新登录"})
		return
	}
	if ok, verr := services.MFAVerifyCode(userID, req.Code, time.Now()); !ok {
		services.MFARestoreChallenge(req.MFAToken, userID)
		if errors.Is(verr, services.ErrMFANotEnabled) {
			// 业务态：签发挑战后密钥被并发清除（禁用/重置）——按业务文案 400，
			// 不累加失败计数（不是验证码错误，也不锁账户）。
			services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "MFA 未启用"), c.ClientIP())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: verr.Error()})
			return
		}
		if verr != nil {
			// 查询/写库故障不是「验证码错误」——不审计验证码错误、
			// 不累加挑战级/账户级失败计数（否则基础设施抖动会烧掉挑战额度
			// 并把用户锁 10 分钟）。
			services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证服务故障"), c.ClientIP())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
			return
		}
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证码错误"), c.ClientIP())
		// 挑战级失败计数——分布式 IP 限流绕过下对单挑战的爆破收敛
		//（10 次作废，需重新走密码步取新挑战）。
		_ = services.MFARecordChallengeFailure(req.MFAToken)
		// 统一登录失败计数（开关语义见 recordLoginFailure）。
		recordLoginFailure(userID)
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误"})
		return
	}
	// 完整登录成功：清零登录失败计数与锁定（密码步未清零，见 Login 注释）。
	// 已验证的登录不因此撤销 JWT，但清零失败必须留痕，避免旧计数无声残留。
	if _, err := db.DB.Exec("UPDATE users SET login_failed_attempts=0, login_locked_until=NULL WHERE id=?", userID); err != nil {
		services.Logf("warn", "MFA 登录成功清零登录失败计数与锁定失败: user_id=%d: %v", userID, err)
	}
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix(), true)
}

// —— 自助端点（JWT）——

// MFAStatus GET /auth/mfa/status
func (h *Handlers) MFAStatus(c *gin.Context) {
	userID := int(contextUserID(c))
	st, err := services.MFAGetStatus(userID)
	if err != nil {
		// ErrNoRows 只可能是「鉴权与 handler 之间用户被并发删除」（jwtAuth 已
		// 校验存在/启用）——与全仓 401 约定一致，不诱导客户端重试。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
			return
		}
		// 其余为基础设施故障（列缺失/恢复码存储损坏/库锁）：固定文案 + 服务端
		// 留痕，不得零日志折叠成 500。
		mfaInternalFailure(c, "读取 MFA 状态", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: st})
}

// MFASetup POST /auth/mfa/setup — 生成 pending secret + otpauth URI（未启用）。
// 已启用 MFA 的用户重新 setup 需当前有效验证码确认（守卫验码放行
// 或本层验码，见下）——此前无任何门：持被劫持会话即可静默轮换第二因子
// （setup 响应明文返回新 secret + URI，攻击者配好自己的 authenticator 后
// activate 即夺取 MFA；受害者未启用场景则被强开攻击者控制的 MFA = 永久
// 登录 DoS）。未启用用户保持无门（首次绑定的可用性优先，会话本身已过密码
// 认证）。登录后不再有密码输入要求（2026-09 用户裁定），原注释
// 的「密码+验证码双重确认」已过时。
// rejectOIDCUserMFAOperation v2.3.0 用户裁定:OIDC 用户与本地 MFA 体系完全
// 解耦——对其禁止本地 MFA 的启用/激活/禁用/重置(身份保证在 IdP 侧)。
// targetUserID=0 表示操作自己(从 JWT 取)。
func rejectOIDCUserMFAOperation(c *gin.Context, targetUserID int) bool {
	uid := targetUserID
	if uid == 0 {
		uid = int(contextUserID(c))
	}
	provider, err := authProviderOf(c.Request.Context(), uid)
	if err != nil {
		// ErrNoRows=目标用户不存在(输入错误,404);真实读故障才是 500。
		// 两者都必须拒绝操作——身份来源不可判定时不按非 OIDC 放行。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
			return true
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户身份失败"})
		return true
	}
	if provider == "oidc" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "OIDC 用户不支持本地 MFA（身份验证由认证服务承担）"})
		return true
	}
	return false
}

// mfaVerifyFailureResponse 收敛「登录后验码失败」的响应与审计口径
// verr != nil = 查询/写库故障 → 500（不把底层 SQL 错误文本透给
// 客户端、也不写「验证码错误」误导排障）；verr == nil = 真验证码错误 → 调用方
// 既有审计文案 + 401。四处入口（重绑/禁用/step-up/管理员重置）共用，与 Login
// 的及 MFAActivate 已确立的三态口径一致。
func mfaVerifyFailureResponse(c *gin.Context, verr error, failureDetail string) {
	if errors.Is(verr, services.ErrMFANotEnabled) {
		// 业务态（用户未启用/已被并发禁用）：400 业务文案，与 MFAActivate 的
		// 三态口径一致（哨兵→400、真码错→401、基础设施故障→500）。
		// 与登录步（MFAVerifyLogin）同口径留痕——并发禁用/重置后的验码尝试
		// 是安全可观测面，不得零审计。
		recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "MFA 未启用"))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: verr.Error()})
		return
	}
	if verr != nil {
		recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("验证服务故障", services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
		return
	}
	recordAudit(c, "认证拒绝", "用户认证", failureDetail)
	c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误"})
}

// mfaInternalFailure 收敛 MFA 写端点的「基础设施故障」响应：固定
// 文案 + 服务端日志留痕，不把底层 SQL 错误文本透给客户端——与
// mfaVerifyFailureResponse / Login 已确立的三态口径一致；业务态错误由调用方
// 按哨兵错误映射 400，不走此路径。
func mfaInternalFailure(c *gin.Context, op string, err error) {
	services.Logf("error", "MFA %s 失败: %v", op, err)
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 操作失败，请稍后重试"})
}

func (h *Handlers) MFASetup(c *gin.Context) {
	// users 表在导入全量替代表清单内：MFA 状态列随表替换，窗口内写入会被
	// 静默覆盖（用户以为 MFA 已启用实被回滚）或阻塞至 busy_timeout——与
	// users/apikeys 写端点同口径 409 fast-fail，先于一切参数解析与身份判定。
	if rejectWriteDuringImport(c, "执行 MFA 写操作") {
		return
	}
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var mfaEnabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&mfaEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
			return
		}
		mfaInternalFailure(c, "读取 MFA 状态", err)
		return
	}
	if mfaEnabled {
		// 2026-09 用户裁定：登录后不再有密码输入要求——重绑仅验当前有效验证码
		//（验码确认保留；验码失败只提示不计数，全系统唯一锁定为
		// 登录阶段 5 次/10 分钟、受「登录失败锁定」开关控制）。
		var req struct {
			Code string `json:"code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
			return
		}
		// 守卫验码放行路径跳过本层验码(同 MFADisable)——拆除/重绑属高敏操作，
		// 仅守卫验码 ≤15s 的窄窗内豁免（mfaDestructiveStepUpWindow）。
		if !mfaStepUpVerifiedForDestructiveOp(c) {
			if mfaVerifyRateLimitedRejection(c, userID) {
				return
			}
			ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now())
			mfaRecordVerifyOutcome(userID, ok, verr)
			if !ok {
				mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("重绑 MFA 前验证失败", services.AuditResultPart("failure")))
				return
			}
		}
	}
	// otpauth 账号位用用户名（services/mfa.go 约定 accountName 即用户名；
	// jwtAuth/apiKeyAuth 均注入 c username）——此前用数字 ID，所有用户的
	// Authenticator 条目都显示「LazyBalancer:1」不可区分。空值回退数字 ID 保可用。
	username := c.GetString("username")
	if username == "" {
		username = strconv.FormatInt(contextUserID(c), 10)
	}
	secret, uri, err := services.MFAGenerateSecret(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 MFA 密钥失败"})
		return
	}
	// 单条 UPDATE 原子落库（新密钥 + 失败计数清零同生共死）——此前
	// 两段写（先清后设）在首成次败时已返回 200+secret 而 pending 为空，用户
	// 扫码后 activate 必报「没有待激活的 MFA 密钥」，且两语句间存在瞬时空窗。
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=?, mfa_pending_fails=0 WHERE id=?", secret, userID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 MFA 密钥失败"})
		return
	}
	// 已启用用户重绑时本步轮换 pending 密钥：此前零留痕，随后 activate 恒记
	// 「启用」，重绑与首绑在审计中不可区分（多管理员/被盗会话时无法归因）。
	// 首绑不记（activate 记「启用」），detail 不落 secret 任何片段。
	if mfaEnabled {
		recordAudit(c, "重新绑定", "用户认证", services.FormatAuditDetail("MFA pending 密钥已轮换", services.AuditResultPart("success")))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"secret": secret, "uri": uri}})
}

// MFAActivate POST /auth/mfa/activate — 验证当前码 → 启用 + 恢复码（仅此一次明文）。
func (h *Handlers) MFAActivate(c *gin.Context) {
	// 导入窗口 409（同 MFASetup——五个 MFA 写端点同门）。
	if rejectWriteDuringImport(c, "执行 MFA 写操作") {
		return
	}
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 先过内存滑动窗限流（与登录后验码同一 per-user 实现）：pending 校验的
	// 收敛此前完全依赖 DB 失败计数硬闸，DB 写不可用（只读挂载/磁盘满/
	// WAL 长占）时计数落不了库，5 次作废不生效，窗口内可对 10^6 码空间
	// 持续枚举。内存层不依赖 DB，故障期仍生效；DB 硬闸保留为跨进程/重启的
	// 二次防线（作废 pending 本身）。
	if mfaVerifyRateLimitedRejection(c, userID) {
		return
	}
	if ok, verr := services.MFAVerifyPending(userID, req.Code, time.Now()); !ok {
		if errors.Is(verr, services.ErrMFANoPendingSecret) {
			// 业务态哨兵（未 setup/pending 被并发覆盖）→ 400 业务文案，
			// 与 verify 四入口的 ErrMFANotEnabled→400 同口径——不得折叠成 500。
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: verr.Error()})
			return
		}
		if verr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
			return
		}
		// 真验证码错误：先在内存窗口记一次（不依赖 DB，故障期即是唯一硬闸），
		// 再落 DB 计数硬闸（达 5 次作废 pending，跨进程/重启有效）。
		services.MFARecordVerifyAttemptFailure(userID, time.Now())
		invalidated, ferr := services.MFARecordPendingFailure(userID)
		if ferr != nil {
			// 失败计数未落库 = DB 硬闸失效；fail-closed 500，不得以「验证码错误」
			// 回应让爆破继续。内存窗口（上方记账）仍限制尝试速率。
			mfaInternalFailure(c, "记录 MFA 绑定失败次数", ferr)
			return
		}
		if invalidated {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误次数过多，绑定已作废，请重新开始绑定"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "验证码错误，请确认 Authenticator 时间同步后重试"})
		return
	}
	services.MFAClearVerifyAttempts(userID)
	services.MFAClearPendingFailures(userID)
	codes, err := services.MFAActivate(userID)
	if err != nil {
		if errors.Is(err, services.ErrMFANoPendingSecret) || errors.Is(err, services.ErrMFASecretChanged) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		mfaInternalFailure(c, "激活", err)
		return
	}
	recordAudit(c, "启用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "MFA 已启用", Data: gin.H{"recovery_codes": codes}})
}

// MFADisable POST /auth/mfa/disable — 确认有效验证码后禁用（2026-09 用户裁定：
// 登录后无密码输入；验码失败只提示不计数，唯一锁定在登录阶段）。
func (h *Handlers) MFADisable(c *gin.Context) {
	// 导入窗口 409（同 MFASetup——五个 MFA 写端点同门）。
	if rejectWriteDuringImport(c, "执行 MFA 写操作") {
		return
	}
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 守卫验码放行路径(标记在)跳过
	// 本层验码——守卫/verify-step 已消费 TOTP 时间片,前端 428 重试带同码时
	// 同片重放拒绝使禁用流程结构性必 401;机器身份/守卫关(无标记)本层验码保持。
	// 拆除 MFA 收窄为 ≤15s 窄窗豁免（mfaDestructiveStepUpWindow）——60s 通用
	// 宽限窗内「仅凭会话拆第二因子」的链路由此关闭。
	if !mfaStepUpVerifiedForDestructiveOp(c) {
		if mfaVerifyRateLimitedRejection(c, userID) {
			return
		}
		ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now())
		mfaRecordVerifyOutcome(userID, ok, verr)
		if !ok {
			// 高敏动作的失败尝试与成功同等可审计（对齐 MFAResetByAdmin 前置验码失败留痕）。
			mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("禁用 MFA 前验证失败", services.AuditResultPart("failure")))
			return
		}
	}
	if err := services.MFAResetForUser(userID); err != nil {
		mfaInternalFailure(c, "禁用", err)
		return
	}
	recordAudit(c, "禁用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "MFA 已禁用"})
}

// MFARecoveryCodes POST /auth/mfa/recovery-codes — 重生成恢复码（2026-09 用户
// 裁定：登录后不再有密码输入要求，JWT 会话即确认；会话安全为信任边界）。
// 补 OIDC 门——五个 MFA 写入口仅此一处缺席，与
// setup/activate/disable 同为自助端点，targetUserID=0（操作自己，从 JWT 取）。
func (h *Handlers) MFARecoveryCodes(c *gin.Context) {
	// 导入窗口 409（同 MFASetup——五个 MFA 写端点同门）。
	if rejectWriteDuringImport(c, "执行 MFA 写操作") {
		return
	}
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var enabled bool
	// DB 读失败不得并入「MFA 未启用」400——缺行（并发删除）=401，基础设施
	// 故障=500 且留痕。
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
			return
		}
		mfaInternalFailure(c, "读取 MFA 状态", err)
		return
	}
	if !enabled {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MFA 未启用"})
		return
	}
	// 原地重写（旧码全部作废）
	codes, err := services.MFARegenerateRecoveryCodes(userID)
	if err != nil {
		mfaInternalFailure(c, "重生成恢复码", err)
		return
	}
	// （2026-09-05 审计裁定）：恢复码重生成是纯会话门下「旧码全作废+明文
	// 下发 10 个登录可用凭证」的高敏动作——成功留痕，与禁用/重置 MFA 同密度。
	recordAudit(c, "生成", "恢复码", services.FormatAuditDetail("MFA", "旧恢复码全部作废", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "恢复码已重新生成（旧码全部作废）", Data: gin.H{"recovery_codes": codes}})
}

// MFAVerifyStep POST /auth/mfa/ — 验证码 → 新 JWT（mfa_ts 刷新）。
func (h *Handlers) MFAVerifyStep(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if mfaVerifyRateLimitedRejection(c, userID) {
		return
	}
	ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now())
	mfaRecordVerifyOutcome(userID, ok, verr)
	if !ok {
		mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("MFA", "step-up 验证失败"))
		return
	}
	// 重签 JWT：保留原身份声明，仅刷新 mfa_ts（与 respondLogin 同构；node_mode 重读）
	var meta db.UserRowMeta
	// 重读用户的 DB 错误不得并入 401「用户不可用」
	// ——基础设施故障与并发删除/行缺失（sql.ErrNoRows）一律 500 fail-closed；
	// 仅读成功但 is_enabled=0 才 401「用户不可用」。（行缺失已在上一段
	// services.MFAVerifyTOTPCode 的同行查询先失败并走 500，此分支属纵深防御）
	// 列清单来自单源（auth_provider 与登录路径同口径）——漏列会让所有
	// step-up 响应的 auth_provider 变成 ""，且存量 OIDC 行（mfa_enabled=1）在
	// verify-step 成功后丢掉 auth_method=oidc 声明（middleware 的 MFA 门短路与
	// 集群票据直通依赖该声明）；is_setup_admin 同列清单载入，避免本路径响应
	// 与其他用户读取端点口径分裂。
	user, err := db.ScanUserRow(db.DB.QueryRow(`SELECT `+db.UserRowColumns("")+` FROM users WHERE id=?`, userID), &meta)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户信息失败"})
		return
	}
	if !user.IsEnabled {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不可用"})
		return
	}
	h.respondLoginWithMFA(c, user, meta.PasswordVersion, time.Now().Unix(), false)
}

// —— 写操作 step-up 判定（路由守卫与 handler 内联副本的单源）——

// step-up 判定的两类基建故障：判定逻辑只有一份，失败口径由调用方按各自裁定
// 保留（路由守卫 fail-open + warn 留痕；特权 Key 创建 fail-closed 500）。
var (
	ErrMFAStepUpGuardUnreadable = errors.New("MFA 写操作验证开关读取失败")
	ErrMFAStepUpStateUnreadable = errors.New("MFA 状态查询失败")
)

// mfaStepUpGraceWindow 宽限窗：距上次验码小于该值的写操作静默放行（TOTP 同片
// 不可重用，零窗会让相邻写操作结构性无码可用）。
const mfaStepUpGraceWindow = 60 * time.Second

// MFAStepUpDecision step-up 判定结果。
type MFAStepUpDecision struct {
	// Applies 请求属于 step-up 覆盖面（JWT 身份 + 守卫开 + 用户启用 MFA）。
	Applies bool
	// Verified 宽限窗内已验证（守卫据此置 mfa_stepup_verified 标记）。
	Verified bool
	// SecondsAgo 距上次验证的整秒数（响应头 X-Mfa-Verified-Seconds-Ago）。
	SecondsAgo int64
}

// mfaStepUpSecondsAgo 把验码年龄换算成对外报告/窄窗判定的秒数（向上取整）。
// int64 截断会把 15.9s 记成 15s，使「≤15s 窄窗」实际放宽到 16s（拆除/重绑
// MFA 免码窗的边界）；单源在此，判定与响应头共用。
func mfaStepUpSecondsAgo(elapsed time.Duration) int64 {
	return int64(math.Ceil(elapsed.Seconds()))
}

// DecideMFAStepUp 判定请求是否需要 MFA step-up 及是否已在宽限窗内通过。
// 调用方按自身路由语义给出 covered（守卫：写方法/敏感导出 GET；特权 API Key
// 创建：固定 true），其余短路条件必须单源——任一侧漏掉 OIDC 会话短路或只读
// 语义写路由豁免，就是 428 误弹码/二因子旁路。
// database 是开关读取的库句柄：守卫链上「同请求同源」——角色读取（调用方）、
// 开关读取（本函数）与 MFA 状态读取（mfaEnabledCheck）不得分叉到不同库。
// mfaEnabledCheck 由调用方注入（守卫保留测试注入点）。
func DecideMFAStepUp(c *gin.Context, covered bool, database *sql.DB, mfaEnabledCheck func(int) (bool, error)) (MFAStepUpDecision, error) {
	// 非写操作/非敏感 GET，或机器身份（API Key/MCP）——无 MFA 概念。
	if !covered || c.GetString("auth_type") != "jwt" {
		return MFAStepUpDecision{}, nil
	}
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	// step-up 机制本体（verify-step）与登出不得要求验码，否则 428→验码→再 428
	// 死锁；只读语义 POST（批量查询/测试/预览）与只读 API Key 同一事实源豁免。
	if path == "/api/v1/auth/mfa/verify-step" || path == "/api/v1/auth/logout" {
		return MFAStepUpDecision{}, nil
	}
	if services.IsReadOnlyWriteRoute(c.Request.Method, path) {
		return MFAStepUpDecision{}, nil
	}
	// OIDC 会话与本地 MFA 体系完全解耦（身份保证在 IdP），DB 查询前显式短路。
	if c.GetString("auth_method") == "oidc" {
		return MFAStepUpDecision{}, nil
	}
	guardEnabled, err := services.MFAWriteGuardEnabledWith(database)
	if err != nil {
		return MFAStepUpDecision{}, fmt.Errorf("%w: %v", ErrMFAStepUpGuardUnreadable, err)
	}
	if !guardEnabled {
		return MFAStepUpDecision{}, nil
	}
	userID, ok := userIDFromContext(c)
	if !ok {
		return MFAStepUpDecision{}, nil
	}
	mfaEnabled, err := mfaEnabledCheck(userID)
	if err != nil {
		return MFAStepUpDecision{}, fmt.Errorf("%w: %v", ErrMFAStepUpStateUnreadable, err)
	}
	if !mfaEnabled {
		// 本地未绑 MFA 保持直通。
		return MFAStepUpDecision{}, nil
	}
	mfaTs := c.GetFloat64("mfa_ts")
	elapsed := time.Since(time.Unix(int64(mfaTs), 0))
	if mfaTs > 0 {
		if elapsed < 0 {
			// 时钟回拨/VM 快照恢复会让旧 mfa_ts 落在未来：负年龄不得等价于
			// 「刚验证」。按未验证处理（fail-safe），并留痕以便定位时序故障。
			services.Logf("warn", "MFA step-up 时间戳在未来（时钟回拨？），按未验证处理: user_id=%d age=%s", userID, elapsed)
			return MFAStepUpDecision{Applies: true}, nil
		}
		if elapsed < mfaStepUpGraceWindow {
			// 向上取整：int64 截断会把 15.9s 记成 15s，使「≤15s 窄窗」实际放宽
			// 到 16s（拆除/重绑免码窗的边界）。
			return MFAStepUpDecision{Applies: true, Verified: true, SecondsAgo: mfaStepUpSecondsAgo(elapsed)}, nil
		}
	}
	return MFAStepUpDecision{Applies: true}, nil
}

// user_id 的类型化读取单源已收敛至 rule_features.go 的
// userIDFromContext（含 float64/int/int64/string 分支；string 分支为测试与
// MCP 转发路径的防御性兼容，生产 JWT 链路恒 float64）。

// —— Admin 端点 ——

// mfaStepUpVerifiedInContext:守卫(开启态)验码放行路径的标记优先;开关
// 关闭或机器身份时守卫未运行,无标记,本层验码保持（消除
// handler 重读开关的毫秒窗 TOCTOU——开关在中间件后翻转不再产生
// 「守卫未验码+本层跳过」的免验窗口)。(MFAResetByAdmin)起用,
// 提升为包级供 MFA 自助写端点(禁用/重绑确认)复用。
func mfaStepUpVerifiedInContext(c *gin.Context) bool {
	v, ok := c.Get("mfa_stepup_verified")
	return ok && v == true
}

// mfaDestructiveStepUpWindow 拆除/重绑 MFA 的免码窗：通用 60s 宽限窗对
// 「拆第二因子」过宽——持会话者（XSS/令牌泄露）可在窗口内免码禁用 MFA 或
// 轮换 pending secret，把账户永久降级为单因子。收窄为 ≤15s：守卫验码后
// 立即发起的拆除操作沿用标记免验（同片重放结构性 401 的接缝语义保持），
// 超过 15s 回落本层验码（需提供下一时间片的有效码）。
// 取舍：可用性让渡——窗口外的拆除操作需再等一个时间片输码，
// 换取「60s 窗内仅凭会话拆 MFA」链路的关闭。
const mfaDestructiveStepUpWindow = 15 * time.Second

// mfaStepUpVerifiedForDestructiveOp 拆除/重绑 MFA 的标记判定：标记在且
// 守卫验码距今 ≤15s 才豁免本层验码；年龄键缺失/类型不符（旧守卫或测试
// 注入缺键）一律不免验，回落本层验码（fail-safe）。
func mfaStepUpVerifiedForDestructiveOp(c *gin.Context) bool {
	if !mfaStepUpVerifiedInContext(c) {
		return false
	}
	ago, ok := c.Get("mfa_stepup_seconds_ago")
	secs, isInt64 := ago.(int64)
	if !ok || !isInt64 {
		return false
	}
	return secs <= int64(mfaDestructiveStepUpWindow.Seconds())
}

// mfaVerifyRateLimitedRejection 登录后验码的仅限流门（per-user 滑动窗
// 5 次失败/60s → 429，成功清零；不置锁不锁定——2026-09「登录后验码只提示
// 不计数不锁定」裁定保持，本层只是爆破速率收敛）。四处登录后验码入口
// （verify-step/禁用/重绑确认/管理员重置前置验码）共用。
func mfaVerifyRateLimitedRejection(c *gin.Context, userID int) bool {
	if !services.MFAVerifyAttemptLimited(userID, time.Now()) {
		return false
	}
	recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验码尝试过于频繁（限流）"))
	c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "验证码尝试过于频繁，请稍后再试"})
	return true
}

// mfaRecordVerifyOutcome 验码结果记账单源：真验证码错误（verr==nil）计一次
// 限流失败；成功清零。基础设施故障与业务态哨兵（ErrMFANotEnabled）不计——
// 抖动不得消耗用户的限流预算。
func mfaRecordVerifyOutcome(userID int, ok bool, verr error) {
	if ok {
		services.MFAClearVerifyAttempts(userID)
		return
	}
	if verr == nil {
		services.MFARecordVerifyAttemptFailure(userID, time.Now())
	}
}

// MFAResetByAdmin POST /users/:id/mfa/reset — 仅 admin 组可达（middleware.go
// 路由门）；本人自助解绑请用 POST /auth/mfa/disable。重置需确认 + 校验——操作者
// 自己启用了 MFA 时须提供有效验证码（防会话劫持后一键拆第二因子）。请求体
// 可选 {code}。
func (h *Handlers) MFAResetByAdmin(c *gin.Context) {
	// 导入窗口 409（同 MFASetup——五个 MFA 写端点同门），先于路径参数解析。
	if rejectWriteDuringImport(c, "执行 MFA 写操作") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的用户 ID"})
		return
	}
	if rejectOIDCUserMFAOperation(c, id) {
		return
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	operatorID := int(contextUserID(c))
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
	// （用户裁决）：写操作守卫（mfaStepUpGuard）开启时第一层豁免——守卫已对
	// 本写操作完成验码（60 秒窗内静默放行或 428→verify-step 刷新 mfa_ts；拆除
	// MFA 另收窄为验码 ≤15s 窄窗，见 mfaDestructiveStepUpWindow），再验
	// 一次会在 TOTP 重放保护下同片互斥：verify-step 消费时间片后第一层无码可用，
	// 必 401（验证码错误→踢出登录→连续失败触发 10 分钟锁定）。
	// mfaStepUpVerifiedInContext:守卫(开启态)验码放行路径的标记优先;开关
	// 关闭或机器身份时守卫未运行,无标记,本层验码保持（消除
	// handler 重读开关的毫秒窗 TOCTOU——开关在中间件后翻转不再产生
	// 「守卫未验码+本层跳过」的免验窗口)。
	// 补正（审计 问题-3）：守卫真正验过码的只有 JWT 路径——mfaStepUpGuard
	// 按设计豁免 auth_type != "jwt"，API Key/MCP 机器身份不被守卫验码，豁免理由
	// 不成立，故不免第一层（防劫持语义对机器身份同样保持）。守卫关闭
	// 或请求为机器身份时才走本层验码——此时守卫均不参与、无双重消费，重放保护
	// 照旧。
	if operatorMfa, err := services.MFAUserEnabled(operatorID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取操作者 MFA 状态失败"})
		return
	} else if operatorMfa && !mfaStepUpVerifiedForDestructiveOp(c) {
		// 管理员拆除 MFA 同样收窄为守卫验码 ≤15s 窄窗豁免（与自助 disable 同口径）。
		if mfaVerifyRateLimitedRejection(c, operatorID) {
			return
		}
		ok, verr := services.MFAVerifyCode(operatorID, req.Code, time.Now())
		mfaRecordVerifyOutcome(operatorID, ok, verr)
		if !ok {
			// 重置前置验码失败留痕——高敏动作的失败尝试与成功同等
			// 可审计（含 brute 尝试面）。
			mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("重置 MFA 前验证失败", services.AuditResultPart("failure")))
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
		mfaInternalFailure(c, "管理员重置", err)
		return
	}
	// detail 同时写目标用户与操作者（username 列即操作者；本人重置时两者相同，
	// 跨用户重置时 detail 可区分——此前仅「用户 X」在列表中无法判断是自重置还是
	// 管理员代重置）。
	detail := fmt.Sprintf("目标用户 %s", target)
	if operatorName := c.GetString("username"); operatorName != target {
		detail = fmt.Sprintf("目标用户 %s（由 %s 操作）", target, operatorName)
	}
	recordAudit(c, "重置", "用户认证", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已重置用户 MFA（用户需重新绑定）"})
}
