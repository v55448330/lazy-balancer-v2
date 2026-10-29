package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// maxAuthJSONBodyBytes 公开 auth 端点（login/setup/ticket-login）的 JSON 请求体
// 上限。这三条路由无认证，前置 loginRateLimit 只限次数不限体积；
// encoding/json 在 binding max= 约束生效前就把整个字符串物化进堆——单个超大
// password 字段即 O(n) 分配，ReadTimeout=30s 下单请求载荷可达带宽×30s，足以
// OOM 单进程应用并连带容器内 Caddy 子进程（与问题/ 认证
// 后同款模式的公开端点补齐）。合法登录/setup/ticket body 恒 <2KB，64KB 为
// 不变量边界而非可调参数，故不做配置项。
const maxAuthJSONBodyBytes int64 = 64 << 10

// guardAuthJSONBody 预检 ContentLength 并包装 MaxBytesReader；超限写 413 并
// 返回 false（调用方立即 return）。读中途超限时 MaxBytesReader 使后续
// ShouldBindJSON 报错走既有 400 分支。
func guardAuthJSONBody(c *gin.Context) bool {
	if c.Request.ContentLength > maxAuthJSONBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAuthJSONBodyBytes)
	return true
}

// loginDummyBcryptHash 用户不存在路径的等时占位哈希：ErrNoRows 直接
// 401 会以 ~bcrypt 耗时差区分用户名存在性（时序侧信道）。init 生成一次，
// DefaultCost 与生产真实哈希同档；对不存在的用户也跑一次注定失败的比较。
var loginDummyBcryptHash []byte

// loginDummyCompare 是未知用户名等时比较的注入点：生产恒为
// bcrypt.CompareHashAndPassword，测试可替换它以断言「未知用户路径确实执行了
// 一次 dummy 比较」（删掉比较语句或改写快路径都会变红）。时序本身不做毫秒级
// 断言（CI 抖动必然 flaky）。
var loginDummyCompare = bcrypt.CompareHashAndPassword

func init() {
	loginDummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("lazy-balancer timing-equalizer dummy"), bcrypt.DefaultCost)
}

// loginCompareHash 返回登录密码比较用的 bcrypt 哈希:OIDC JIT
// 用户 password_hash 为空(auth_oidc.go:476 置空),空哈希使
// bcrypt.CompareHashAndPassword 走格式错误快路径(µs 级),时序差会暴露
// 「该用户名存在但无本地密码」——改用 loginDummyBcryptHash 等时占位,与
// 上方 ErrNoRows 路径同型。
func loginCompareHash(passwordHash string) []byte {
	if passwordHash == "" {
		return loginDummyBcryptHash
	}
	return []byte(passwordHash)
}

// 登录失败锁定阈值/冷却（2026-09 用户裁定：登录阶段密码与 MFA 验证失败同计
// 一个账户级计数，受基础设置「登录失败锁定」开关 mfa_lockout_enabled 控制——
// 开关关闭则只计数不锁定；初版的「常开」语义据此调整为开关语义）。
const (
	loginLockMaxAttempts = 5
	loginLockCooldown    = 10 * time.Minute
)

// loginLockoutEnabled 读「登录失败锁定」开关（与 services.MFALockoutEnabled
// 同一配置项；handler 侧就近封装避免跨包零散查询）。
// 错误向上传播——锁定门不得因配置读取失败静默降级为关闭。
func loginLockoutEnabled() (bool, error) {
	return services.MFALockoutEnabled()
}

// recordLoginFailure 登录阶段失败（密码或 MFA 验证码）的单条条件 UPDATE 原子
// 递增——开关开启且 ≥5 同语句置锁并清零（避免锁满后再计延长冷却）；开关关闭
// 仅累加计数不置锁（与 mfaRecordFailure 的开关语义同型）。（历史
// 裁定·有意设计）：关闭期累计的计数不清零，重新开启后立即参与判定——失败
// 计数是事实，关闭期清零反而给免费重置窗口。
func recordLoginFailure(userID int) {
	now := time.Now()
	enabled, err := loginLockoutEnabled()
	if err != nil {
		// 开关读不到时按「开启」处理（fail-closed）——失败计数与
		// 锁定门不得因基础设施故障静默消失；故障本身留运行日志。
		services.Logf("error", "读取登录失败锁定开关失败（按开启处理）: %v", err)
		enabled = true
	}
	if !enabled {
		if _, err := db.DB.Exec(`UPDATE users SET login_failed_attempts=COALESCE(login_failed_attempts,0)+1 WHERE id=?`, userID); err != nil {
			// 记账失败不改变认证响应（失败仍是失败），但必须留痕——
			// 否则「登录失败计数/账户锁定」静默失效，暴力破解计数形同虚设。
			services.Logf("error", "登录失败计数写入失败（账户锁定可能失效）: user_id=%d: %v", userID, err)
		}
		return
	}
	if _, err := db.DB.Exec(`UPDATE users SET
		login_failed_attempts=CASE WHEN COALESCE(login_failed_attempts,0)+1>=? THEN 0 ELSE COALESCE(login_failed_attempts,0)+1 END,
		login_locked_until=CASE WHEN COALESCE(login_failed_attempts,0)+1>=? THEN ? ELSE login_locked_until END
		WHERE id=?`,
		loginLockMaxAttempts, loginLockMaxAttempts,
		now.Add(loginLockCooldown).UTC().Format("2006-01-02 15:04:05"), userID); err != nil {
		services.Logf("error", "登录失败计数写入失败（账户锁定可能失效）: user_id=%d: %v", userID, err)
	}
}

// parseLoginLockedUntil 锁定时间解析单源——写侧恒为 UTC「2006-01-02 15:04:05」，
// 兼容带外写入的 RFC3339/毫秒/带时区偏移形态（导入/手工修库）。两函数
// （判定与文案）共用，不再字符串比较（'T' 与 ' ' 的字典序比较在同日边界会错判
// 且对 RFC3339 形态恒判已锁定）。解析失败仍按锁定 fail-closed——但布局覆盖
// 已知带外形态，避免任何一种落入「解析失败 → 永久锁定」的不可自愈分支。
func parseLoginLockedUntil(raw string) (time.Time, bool) {
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05Z07:00",
		time.RFC3339,
		time.RFC3339Nano,
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// loginLockedNow 账户当前是否处于登录锁定（开关关闭视为未锁）。
// 开关读取失败返回错误，由调用方 fail-closed（500），不得把
// 「读不到」当作「未锁定」放行。锁值非空但解析失败（损坏形态）同样
// fail-closed 按锁定处理——存在锁值即不放行。
func loginLockedNow(lockedUntil sql.NullString) (bool, error) {
	enabled, err := loginLockoutEnabled()
	if err != nil {
		return false, err
	}
	if !enabled || !lockedUntil.Valid {
		return false, nil
	}
	until, ok := parseLoginLockedUntil(lockedUntil.String)
	if !ok {
		return true, nil
	}
	return until.After(time.Now().UTC()), nil
}

// loginLockRemainingMinutes 剩余锁定时长（分钟，向上取整，下限 1）——锁定
// 文案据此派生：硬编码「10 分钟」与 loginLockCooldown 漂移，
// 且锁定中途重试时剩余时长本就更短。解析失败/无值兜底为冷却全长。
func loginLockRemainingMinutes(lockedUntil sql.NullString, now time.Time) int {
	fallback := int(loginLockCooldown / time.Minute)
	if !lockedUntil.Valid {
		return fallback
	}
	until, ok := parseLoginLockedUntil(lockedUntil.String)
	if !ok {
		return fallback
	}
	remaining := int(math.Ceil(until.Sub(now).Minutes()))
	if remaining < 1 {
		return 1
	}
	return remaining
}

func (h *Handlers) Login(c *gin.Context) {
	var req models.LoginRequest
	if !guardAuthJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		services.RecordAuditLog("", "登录失败", "用户认证", services.AuditResultPart("invalid_request"), c.ClientIP())
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	// 用户行列清单来自 db.UserRowColumns 单源（含 mfa_enabled/is_setup_admin
	// ——登录响应与其余用户读取端点同口径）；password_hash/login_locked_until
	// 仅为本路径需要的追加列。
	var meta db.UserRowMeta
	var passwordHash string
	var loginLockedUntil sql.NullString
	user, err := db.ScanUserRow(db.DB.QueryRow("SELECT "+db.UserRowColumns("")+", password_hash, login_locked_until FROM users WHERE username = ?", req.Username),
		&meta, &passwordHash, &loginLockedUntil)

	if err == sql.ErrNoRows {
		// 对不存在的用户名也执行一次注定失败的 bcrypt 比较（结果刻意
		// 丢弃，只取等时副作用），消除与「密码错误」路径的时序差后返回同形 401。
		_ = loginDummyCompare(loginDummyBcryptHash, []byte(req.Password))
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("invalid_credentials"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户名或密码错误"})
		return
	}
	if err != nil {
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	// 登录失败锁定（用户裁定：受「登录失败锁定」开关控制）。锁定期间仍跑一次
	// 真实 bcrypt 再 429——等时占位，与「用户名或密码错误」路径同耗时，不泄露
	// 锁定账户的密码正误（防枚举）。
	locked, lockErr := loginLockedNow(loginLockedUntil)
	if lockErr != nil {
		// 开关读取失败 fail-closed——不进入认证流程。
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	if locked {
		_ = bcrypt.CompareHashAndPassword(loginCompareHash(passwordHash), []byte(req.Password))
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.FormatAuditDetail(services.AuditUserPart(user.ID, user.Username), "账户已锁定"), c.ClientIP())
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: fmt.Sprintf("账户已锁定，请 %d 分钟后重试", loginLockRemainingMinutes(loginLockedUntil, time.Now().UTC()))})
		return
	}

	// 空哈希(OIDC JIT 用户)等时比较只取耗时
	// 副作用,结果必须恒败——dummy 明文是源码公开常量,比较通过不得成为
	// 认证依据(auth_oidc.go:476 的设计不变量「OIDC 用户密码登录天然不可
	// 用」由本分支显式承载,不再依赖 bcrypt 对空哈希的格式错误行为)。
	compareErr := bcrypt.CompareHashAndPassword(loginCompareHash(passwordHash), []byte(req.Password))
	if passwordHash == "" {
		compareErr = bcrypt.ErrHashTooShort
	}
	if compareErr != nil {
		recordLoginFailure(user.ID)
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("invalid_credentials"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户名或密码错误"})
		return
	}
	if !user.IsEnabled {
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.FormatAuditDetail(services.AuditUserPart(user.ID, user.Username), "账号已禁用"), c.ClientIP())
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "账号已禁用，请联系管理员"})
		return
	}

	// v2.1.8 MFA 两步登录：密码通过且用户已启用 MFA → 签发 5 分钟单次挑战，
	// 不发 JWT；前端携 mfa_token 调 /auth/mfa/verify。
	// MFA 是主认证控制（非纵深层），is_enabled 读取已并入本次用户查询：读库
	// 失败在上面统一 500（fail-closed）——此前 mfa_enabled 单独查询失败落穿
	// respondLogin 直接发 JWT，构成二因子静默绕过。
	if meta.MFAEnabled {
		// 密码正确但账户启用 MFA 时不在密码步清零计数——完整登录以 MFA 验证
		// 成功为准（否则「输对密码→连错 4 次验证码→重登清零」可无限绕过锁定）；
		// 未启用 MFA 则密码即完整登录，清零计数。
		mfaToken, ierr := services.MFAIssueChallenge(user.ID)
		if ierr != nil {
			// 基础设施故障（挑战表损坏/写库失败）必须留痕：与同函数其余 500
			// 分支及 MFAVerifyLogin 的三处故障留痕同口径，否则「密码正确却
			// 拿不到挑战」在审计里完全不可见。
			services.Logf("error", "登录: 签发 MFA 挑战失败: user_id=%d: %v", user.ID, ierr)
			services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "签发 MFA 挑战失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"mfa_required": true, "mfa_token": mfaToken})
		return
	}
	// 完整登录成功（无 MFA）：清零登录失败计数与锁定。已验证登录不因收尾
	// 清零失败撤销 JWT，但旧计数残留必须留痕（与 MFA 成功路径同口径）。
	if _, err := db.DB.Exec("UPDATE users SET login_failed_attempts=0, login_locked_until=NULL WHERE id=?", user.ID); err != nil {
		services.Logf("warn", "登录成功清零登录失败计数与锁定失败: user_id=%d: %v", user.ID, err)
	}

	h.respondLoginWithMFA(c, user, meta.PasswordVersion, 0, true, "")
}

// loginExpireMinutes 读取 global_config.jwt_expire_minutes 并钳制到合法区间
// （≤0 或 >1440 或查询失败一律回退 20）。仅由 signSessionJWT 消费，
// 密码/MFA 与 OIDC 会话的令牌有效期因此保持同一口径。
func loginExpireMinutes() int {
	expireMinutes := 20
	if err := db.DB.QueryRow("SELECT COALESCE(jwt_expire_minutes,20) FROM global_config WHERE id=1").Scan(&expireMinutes); err != nil || expireMinutes <= 0 || expireMinutes > 1440 {
		return 20
	}
	return expireMinutes
}

// jwtJTIReader 生成 jti 的随机源（生产恒 crypto/rand.Read）。仅测试替换，
// 用于构造「签发失败」分支（验证失败路径不推进 last_login）。
var jwtJTIReader = rand.Read

// lastLoginTouchFailing 登录成功记账的连续失败状态：首条失败升级为 error 级
// 留痕（持久故障可见），后续失败降回 warn，成功后复位——登录热路径不得刷屏。
var lastLoginTouchFailing atomic.Bool

// touchLastLogin 登录成功后的 last_login 记账（单源：密码登录与 OIDC 回调
// 共用同一顺序与错误策略）。
//
// 顺序口径（两条路径统一）：签发成功 → 审计「登录成功」 → last_login 尽力
// 更新。last_login 是账号活动证据而非授权前提：记账失败不得撤销已签发的
// 会话（旧密码路径 500 丢令牌、旧 OIDC 路径 warn 放行，两条路径的审计与
// 活动证据因此可能互相矛盾）。失败必须留痕：连续失败的首条升级为 error 级。
func touchLastLogin(userID int, username, clientIP string) (time.Time, bool) {
	lastLogin := time.Now().UTC()
	_, err := db.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", lastLogin, userID)
	if err == nil {
		lastLoginTouchFailing.Store(false)
		return lastLogin, true
	}
	level := "warn"
	if !lastLoginTouchFailing.Swap(true) {
		level = "error"
	}
	services.Logf(level, "登录成功更新 last_login 失败（user_id=%d username=%s client_ip=%s）: %v", userID, username, clientIP, err)
	return lastLogin, false
}

// signSessionJWT 是本地密码/MFA 与 OIDC 会话的唯一签发点：公共声明、jti
// 随机源与过期钳制在此收敛。mfaTs<=0 不写 mfa_ts；authMethod 空串不写
// auth_method（本地会话历史契约），OIDC 调用方显式传 "oidc"。
func signSessionJWT(secret string, userID int, username, role string, passwordVersion int64, mfaTs int64, authMethod string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(time.Duration(loginExpireMinutes()) * time.Minute)
	jtiBytes := make([]byte, 32)
	if _, err := jwtJTIReader(jtiBytes); err != nil {
		return "", time.Time{}, err
	}
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"pwd_ver":  passwordVersion,
		"jti":      hex.EncodeToString(jtiBytes),
		"iat":      now.Unix(),
		"exp":      expiresAt.Unix(),
	}
	if mfaTs > 0 {
		claims["mfa_ts"] = mfaTs
	}
	if authMethod != "" {
		claims["auth_method"] = authMethod
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expiresAt, nil
}

// respondLoginWithMFA 携带 mfa_ts 声明签发（0=未验证/不写入——非 MFA 用户登录、
// MFA 首次签发在 verify 成功时传 now；票据登录暂传 0）。isLogin=false 时跳过
// 登录审计与 last_login 更新（verify-step 的 step-up 场景， D-新6）。
func (h *Handlers) respondLoginWithMFA(c *gin.Context, user models.User, passwordVersion int64, mfaTs int64, isLogin bool, authMethod string) {
	// node_mode 仅用于登录响应体的展示字段（JWT claim 已删除——
	// jwtAuth 不消费，客户端声明无意义；响应体 NodeMode 保留）。
	// 三态化：角色查询失败/库未装配不得静默呈现 master——写闸与 /system/info
	// 对同一故障分别是 fail-closed 500 与 unknown，登录响应给 master 会让前端
	// 按可写视图放行（授权侧仍拒，但排障方向被误导）。
	nodeMode := "unknown"
	if db.DB == nil {
		services.Logf("warn", "login: 数据库未装配，节点角色未知（node_mode=unknown）")
	} else if isMaster, err := services.RoleOf(c.Request.Context(), db.DB); err != nil {
		services.Logf("warn", "login: 节点角色查询失败，按 unknown 下发（前端只读）: %v", err)
	} else if isMaster {
		nodeMode = "master"
	} else {
		nodeMode = "slave"
	}

	// authMethod 由实际认证路径显式传入：本地密码登录即使读到导入遗留的
	// auth_provider=oidc 混合行，也不能获得 OIDC 的 MFA 写门豁免。
	tokenString, _, err := signSessionJWT(h.cfg.JWTSecret, user.ID, user.Username, user.Role, passwordVersion, mfaTs, authMethod)
	if err != nil {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "签发登录令牌失败"})
		return
	}
	if isLogin {
		// 与 OIDC 回调同序同源（touchLastLogin 单源）：先落「登录成功」审计
		// （身份已由签发结果确认），再尽力推进 last_login。旧实现把 last_login
		// 写失败当 500 并丢弃已签发令牌，与 OIDC 路径（warn 放行）分叉——
		// 取证时两条路径的「最后活动时间」与审计可信度不一致。
		services.RecordAuditLog(user.Username, "登录成功", "用户认证", services.FormatAuditDetail(services.AuditUserPart(user.ID, user.Username), services.AuditResultPart("success")), c.ClientIP())
		if lastLogin, ok := touchLastLogin(user.ID, user.Username, c.ClientIP()); ok {
			user.LastLogin = sql.NullTime{Time: lastLogin, Valid: true}
		}
	}

	// 登录/step-up 响应必须携带 mfa_enabled——此前所有登录路径的
	// user.mfa_enabled 恒 false，导致前端「登录从节点需先启用 MFA」预检对自己
	// 已启用的用户误报。标志经 NewUserResponse 签名单源填充（遗漏即
	// 编译失败）。与登录密码步的 mfa_enabled 判定查询为两处独立查询（历史
	// 裁定保留：step-up/登录共用本函数，透传会增加 MFA 关键流签名
	// 复杂度，代价仅一次索引点查）。
	var mfaEnabled int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", user.ID).Scan(&mfaEnabled); err != nil {
		// 查询失败此前静默保持 false——响应语义不变
		//（该字段为展示性预检），但错误必须留痕便于诊断。
		services.Logf("error", "login response mfa_enabled lookup: %v", err)
	}
	response := models.NewUserResponse(user, mfaEnabled == 1)

	c.JSON(http.StatusOK, models.LoginResponse{
		Token:    tokenString,
		User:     response,
		NodeMode: nodeMode,
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	// API Key 认证无会话令牌概念（jwtAuth 只为 JWT 写
	// token_revocation_hash/token_expires_at）——旧代码 API Key 登出恒落 500
	// 分支。对齐仓内 DELETE 幂等契约（重复调用 404——见 apidocs
	// operationDescription 的删除类约定），按「无会话令牌可吊销」返回 404。
	if c.GetString("auth_type") == "api_key" {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API 密钥认证无会话令牌可吊销"})
		return
	}
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	revocationHash := c.GetString("token_revocation_hash")
	expiresAt, ok := c.Get("token_expires_at")
	expiresAtTime, valid := expiresAt.(time.Time)
	if revocationHash == "" || !ok || !valid {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "登出失败"})
		return
	}
	if _, err := db.DB.Exec("INSERT INTO revoked_jti (jti_hash,expires_at) VALUES (?,?) ON CONFLICT(jti_hash) DO UPDATE SET expires_at=excluded.expires_at", revocationHash, expiresAtTime.UTC().Format(models.RevokedTokenTimeFormat)); err != nil {
		services.Logf("error", "登出吊销会话失败（令牌尚未吊销）: username=%s: %v", usernameStr, err)
		services.RecordAuditLog(usernameStr, "登出", "用户认证", services.AuditResultPart("failure"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "登出失败"})
		return
	}
	services.RecordAuditLog(usernameStr, "登出", "用户认证", services.AuditResultPart("success"), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已退出登录"})
}

func (h *Handlers) GetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "未登录或登录已过期"})
		return
	}

	// 复用 contextUserID。
	userIDInt := int(contextUserID(c))

	var meta db.UserRowMeta
	user, err := db.ScanUserRow(db.DB.QueryRow(`SELECT `+db.UserRowColumns("")+` FROM users WHERE id = ?`, userIDInt), &meta)

	if err != nil {
		// 基础设施故障与用户不存在不可混同：鉴权层之后、本查询之前用户被
		// 并发删除时 ErrNoRows 不是 500——与 jwtAuth 同文案 401，客户端据此
		// 重新登录而不是重试。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}

	// AuthProvider/IsSetupAdmin 均由单源查询载入，构造器单点复制（不再
	// 手工补字段——历史上正因手工补漏项，OIDC 来源与 break-glass 标记
	// 在同一端点上先后缺失）。
	response := models.NewUserResponse(user, meta.MFAEnabled)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: response})
}

type UpdateCurrentUserRequest struct {
	DisplayName *string `json:"display_name" binding:"omitempty,max=50"`
	// bcrypt 的字节上限 72——x/crypto v0.55+ 超出即返回 ErrPasswordTooLong
	// (密码策略:8-24 可打印 ASCII,四类字符)
	// 同族：binding 只拦空，长度/复杂度交
	// validatePasswordPolicy 友好文案（CurrentPassword 例外见下）。
	Password string `json:"password" binding:"omitempty"`
	// （用户已批准契约，2026-09 裁定保留——登录后密码确认门）：提交新
	// 密码时必须携带当前密码过共享确认门——此前仅凭会话即可改密，劫持会话可直接
	// 置换密码把原主锁在门外。仅改昵称不要求。
	// 边界精确化：本端点（PATCH /users/me）不是「唯一」改密入口——重置语义的
	// 入口（PUT /users/:id 的 password 字段、POST /users/:id/reset-password）
	// 不验当前密码，仅会话/角色门（见 users.go ResetUserPassword 注释与
	// middleware 的 adminOrSelfParam）。安全评审不得据此假设「任何改密都要
	// 当前密码」。
	// 当前密码不套用新密码策略 8-24——登录不做策略校验（存量密码可能
	// 来自旧策略），25-72 字符的存量密码必须仍能自助更换；这里只保留 bcrypt
	// 物理上限 72（>72 字节比较必败，400 文案与 401 无行为差异）。
	CurrentPassword string `json:"current_password" binding:"omitempty,max=72"`
}

// 密码策略（2026-09-28 用户裁定）：8-24 个可打印 ASCII 字符，
// 仅限数字、大小写字母、特殊字符(可打印 ASCII)——不强制四类全含，
// 不允许汉字或其他非 ASCII 字符。仅适用于设置/修改/重置——登录不做策略校验
// （存量密码可能在旧策略下设置）。注：bcrypt 字节上限 72（v0.55 起 >72 返回
// ErrPasswordTooLong）——策略 24 字符 ASCII 上限远低于该界（删
// 陈旧常量名引用）。
const (
	minPasswordLength = 8
	maxPasswordLength = 24
)

// validatePasswordPolicy 密码策略校验（设置/修改/重置时调用）。
// 2026-09-28 用户裁定（修正）:仅限 8-24 个可打印 ASCII 字符(数字/大小写
// 字母/特殊字符),不允许汉字或其他非 ASCII——不强制四类字符必须全含。
func validatePasswordPolicy(password string) error {
	if password == "" {
		return nil // 空密码=不修改(UpdateCurrentUser/UpdateUser 的 omitempty 场景;
		// CreateUser/ResetUserPassword 由 binding required 拦截空值——
		// 修复：ResetUserPassword 曾误用 omitempty 致空密码可落库)
	}
	if len(password) < minPasswordLength {
		return fmt.Errorf("密码长度不能少于 %d 位", minPasswordLength)
	}
	if len(password) > maxPasswordLength {
		return fmt.Errorf("密码长度不能超过 %d 位", maxPasswordLength)
	}
	for _, r := range password {
		if r < 32 || r > 126 {
			return errors.New("密码仅支持数字、大小写字母和特殊字符，不允许汉字或其他非 ASCII 字符")
		}
	}
	return nil
}

// validateUsernamePolicy 用户名策略（2026-09-28 用户裁定）：仅允许小写英文
// 开头，字符只允许小写字母或小写字母+数字——不允许大写、汉字、特殊字符、
// 下划线、连字符。长度 3-50 由 binding 层覆盖。（裁定·双向
// 声明）：本策略仅约束本地创建/改名；OIDC JIT 开户有意豁免（IdP 源属性，
// 强行归一会破坏身份链——见 auth_oidc.go 开户分支同名声明）。
var usernamePolicyRe = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

func validateUsernamePolicy(username string) error {
	if !usernamePolicyRe.MatchString(username) {
		return errors.New("用户名仅允许小写英文开头，字符只允许小写字母或小写字母+数字")
	}
	return nil
}

func (h *Handlers) UpdateCurrentUser(c *gin.Context) {
	// users 在导入全量替代表清单内：窗口内写入会被静默覆盖或阻塞至
	// busy_timeout——与节点写族同口径 409 fast-fail，先于解析 body。
	if rejectWriteDuringImport(c, "执行用户写操作") {
		return
	}
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "未登录或登录已过期"})
		return
	}

	// 复用 contextUserID。
	userIDInt := int(contextUserID(c))

	var req UpdateCurrentUserRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 2026-09-18 用户裁定:OIDC 用户的显示名/密码源自 IdP——本地不可改,
	// 要改请去认证服务修改(自助路径)。门控按「值实际变化」判定（与
	// UpdateUser 同构）：非空密码恒视为改密尝试（门前置，保持 OIDC 400
	// 先于当前密码校验）；display_name 与库中同值属无变更的局部更新，
	// 在事务内读到旧值后再判（见下方 displayNameChanged）。
	if req.Password != "" {
		oidcUser, err := isOIDCUser(c.Request.Context(), userIDInt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户身份失败"})
			return
		}
		if oidcUser {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "OIDC 用户的显示名与密码由认证服务管理，请前往 OIDC 服务修改"})
			return
		}
	}
	if err := validatePasswordPolicy(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if req.Password != "" {
		// 2026-09 用户裁定：改密是登录后唯一需要密码确认的例外操作；失败仅
		// 401 不计数不锁定（全系统唯一锁定在登录阶段，5 次/10 分钟受开关控制）。
		if req.CurrentPassword == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "修改密码需提供当前密码"})
			return
		}
		var currentHash string
		if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", userIDInt).Scan(&currentHash); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
				return
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)) != nil {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "当前密码错误"})
			return
		}
	}
	var passwordHash string
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
			return
		}
		passwordHash = string(hash)
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "UpdateCurrentUser rollback failed for id=%d: %v", userIDInt, rollbackErr)
			}
		}
	}()

	var oldDisplayName string
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(display_name,'') FROM users WHERE id = ?", userIDInt).Scan(&oldDisplayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}

	// OIDC 门的 display_name 侧（值变化判定，见上方注释）：同值提交属无
	// 变更局部更新放行；改值才拦。与下方 UPDATE 分支同一谓词。
	displayNameChanged := req.DisplayName != nil && *req.DisplayName != oldDisplayName
	if displayNameChanged {
		oidcUser, err := isOIDCUser(c.Request.Context(), userIDInt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户身份失败"})
			return
		}
		if oidcUser {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "OIDC 用户的显示名与密码由认证服务管理，请前往 OIDC 服务修改"})
			return
		}
	}

	changed := []string{}
	sets := make([]string, 0, 3)
	args := make([]any, 0, 3)
	if displayNameChanged {
		sets = append(sets, "display_name = ?")
		args = append(args, *req.DisplayName)
		changed = append(changed, "昵称")
	}
	if passwordHash != "" {
		// 复用 passwordResetColumns——自助改密与管理员重置同语义，
		// 清空登录失败计数与锁定（否则锁定中的会话改密后仍被旧锁 429）。
		sets = append(sets, passwordResetColumns()...)
		args = append(args, passwordHash)
		changed = append(changed, "密码")
	}
	if len(sets) > 0 {
		args = append(args, userIDInt)
		if _, err := tx.ExecContext(c.Request.Context(), "UPDATE users SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
	}
	if passwordHash != "" {
		// 改密在同一事务内吊销在册 MFA 挑战（版本绑定是主防线，
		// 这里保证旧挑战不会以任何路径残留）。
		if err := revokeMFAChallenges(tx, userIDInt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
	}

	var meta db.UserRowMeta
	// 响应回填与 GET /users/me、登录响应同口径（单源列清单：mfa_enabled 与
	// is_setup_admin 一并载入）——此前 PATCH /users/me 恒返回 mfa_enabled=false，
	// is_setup_admin 同样恒 false，MFA 已启用用户/break-glass 判定被误导。
	user, err := db.ScanUserRow(tx.QueryRowContext(c.Request.Context(), `SELECT `+db.UserRowColumns("")+` FROM users WHERE id = ?`, userIDInt), &meta)

	if err != nil {
		// 鉴权层与本事务之间用户被并发删除：ErrNoRows=401（与 jwtAuth 同
		// 文案），不得折叠为 500 诱导客户端重试。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交用户更新失败"})
		return
	}
	committed = true

	if len(changed) == 0 {
		recordAudit(c, "更新信息", "用户", services.FormatAuditDetail(services.AuditUserPart(user.ID, user.Username), "无修改"))
	} else {
		recordAudit(c, "更新信息", "用户", services.FormatAuditDetail(services.AuditUserPart(user.ID, user.Username), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	response := models.NewUserResponse(user, meta.MFAEnabled)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: response})
}

// setupRoleAllowsInit 初始化端点（公开无 JWT）的角色判定：从节点返回 false，
// 主节点返回 true。真实读失败 fail-closed（由调用方 500）——与 readOnlyGuard/
// clusterVersionMiddleware 同口径；仅「global_config 缺行」（老库/未迁移形态，
// 与 RoleOf 内部 COALESCE(is_master,1) 的历史语义一致）按主节点处理，不得把
// 未迁移库当成瞬态故障。
func setupRoleAllowsInit(ctx context.Context) (bool, error) {
	isMaster, err := services.RoleOf(ctx, db.DB)
	if err == nil {
		return isMaster, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return false, err
}

func (h *Handlers) GetSetupStatus(c *gin.Context) {
	// 从节点无初始化语义——users 由主端同步,同步未收敛的瞬态空表
	// 不得引导建号(建号会被同步覆盖)。角色读失败 fail-closed 500。
	master, roleErr := setupRoleAllowsInit(c.Request.Context())
	if roleErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取节点角色失败"})
		return
	}
	if !master {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"needs_setup": false}})
		return
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查初始化状态失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"needs_setup": count == 0}})
}

func (h *Handlers) SetupAdmin(c *gin.Context) {
	// 从节点禁止初始化建号(公开路由无 JWT,is_master 读 global_config)；
	// 角色读失败 fail-closed 500（不得落回主节点语义放行建号）。
	master, roleErr := setupRoleAllowsInit(c.Request.Context())
	if roleErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取节点角色失败"})
		return
	}
	if !master {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "从节点不支持初始化，请在主节点完成初始化"})
		return
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查初始化状态失败"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "系统已完成初始化，请直接登录"})
		return
	}
	var req struct {
		Username    string `json:"username" binding:"required,min=3,max=50"`
		Password    string `json:"password" binding:"required"`
		DisplayName string `json:"display_name" binding:"max=50"`
	}
	if !guardAuthJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户名至少 3 位，密码至少 8 位"})
		return
	}
	if err := validateUsernamePolicy(req.Username); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validatePasswordPolicy(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
		return
	}
	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled, is_setup_admin) SELECT ?, ?, 'admin', ?, 1, 1 WHERE NOT EXISTS (SELECT 1 FROM users)",
		req.Username, string(hash), req.DisplayName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建管理员失败"})
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认管理员创建结果失败"})
		return
	}
	if affected == 0 {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "系统已完成初始化，请直接登录"})
		return
	}
	id, _ := result.LastInsertId()
	services.RecordAuditLog(req.Username, "创建", "用户", services.FormatAuditDetail(services.AuditUserPart(int(id), req.Username), "首个管理员，系统初始化"), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "管理员账号创建成功，请登录"})
}
