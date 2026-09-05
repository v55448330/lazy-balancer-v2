package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

const revokedTokenTimeFormat = "2006-01-02T15:04:05Z"

// maxAuthJSONBodyBytes 公开 auth 端点（login/setup/ticket-login）的 JSON 请求体
// 上限（R68 F-B1）。这三条路由无认证，前置 loginRateLimit 只限次数不限体积；
// encoding/json 在 binding max= 约束生效前就把整个字符串物化进堆——单个超大
// password 字段即 O(n) 分配，ReadTimeout=30s 下单请求载荷可达带宽×30s，足以
// OOM 单进程应用并连带容器内 Caddy 子进程（与 R36 BLOCKING-1/R62 C3-F1 认证
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

// loginDummyBcryptHash 用户不存在路径的等时占位哈希（D5-S5）：ErrNoRows 直接
// 401 会以 ~bcrypt 耗时差区分用户名存在性（时序侧信道）。init 生成一次，
// DefaultCost 与生产真实哈希同档；对不存在的用户也跑一次注定失败的比较。
var loginDummyBcryptHash []byte

func init() {
	loginDummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("lazy-balancer timing-equalizer dummy"), bcrypt.DefaultCost)
}

// 登录失败锁定阈值/冷却（2026-09 用户裁定：登录阶段密码与 MFA 验证失败同计
// 一个账户级计数，受基础设置「登录失败锁定」开关 mfa_lockout_enabled 控制——
// 开关关闭则只计数不锁定；M7 初版的「常开」语义据此调整为开关语义）。
const (
	loginLockMaxAttempts = 5
	loginLockCooldown    = 10 * time.Minute
)

// loginLockoutEnabled 读「登录失败锁定」开关（与 services.MFALockoutEnabled
// 同一配置项；handler 侧就近封装避免跨包零散查询）。
func loginLockoutEnabled() bool {
	return services.MFALockoutEnabled()
}

// recordLoginFailure 登录阶段失败（密码或 MFA 验证码）的单条条件 UPDATE 原子
// 递增——开关开启且 ≥5 同语句置锁并清零（避免锁满后再计延长冷却）；开关关闭
// 仅累加计数不置锁（与 mfaRecordFailure 的开关语义同型）。
func recordLoginFailure(userID int) {
	now := time.Now()
	if !loginLockoutEnabled() {
		_, _ = db.DB.Exec(`UPDATE users SET login_failed_attempts=COALESCE(login_failed_attempts,0)+1 WHERE id=?`, userID)
		return
	}
	_, _ = db.DB.Exec(`UPDATE users SET
		login_failed_attempts=CASE WHEN COALESCE(login_failed_attempts,0)+1>=? THEN 0 ELSE COALESCE(login_failed_attempts,0)+1 END,
		login_locked_until=CASE WHEN COALESCE(login_failed_attempts,0)+1>=? THEN ? ELSE login_locked_until END
		WHERE id=?`,
		loginLockMaxAttempts, loginLockMaxAttempts,
		now.Add(loginLockCooldown).UTC().Format("2006-01-02 15:04:05"), userID)
}

// loginLockedNow 账户当前是否处于登录锁定（开关关闭视为未锁）。
func loginLockedNow(lockedUntil sql.NullString) bool {
	return loginLockoutEnabled() && lockedUntil.Valid && lockedUntil.String > time.Now().UTC().Format("2006-01-02 15:04:05")
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

	var user models.User
	var passwordHash string
	var passwordVersion int64
	var loginLockedUntil sql.NullString
	err := db.DB.QueryRow("SELECT id, username, password_hash, role, display_name, is_enabled, created_at, last_login, password_version, login_locked_until FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &passwordHash, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &passwordVersion, &loginLockedUntil)

	if err == sql.ErrNoRows {
		// D5-S5：对不存在的用户名也执行一次注定失败的 bcrypt 比较（结果刻意
		// 丢弃，只取等时副作用），消除与「密码错误」路径的时序差后返回同形 401。
		_ = bcrypt.CompareHashAndPassword(loginDummyBcryptHash, []byte(req.Password))
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
	if loginLockedNow(loginLockedUntil) {
		_ = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("用户 %d", user.ID), "账户已锁定"), c.ClientIP())
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: "账户已锁定，请 10 分钟后重试"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		recordLoginFailure(user.ID)
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("invalid_credentials"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户名或密码错误"})
		return
	}
	// 密码正确但账户启用 MFA 时不在密码步清零计数——完整登录以 MFA 验证成功
	// 为准（否则「输对密码→连错 4 次验证码→重登清零」可无限绕过锁定）；未启用
	// MFA 则密码即完整登录，清零计数。
	if !user.IsEnabled {
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("用户 %d", user.ID), "账号已禁用"), c.ClientIP())
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "账号已禁用，请联系管理员"})
		return
	}

	// v2.1.8 MFA 两步登录：密码通过且用户已启用 MFA → 签发 5 分钟单次挑战，
	// 不发 JWT；前端携 mfa_token 调 /auth/mfa/verify。
	// R72 C-I-3：MFA 是主认证控制（非纵深层），判定 DB 错误必须 fail-closed——
	// 此前 err != nil 落穿 respondLogin 直接发 JWT，构成二因子静默绕过。
	var mfaEnabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", user.ID).Scan(&mfaEnabled); err != nil {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	if mfaEnabled {
		mfaToken, ierr := services.MFAIssueChallenge(user.ID)
		if ierr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "签发 MFA 挑战失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"mfa_required": true, "mfa_token": mfaToken})
		return
	}
	// 完整登录成功（无 MFA）：清零登录失败计数与锁定。
	_, _ = db.DB.Exec("UPDATE users SET login_failed_attempts=0, login_locked_until=NULL WHERE id=?", user.ID)

	h.respondLogin(c, user, passwordVersion)
}

func (h *Handlers) respondLogin(c *gin.Context, user models.User, passwordVersion int64) {
	// R72 D-新6：last_login 更新与「登录成功」审计仅登录路径——step-up
	// （verify-step）复用本函数时不再记假登录/刷新 last_login。
	h.respondLoginWithMFA(c, user, passwordVersion, 0, true)
}

// respondLoginWithMFA 携带 mfa_ts 声明签发（0=未验证/不写入——非 MFA 用户登录、
// MFA 首次签发在 verify 成功时传 now；票据登录暂传 0）。isLogin=false 时跳过
// 登录审计与 last_login 更新（verify-step 的 step-up 场景，R72 D-新6）。
func (h *Handlers) respondLoginWithMFA(c *gin.Context, user models.User, passwordVersion int64, mfaTs int64, isLogin bool) {
	if isLogin {
		lastLogin := time.Now().UTC()
		if _, err := db.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", lastLogin, user.ID); err != nil {
			services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新登录时间失败"})
			return
		}
		user.LastLogin = sql.NullTime{Time: lastLogin, Valid: true}
	}

	nodeMode := "master"
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
		nodeMode = "slave"
	}

	expireMinutes := 20
	if err := db.DB.QueryRow("SELECT COALESCE(jwt_expire_minutes,20) FROM global_config WHERE id=1").Scan(&expireMinutes); err != nil || expireMinutes <= 0 || expireMinutes > 1440 {
		expireMinutes = 20
	}
	expireDuration := time.Duration(expireMinutes) * time.Minute
	now := time.Now()
	jtiBytes := make([]byte, 32)
	if _, err := rand.Read(jtiBytes); err != nil {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "签发登录令牌失败"})
		return
	}
	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID,
		"username":  user.Username,
		"role":      user.Role,
		"node_mode": nodeMode,
		"pwd_ver":   passwordVersion,
		"jti":       hex.EncodeToString(jtiBytes),
		"iat":       now.Unix(),
		"exp":       now.Add(expireDuration).Unix(),
	})
	if mfaTs > 0 {
		claims := token.Claims.(jwt.MapClaims)
		claims["mfa_ts"] = mfaTs
	}

	tokenString, err := token.SignedString([]byte(h.cfg.JWTSecret))
	if err != nil {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "签发登录令牌失败"})
		return
	}
	if isLogin {
		services.RecordAuditLog(user.Username, "登录成功", "用户认证", services.FormatAuditDetail(fmt.Sprintf("用户 %d", user.ID), services.AuditResultPart("success")), c.ClientIP())
	}

	response := models.NewUserResponse(user)
	// R72 十次：登录/step-up 响应携带 mfa_enabled——NewUserResponse 不含该字段
	//（User 模型无此列），此前所有登录路径的 user.mfa_enabled 恒 false，导致
	// 前端「登录从节点需先启用 MFA」预检对自己已启用的用户误报。一次查询填齐。
	var mfaEnabled int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", user.ID).Scan(&mfaEnabled); err == nil {
		response.MFAEnabled = mfaEnabled == 1
	}

	c.JSON(http.StatusOK, models.LoginResponse{
		Token:    tokenString,
		User:     response,
		NodeMode: nodeMode,
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	// 第 15 轮审计 S-4：API Key 认证无会话令牌概念（jwtAuth 只为 JWT 写
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
	if _, err := db.DB.Exec("INSERT INTO revoked_jti (jti_hash,expires_at) VALUES (?,?) ON CONFLICT(jti_hash) DO UPDATE SET expires_at=excluded.expires_at", revocationHash, expiresAtTime.UTC().Format(revokedTokenTimeFormat)); err != nil {
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

	var userIDInt int
	switch v := userID.(type) {
	case float64:
		userIDInt = int(v)
	case int:
		userIDInt = v
	case int64:
		userIDInt = int(v)
	default:
		userIDInt = 0
	}

	var user models.User
	var mfaEnabled int
	err := db.DB.QueryRow(`
		SELECT id, username, role, display_name, is_enabled, created_at, last_login, COALESCE(mfa_enabled,0)
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &mfaEnabled)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "用户不存在或已被删除"})
		return
	}

	response := models.NewUserResponse(user)
	response.MFAEnabled = mfaEnabled == 1
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: response})
}

type UpdateCurrentUserRequest struct {
	DisplayName *string `json:"display_name" binding:"omitempty,max=50"`
	// bcrypt 只取前 72 字节（超出即静默截断），超长密码直接 400 而不是落库后被截断
	Password string `json:"password" binding:"omitempty,max=72"`
	// M5（用户已批准契约）：提交新密码时必须携带当前密码过共享确认门——此前仅凭
	// 会话即可改密，劫持会话可直接置换密码把原主锁在门外。仅改昵称不要求。
	CurrentPassword string `json:"current_password" binding:"omitempty,max=72"`
}

func (h *Handlers) UpdateCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "未登录或登录已过期"})
		return
	}

	var userIDInt int
	switch v := userID.(type) {
	case float64:
		userIDInt = int(v)
	case int:
		userIDInt = v
	case int64:
		userIDInt = int(v)
	default:
		userIDInt = 0
	}

	var req UpdateCurrentUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if passwordTooShort(req.Password) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "密码至少 6 位"})
		return
	}
	if req.Password != "" {
		// M5（契约）：改密需当前密码——缺失 400；错误/冷却中由共享门写入 401/429。
		if req.CurrentPassword == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "修改密码需提供当前密码"})
			return
		}
		if err := confirmPasswordWithGate(c, userIDInt, req.CurrentPassword); err != nil {
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
				log.Printf("UpdateCurrentUser rollback failed for id=%d: %v", userIDInt, rollbackErr)
			}
		}
	}()

	var oldDisplayName string
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(display_name,'') FROM users WHERE id = ?", userIDInt).Scan(&oldDisplayName); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}

	changed := []string{}
	sets := make([]string, 0, 3)
	args := make([]any, 0, 3)
	if req.DisplayName != nil && *req.DisplayName != oldDisplayName {
		sets = append(sets, "display_name = ?")
		args = append(args, *req.DisplayName)
		changed = append(changed, "昵称")
	}
	if passwordHash != "" {
		sets = append(sets, "password_hash = ?", "password_changed_at = datetime('now')", "password_version = password_version + 1")
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

	var user models.User
	err = tx.QueryRowContext(c.Request.Context(), `
		SELECT id, username, role, display_name, is_enabled, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交用户更新失败"})
		return
	}
	committed = true

	if len(changed) == 0 {
		recordAudit(c, "更新信息", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", userIDInt), "无修改"))
	} else {
		recordAudit(c, "更新信息", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", userIDInt), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: models.NewUserResponse(user)})
}

func (h *Handlers) GetSetupStatus(c *gin.Context) {
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查初始化状态失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"needs_setup": count == 0}})
}

func (h *Handlers) SetupAdmin(c *gin.Context) {
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
		Password    string `json:"password" binding:"required,min=6,max=72"`
		DisplayName string `json:"display_name" binding:"max=50"`
	}
	if !guardAuthJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户名至少 3 位，密码至少 6 位"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
		return
	}
	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled) SELECT ?, ?, 'admin', ?, 1 WHERE NOT EXISTS (SELECT 1 FROM users)",
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
	services.RecordAuditLog(req.Username, "创建", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), req.Username, "首个管理员，系统初始化"), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "管理员账号创建成功，请登录"})
}
