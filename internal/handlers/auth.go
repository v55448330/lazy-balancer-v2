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
	err := db.DB.QueryRow("SELECT id, username, password_hash, role, display_name, is_enabled, created_at, last_login, password_version FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &passwordHash, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &passwordVersion)

	if err == sql.ErrNoRows {
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("invalid_credentials"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户名或密码错误"})
		return
	}
	if err != nil {
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		services.RecordAuditLog(req.Username, "登录失败", "用户认证", services.AuditResultPart("invalid_credentials"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户名或密码错误"})
		return
	}

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
