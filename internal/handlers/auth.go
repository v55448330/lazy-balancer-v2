package handlers

import (
	"database/sql"
	"fmt"
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

func (h *Handlers) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		services.RecordAuditLog("", "登录失败", "用户认证", services.AuditResultPart("invalid_request"), c.ClientIP())
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	var user models.User
	var passwordHash string
	err := db.DB.QueryRow("SELECT id, username, password_hash, role, display_name, is_enabled, last_login FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &passwordHash, &user.Role, &user.DisplayName, &user.IsEnabled, &user.LastLogin)

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

	// Update last login
	db.DB.Exec("UPDATE users SET last_login = datetime('now') WHERE id = ?", user.ID)

	nodeMode := "master"
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
		nodeMode = "slave"
	}

	expireMinutes := 20
	if err := db.DB.QueryRow("SELECT COALESCE(jwt_expire_minutes,20) FROM global_config WHERE id=1").Scan(&expireMinutes); err != nil || expireMinutes <= 0 {
		expireMinutes = 20
	}
	expireDuration := time.Duration(expireMinutes) * time.Minute

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID,
		"username":  user.Username,
		"role":      user.Role,
		"node_mode": nodeMode,
		"exp":       time.Now().Add(expireDuration).Unix(),
	})

	tokenString, _ := token.SignedString([]byte(h.cfg.JWTSecret))
	services.RecordAuditLog(user.Username, "登录成功", "用户认证", services.FormatAuditDetail(fmt.Sprintf("用户 %d", user.ID), services.AuditResultPart("success")), c.ClientIP())

	c.JSON(http.StatusOK, models.LoginResponse{
		Token:    tokenString,
		User:     user,
		NodeMode: nodeMode,
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	services.RecordAuditLog(usernameStr, "登出", "用户认证", services.AuditResultPart("success"), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Logged out"})
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
	default:
		userIDInt = 0
	}

	var user models.User
	err := db.DB.QueryRow(`
		SELECT id, username, role, display_name, is_enabled, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "用户不存在或已被删除"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: user})
}

type UpdateCurrentUserRequest struct {
	DisplayName *string `json:"display_name"`
	Password    string  `json:"password"`
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
	default:
		userIDInt = 0
	}

	var req UpdateCurrentUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	var oldDisplayName string
	if err := db.DB.QueryRow("SELECT COALESCE(display_name,'') FROM users WHERE id = ?", userIDInt).Scan(&oldDisplayName); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}

	// Update display name
	changed := []string{}
	if req.DisplayName != nil && *req.DisplayName != oldDisplayName {
		if _, err := db.DB.Exec("UPDATE users SET display_name = ? WHERE id = ?", *req.DisplayName, userIDInt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新显示名失败"})
			return
		}
		changed = append(changed, "昵称")
	}

	// Update password if provided
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
			return
		}
		if _, err := db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), userIDInt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新密码失败"})
			return
		}
		changed = append(changed, "密码")
	}

	// Return updated user
	var user models.User
	err := db.DB.QueryRow(`
		SELECT id, username, role, display_name, is_enabled, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}

	if len(changed) == 0 {
		recordAudit(c, "更新资料", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", userIDInt), "无修改"))
	} else {
		recordAudit(c, "更新资料", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", userIDInt), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: user})
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
		Password    string `json:"password" binding:"required,min=6"`
		DisplayName string `json:"display_name" binding:"max=50"`
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
	affected, _ := result.RowsAffected()
	if affected == 0 {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "系统已完成初始化，请直接登录"})
		return
	}
	id, _ := result.LastInsertId()
	services.RecordAuditLog(req.Username, "创建", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), req.Username, "首个管理员，系统初始化"), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "管理员账号创建成功，请登录"})
}
