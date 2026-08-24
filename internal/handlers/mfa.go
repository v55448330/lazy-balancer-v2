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

	if ok, verr := services.MFAVerifyCode(userID, req.Code, time.Now()); !ok {
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证码错误"), c.ClientIP())
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
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix())
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
func (h *Handlers) MFASetup(c *gin.Context) {
	userID := getContextUserIDInt(c)
	username := getContextUserID(c)
	secret, uri, err := services.MFAGenerateSecret(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 MFA 密钥失败"})
		return
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=? WHERE id=?", secret, userID); err != nil {
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "验证码错误，请确认 Authenticator 时间同步后重试"})
		return
	}
	codes, err := services.MFAActivate(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "启用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")), c.ClientIP())
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
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", userID).Scan(&hash); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "密码错误"})
		return
	}
	if ok, verr := services.MFAVerifyCode(userID, req.Code, time.Now()); !ok {
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
	services.RecordAuditLog(getContextUserID(c), "禁用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")), c.ClientIP())
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
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", userID).Scan(&hash); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "密码错误"})
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
	if ok, verr := services.MFAVerifyCode(userID, req.Code, time.Now()); !ok {
		services.RecordAuditLog(getContextUserID(c), "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "step-up 验证失败"), c.ClientIP())
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
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix())
}

// —— Admin 端点 ——

// MFAResetByAdmin POST /users/:id/mfa/reset — 重置指定用户（含自己）。
func (h *Handlers) MFAResetByAdmin(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的用户 ID"})
		return
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
	services.RecordAuditLog(getContextUserID(c), "重置", "用户认证", services.FormatAuditDetail(fmt.Sprintf("用户 %s", target), services.AuditResultPart("success")), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已重置用户 MFA（用户需重新绑定）"})
}
