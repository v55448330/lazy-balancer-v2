package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, username, role, display_name, is_enabled, created_at, last_login FROM users ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var users []models.UserResponse
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.DisplayName, &u.IsEnabled, &u.CreatedAt, &u.LastLogin); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
			return
		}
		users = append(users, models.NewUserResponse(u))
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: users})
}

func (h *Handlers) CreateUser(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid role"})
		return
	}
	if passwordTooShort(req.Password) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Password must be at least 6 characters"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
		return
	}

	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled) VALUES (?, ?, ?, ?, 1)",
		req.Username, string(hash), req.Role, req.DisplayName)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "用户名已存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建用户失败"})
		return
	}

	id, _ := result.LastInsertId()
	recordAudit(c, "创建", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), req.Username, fmt.Sprintf("角色：%s", req.Role)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "User created", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid user ID"})
		return
	}

	var req struct {
		Username    *string `json:"username"`
		Password    *string `json:"password"`
		Role        *string `json:"role"`
		DisplayName *string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.Role != nil && *req.Role != "" && *req.Role != "admin" && *req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid role"})
		return
	}
	if req.Password != nil && passwordTooShort(*req.Password) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Password must be at least 6 characters"})
		return
	}
	var passwordHash string
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
			return
		}
		passwordHash = string(hash)
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("UpdateUser rollback failed for id=%d: %v", id, rollbackErr)
			}
		}
	}()

	var oldUsername, oldRole, oldDisplayName string
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, COALESCE(display_name,'') FROM users WHERE id = ?", id).Scan(&oldUsername, &oldRole, &oldDisplayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query user"})
		}
		return
	}

	changed := []string{}
	sets := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if req.Username != nil && *req.Username != "" && *req.Username != oldUsername {
		sets = append(sets, "username = ?")
		args = append(args, *req.Username)
		changed = append(changed, "用户名")
	}
	if req.Role != nil && *req.Role != "" && *req.Role != oldRole {
		sets = append(sets, "role = ?")
		args = append(args, *req.Role)
		changed = append(changed, "角色")
	}
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
		args = append(args, id)
		if _, err := tx.ExecContext(c.Request.Context(), "UPDATE users SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user"})
			return
		}
	}
	var user models.User
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT id,username,role,display_name,is_enabled,created_at,last_login FROM users WHERE id=?`, id).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query user"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user"})
		return
	}
	committed = true

	if len(changed) == 0 {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), "无修改"))
	} else {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User updated", Data: models.NewUserResponse(user)})
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	userID, _ := c.Get("user_id")
	var userIDInt int
	switch v := userID.(type) {
	case float64:
		userIDInt = int(v)
	case int:
		userIDInt = v
	default:
		userIDInt = 0
	}

	if userIDInt == id {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Cannot delete yourself"})
		return
	}

	var targetUsername string
	if err := db.DB.QueryRow("SELECT username FROM users WHERE id = ?", id).Scan(&targetUsername); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		return
	}
	result, err := db.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete user"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete user"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		return
	}

	recordAudit(c, "删除", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), targetUsername))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User deleted"})
}

func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid user ID"})
		return
	}

	var req struct {
		IsEnabled bool `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	result, err := db.DB.Exec("UPDATE users SET is_enabled = ? WHERE id = ?", req.IsEnabled, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user status"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user status"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		return
	}

	status := "disabled"
	if req.IsEnabled {
		status = "enabled"
	}
	recordAudit(c, "修改状态", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), services.AuditResultPart(status)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User status updated"})
}

func (h *Handlers) ResetUserPassword(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid user ID"})
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" || passwordTooShort(req.NewPassword) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
		return
	}

	result, err := db.DB.Exec("UPDATE users SET password_hash = ?, password_changed_at = datetime('now'), password_version = password_version + 1 WHERE id = ?", string(hash), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to reset password"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to reset password"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		return
	}

	recordAudit(c, "重置密码", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Password reset successfully"})
}
