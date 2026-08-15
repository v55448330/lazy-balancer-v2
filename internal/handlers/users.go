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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()

	var users []models.UserResponse
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.DisplayName, &u.IsEnabled, &u.CreatedAt, &u.LastLogin); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
			return
		}
		users = append(users, models.NewUserResponse(u))
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: users})
}

func (h *Handlers) CreateUser(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "角色无效"})
		return
	}
	if passwordTooShort(req.Password) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "密码至少 6 位"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
		return
	}

	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled) VALUES (?, ?, ?, ?, 1)",
		req.Username, string(hash), req.Role, req.DisplayName)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "用户名已存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建用户失败"})
		return
	}

	id, _ := result.LastInsertId()
	recordAudit(c, "创建", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), req.Username, fmt.Sprintf("角色：%s", req.Role)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "用户创建成功", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		Username    *string `json:"username"`
		Password    *string `json:"password"`
		Role        *string `json:"role"`
		DisplayName *string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	if req.Role != nil && *req.Role != "" && *req.Role != "admin" && *req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "角色无效"})
		return
	}
	if req.Password != nil && passwordTooShort(*req.Password) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "密码至少 6 位"})
		return
	}
	var passwordHash string
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
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
				log.Printf("UpdateUser rollback failed for id=%d: %v", id, rollbackErr)
			}
		}
	}()

	var oldUsername, oldRole, oldDisplayName string
	var oldEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, COALESCE(display_name,''), is_enabled FROM users WHERE id = ?", id).Scan(&oldUsername, &oldRole, &oldDisplayName, &oldEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
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
		query := "UPDATE users SET " + strings.Join(sets, ", ") + " WHERE id = ?"
		if oldEnabled && oldRole == "admin" && req.Role != nil && *req.Role == "user" {
			query += " AND EXISTS (SELECT 1 FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1)"
			args = append(args, id)
		}
		result, err := tx.ExecContext(c.Request.Context(), query, args...)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "already exists") {
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "用户名已存在"})
				return
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
			return
		}
		if rowsAffected == 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "不能移除最后一个已启用管理员"})
			return
		}
	}
	var user models.User
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT id,username,role,display_name,is_enabled,created_at,last_login FROM users WHERE id=?`, id).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户失败"})
		return
	}
	committed = true

	if len(changed) == 0 {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), "无修改"))
	} else {
		recordAudit(c, "更新", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户更新成功", Data: models.NewUserResponse(user)})
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	userID, _ := c.Get("user_id")
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

	if userIDInt == id {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "不能删除当前登录用户"})
		return
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Printf("DeleteUser rollback failed for id=%d: %v", id, err)
		}
	}()

	var targetUsername, targetRole string
	var targetEnabled bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT username, role, is_enabled FROM users WHERE id = ?", id).Scan(&targetUsername, &targetRole, &targetEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		}
		return
	}
	if targetRole == "admin" && targetEnabled {
		var otherAdmins int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1", id).Scan(&otherAdmins); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
			return
		}
		if otherAdmins == 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "不能删除最后一个已启用管理员"})
			return
		}
	}
	if _, err := tx.ExecContext(c.Request.Context(), "DELETE FROM api_keys WHERE created_by = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除用户失败"})
		return
	}

	recordAudit(c, "删除", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), targetUsername))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户删除成功"})
}

func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		IsEnabled bool `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Printf("ToggleUserStatus rollback failed for id=%d: %v", id, err)
		}
	}()
	query := "UPDATE users SET is_enabled = ? WHERE id = ?"
	args := []any{req.IsEnabled, id}
	if !req.IsEnabled {
		query += " AND (role <> 'admin' OR is_enabled = 0 OR EXISTS (SELECT 1 FROM users WHERE id <> ? AND role = 'admin' AND is_enabled = 1))"
		args = append(args, id)
	}
	result, err := tx.ExecContext(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}
	if rowsAffected == 0 {
		var exists int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE id = ?", id).Scan(&exists); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		} else if exists == 0 {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		} else {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "不能禁用最后一个已启用管理员"})
		}
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新用户状态失败"})
		return
	}

	status := "disabled"
	if req.IsEnabled {
		status = "enabled"
	}
	recordAudit(c, "修改状态", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), services.AuditResultPart(status)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "用户状态更新成功"})
}

func (h *Handlers) ResetUserPassword(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "用户 ID 无效"})
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" || passwordTooShort(req.NewPassword) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "密码加密失败"})
		return
	}

	result, err := db.DB.Exec("UPDATE users SET password_hash = ?, password_changed_at = datetime('now'), password_version = password_version + 1 WHERE id = ?", string(hash), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重置密码失败"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
		return
	}

	recordAudit(c, "重置密码", "用户", services.FormatAuditDetail(fmt.Sprintf("用户 %d", id), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "密码重置成功"})
}
