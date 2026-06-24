package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) ListUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, username, role, display_name, is_enabled, created_at, last_login FROM users ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.Role, &u.DisplayName, &u.IsEnabled, &u.CreatedAt, &u.LastLogin)
		users = append(users, u)
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
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "User created", Data: gin.H{"id": id}})
}


func (h *Handlers) UpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		DisplayName string `json:"display_name"`
	}
	c.ShouldBindJSON(&req)

	if req.Role != "" && req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid role"})
		return
	}

	if req.Username != "" {
		db.DB.Exec("UPDATE users SET username = ? WHERE id = ?", req.Username, id)
	}

	if req.Role != "" {
		db.DB.Exec("UPDATE users SET role = ? WHERE id = ?", req.Role, id)
	}

	// DisplayName can be updated even if empty (to clear it)
	db.DB.Exec("UPDATE users SET display_name = ? WHERE id = ?", req.DisplayName, id)

	if req.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), id)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User updated"})
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

	result, err := db.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete user"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User deleted"})
}


func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		IsEnabled bool `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	_, err := db.DB.Exec("UPDATE users SET is_enabled = ? WHERE id = ?", req.IsEnabled, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user status"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User status updated"})
}


func (h *Handlers) ResetUserPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
		return
	}

	_, err = db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Password reset successfully"})
}

