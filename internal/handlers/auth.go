package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var user models.User
	var passwordHash string
	err := db.DB.QueryRow("SELECT id, username, password_hash, role, display_name, last_login FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &passwordHash, &user.Role, &user.DisplayName, &user.LastLogin)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Invalid credentials"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Invalid credentials"})
		return
	}

	// Update last login
	db.DB.Exec("UPDATE users SET last_login = datetime('now') WHERE id = ?", user.ID)

	// Get node mode
	nodeMode := h.cfg.NodeMode
	if nodeMode == "" {
		nodeMode = "master"
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID,
		"username":  user.Username,
		"role":      user.Role,
		"node_mode": nodeMode,
		"exp":       time.Now().Add(h.cfg.JWTExpire).Unix(),
	})

	tokenString, _ := token.SignedString([]byte(h.cfg.JWTSecret))

	c.JSON(http.StatusOK, models.LoginResponse{
		Token:    tokenString,
		User:     user,
		NodeMode: nodeMode,
	})
}


func (h *Handlers) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Logged out"})
}


func (h *Handlers) GetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Not authenticated"})
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
		SELECT id, username, role, display_name, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "User not found"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: user})
}


type UpdateCurrentUserRequest struct {
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

func (h *Handlers) UpdateCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Not authenticated"})
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// Update display name
	if req.DisplayName != "" {
		db.DB.Exec("UPDATE users SET display_name = ? WHERE id = ?", req.DisplayName, userIDInt)
	}

	// Update password if provided
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
			return
		}
		db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), userIDInt)
	}

	// Return updated user
	var user models.User
	err := db.DB.QueryRow(`
		SELECT id, username, role, display_name, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get user"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: user})
}

