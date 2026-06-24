package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) ListAPIKeys(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.created_at, u.username 
		FROM api_keys k 
		JOIN users u ON k.created_by = u.id 
		ORDER BY k.id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	type APIKeyWithUser struct {
		ID        int          `json:"id"`
		Name      string       `json:"name"`
		KeyPrefix string       `json:"key_prefix"`
		CreatedBy int          `json:"created_by"`
		Username  string       `json:"username"`
		LastUsed  sql.NullTime `json:"last_used"`
		ExpiresAt sql.NullTime `json:"expires_at"`
		CreatedAt time.Time    `json:"created_at"`
	}

	var keys []APIKeyWithUser
	for rows.Next() {
		var k APIKeyWithUser
		rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.CreatedBy, &k.LastUsed, &k.ExpiresAt, &k.CreatedAt, &k.Username)
		keys = append(keys, k)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}


func (h *Handlers) CreateAPIKey(c *gin.Context) {
	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// Generate API key
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	apiKey := "lb_sk_" + base64.URLEncoding.EncodeToString(keyBytes)[:32]

	// Hash the key for storage
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := apiKey[:12]

	userID, _ := c.Get("user_id")

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt
	}

	result, err := db.DB.Exec(`
		INSERT INTO api_keys (name, key_hash, key_prefix, created_by, expires_at) 
		VALUES (?, ?, ?, ?, ?)
	`, req.Name, keyHash, keyPrefix, userID, expiresAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create API key"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Data: gin.H{
		"id":      id,
		"key":     apiKey,
		"message": "This key will only be shown once. Please save it securely.",
	}})
}


func (h *Handlers) DeleteAPIKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API key deleted"})
}

