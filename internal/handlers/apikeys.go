package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListCurrentUserAPIKeys(c *gin.Context) {
	userID := currentUserID(c)
	rows, err := db.DB.Query(`
		SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.is_enabled, k.created_at, u.username
		FROM api_keys k
		JOIN users u ON k.created_by = u.id
		WHERE k.created_by = ?
		ORDER BY k.id
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()
	keys, err := scanAPIKeys(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}

func (h *Handlers) CreateCurrentUserAPIKey(c *gin.Context) {
	createAPIKeyForUser(c, currentUserID(c))
}

func (h *Handlers) DeleteCurrentUserAPIKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	userID := currentUserID(c)
	var name string
	if err := db.DB.QueryRow("SELECT name FROM api_keys WHERE id = ? AND created_by = ?", id, userID).Scan(&name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API key not found"})
		return
	}
	if _, err := db.DB.Exec("DELETE FROM api_keys WHERE id = ? AND created_by = ?", id, userID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete API key"})
		return
	}
	recordAudit(c, "删除", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API key deleted"})
}

func currentUserID(c *gin.Context) int {
	userID, _ := c.Get("user_id")
	switch v := userID.(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

type apiKeyWithUser struct {
	ID        int          `json:"id"`
	Name      string       `json:"name"`
	KeyPrefix string       `json:"key_prefix"`
	CreatedBy int          `json:"created_by"`
	Username  string       `json:"username"`
	LastUsed  sql.NullTime `json:"last_used"`
	ExpiresAt sql.NullTime `json:"expires_at"`
	IsEnabled bool         `json:"is_enabled"`
	CreatedAt time.Time    `json:"created_at"`
}

func scanAPIKeys(rows *sql.Rows) ([]apiKeyWithUser, error) {
	var keys []apiKeyWithUser
	for rows.Next() {
		var k apiKeyWithUser
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.CreatedBy, &k.LastUsed, &k.ExpiresAt, &k.IsEnabled, &k.CreatedAt, &k.Username); err != nil {
			return nil, fmt.Errorf("scan API key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API keys: %w", err)
	}
	if keys == nil {
		keys = []apiKeyWithUser{}
	}
	return keys, nil
}

func createAPIKeyForUser(c *gin.Context, userID int) {
	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 API 密钥失败"})
		return
	}
	apiKey := "lb_sk_" + base64.URLEncoding.EncodeToString(keyBytes)[:32]
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := apiKey[:12]

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
	expiry := "永不过期"
	if expiresAt != nil {
		expiry = expiresAt.Format("2006-01-02")
	}
	recordAudit(c, "创建", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), req.Name, fmt.Sprintf("过期：%s", expiry)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Data: gin.H{
		"id":      id,
		"key":     apiKey,
		"message": "This key will only be shown once. Please save it securely.",
	}})
}

func (h *Handlers) ListAPIKeys(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.is_enabled, k.created_at, u.username
		FROM api_keys k
		JOIN users u ON k.created_by = u.id
		ORDER BY k.id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()
	keys, err := scanAPIKeys(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}

func (h *Handlers) CreateAPIKey(c *gin.Context) {
	createAPIKeyForUser(c, currentUserID(c))
}

func (h *Handlers) UpdateCurrentUserAPIKeyStatus(c *gin.Context) {
	updateAPIKeyStatus(c, true)
}

func (h *Handlers) UpdateAPIKeyStatus(c *gin.Context) {
	updateAPIKeyStatus(c, false)
}

func updateAPIKeyStatus(c *gin.Context, currentUserOnly bool) {
	id, _ := strconv.Atoi(c.Param("id"))
	userID := currentUserID(c)
	var req struct {
		IsEnabled bool `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}
	query := "SELECT name FROM api_keys WHERE id = ?"
	args := []interface{}{id}
	if currentUserOnly {
		query += " AND created_by = ?"
		args = append(args, userID)
	}
	var name string
	if err := db.DB.QueryRow(query, args...).Scan(&name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API key not found"})
		return
	}
	update := "UPDATE api_keys SET is_enabled = ? WHERE id = ?"
	updateArgs := []interface{}{req.IsEnabled, id}
	if currentUserOnly {
		update += " AND created_by = ?"
		updateArgs = append(updateArgs, userID)
	}
	if _, err := db.DB.Exec(update, updateArgs...); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update API key status"})
		return
	}
	status := "disabled"
	if req.IsEnabled {
		status = "enabled"
	}
	recordAudit(c, "修改状态", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name, services.AuditResultPart(status)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API key status updated"})
}

func (h *Handlers) DeleteAPIKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var name string
	if err := db.DB.QueryRow("SELECT name FROM api_keys WHERE id = ?", id).Scan(&name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API key not found"})
		return
	}
	result, err := db.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete API key"})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API key not found"})
		return
	}
	recordAudit(c, "删除", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API key deleted"})
}
