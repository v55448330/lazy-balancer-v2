package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListCurrentUserAPIKeys(c *gin.Context) {
	userID := currentUserID(c)
	rows, err := db.DB.Query(`
		SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.is_enabled,
		       k.mcp_enabled, k.read_only, COALESCE(k.mcp_ip_whitelist,''), k.created_at, u.username
		FROM api_keys k
		JOIN users u ON k.created_by = u.id
		WHERE k.created_by = ?
		ORDER BY k.id
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()
	keys, err := scanAPIKeys(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}

func (h *Handlers) CreateCurrentUserAPIKey(c *gin.Context) {
	createAPIKeyForUser(c, currentUserID(c))
}

func (h *Handlers) DeleteCurrentUserAPIKey(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ID 参数无效"})
		return
	}
	userID := currentUserID(c)
	var name string
	if err := db.DB.QueryRow("SELECT name FROM api_keys WHERE id = ? AND created_by = ?", id, userID).Scan(&name); dbQueryNotFound(c, err, "API 密钥不存在", "DeleteCurrentUserAPIKey query key") {
		return
	}
	result, err := db.DB.Exec("DELETE FROM api_keys WHERE id = ? AND created_by = ?", id, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除 API 密钥失败"})
		return
	}
	rows, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认 API 密钥删除结果失败"})
		return
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API 密钥不存在"})
		return
	}
	recordAudit(c, "删除", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API 密钥已删除"})
}

func currentUserID(c *gin.Context) int {
	userID, _ := c.Get("user_id")
	switch v := userID.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	default:
		return 0
	}
}

func scanAPIKeys(rows *sql.Rows) ([]models.APIKeyWithUserResponse, error) {
	var keys []models.APIKeyWithUserResponse
	for rows.Next() {
		var key models.APIKey
		var username string
		var whitelistJSON string
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyPrefix, &key.CreatedBy, &key.LastUsed, &key.ExpiresAt, &key.IsEnabled, &key.MCPEnabled, &key.ReadOnly, &whitelistJSON, &key.CreatedAt, &username); err != nil {
			return nil, fmt.Errorf("scan API key: %w", err)
		}
		if whitelistJSON != "" {
			if err := json.Unmarshal([]byte(whitelistJSON), &key.MCPIPWhitelist); err != nil {
				return nil, fmt.Errorf("decode API key MCP IP whitelist: %w", err)
			}
		}
		if key.MCPIPWhitelist == nil {
			key.MCPIPWhitelist = []string{}
		}
		keys = append(keys, models.NewAPIKeyWithUserResponse(key, username))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API keys: %w", err)
	}
	if keys == nil {
		keys = []models.APIKeyWithUserResponse{}
	}
	return keys, nil
}

func createAPIKeyForUser(c *gin.Context, userID int) {
	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if c.GetString("role") != "admin" {
		req.ReadOnly = true
	}
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "过期时间不能早于当前时间"})
		return
	}
	// M6（2026-09 用户裁定）：特权 Key（非只读或 MCP）创建不验密码——API Key
	// 面向程序使用，创建/使用均不叠加交互确认；改密亦不吊销 Key（风险由后台
	// 禁用 Key/账户与只读 Key 承载）。可选防线是「写操作验证」（mfa_write_guard）：
	// 开启且创建者为启用 MFA 的 JWT 用户时，特权 Key 创建按 mfaStepUpGuard 同
	// 语义要求 60 秒内 MFA 验证（428 → 全局弹码 → 携新 JWT 重试）；API Key
	// 机器身份豁免（与路由级守卫一致），未启用 MFA 直通。
	if !req.ReadOnly || req.MCPEnabled {
		if c.GetString("auth_type") == "jwt" && services.MFAWriteGuardEnabled() {
			var mfaEnabled bool
			if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&mfaEnabled); err != nil {
				// 与 mfaStepUpGuard 同口径：MFA 状态查询失败 fail-closed（R72 C-I-3）。
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 状态查询失败"})
				return
			}
			if mfaEnabled {
				mfaTs := c.GetFloat64("mfa_ts")
				if elapsed := time.Since(time.Unix(int64(mfaTs), 0)); mfaTs > 0 && elapsed < 60*time.Second {
					c.Header("X-Mfa-Verified-Seconds-Ago", strconv.FormatInt(int64(elapsed.Seconds()), 10))
				} else {
					c.JSON(http.StatusPreconditionRequired, gin.H{"code": 428, "message": "MFA_STEP_UP_REQUIRED", "detail": "此操作需要 MFA 验证"})
					return
				}
			}
		}
	}
	whitelist, err := services.NormalizeCIDRs(req.MCPIPWhitelist)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MCP IP 白名单无效: " + err.Error()})
		return
	}
	whitelistJSON, err := encodeMCPIPWhitelist(whitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "序列化 MCP IP 白名单失败"})
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
		INSERT INTO api_keys (name, key_hash, key_prefix, created_by, expires_at, mcp_enabled, read_only, mcp_ip_whitelist)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, keyHash, keyPrefix, userID, expiresAt, req.MCPEnabled, req.ReadOnly, whitelistJSON)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建 API 密钥失败"})
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取新建 API 密钥 ID 失败"})
		return
	}
	expiry := "永不过期"
	if expiresAt != nil {
		expiry = expiresAt.Format("2006-01-02")
	}
	recordAudit(c, "创建", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), req.Name, fmt.Sprintf("过期：%s", expiry)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Data: gin.H{
		"id":      id,
		"key":     apiKey,
		"message": "完整密钥仅显示一次，请妥善保存。",
	}})
}

func (h *Handlers) ListAPIKeys(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.is_enabled,
		       k.mcp_enabled, k.read_only, COALESCE(k.mcp_ip_whitelist,''), k.created_at, u.username
		FROM api_keys k
		JOIN users u ON k.created_by = u.id
		ORDER BY k.id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()
	keys, err := scanAPIKeys(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
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
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ID 参数无效"})
		return
	}
	userID := currentUserID(c)
	var req models.UpdateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if req.IsEnabled == nil && req.MCPEnabled == nil && req.ReadOnly == nil && req.MCPIPWhitelist == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "至少需要提交一个字段"})
		return
	}
	if currentUserOnly && c.GetString("role") != "admin" && req.ReadOnly != nil && !*req.ReadOnly {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "普通用户密钥必须为只读"})
		return
	}
	if currentUserOnly && c.GetString("role") != "admin" {
		readOnly := true
		req.ReadOnly = &readOnly
	}
	var whitelistJSON *string
	if req.MCPIPWhitelist != nil {
		whitelist, err := services.NormalizeCIDRs(*req.MCPIPWhitelist)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MCP IP 白名单无效: " + err.Error()})
			return
		}
		encoded, err := encodeMCPIPWhitelist(whitelist)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "序列化 MCP IP 白名单失败"})
			return
		}
		whitelistJSON = &encoded
	}
	query := "SELECT name FROM api_keys WHERE id = ?"
	args := []any{id}
	if currentUserOnly {
		query += " AND created_by = ?"
		args = append(args, userID)
	}
	var name string
	if err := db.DB.QueryRow(query, args...).Scan(&name); dbQueryNotFound(c, err, "API 密钥不存在", "updateAPIKeyStatus query key") {
		return
	}
	setClauses := make([]string, 0, 4)
	updateArgs := make([]any, 0, 6)
	for _, field := range []struct {
		name  string
		value any
	}{{"is_enabled", req.IsEnabled}, {"mcp_enabled", req.MCPEnabled}, {"read_only", req.ReadOnly}, {"mcp_ip_whitelist", whitelistJSON}} {
		switch value := field.value.(type) {
		case *bool:
			if value != nil {
				setClauses = append(setClauses, field.name+" = ?")
				updateArgs = append(updateArgs, *value)
			}
		case *string:
			if value != nil {
				setClauses = append(setClauses, field.name+" = ?")
				updateArgs = append(updateArgs, *value)
			}
		}
	}
	update := "UPDATE api_keys SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	updateArgs = append(updateArgs, id)
	if currentUserOnly {
		update += " AND created_by = ?"
		updateArgs = append(updateArgs, userID)
	}
	result, err := db.DB.Exec(update, updateArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新 API 密钥失败"})
		return
	}
	rows, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认 API 密钥更新结果失败"})
		return
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API 密钥不存在"})
		return
	}
	recordAudit(c, "更新", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API 密钥已更新"})
}

func encodeMCPIPWhitelist(whitelist []string) (string, error) {
	if len(whitelist) == 0 {
		return "", nil
	}
	data, err := json.Marshal(whitelist)
	if err != nil {
		return "", fmt.Errorf("marshal MCP IP whitelist: %w", err)
	}
	return string(data), nil
}

func (h *Handlers) DeleteAPIKey(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ID 参数无效"})
		return
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM api_keys WHERE id = ?", id).Scan(&name); dbQueryNotFound(c, err, "API 密钥不存在", "DeleteAPIKey query key") {
		return
	}
	result, err := db.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除 API 密钥失败"})
		return
	}
	rows, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认 API 密钥删除结果失败"})
		return
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "API 密钥不存在"})
		return
	}
	recordAudit(c, "删除", "API密钥", services.FormatAuditDetail(fmt.Sprintf("密钥 %d", id), name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API 密钥已删除"})
}
