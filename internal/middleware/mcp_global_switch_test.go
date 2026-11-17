package middleware

// MCP 全局开关门钉测：notify_settings 键 notify.mcp_enabled='0' → /mcp 503
// 「MCP 已停用」；缺行 → 放行（fail-open）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func withIsolatedSwitchDatabase(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
}

func TestMCPGlobalSwitchGuardDisabledReturns503(t *testing.T) {
	withIsolatedSwitchDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO notify_settings(key, value) VALUES ('notify.mcp_enabled', '0')`); err != nil {
		t.Fatalf("seed switch: %v", err)
	}

	router := gin.New()
	router.POST("/mcp", mcpGlobalSwitchGuard(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503", response.Code, response.Body.String())
	}
	var payload struct {
		Code       int    `json:"code"`
		Message    string `json:"message"`
		MessageKey string `json:"message_key"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.MessageKey != "k_963a42ce" || payload.Message != "MCP 已停用" {
		t.Errorf("message=%q key=%q, want 停用文案", payload.Message, payload.MessageKey)
	}
}

func TestMCPGlobalSwitchGuardMissingRowPassesThrough(t *testing.T) {
	withIsolatedSwitchDatabase(t)
	router := gin.New()
	reached := false
	router.POST("/mcp", mcpGlobalSwitchGuard(), func(c *gin.Context) {
		reached = true
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if response.Code != http.StatusOK || !reached {
		t.Fatalf("缺行应放行: status=%d reached=%v", response.Code, reached)
	}
}
