package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// SYS42-1(第 42 轮审计):预览端点(config_import_v1.go)对 v2 JSON 备份先剥
// UTF-8 BOM,导入核心(importConfigBackupCore)此前未剥——同一份带 BOM 的备份
// 预览通过、导入 400「备份文件格式不正确」。BOM(\xef\xbb\xbf)与 gzip 魔数
// (0x1f 0x8b)不冲突,剥 BOM 必须在 isLbbakBytes 检测之前,且不得影响既有
// 无 BOM / lbbak 两形态。
func TestImportConfigBackup_stripsBOMBeforeFormatDetection(t *testing.T) {
	// Given:同一启用管理员的合法 v2 备份,三种字节形态
	tables := map[string][]map[string]any{
		"users": {{"id": 7, "username": "bom-admin", "password_hash": "hash", "role": "admin", "is_enabled": true, "password_version": 1}},
	}
	tests := []struct {
		name string
		body func(t *testing.T) []byte
	}{
		{name: "bom-prefixed v2 json", body: func(t *testing.T) []byte {
			return append([]byte("\xef\xbb\xbf"), []byte(completeBackupJSON(t, tables))...)
		}},
		{name: "plain v2 json", body: func(t *testing.T) []byte {
			return []byte(completeBackupJSON(t, tables))
		}},
		{name: "lbbak payload", body: func(t *testing.T) []byte {
			return buildTestLbbak(t, completeBackupJSON(t, tables), nil)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)

			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(tt.body(t)))
			request.Header.Set("Content-Type", "application/octet-stream")
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var username string
			if err := db.DB.QueryRow("SELECT username FROM users WHERE id=7").Scan(&username); err != nil || username != "bom-admin" {
				t.Fatalf("imported admin missing: username=%q err=%v", username, err)
			}
		})
	}
}
