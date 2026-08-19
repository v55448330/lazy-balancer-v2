package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R41 B1: pre-R40 备份可携带 ≥2 个 is_default=1 的拦截页。导入后仅 MIN(id)
// 保留默认，其余降级为非默认，避免产生不可编辑/删除的死行及 branding 覆盖误伤。
func TestImportConfigBackup_demotesExtraDefaultBlockPages(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {
			{"id": 1, "name": "默认拦截页面", "description": "sys", "content": "<html>a</html>", "is_default": true},
			{"id": 5, "name": "旧默认页", "description": "legacy", "content": "<html>b</html>", "is_default": true},
			{"id": 7, "name": "自定义页", "description": "custom", "content": "<html>c</html>", "is_default": false},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var defaultCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaultCount); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if defaultCount != 1 {
		t.Fatalf("default page count=%d, want 1（仅 MIN(id) 保留默认）", defaultCount)
	}
	var defaultID int
	if err := db.DB.QueryRow("SELECT id FROM security_block_pages WHERE is_default=1").Scan(&defaultID); err != nil {
		t.Fatalf("read default page id: %v", err)
	}
	if defaultID != 1 {
		t.Fatalf("default page id=%d, want 1（MIN(id)）", defaultID)
	}
	var legacyDefault bool
	if err := db.DB.QueryRow("SELECT is_default FROM security_block_pages WHERE id=5").Scan(&legacyDefault); err != nil {
		t.Fatalf("read legacy page: %v", err)
	}
	if legacyDefault {
		t.Fatalf("id=5 应被降级为非默认页")
	}
	var customDefault bool
	if err := db.DB.QueryRow("SELECT is_default FROM security_block_pages WHERE id=7").Scan(&customDefault); err != nil {
		t.Fatalf("read custom page: %v", err)
	}
	if customDefault {
		t.Fatalf("id=7 本就不是默认页，不应被误改")
	}
}

// R41 B3: 备份未携带任何拦截页时，重播种必须在导入事务内随提交生效，
// 提交后系统存在 id=1 的默认页（拦截响应不退化）。
func TestImportConfigBackup_reseedsDefaultBlockPageWhenBackupHasNone(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		// security_block_pages 为空数组：DELETE 清空后 INSERT 零行 → 重播种应触发
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1 AND id=1").Scan(&count); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if count != 1 {
		t.Fatalf("reseeded default page count=%d, want 1（重播种随事务提交）", count)
	}
}

// R41 B3（事务性反例）: 导入在提交前被拒绝（无启用管理员），重播种不得脱离
// 事务单独落库——security_block_pages 保持导入前状态（种子行 id=1 仍在）。
func TestImportConfigBackup_reseedRollsBackWithFailedImport(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	// 备份清空 security_block_pages 但不含启用管理员 → 导入应在管理员校验处回滚
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1 AND id=1").Scan(&count); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if count != 1 {
		t.Fatalf("default page count=%d after rolled-back import, want 1（重播种随事务回滚）", count)
	}
}
