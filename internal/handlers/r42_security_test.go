package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R42 B42-1: 备份携带 id=1 的非默认拦截页时，重播种 INSERT OR IGNORE 因 PK
// 冲突静默 no-op——导入后仍零默认页，必须记「导入警告」审计而非无声放过。
func TestImportConfigBackup_warnsWhenReseedConflictsWithExistingNonDefaultID1(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {
			{"id": 1, "name": "旧自定义页", "description": "legacy", "content": "<html>legacy</html>", "is_default": false},
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
	if defaultCount != 0 {
		t.Fatalf("default page count=%d, want 0（id=1 被非默认行占用，重播种 no-op）", defaultCount)
	}
	var warnings int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='导入警告' AND detail LIKE '%默认拦截页面重播种未生效（id=1 已存在）%'").Scan(&warnings); err != nil {
		t.Fatalf("count audit warnings: %v", err)
	}
	if warnings != 1 {
		t.Fatalf("重播种 no-op 警告数=%d, want 1", warnings)
	}
}

// R42 B42-2: 多默认页导入且保留行（MIN id）内容为种子库存时，被降级行中内容
// 非空且非库存、id 最大者的 content 提升到保留行——用户定制内容不因降级丢失。
func TestImportConfigBackup_promotesDemotedBlockPageContentWhenKeptIsStock(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	stock := renderDefaultBlockPage(loadBrandingConfig(h.cfg.DataDir))
	customContent := "<html>用户定制拦截页</html>"
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {
			{"id": 1, "name": "默认拦截页面", "description": "sys", "content": stock, "is_default": true},
			{"id": 5, "name": "旧默认页", "description": "legacy", "content": customContent, "is_default": true},
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
		t.Fatalf("default page count=%d, want 1", defaultCount)
	}
	var keptContent string
	if err := db.DB.QueryRow("SELECT content FROM security_block_pages WHERE id=1").Scan(&keptContent); err != nil {
		t.Fatalf("read kept page content: %v", err)
	}
	if keptContent != customContent {
		t.Fatalf("保留行内容=%q, want 被降级行的定制内容 %q", keptContent, customContent)
	}
}

// R42 B42-2（反例）: 保留行内容已被用户定制（非库存）时不得被被降级行覆盖。
func TestImportConfigBackup_keepsCustomizedDefaultBlockPageContentOnDemote(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	customKept := "<html>我自己的默认页</html>"
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {
			{"id": 1, "name": "默认拦截页面", "description": "sys", "content": customKept, "is_default": true},
			{"id": 5, "name": "旧默认页", "description": "legacy", "content": "<html>另一个定制</html>", "is_default": true},
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
	var keptContent string
	if err := db.DB.QueryRow("SELECT content FROM security_block_pages WHERE id=1").Scan(&keptContent); err != nil {
		t.Fatalf("read kept page content: %v", err)
	}
	if keptContent != customKept {
		t.Fatalf("保留行定制内容被覆盖为 %q, want 保持 %q", keptContent, customKept)
	}
}
