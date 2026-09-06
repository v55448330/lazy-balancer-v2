package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// S-6（2026-09-05 审计裁定）：global_config.metrics_public/metrics_origins 死列
// 删除后的备份兼容契约——①携带这两键的历史备份导入无错（恢复侧按现存列过滤，
// 未知键静默跳过，其余配置正常落库）；②新导出的备份不再携带两键。
func TestImportConfigBackup_toleratesDeadMetricsConfigKeys(t *testing.T) {
	// Given：老格式备份（Config 携带两个已删死列的键 + 一个正常键）
	h := newBackupTestHandlers(t)
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	importCfg := map[string]any{
		"metrics_public":         true,
		"metrics_origins":        "https://legacy.example.test",
		"metrics_retention_days": 3650,
		"timezone":               "Asia/Shanghai",
		"log_level":              "warn",
		"github_proxy_url":       "https://v4.gh-proxy.org/",
	}
	importBackup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
		Config: importCfg,
		Tables: completeTables,
	}
	importBackup.Meta.Checksum = checksumBackupPayload(t, completeTables, importCfg)
	body, err := json.Marshal(importBackup)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	router.GET("/config/export", h.ExportConfigBackup)

	// When：导入老备份
	importRec := httptest.NewRecorder()
	importReq := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	importReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importRec, importReq)

	// Then：导入成功（未知键被跳过，非整包拒绝）
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（携带已删死列键的历史备份必须兼容）", importRec.Code, importRec.Body.String())
	}
	var timezone string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'') FROM global_config WHERE id=1").Scan(&timezone); err != nil {
		t.Fatalf("read imported timezone: %v", err)
	}
	if timezone != "Asia/Shanghai" {
		t.Fatalf("timezone=%q, want Asia/Shanghai（其余配置正常落库）", timezone)
	}

	// And When：重新导出
	exportRec := httptest.NewRecorder()
	router.ServeHTTP(exportRec, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then：新备份不含两个死键，正常键仍在
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s, want 200", exportRec.Code, exportRec.Body.String())
	}
	var exported configBackup
	if err := json.Unmarshal(exportRec.Body.Bytes(), &exported); err != nil {
		t.Fatalf("parse export: %v", err)
	}
	if _, exists := exported.Config["metrics_public"]; exists {
		t.Fatal("new export still carries metrics_public（死列不得再进入备份）")
	}
	if _, exists := exported.Config["metrics_origins"]; exists {
		t.Fatal("new export still carries metrics_origins（死列不得再进入备份）")
	}
	if _, exists := exported.Config["metrics_retention_days"]; exists {
		t.Fatal("new export still carries metrics_retention_days（死列不得再进入备份）")
	}
	if exported.Config["timezone"] != "Asia/Shanghai" {
		t.Fatalf("exported timezone=%v, want Asia/Shanghai", exported.Config["timezone"])
	}
}
