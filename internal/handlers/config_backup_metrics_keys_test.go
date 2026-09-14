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

// CL14-新2(第 14 轮审计):CL13-新3 钉住——备份携带字面量 "null" 白名单导入后
// 归一为 ''(中间件把非空串当白名单配置,null 解析成功但 0 CIDR→全来源 403)。
func TestImportConfigBackup_normalizesNullWhitelist(t *testing.T) {
	h := newBackupTestHandlers(t)
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	// 旧从节点库(pre-fix)导出形态:mcp_ip_whitelist 为字符串 "null"
	completeTables["api_keys"] = []map[string]any{{"id": 1, "name": "k", "key_hash": "h", "key_prefix": "p", "created_by": 1, "is_enabled": 1, "mcp_ip_whitelist": "null"}}
	importCfg := map[string]any{"timezone": "Asia/Shanghai"}
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
	importRec := httptest.NewRecorder()
	importReq := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	importReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(mcp_ip_whitelist,'') FROM api_keys WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("imported whitelist=%q, want '' (literal null normalized)", stored)
	}
}

// CL15-新1(第 15 轮审计):CL14-新1 钉住——sync_users 入保护键,导出不含、
// 导入携带 0 值不落库(恒同步不变量的第五强制点)。
func TestExportImportConfigBackup_syncUsersProtected(t *testing.T) {
	h := newBackupTestHandlers(t)
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	// 导出侧:携带其他配置键,sync_users 若意外存在应被剔除
	exportCfg := map[string]any{"timezone": "Asia/Shanghai", "sync_users": false}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
		Config: exportCfg,
		Tables: completeTables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, exportCfg)
	body, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	importRec := httptest.NewRecorder()
	importReq := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	importReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var v int
	if err := db.DB.QueryRow("SELECT COALESCE(sync_users,1) FROM global_config WHERE id=1").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("sync_users=%d after import carrying 0, want 1 (protected key)", v)
	}
}
