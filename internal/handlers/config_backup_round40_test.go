package handlers

// 第 40 轮审计修复(备份导入导出域)行为规格:
// A40-2-F1 lb_rules 同批替换时 ACME 悬挂预检跳过、A40-2-F3 空 users 表不
// 吊销不误告、A40-2-F4 commit 失败响应携带规则库落盘警告、A40-2-F5 导出
// sections 尾逗号宽容(与 lbbak 导入侧同口径)。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// round40BackupJSON 构造自定义 sections/表区的 v2 备份;值为 nil 的表整体
// 缺席(模拟分类导出产物——缺席表不得被当作「清空本地表」应用)。
func round40BackupJSON(t *testing.T, sections []string, tables map[string][]map[string]any) string {
	t.Helper()
	payload := map[string][]map[string]any{}
	for table, rows := range tables {
		if rows == nil {
			continue
		}
		payload[table] = rows
	}
	cfg := map[string]any{}
	backup := configBackup{
		Meta:     configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-09-18T00:00:00Z"},
		Config:   cfg,
		Tables:   payload,
		Sections: sections,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, payload, cfg)
	return marshalJSONForTest(t, backup)
}

func marshalJSONForTest(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

func postJSONImport(t *testing.T, g *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)
	return rec
}

// A40-2-F1:lb_rules 与证书表同批替换时,悬挂预检读取的是「导入前」live
// 规则——这些规则马上会被备份内的规则整体替换,预检恒误报。
func TestImportBackup_lbRulesCoReplacedSkipsAcmeDanglingPreflight(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,tls_source,acme_config_id) VALUES ('live1','live','http','live.example.com',8080,1,'acme_dns',99)`); err != nil {
		t.Fatalf("seed live acme rule: %v", err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	})

	rec := postJSONImport(t, g, backup)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "悬挂") {
		t.Fatalf("lb_rules co-replaced import must not warn dangling ACME refs (live rules are replaced wholesale), body=%s", rec.Body.String())
	}
}

// A40-2-F3:sections 含 users 但备份无 users 表(缺席)——密码吊销与操作者
// 替换告警都不应触发:本地用户表根本未被触碰。
func TestImportBackup_emptyUsersSectionDoesNotBumpOrWarn(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/config/import", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		c.Set("username", "current-admin")
		h.ImportConfigBackup(c)
	})
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (1,'current-admin','hash','admin',1,7)`); err != nil {
		t.Fatalf("seed local admin: %v", err)
	}
	backup := round40BackupJSON(t, []string{"users"}, map[string][]map[string]any{
		"users":    nil, // 缺席
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	})

	rec := postJSONImport(t, g, backup)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var version int
	if err := db.DB.QueryRow(`SELECT password_version FROM users WHERE username='current-admin'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 7 {
		t.Fatalf("absent users table must not bump password_version, got %d", version)
	}
	if strings.Contains(rec.Body.String(), "系统数据") {
		t.Fatalf("absent users table must not warn operator replaced / sessions revoked, body=%s", rec.Body.String())
	}
}

// A40-2-F5:导出 ?sections=rules, (尾逗号/空白段) 与 lbbak 导入侧同口径宽容。
func TestExportConfigBackup_sectionsTrailingCommaAccepted(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules,", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export with trailing comma: %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// A40-2-F4:commit 失败(Caddy 应用失败)时,落盘警告不得随失败响应丢失——
// 规则库文件已写 live 树而 DB 已回滚,丢警告=状态分裂不可见。
func TestImportBackup_commitFailureCarriesWafApplyWarning(t *testing.T) {
	// unreachable caddy:commit 内 ApplyConfigFromTxCertAwareForce 必败(整个事务回滚)
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	cfg := &config.Config{CaddyAdminURL: "http://127.0.0.1:1", DataDir: t.TempDir()}
	h := &Handlers{
		cfg:            cfg,
		caddyService:   services.NewCaddyService(cfg.CaddyAdminURL),
		clusterService: services.NewClusterService(db.DB, nil, ""),
	}
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/config/import", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		h.ImportConfigBackup(c)
	})
	// xdb 落盘路径指向目录 → 写入必败 → wafApplyWarning 非空
	crsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(services.OverrideWafLivePathsForTest(crsDir, t.TempDir()))

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	})
	body := buildTestLbbak(t, backup, []byte("NEW-XDB-PAYLOAD"))

	rec := postLbbakImport(g, t, body, "")
	if rec.Code == http.StatusOK {
		t.Fatalf("import with unreachable caddy must fail, got 200 %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "规则库文件落盘失败") {
		t.Fatalf("commit-failure response must carry waf apply warning, body=%s", rec.Body.String())
	}
}
