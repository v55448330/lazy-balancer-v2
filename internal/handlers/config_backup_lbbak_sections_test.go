package handlers

// 第 39 轮审计修复(簇 A·备份导入管线)行为规格:
// R39-1 lbbak 导入分类选择(query sections)、R39-11 password_version 吊销收窄、
// BE-C1-1 解压炸弹上限、R39-12 .version 伴生文件保留、R39-13 落盘失败警告、
// BE-C1-6 仅全局配置导出拒绝、BE-C1-10 单侧文件-版本表绑定、R39-14 ACME 引用
// 预检警告、LB-A2-2 NULL 归一 5→2。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// buildTestLbbak 把 JSON 备份(可选附 waf 文件)打包为 lbbak 载荷。
func buildTestLbbak(t *testing.T, jsonBackup string, xdbBytes []byte) []byte {
	t.Helper()
	var bundle *services.WafFileBundle
	if xdbBytes != nil {
		sum := sha256.Sum256(xdbBytes)
		bundle = &services.WafFileBundle{
			IP2RegionTag: "test-tag",
			IP2RegionSha: hex.EncodeToString(sum[:]),
			XdbB64:       xdbBytes,
		}
	}
	payload, err := buildLbbakPayload([]byte(jsonBackup), bundle)
	if err != nil {
		t.Fatalf("buildLbbakPayload: %v", err)
	}
	return payload
}

func postLbbakImport(g http.Handler, t *testing.T, body []byte, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import"+query, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	g.ServeHTTP(rec, req)
	return rec
}

// overrideTestWafPaths 重定向 CRS/xdb 活动路径到临时目录,返回还原函数。
func overrideTestWafPaths(t *testing.T) (crsDir, xdbPath string) {
	t.Helper()
	crsDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	xdbPath = filepath.Join(t.TempDir(), "ip2region.xdb")
	t.Cleanup(services.OverrideWafLivePathsForTest(crsDir, xdbPath))
	return crsDir, xdbPath
}

// R39-1:lbbak 导入的 ?sections= 必须生效——未选分类的表与 waf 文件都不得动。
func TestLbbakImport_sectionsQueryScoped(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	crsDir, xdbPath := overrideTestWafPaths(t)
	// 本地 xdb(旧内容,导入不应覆盖)
	if err := os.WriteFile(xdbPath, []byte("LOCAL-XDB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatal(err)
	}

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	})
	body := buildTestLbbak(t, backup, []byte("NEW-XDB-PAYLOAD"))

	rec := postLbbakImport(g, t, body, "?sections=rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("lbbak import sections=rules: %d %s", rec.Code, rec.Body.String())
	}

	var keeper int
	db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='local-keeper'`).Scan(&keeper)
	if keeper != 1 {
		t.Fatalf("sections=rules lbbak import must not touch users (local-keeper gone)")
	}
	var rules int
	db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='imp1'`).Scan(&rules)
	if rules != 1 {
		t.Fatalf("sections=rules lbbak import must apply rules")
	}
	// waf 文件未选分类 → 不得落盘(本地 xdb 保持旧内容)
	got, err := os.ReadFile(xdbPath)
	if err != nil || string(got) != "LOCAL-XDB" {
		t.Fatalf("unselected waf_files must not land, xdb=%q err=%v", string(got), err)
	}
	_ = crsDir
}

// R39-11:password_version 吊销收窄为「选中系统数据」——仅规则导入不吊销,
// 含系统数据导入吊销且响应携带提示。
func TestLbbakImport_passwordVersionBumpScoped(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (5,'keeper','x','admin',1,7)`); err != nil {
		t.Fatal(err)
	}

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "imp2", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	})
	body := buildTestLbbak(t, backup, nil)

	// 仅 rules:password_version 不动,响应无吊销提示
	rec := postLbbakImport(g, t, body, "?sections=rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var ver int
	db.DB.QueryRow(`SELECT COALESCE(password_version,0) FROM users WHERE username='keeper'`).Scan(&ver)
	if ver != 7 {
		t.Fatalf("rules-only import must not bump password_version, got %d", ver)
	}
	if strings.Contains(rec.Body.String(), "吊销") {
		t.Fatalf("rules-only import must not warn about session revocation: %s", rec.Body.String())
	}

	// 重置规则避免冲突后全量导入:吊销发生+提示在响应
	if _, err := db.DB.Exec(`DELETE FROM lb_rules WHERE caddy_id='imp2'`); err != nil {
		t.Fatal(err)
	}
	body2 := buildTestLbbak(t, completeBackupJSON(t, nil), nil)
	rec = postLbbakImport(g, t, body2, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("full import: %d %s", rec.Code, rec.Body.String())
	}
	var ver2 int
	db.DB.QueryRow(`SELECT COALESCE(password_version,0) FROM users WHERE username='backup-admin'`).Scan(&ver2)
	if ver2 < 1 {
		t.Fatalf("users-section import must bump password_version, got %d", ver2)
	}
	if !strings.Contains(rec.Body.String(), "吊销") {
		t.Fatalf("users-section import must warn about session revocation: %s", rec.Body.String())
	}
}

// craftLbbakRaw 直接构造 gzip+tar 载荷(绕过 buildLbbakPayload 的固定条目,
// 用于上限测试的畸形形状)。
func craftLbbakRaw(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// BE-C1-1:parseLbbak 条目数与总解压字节上限。
func TestParseLbbak_entryAndTotalCaps(t *testing.T) {
	// 条目数上限(>64 拒绝)
	entries := map[string][]byte{}
	for i := 0; i < 65; i++ {
		entries[fmt.Sprintf("e%03d", i)] = []byte("x")
	}
	payload := craftLbbakRaw(t, entries)
	if _, err := parseLbbak(payload); err == nil || !strings.Contains(err.Error(), "条目") {
		t.Fatalf("65 entries must be rejected, got err=%v", err)
	}

	// 总解压字节上限(var 收窄构造边界)
	old := maxLbbakTotalBytes
	maxLbbakTotalBytes = 8
	t.Cleanup(func() { maxLbbakTotalBytes = old })
	payload = craftLbbakRaw(t, map[string][]byte{"manifest.json": []byte(`{"format":"lbbak","checksum":{}}`), "config.json": bytes.Repeat([]byte("y"), 16)})
	if _, err := parseLbbak(payload); err == nil || !strings.Contains(err.Error(), "解压") {
		t.Fatalf("over-total-bytes must be rejected, got err=%v", err)
	}
}

// R39-12:含 xdb 的 lbbak 导入(字节未变)不得删除 .version 伴生文件——
// 版本 tag 从备份表区传入。
func TestLbbakImport_preservesXdbVersionSidecar(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	_, xdbPath := overrideTestWafPaths(t)

	xdb := []byte("XDB-BYTES")
	if err := os.WriteFile(xdbPath, xdb, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdbPath+".version", []byte("tag-keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip2region_version": {{"id": 1, "version": "tag-keep", "auto_update": 1}},
	})
	body := buildTestLbbak(t, backup, xdb)
	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(xdbPath + ".version")
	if err != nil || strings.TrimSpace(string(got)) != "tag-keep" {
		t.Fatalf("xdb .version sidecar must be preserved/aligned to backup tag, got %q err=%v", string(got), err)
	}
}

// R39-13:规则库文件落盘失败必须进入响应 warnings(不得静默纯成功)。
func TestLbbakImport_wafFileFailureWarns(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	_, xdbPath := overrideTestWafPaths(t)
	// 制造落盘失败:预占 xdb.sync 为目录 → WriteFile 失败
	if err := os.MkdirAll(xdbPath+".sync", 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(xdbPath + ".sync") })

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip2region_version": {{"id": 1, "version": "t", "auto_update": 1}},
	})
	body := buildTestLbbak(t, backup, []byte("DIFFERENT-XDB"))
	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("import should still succeed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "规则库文件落盘失败") {
		t.Fatalf("waf file apply failure must surface in response warnings: %s", rec.Body.String())
	}
}

// 三分类合并(2026-09-19 用户裁定):legacy 分类键 global_config 是「系统数据」
// (users)的别名、waf_files 是「安全防护」(security)的别名——旧书签/脚本的
// ?sections= 导出必须成功且携带对应表族,不再 400(BE-C1-6 死备份哨兵随
// 分类合并撤销:users 恒有表,「仅全局配置」形态不可达)。
func TestExportConfigBackup_legacySectionAliases(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)

	tests := []struct {
		name       string
		query      string
		wantTables []string
		skipTables []string
		wantGlobal bool
	}{
		{
			name:       "global_config alias exports user data with config block",
			query:      "/config/export?sections=global_config",
			wantTables: []string{"users", "api_keys", "ca_providers", "certificate_configs"},
			skipTables: []string{"lb_rules", "security_policies", "security_crs_version"},
			wantGlobal: true,
		},
		{
			name:       "waf_files alias exports security tables",
			query:      "/config/export?sections=waf_files",
			wantTables: []string{"security_policies", "security_crs_version", "security_ip2region_version"},
			skipTables: []string{"users", "lb_rules"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.query, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("legacy alias export must succeed, got %d %s", rec.Code, rec.Body.String())
			}
			parsed, err := parseLbbak(rec.Body.Bytes())
			if err != nil {
				t.Fatalf("parse lbbak: %v", err)
			}
			var backup configBackup
			if err := json.Unmarshal(parsed.ConfigJSON, &backup); err != nil {
				t.Fatalf("unmarshal config.json: %v", err)
			}
			for _, table := range tt.wantTables {
				if _, ok := backup.Tables[table]; !ok {
					t.Fatalf("alias export must include table %s", table)
				}
			}
			for _, table := range tt.skipTables {
				if _, ok := backup.Tables[table]; ok {
					t.Fatalf("alias export must not include table %s", table)
				}
			}
			if tt.wantGlobal && len(backup.Config) == 0 {
				t.Fatal("global_config alias export must carry the global config block")
			}
			if !tt.wantGlobal && backup.Config != nil {
				t.Fatal("waf_files alias export must not carry the global config block")
			}
		})
	}
}

// 三分类合并勘误(2026-09-19):users 分类备份(系统数据表族+全局配置区)
// 必须可导入。旧「全量形态」探测器以「含 users 表」判定全量,把分类备份
// 误判为全量并以「缺少 lb_rules」拒绝——恰好制造 BE-C1-6 要消灭的死备份
// 形态(旧五分类模型下 users-only 导出同样中招,新增 users=系统数据含全局
// 配置后触发面扩大到 global_config 别名导出)。
func TestImportConfigBackup_usersCategoryBackupImports(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	tables := map[string][]map[string]any{
		"users":               {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		"api_keys":            {},
		"ca_providers":        {},
		"certificate_configs": {},
	}
	cfg := map[string]any{"log_level": "warn"}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-09-19T00:00:00Z"},
		Config: cfg,
		Tables: tables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, tables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	rec := postLbbakImport(g, t, buildTestLbbak(t, string(data), nil), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("users-category backup must import, got %d %s", rec.Code, rec.Body.String())
	}
	// 全局配置区随系统数据分类导入生效
	var level string
	if err := db.DB.QueryRow(`SELECT log_level FROM global_config WHERE id=1`).Scan(&level); err != nil || level != "warn" {
		t.Fatalf("log_level=%q err=%v, want warn (config block applied with users category)", level, err)
	}
}

// BE-C1-10:单侧 waf 文件缺失时对应版本表跳过并警告(xdb 在、CRS 缺 →
// security_crs_version 不被空表覆盖)。
func TestLbbakImport_singleSideWafBinding(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	// 本地 CRS 版本记录(导入后应保留)
	if _, err := db.DB.Exec(`INSERT INTO security_crs_version (id,version) VALUES (1,'v9.9.9')
		ON CONFLICT(id) DO UPDATE SET version='v9.9.9'`); err != nil {
		t.Fatal(err)
	}

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip2region_version": {{"id": 1, "version": "tag-x", "auto_update": 1}},
	})
	body := buildTestLbbak(t, backup, []byte("ONLY-XDB"))
	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var crs string
	db.DB.QueryRow(`SELECT version FROM security_crs_version WHERE id=1`).Scan(&crs)
	if crs != "v9.9.9" {
		t.Fatalf("missing CRS file must skip security_crs_version (got %q)", crs)
	}
	if !strings.Contains(rec.Body.String(), "CRS") || !strings.Contains(rec.Body.String(), "跳过") {
		t.Fatalf("single-side waf import must warn about skipped CRS metadata: %s", rec.Body.String())
	}
}

// R39-14:「系统数据」分类导入替换 ACME 配置表时,live 启用规则的悬挂引用
// 必须以警告显性化(不阻断)。
func TestImportConfigBackup_warnsDanglingACMEReferences(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,tls_source,acme_config_id)
		VALUES ('live1','live','http','b.example.com',80,1,'acme_dns',42)`); err != nil {
		t.Fatal(err)
	}

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"certificate_configs": {},
	})
	// JSON 注入 sections=users(系统数据)
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(backup), &parsed); err != nil {
		t.Fatal(err)
	}
	parsed["sections"] = json.RawMessage(`["users"]`)
	assembled, _ := json.Marshal(parsed)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(assembled)))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "DNS 提供商") || !strings.Contains(rec.Body.String(), "悬挂") {
		t.Fatalf("dangling ACME references must be warned: %s", rec.Body.String())
	}
}

// LB-A2-2:NULL health_check_timeout 归一为 2(与写侧/渲染/快照通道同口径)。
func TestImportConfigBackup_normalizesNullHealthCheckTimeout(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)

	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-admin','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "nullh", "name": "n", "protocol": "http", "domain": "c.example.com", "listen_port": 80, "enabled": 1, "health_check_timeout": nil}},
	})
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(backup), &parsed); err != nil {
		t.Fatal(err)
	}
	parsed["sections"] = json.RawMessage(`["rules"]`)
	assembled, _ := json.Marshal(parsed)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(assembled)))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var got int
	db.DB.QueryRow(`SELECT COALESCE(health_check_timeout,-1) FROM lb_rules WHERE caddy_id='nullh'`).Scan(&got)
	if got != 2 {
		t.Fatalf("NULL health_check_timeout must normalize to 2, got %d", got)
	}
}
