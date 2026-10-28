package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func backupJSONFixture(t *testing.T, tables map[string][]map[string]any, config map[string]any, sections []string) []byte {
	t.Helper()
	backup := configBackup{
		Sections: sections,
		Meta: configBackupMeta{
			App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-10-19T00:00:00Z",
			Checksum: checksumBackupPayload(t, tables, config),
		},
		Config: config,
		Tables: tables,
	}
	raw, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return raw
}

func postImportBytes(t *testing.T, h *Handlers, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	req := httptest.NewRequest(http.MethodPost, "/config/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func threatRowShared(name string) map[string]any {
	return map[string]any{
		"id": 1, "name": name, "display_name": name, "url": "https://example.test/list.txt",
		"format": "plain", "update_enabled": 1, "apply_enabled": 1, "entry_count": 1,
		"version": "v1", "update_status": "idle", "message": "",
	}
}

func seedLiveAdminShared(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
}

func TestFailedBackupRowsPrunedWithoutSuccess(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_sections='{broken' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for i := range autoBackupFailedRowsKeep + 2 {
		if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "tester", 0); err == nil {
			t.Fatalf("failure %d unexpectedly succeeded", i)
		}
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='failed'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != autoBackupFailedRowsKeep {
		t.Fatalf("failed rows=%d, want bounded at %d", count, autoBackupFailedRowsKeep)
	}
	var oldestMessage string
	if err := db.DB.QueryRow(`SELECT message FROM auto_backups WHERE status='failed' ORDER BY created_at ASC,id ASC LIMIT 1`).Scan(&oldestMessage); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(oldestMessage, "备份范围") {
		t.Fatalf("unexpected retained failure: %q", oldestMessage)
	}
}

func TestPureJSONThreatPreviewMatchesImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (id,name,display_name,update_enabled,apply_enabled) VALUES (91,'ustc','本地威胁源',1,1)`); err != nil {
		t.Fatal(err)
	}
	body := backupJSONFixture(t, map[string][]map[string]any{
		"security_threat_sources": {threatRowShared("firehol_l1")},
	}, nil, []string{"security"})

	// 纯 JSON 的威胁源表保留本地（不导入），该包实际零导入——预览与导入
	// 必须同判定拒绝（此前预览 valid=true 且只给告警、导入 200 谎报成功）。
	preview := postValidateBytes(t, h, body)
	if preview.Valid {
		t.Fatalf("threat-only pure JSON must be rejected as zero-import: %+v", preview)
	}
	if !strings.Contains(preview.Error, "均被跳过") {
		t.Fatalf("preview error=%q, want zero-import explanation", preview.Error)
	}

	rec := postImportBytes(t, h, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400（零导入）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "均被跳过") {
		t.Fatalf("import error=%s, want zero-import explanation", rec.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "ustc" {
		t.Fatalf("live threat source replaced by pure JSON backup: %q", name)
	}
}

func TestSoftSkipPrecedesRowValidation(t *testing.T) {
	t.Run("empty domain rule with invalid gated fields", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedLiveAdminShared(t)
		body := backupJSONFixture(t, map[string][]map[string]any{
			"lb_rules": {{
				"caddy_id": "lb_empty", "name": "empty", "protocol": "http", "domain": " ",
				"listen_port": 8080, "enabled": "1", "created_at": "garbage",
			}},
		}, nil, []string{"rules"})
		preview := postValidateBytes(t, h, body)
		if !preview.Valid || preview.Summary["lb_rules"] != 0 || len(preview.Warnings) == 0 {
			t.Fatalf("preview=%+v, want skipped empty-domain rule", preview)
		}
		rec := postImportBytes(t, h, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s, want soft-skipped rule accepted", rec.Code, rec.Body.String())
		}
		var count int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_empty'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("soft-skipped rule was imported: %d", count)
		}
	})
	t.Run("empty block page with invalid gated fields", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		body := backupJSONFixture(t, map[string][]map[string]any{
			"security_block_pages": {{"id": 91, "name": "empty", "content": "", "is_default": "1"}},
		}, nil, []string{"security"})
		preview := postValidateBytes(t, h, body)
		if !preview.Valid || preview.Summary["security_block_pages"] != 0 || len(preview.Warnings) == 0 {
			t.Fatalf("preview=%+v, want skipped empty block page", preview)
		}
	})
}

func ipListQuotaRowsShared(userCount int) []map[string]any {
	rows := make([]map[string]any, 0, userCount+len(db.ThreatSystemLists())+1)
	for i := 0; i < userCount; i++ {
		rows = append(rows, map[string]any{
			"id": 100 + i, "name": fmt.Sprintf("user-list-%d", i+1), "category": "custom",
			"entries": "[]", "system": 0,
		})
	}
	id := 1
	for _, seed := range db.ThreatSystemLists() {
		rows = append(rows, map[string]any{
			"id": id, "name": seed.Name, "category": "恶意 IP", "entries": "[]", "system": 1,
		})
		id++
	}
	rows = append(rows, map[string]any{
		"id": id, "name": services.AutobanPresetListName, "category": "自动封禁", "entries": "[]", "system": 1,
	})
	return rows
}

func TestIPListQuotaMatchesPostImportState(t *testing.T) {
	t.Run("200 users plus seeded system rows stay within final ceiling", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedLiveAdminShared(t)
		rec := postImportBytes(t, h, backupJSONFixture(t, map[string][]map[string]any{
			"security_ip_lists": ipListQuotaRowsShared(200),
		}, nil, []string{"security"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200-user backup accepted", rec.Code, rec.Body.String())
		}
		var total, users int
		if err := db.DB.QueryRow(`SELECT COUNT(*),SUM(CASE WHEN COALESCE(system,0)=0 THEN 1 ELSE 0 END) FROM security_ip_lists`).Scan(&total, &users); err != nil {
			t.Fatal(err)
		}
		// 导入提交后补播全部内置 system 名单：威胁三源 + 自动封禁 + 四个爬虫
		// 官方名单（备份未携带爬虫行时逐引擎补种）。
		wantSystem := len(db.ThreatSystemLists()) + 1 + len(services.CrawlerSystemListNames())
		if total != 200+wantSystem || users != 200 {
			t.Fatalf("final lists=%d users=%d, want %d/200", total, users, 200+wantSystem)
		}
	})
	t.Run("legacy 201 rows with system rows accepted", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedLiveAdminShared(t)
		rec := postImportBytes(t, h, backupJSONFixture(t, map[string][]map[string]any{
			"security_ip_lists": ipListQuotaRowsShared(197),
		}, nil, []string{"security"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want legacy >200 total with 197 user rows accepted", rec.Code, rec.Body.String())
		}
		var total, users int
		if err := db.DB.QueryRow(`SELECT COUNT(*),SUM(CASE WHEN COALESCE(system,0)=0 THEN 1 ELSE 0 END) FROM security_ip_lists`).Scan(&total, &users); err != nil {
			t.Fatal(err)
		}
		wantSystem := len(db.ThreatSystemLists()) + 1 + len(services.CrawlerSystemListNames())
		if total != 197+wantSystem || users != 197 {
			t.Fatalf("final lists=%d users=%d, want %d/197", total, users, 197+wantSystem)
		}
	})
	t.Run("201 user rows rejected", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedLiveAdminShared(t)
		rec := postImportBytes(t, h, backupJSONFixture(t, map[string][]map[string]any{
			"security_ip_lists": ipListQuotaRowsShared(201),
		}, nil, []string{"security"}))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "数量已达上限") {
			t.Fatalf("status=%d body=%s, want user quota rejection", rec.Code, rec.Body.String())
		}
	})
}

func TestCommittedThreatStateWouldPassNameOnlyRollbackAssertion(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources; DELETE FROM security_crs_version; DELETE FROM security_ip2region_version`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (id,name,display_name,update_enabled,apply_enabled) VALUES (91,'ustc','本地威胁源',1,1)`); err != nil {
		t.Fatal(err)
	}
	backupJSON := backupJSONFixture(t, map[string][]map[string]any{
		"security_threat_sources": {threatRowShared("ustc")},
	}, nil, []string{"security"})
	payload := buildLbbakWithExtraThreatEntry(t, string(backupJSON), []byte("5.6.7.8\n"))

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil)
	h.importConfigBackupCore(c, payload, "", "导入")
	if rec.Code != http.StatusOK {
		t.Fatalf("commit probe status=%d body=%s", rec.Code, rec.Body.String())
	}
	var id int
	var name, displayName string
	if err := db.DB.QueryRow(`SELECT id,name,display_name FROM security_threat_sources`).Scan(&id, &name, &displayName); err != nil {
		t.Fatal(err)
	}
	// 旧断言只比较 name；提交态这里同样是 ustc，因此它无法证明回滚。
	if name != "ustc" {
		t.Fatalf("probe setup name=%q, old name-only assertion would not pass", name)
	}
	if id != 1 || displayName != "ustc" {
		t.Fatalf("probe id=%d display=%q, want committed backup identity 1/ustc", id, displayName)
	}
}

func TestSentinelFailureRollsBackWafFilesWithNotice(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources; DELETE FROM security_crs_version; DELETE FROM security_ip2region_version`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (id,name,display_name,update_enabled,apply_enabled) VALUES (91,'ustc','本地威胁源',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(fmt.Sprintf(`CREATE TRIGGER failSentinelShared BEFORE INSERT ON security_crs_version
		WHEN NEW.version='%s' BEGIN SELECT RAISE(ABORT,'forced sentinel failure'); END`, importVersionSeedSentinel)); err != nil {
		t.Fatal(err)
	}
	backupJSON := backupJSONFixture(t, map[string][]map[string]any{
		"security_threat_sources": {threatRowShared("ustc")},
	}, nil, []string{"security"})
	payload := buildLbbakWithExtraThreatEntry(t, string(backupJSON), []byte("5.6.7.8\n"))

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil)
	h.importConfigBackupCore(c, payload, "", "导入")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want injected sentinel failure", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "threat-ustc.iplist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("threat file must be rolled back to pre-import (absent), err=%v", err)
	}
	var response struct {
		Data struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range response.Data.Warnings {
		found = found || (strings.Contains(warning, "数据库已回滚") && strings.Contains(warning, "已回退到导入前状态"))
	}
	if !found {
		t.Fatalf("warnings=%v, want explicit file rollback notice; body=%s", response.Data.Warnings, rec.Body.String())
	}
	var localID int
	var localName, localDisplayName string
	if err := db.DB.QueryRow(`SELECT id,name,display_name FROM security_threat_sources`).Scan(&localID, &localName, &localDisplayName); err != nil {
		t.Fatal(err)
	}
	if localID != 91 || localName != "ustc" || localDisplayName != "本地威胁源" {
		t.Fatalf("DB did not roll back to local threat identity: id=%d name=%q display=%q", localID, localName, localDisplayName)
	}
}

func TestClusterVersionSuppressionUsesEffectiveRole(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=NULL,cluster_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	restore, err := suppressImportClusterVersionBumps(ctx, tx)
	if err != nil {
		t.Fatalf("NULL role must use COALESCE(is_master,1): %v", err)
	}
	var suppressed int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&suppressed); err != nil {
		t.Fatal(err)
	}
	if suppressed != 0 {
		t.Fatalf("suppression did not apply to NULL-as-master: effective role=%d", suppressed)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	var restored int
	if err := tx.QueryRowContext(ctx, `SELECT is_master FROM global_config WHERE id=1`).Scan(&restored); err != nil {
		t.Fatal(err)
	}
	if restored != 1 {
		t.Fatalf("restored role=%d, want effective master 1", restored)
	}
}

func TestImportSuppressesPerRowClusterVersionBumps(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_old','old','http','old.example.test',18080,1)`); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"INSERT", "DELETE"} {
		if _, err := db.DB.Exec(fmt.Sprintf(`CREATE TRIGGER cluster_version_lb_rules_%s AFTER %s ON lb_rules
			WHEN (SELECT COALESCE(is_master,1) FROM global_config WHERE id=1)=1
			BEGIN UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1; END`, strings.ToLower(operation), operation)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	rules := []map[string]any{
		{"caddy_id": "lb_new1", "name": "new1", "protocol": "http", "domain": "new1.example.test", "listen_port": 18081, "enabled": 1},
		{"caddy_id": "lb_new2", "name": "new2", "protocol": "http", "domain": "new2.example.test", "listen_port": 18082, "enabled": 1},
	}
	upstreams := []map[string]any{
		{"id": 101, "rule_id": "lb_new1", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1},
		{"id": 102, "rule_id": "lb_new2", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1},
	}
	rec := postImportBytes(t, h, backupJSONFixture(t, map[string][]map[string]any{
		"lb_rules": rules, "upstreams": upstreams,
	}, nil, []string{"rules"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var version, master, ruleCount int
	if err := db.DB.QueryRow(`SELECT cluster_version,COALESCE(is_master,1),(SELECT COUNT(*) FROM lb_rules) FROM global_config WHERE id=1`).Scan(&version, &master, &ruleCount); err != nil {
		t.Fatal(err)
	}
	if version != 1 || master != 1 || ruleCount != 2 {
		t.Fatalf("version=%d master=%d rules=%d, want one final bump, restored master role, two rows", version, master, ruleCount)
	}
}

func policyBackupShared(t *testing.T) []byte {
	t.Helper()
	return backupJSONFixture(t, map[string][]map[string]any{
		"security_policies": {{
			"id": 5, "name": "live refs", "mode": "off", "ip_acl_mode": "deny", "geoip_mode": "deny",
			"ip_acl_list_refs": "[77]", "ip_whitelist_refs": "[]", "crs_rule_groups": "[]",
			"crs_excluded_rules": "[]", "custom_rules": "[]", "rate_limit_enabled": 0,
		}},
	}, nil, []string{"security"})
}

func TestPolicyIPListReferencesFallbackToLive(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,category,entries,system) VALUES (77,'live list','custom','[{"value":"192.0.2.1"}]',0)`); err != nil {
		t.Fatal(err)
	}
	body := policyBackupShared(t)
	preview := postValidateBytes(t, h, body)
	if !preview.Valid {
		t.Fatalf("live-resolvable policy reference rejected in preview: %s", preview.Error)
	}
	rec := postImportBytes(t, h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var policyID, listID int
	if err := db.DB.QueryRow(`SELECT (SELECT id FROM security_policies WHERE name='live refs'),(SELECT id FROM security_ip_lists WHERE id=77)`).Scan(&policyID, &listID); err != nil {
		t.Fatal(err)
	}
	if policyID != 5 || listID != 77 {
		t.Fatalf("policy=%d list=%d, want imported policy and preserved live list", policyID, listID)
	}
}

func TestPolicyIPListLiveFallbackRevalidatesInsideImportLock(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,category,entries,system) VALUES (77,'live list','custom','[{"value":"192.0.2.1"}]',0)`); err != nil {
		t.Fatal(err)
	}
	configImportBeforeLock = func() {
		if _, err := db.DB.Exec(`DELETE FROM security_ip_lists WHERE id=77`); err != nil {
			panic(err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = nil })
	rec := postImportBytes(t, h, policyBackupShared(t))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "导入期间") {
		t.Fatalf("status=%d body=%s, want locked live-reference rejection", rec.Code, rec.Body.String())
	}
	var policies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=5`).Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if policies != 0 {
		t.Fatal("policy imported despite live list disappearing before lock")
	}
}

func TestAutoBackupSettingsReturnsSchedulerNextRun(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	past := time.Now().In(services.CurrentLocation()).Add(-time.Hour).Format("15:04")
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1,auto_backup_frequency='daily',auto_backup_time=?,auto_backup_last_run=NULL WHERE id=1`, past); err != nil {
		t.Fatal(err)
	}
	rec := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	var response struct {
		Data struct {
			NextRunAt  *string `json:"next_run_at"`
			CatchUpDue bool    `json:"catch_up_due"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || response.Data.NextRunAt == nil || !response.Data.CatchUpDue {
		t.Fatalf("status=%d next=%v catchup=%v body=%s, want real missed-slot schedule", rec.Code, response.Data.NextRunAt, response.Data.CatchUpDue, rec.Body.String())
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, time.Now().Add(time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	rec = serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	response.Data.NextRunAt = nil
	response.Data.CatchUpDue = true
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.NextRunAt == nil || response.Data.CatchUpDue {
		t.Fatalf("next=%v catchup=%v, want covered watermark and future slot", response.Data.NextRunAt, response.Data.CatchUpDue)
	}
}

func TestRestoreRejectsOversizedFileBeforeImport(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	filename := "lbbak-manual-oversized.lbbak"
	path := filepath.Join(h.cfg.BackupDir, filename)
	if err := os.WriteFile(path, []byte("not a backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxConfigImportBytes+1); err != nil {
		t.Fatal(err)
	}
	id, err := insertAutoBackupRow(filename, "success", maxConfigImportBytes+1, `["users"]`, "manual", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auto-backup/:id/restore", h.RestoreAutoBackup)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/auto-backup/%d/restore", id), nil))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413 before oversized restore import", rec.Code, rec.Body.String())
	}
}

func TestAutoBackupCleansOnlyOwnedTempFiles(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	owned := []string{
		"lbbak-auto-20000101-000000.lbbak.tmp",
		".lbbak-auto-20000101-000000.lbbak-12345.tmp",
	}
	for _, name := range owned {
		if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, name), []byte("stale secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(h.cfg.BackupDir, "ops-notes.tmp")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "tester", 0); err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	for _, name := range owned {
		if _, err := os.Stat(filepath.Join(h.cfg.BackupDir, name)); !os.IsNotExist(err) {
			t.Fatalf("owned stale temp %s remains, err=%v", name, err)
		}
	}
	if raw, err := os.ReadFile(unrelated); err != nil || string(raw) != "keep" {
		t.Fatalf("unrelated temp was touched: raw=%q err=%v", raw, err)
	}
	matches, err := filepath.Glob(filepath.Join(h.cfg.BackupDir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0] != unrelated {
		t.Fatalf("unexpected temp files after atomic backup: %v", matches)
	}
}

func TestBackupProductVersionMetadataAndWarning(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.Version = "v9.8.7"
	payload, _, _, _, err := h.buildLbbakExport(context.Background(), []string{"rules"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseLbbak(payload)
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Meta map[string]any `json:"meta"`
	}
	if err := json.Unmarshal(parsed.ConfigJSON, &exported); err != nil {
		t.Fatal(err)
	}
	if exported.Meta["app_version"] != "v9.8.7" {
		t.Fatalf("export meta=%v, want real app_version", exported.Meta)
	}

	tables := map[string][]map[string]any{"lb_rules": {}}
	raw := map[string]any{
		"meta": map[string]any{
			"app": "lazy-balancer-v2", "version": 2, "exported_at": "2026-10-19T00:00:00Z",
			"app_version": "v1.2.3", "checksum": checksumBackupPayload(t, tables, nil),
		},
		"config": nil, "tables": tables, "sections": []string{"rules"},
	}
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	preview := postValidateBytes(t, h, body)
	found := false
	for _, warning := range preview.Warnings {
		found = found || (strings.Contains(warning, "v1.2.3") && strings.Contains(warning, "v9.8.7"))
	}
	if !preview.Valid || !found {
		t.Fatalf("preview=%+v, want cross-product-version compatibility warning", preview)
	}
}

func TestImportAcceptsBackupAboveFormer48MBLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", io.NopCloser(bytes.NewReader(nil)))
	c.Request.ContentLength = 49 << 20
	if !limitConfigImportBody(c) {
		t.Fatalf("49MB lbbak rejected before parsing: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLbbakExportRejectsPayloadBeyondImportLimit(t *testing.T) {
	previous := maxConfigImportBytes
	maxConfigImportBytes = 1024
	t.Cleanup(func() { maxConfigImportBytes = previous })

	if _, err := buildLbbakPayload([]byte(`{"meta":{}}`), nil); err != nil {
		t.Fatalf("small export must remain round-trippable: %v", err)
	}
	incompressible := make([]byte, 8192)
	rng := rand.New(rand.NewPCG(85, 86))
	for i := range incompressible {
		incompressible[i] = byte(rng.IntN(256))
	}
	if _, err := buildLbbakPayload(incompressible, nil); err == nil || !strings.Contains(err.Error(), "可还原") {
		t.Fatalf("oversized export err=%v, want explicit restorable-limit rejection", err)
	}
}

func TestLbbakExportRejectsDecompressedOverflow(t *testing.T) {
	withIsolatedGlobal(t)
	previous := maxLbbakTotalBytes
	maxLbbakTotalBytes = 1024
	t.Cleanup(func() { maxLbbakTotalBytes = previous })

	if _, err := buildLbbakPayload(bytes.Repeat([]byte("a"), 2048), nil); err == nil || !strings.Contains(err.Error(), "解压总字节") {
		t.Fatalf("compressible overflow err=%v, want decompressed-limit rejection", err)
	}
}
