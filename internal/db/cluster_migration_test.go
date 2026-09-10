package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestInitialize_migrates_cluster_columns_and_token_table(t *testing.T) {
	// Given
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, caddy_config TEXT, is_master BOOLEAN DEFAULT 1);
		INSERT INTO global_config VALUES (1, '{}', 1);
		CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT NOT NULL, mode TEXT, ip_address TEXT, port INTEGER, master_id INTEGER, is_approved BOOLEAN, sync_enabled BOOLEAN, sync_interval INTEGER, sync_scope TEXT, status TEXT, last_seen DATETIME, created_at DATETIME);`); err != nil {
		t.Fatalf("seed legacy database: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize migrated database: %v", err)
	}

	// Then
	var clusterVersion int
	if err := DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&clusterVersion); err != nil {
		t.Fatalf("read cluster defaults: %v", err)
	}
	if clusterVersion != 0 {
		t.Fatalf("cluster version=%d, want 0", clusterVersion)
	}
	var syncCaddyColumn int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='sync_caddy_config'").Scan(&syncCaddyColumn); err != nil {
		t.Fatalf("query sync_caddy_config column: %v", err)
	}
	if syncCaddyColumn != 0 {
		t.Fatalf("sync_caddy_config column still present (count=%d), want dropped", syncCaddyColumn)
	}
	var tokenTable int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cluster_register_tokens'").Scan(&tokenTable); err != nil {
		t.Fatalf("query token table: %v", err)
	}
	if tokenTable != 1 {
		t.Fatalf("cluster_register_tokens count=%d, want 1", tokenTable)
	}
	var usedTicketTable int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='used_login_tickets'").Scan(&usedTicketTable); err != nil {
		t.Fatalf("query used ticket table: %v", err)
	}
	if usedTicketTable != 1 {
		t.Fatalf("used_login_tickets count=%d, want 1", usedTicketTable)
	}
	var revokedJTITable int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='revoked_jti'").Scan(&revokedJTITable); err != nil {
		t.Fatalf("query revoked JWT table: %v", err)
	}
	if revokedJTITable != 1 {
		t.Fatalf("revoked_jti count=%d, want 1", revokedJTITable)
	}
	for _, column := range []string{"cluster_token_hash", "registration_secret", "reported_version", "health_json", "last_sync_at", "last_sync_error", "access_url"} {
		var count int
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name=?", column).Scan(&count); err != nil {
			t.Fatalf("query nodes column %s: %v", column, err)
		}
		if count != 1 {
			t.Fatalf("nodes column %s count=%d, want 1", column, count)
		}
	}
}

// 2026-09-09 裁定:WAF 模式四态化存量迁移——mode=off 且挂启用中自定义规则的
// 策略迁移 custom_only(行为零突变);off 且无启用自定义规则的策略保持 off。
func TestMigrateSecurityPolicyCustomOnlyMode(t *testing.T) {
	dir := t.TempDir()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	seed := func(name, mode, customRules string) {
		t.Helper()
		if _, err := DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules) VALUES (?,?,?)`, name, mode, customRules); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	enabledRule := `[{"id":1,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`
	disabledRule := `[{"id":2,"name":"r2","enabled":false,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/y"}]}]`
	seed("off带启用规则", "off", enabledRule)
	seed("off带禁用规则", "off", disabledRule)
	seed("off无规则", "off", "[]")
	seed("blocking带规则", "blocking", enabledRule)

	// v2.1.0 起 custom_rules 存规则 ID 数组(引用 security_custom_rules 表)
	if _, err := DB.Exec(`INSERT INTO security_custom_rules (name, action, score, enabled) VALUES ('引用规则','block',5,1)`); err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	var refID int64
	if err := DB.QueryRow(`SELECT id FROM security_custom_rules WHERE name='引用规则'`).Scan(&refID); err != nil {
		t.Fatalf("read ref id: %v", err)
	}
	seed("off挂ID数组", "off", fmt.Sprintf(`[%d]`, refID))

	// Initialize 已空跑过一次迁移并置位一次性门——模拟「升级窗口」需重置旗标
	// (生产升级路径:存量行先在库,runMigrations 首次执行即完成迁移并置位)
	if _, err := DB.Exec(`UPDATE global_config SET waf_mode4_migrated=0 WHERE id=1`); err != nil {
		t.Fatalf("reset flag: %v", err)
	}
	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	modeOf := func(name string) string {
		t.Helper()
		var mode string
		if err := DB.QueryRow(`SELECT mode FROM security_policies WHERE name=?`, name).Scan(&mode); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return mode
	}
	if got := modeOf("off带启用规则"); got != "custom_only" {
		t.Fatalf("off+启用规则 = %q, want custom_only", got)
	}
	if got := modeOf("off挂ID数组"); got != "custom_only" {
		t.Fatalf("off+ID数组引用启用规则 = %q, want custom_only", got)
	}
	// 一次性门:迁移后用户主动改回 off(规则保留)不应被下次运行再次迁移
	if _, err := DB.Exec(`UPDATE security_policies SET mode='off' WHERE name='off带启用规则'`); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if got := modeOf("off带启用规则"); got != "off" {
		t.Fatalf("迁移必须一次性:主动改回 off 后被再次迁移为 %q", got)
	}
	for name, want := range map[string]string{"off带禁用规则": "off", "off无规则": "off", "blocking带规则": "blocking"} {
		if got := modeOf(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

// S3(2026-09-10 审计):迁移 SQL 对畸形 custom_rules JSON 无容错——json_each 抛
// malformed JSON 会让 runMigrations 失败→启动失败。修复后畸形行跳过(不迁移不
// 炸),其余行照常迁移。
func TestMigrateSecurityPolicyCustomOnlyMode_toleratesMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules) VALUES ('畸形','off','"text"')`); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules) VALUES ('正常off启用','off','[{"id":1,"enabled":true,"action":"block","score":5}]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`UPDATE global_config SET waf_mode4_migrated=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("畸形 JSON 不得使迁移失败: %v", err)
	}
	modeOf := func(name string) string {
		var mode string
		if err := DB.QueryRow(`SELECT mode FROM security_policies WHERE name=?`, name).Scan(&mode); err != nil {
			t.Fatal(err)
		}
		return mode
	}
	if got := modeOf("正常off启用"); got != "custom_only" {
		t.Fatalf("正常行 = %q, want custom_only(畸形行不拖累他行)", got)
	}
	if got := modeOf("畸形"); got != "off" {
		t.Fatalf("畸形行 = %q, want off(跳过)", got)
	}
}

// B-1(第 4 轮审计 P1):导入归一 SQL 缺 json_type 门——顶层字符串形状使
// json_each→json_extract 抛 malformed JSON→整包导入 500 回滚。
// 迁移路径(db.go)已有双门,导入路径必须同口径。
// 此测试直接跑与 config_backup.go 导入归一同款 SQL 形状,验证顶层字符串不炸。
func TestImportNormalization_jsonTypeGateBlocksTopLevelString(t *testing.T) {
	dir := t.TempDir()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	// 种子:顶层字符串(旧世界畸形,合法 JSON 但非容器)
	if _, err := DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules) VALUES ('顶层串','off','"str"')`); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules) VALUES ('正常启用','off','[{"id":1,"enabled":true,"action":"block","score":5}]')`); err != nil {
		t.Fatal(err)
	}
	// 与 config_backup.go:1776-1782 同款 SQL + json_type 双门
	_, err := DB.Exec(`UPDATE security_policies SET mode='custom_only'
WHERE mode='off' AND json_valid(COALESCE(custom_rules,'[]')) AND json_type(COALESCE(custom_rules,'[]')) IN ('array','object') AND EXISTS (
  SELECT 1 FROM json_each(COALESCE(custom_rules,'[]')) je
  WHERE json_extract(je.value,'$.enabled')=1
     OR (json_type(je.value)='integer' AND EXISTS (
          SELECT 1 FROM security_custom_rules r
          WHERE r.id=je.value AND COALESCE(r.enabled,1)=1)))`)
	if err != nil {
		t.Fatalf("导入归一双门 SQL 对顶层字符串不得报错: %v", err)
	}
	var mode string
	if err := DB.QueryRow(`SELECT mode FROM security_policies WHERE name='顶层串'`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "off" {
		t.Fatalf("顶层串 = %q, want off(应被 json_type 门跳过)", mode)
	}
	if err := DB.QueryRow(`SELECT mode FROM security_policies WHERE name='正常启用'`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "custom_only" {
		t.Fatalf("正常启用 = %q, want custom_only", mode)
	}
}
