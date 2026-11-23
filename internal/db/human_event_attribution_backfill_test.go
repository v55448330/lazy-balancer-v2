package db

// 历史人机事件归属回填的选策略口径必须与实时直写单源（stage2 ∪ mixed）：
// 只认 stage2 会让升级库中 mixed 策略的历史人机事件永久 policy_id=0
// （触发详情「无策略归属」）。

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestBackfillHumanEventPolicyAttribution_includesMixedPolicy(t *testing.T) {
	oldDB, oldMetricsDB := DB, MetricsDB
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB = oldDB, oldMetricsDB
	})
	// Initialize 已跑过一次性回填并置位 marker；移除 marker 让回填可再执行。
	if _, err := MetricsDB.Exec(`DELETE FROM metrics_meta WHERE key='human_event_attribution_backfill_v1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-backfill','bf','http','bf.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	res, err := DB.Exec(`INSERT INTO security_policies (name,policy_type,enabled) VALUES ('混合策略','mixed',1)`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb-backfill',?)`, policyID); err != nil {
		t.Fatal(err)
	}
	if _, err := MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, client_ip, event_type, action, policy_id) VALUES ('2026-11-20 10:00:00','lb-backfill','203.0.113.5','human','challenged',0)`); err != nil {
		t.Fatal(err)
	}

	if err := backfillHumanEventPolicyAttribution(); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var gotPolicyID int
	var gotPolicyName, gotRuleName string
	if err := MetricsDB.QueryRow(`SELECT COALESCE(policy_id,0), COALESCE(policy_name,''), COALESCE(rule_name,'') FROM security_events WHERE event_type='human'`).
		Scan(&gotPolicyID, &gotPolicyName, &gotRuleName); err != nil {
		t.Fatal(err)
	}
	if gotPolicyID != int(policyID) || gotPolicyName != "混合策略" {
		t.Fatalf("mixed 策略归属未回填：policy_id=%d policy_name=%q, want %d/混合策略", gotPolicyID, gotPolicyName, policyID)
	}
	if gotRuleName != "bf" {
		t.Fatalf("rule_name=%q, want bf", gotRuleName)
	}
}

// openHumanAttributionFixture 建最小主库（lb_rules/绑定/策略）与 metrics 库
// （security_events/metrics_meta），接管全局句柄并在收尾关闭+归位。
func openHumanAttributionFixture(t *testing.T) (mainDB, metricsDB *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	mainDB, err := sql.Open("sqlite", filepath.Join(dir, "main.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open main db: %v", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE lb_rules (caddy_id TEXT PRIMARY KEY, name TEXT)`,
		`CREATE TABLE security_policy_bindings (rule_caddy_id TEXT, policy_id INTEGER, rank INTEGER)`,
		`CREATE TABLE security_policies (id INTEGER PRIMARY KEY, name TEXT, policy_type TEXT)`,
	} {
		if _, err := mainDB.Exec(ddl); err != nil {
			t.Fatalf("create main schema %q: %v", ddl, err)
		}
	}
	metricsDB, err = sql.Open("sqlite", filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatalf("open metrics db: %v", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_time TEXT, rule_caddy_id TEXT, client_ip TEXT, event_type TEXT, action TEXT,
			policy_id INTEGER, rule_name TEXT DEFAULT '', policy_name TEXT DEFAULT '', rule_triggered TEXT DEFAULT '')`,
		`CREATE TABLE metrics_meta (key TEXT PRIMARY KEY, value TEXT)`,
	} {
		if _, err := metricsDB.Exec(ddl); err != nil {
			t.Fatalf("create metrics schema %q: %v", ddl, err)
		}
	}
	oldDB, oldMetricsDB := DB, MetricsDB
	DB, MetricsDB = mainDB, metricsDB
	t.Cleanup(func() {
		_ = mainDB.Close()
		_ = metricsDB.Close()
		DB, MetricsDB = oldDB, oldMetricsDB
	})
	return mainDB, metricsDB
}

func seedHumanEvent(t *testing.T, metricsDB *sql.DB, ruleTriggered, ruleCaddyID string) {
	t.Helper()
	if _, err := metricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, client_ip, event_type, action, policy_id, rule_triggered)
		VALUES ('2026-11-20 10:00:00', ?, '203.0.113.5', 'human', 'challenged', 0, ?)`, ruleCaddyID, ruleTriggered); err != nil {
		t.Fatalf("seed human event: %v", err)
	}
}

func humanAttributionMarker(t *testing.T, metricsDB *sql.DB) (string, bool) {
	t.Helper()
	var value string
	err := metricsDB.QueryRow(`SELECT value FROM metrics_meta WHERE key='human_event_attribution_backfill_v1'`).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		t.Fatalf("read attribution marker: %v", err)
	}
	return value, true
}

// 规则归属查询失败必须向上返回且不置 marker：吞错后置 marker 会让历史事件
// 永久停在「无策略归属」，且下次启动不再重试。
func TestBackfillHumanEventPolicyAttribution_propagatesLookupError(t *testing.T) {
	mainDB, metricsDB := openHumanAttributionFixture(t)
	seedHumanEvent(t, metricsDB, "human_challenge", "lb-x")
	if _, err := mainDB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules to force lookup error: %v", err)
	}

	if err := backfillHumanEventPolicyAttribution(); err == nil {
		t.Fatal("规则归属查询失败必须返回错误（不得吞错置 marker）")
	}
	if _, ok := humanAttributionMarker(t, metricsDB); ok {
		t.Fatal("查询失败时不得写回填 marker（否则本批事件永久无归属）")
	}
	var policyID int
	var ruleName string
	if err := metricsDB.QueryRow(`SELECT COALESCE(policy_id,0), COALESCE(rule_name,'') FROM security_events`).Scan(&policyID, &ruleName); err != nil {
		t.Fatal(err)
	}
	if policyID != 0 || ruleName != "" {
		t.Fatalf("查询失败时事件不得被改写: policy_id=%d rule_name=%q", policyID, ruleName)
	}
}

// 规则已删（sql.ErrNoRows）不是错误：按「人机验证」默认归属保留事件并置
// marker（与历史行为一致，不得因规则删除阻断启动）。
func TestBackfillHumanEventPolicyAttribution_missingRuleKeepsDefaultAttribution(t *testing.T) {
	_, metricsDB := openHumanAttributionFixture(t)
	seedHumanEvent(t, metricsDB, "human_challenge", "lb-gone")

	if err := backfillHumanEventPolicyAttribution(); err != nil {
		t.Fatalf("backfill: %v（规则已删不得阻断）", err)
	}
	var policyID int
	var ruleName string
	if err := metricsDB.QueryRow(`SELECT COALESCE(policy_id,0), COALESCE(rule_name,'') FROM security_events`).Scan(&policyID, &ruleName); err != nil {
		t.Fatal(err)
	}
	if policyID != 0 || ruleName != "人机验证" {
		t.Fatalf("event=(%d,%q), want (0,人机验证)", policyID, ruleName)
	}
	if value, ok := humanAttributionMarker(t, metricsDB); !ok || value != "1" {
		t.Fatalf("marker=%q/%v, want 1/true", value, ok)
	}
}

// 回填必须单事务批处理：中途失败整批回滚且不置 marker，不得留下部分行已改
// 的半迁移态。
func TestBackfillHumanEventPolicyAttribution_atomicOnMidwayFailure(t *testing.T) {
	_, metricsDB := openHumanAttributionFixture(t)
	seedHumanEvent(t, metricsDB, "human_challenge", "lb-gone")
	seedHumanEvent(t, metricsDB, "human_challenge", "lb-gone")
	if _, err := metricsDB.Exec(`CREATE TRIGGER fail_last_update BEFORE UPDATE ON security_events
		WHEN OLD.id=(SELECT MAX(id) FROM security_events) BEGIN SELECT RAISE(ABORT,'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}

	if err := backfillHumanEventPolicyAttribution(); err == nil {
		t.Fatal("中途更新失败必须返回错误")
	}
	if _, ok := humanAttributionMarker(t, metricsDB); ok {
		t.Fatal("中途失败不得写回填 marker")
	}
	var updated int
	if err := metricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE COALESCE(rule_name,'')<>''`).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if updated != 0 {
		t.Fatalf("失败批次已改写行=%d, want 0（逐行自动提交会留下半迁移态）", updated)
	}
}

// human_pass（挑战成功=放行结果）不参与归属回填：这些行由删除迁移清理，先
// 回填纯白写且会污染 marker 计数。
func TestBackfillHumanEventPolicyAttribution_skipsHumanPassEvents(t *testing.T) {
	_, metricsDB := openHumanAttributionFixture(t)
	seedHumanEvent(t, metricsDB, "human_pass", "lb-gone")
	seedHumanEvent(t, metricsDB, "human_challenge", "lb-gone")

	if err := backfillHumanEventPolicyAttribution(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var passRuleName, passPolicyName string
	if err := metricsDB.QueryRow(`SELECT COALESCE(rule_name,''), COALESCE(policy_name,'') FROM security_events WHERE rule_triggered='human_pass'`).
		Scan(&passRuleName, &passPolicyName); err != nil {
		t.Fatal(err)
	}
	if passRuleName != "" || passPolicyName != "" {
		t.Fatalf("human_pass row 被回填: rule_name=%q policy_name=%q（应留给删除迁移）", passRuleName, passPolicyName)
	}
	if value, ok := humanAttributionMarker(t, metricsDB); !ok || value != "1" {
		t.Fatalf("marker=%q/%v, want 1（只计安全事件，不含 human_pass）", value, ok)
	}
}

// 启动序：删除迁移（human_pass 清理）先于归属回填。二次 Initialize 时先清掉
// 两个 marker，让两迁移都重跑；human_pass 行必须被删且不进入回填计数。
func TestInitialize_cleanupHumanPassRunsBeforeAttributionBackfill(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := MetricsDB.Exec(`DELETE FROM metrics_meta WHERE key IN ('human_event_attribution_backfill_v1','human_pass_events_cleanup_v1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, client_ip, event_type, action, policy_id, rule_triggered) VALUES
		('2026-11-20 10:00:00','', '203.0.113.5','human','allowed',0,'human_pass'),
		('2026-11-20 10:01:00','', '203.0.113.6','human','challenged',0,'human_challenge')`); err != nil {
		t.Fatal(err)
	}

	if err := Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("reinitialize: %v", err)
	}

	// Then human_pass 已清理；回填只计 1 条安全事件。
	var passRows int
	if err := MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE rule_triggered='human_pass'`).Scan(&passRows); err != nil {
		t.Fatal(err)
	}
	if passRows != 0 {
		t.Fatalf("human_pass 残留=%d, want 0", passRows)
	}
	var marker string
	if err := MetricsDB.QueryRow(`SELECT value FROM metrics_meta WHERE key='human_event_attribution_backfill_v1'`).Scan(&marker); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if marker != "1" {
		t.Fatalf("回填 marker=%q, want 1（human_pass 不得计入）", marker)
	}
}
