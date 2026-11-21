package db

// 历史人机事件归属回填的选策略口径必须与实时直写单源（stage2 ∪ mixed）：
// 只认 stage2 会让升级库中 mixed 策略的历史人机事件永久 policy_id=0
// （触发详情「无策略归属」）。

import (
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
