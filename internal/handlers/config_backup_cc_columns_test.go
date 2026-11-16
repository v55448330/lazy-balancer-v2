package handlers

// CC 三态列导入门钉测（导入不宽于保存侧）：cc_trigger_action 枚举外归一
// challenge；cc_queue_wait_sec 钳位 [0,300]（防手造备份突破保存侧上限）。

import "testing"

func TestValidateV2BackupSecurityPolicies_ccColumnsNormalized(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "cc-import", "mode": "blocking",
			"cc_trigger_action": "bogus", "cc_queue_wait_sec": int64(500),
		}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("CC 列归一后应接受（不宽于保存侧归一而非硬拒）: %v", err)
	}
	p := tables["security_policies"][0]
	if p["cc_trigger_action"] != "challenge" {
		t.Fatalf("cc_trigger_action 枚举外应归一 challenge，实际 %v", p["cc_trigger_action"])
	}
	if p["cc_queue_wait_sec"] != int64(300) {
		t.Fatalf("cc_queue_wait_sec 500 应钳位 300，实际 %v", p["cc_queue_wait_sec"])
	}
}

func TestValidateV2BackupSecurityPolicies_ccValidPreserved(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "cc-valid", "mode": "blocking",
			"cc_trigger_action": "queue", "cc_queue_wait_sec": int64(20),
		}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("合法 CC 列应接受: %v", err)
	}
	p := tables["security_policies"][0]
	if p["cc_trigger_action"] != "queue" || p["cc_queue_wait_sec"] != int64(20) {
		t.Fatalf("合法 CC 列应保持原值，实际 %v/%v", p["cc_trigger_action"], p["cc_queue_wait_sec"])
	}
}

func TestValidateV2BackupSecurityPolicies_ccNegativeWaitClamped(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "cc-neg", "mode": "blocking",
			"cc_trigger_action": "reject", "cc_queue_wait_sec": int64(-5),
		}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("负等待应钳位接受: %v", err)
	}
	if tables["security_policies"][0]["cc_queue_wait_sec"] != int64(0) {
		t.Fatalf("负等待应钳位 0，实际 %v", tables["security_policies"][0]["cc_queue_wait_sec"])
	}
}
