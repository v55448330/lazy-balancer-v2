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

// CC 数值四列导入门（与保存侧 cc*OrDefault 单源同口径）：越界显式值钳制、
// 非整数形态归一默认、合法值保持。
func TestValidateV2BackupSecurityPolicies_ccNumericColumnsClamped(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "cc-num", "mode": "blocking",
			"cc_rps_limit": int64(999999), "cc_rps_window": int64(0),
			"cc_4xx_ratio": int64(150), "cc_session_ua_threshold": int64(-3),
		}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("数值列钳制后应接受: %v", err)
	}
	p := tables["security_policies"][0]
	if p["cc_rps_limit"] != int64(ccRPSLimitMax) {
		t.Fatalf("cc_rps_limit 999999 应钳位 %d，实际 %v", ccRPSLimitMax, p["cc_rps_limit"])
	}
	if p["cc_rps_window"] != int64(10) {
		t.Fatalf("cc_rps_window 0 应归一默认 10，实际 %v", p["cc_rps_window"])
	}
	if p["cc_4xx_ratio"] != int64(100) {
		t.Fatalf("cc_4xx_ratio 150 应钳位 100，实际 %v", p["cc_4xx_ratio"])
	}
	if p["cc_session_ua_threshold"] != int64(5) {
		t.Fatalf("cc_session_ua_threshold -3 应归一默认 5，实际 %v", p["cc_session_ua_threshold"])
	}
}

func TestValidateV2BackupSecurityPolicies_ccNumericNonIntegerDefaults(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "cc-nonint", "mode": "blocking",
			"cc_rps_limit": "abc", "cc_rps_window": true,
			"cc_4xx_ratio": nil, "cc_session_ua_threshold": 1.5,
		}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("非整数形态归一后应接受: %v", err)
	}
	p := tables["security_policies"][0]
	if p["cc_rps_limit"] != int64(40) || p["cc_rps_window"] != int64(10) ||
		p["cc_4xx_ratio"] != int64(70) || p["cc_session_ua_threshold"] != int64(5) {
		t.Fatalf("非整数形态应归一治理默认 40/10/70/5，实际 %v/%v/%v/%v",
			p["cc_rps_limit"], p["cc_rps_window"], p["cc_4xx_ratio"], p["cc_session_ua_threshold"])
	}
}

func TestValidateV2BackupSecurityPolicies_ccNumericValidPreserved(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "cc-numvalid", "mode": "blocking",
			"cc_rps_limit": int64(80), "cc_rps_window": int64(30),
			"cc_4xx_ratio": int64(0), "cc_session_ua_threshold": int64(9),
		}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("合法数值列应接受: %v", err)
	}
	p := tables["security_policies"][0]
	if p["cc_rps_limit"] != int64(80) || p["cc_rps_window"] != int64(30) ||
		p["cc_4xx_ratio"] != int64(0) || p["cc_session_ua_threshold"] != int64(9) {
		t.Fatalf("合法数值列应保持原值（含 0=自动语义），实际 %v/%v/%v/%v",
			p["cc_rps_limit"], p["cc_rps_window"], p["cc_4xx_ratio"], p["cc_session_ua_threshold"])
	}
}
