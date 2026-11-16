package handlers

// P2-03 修复钉测：CC 事件（human_* 挑战 / cc_rate_reject 拒绝）攻击族必须归
// CC防护，不得落「其他」；CC 筛选 SQL 条件必须覆盖 cc_rate_reject。

import (
	"strings"
	"testing"
)

func TestCategorizeAttack_ccEventsBelongToCCFamily(t *testing.T) {
	cases := []struct {
		triggered string
		msg       string
	}{
		{"cc_rate_reject", "限流拒绝（429）"},
		{"human_challenge", ""},
		{"human_failed", ""},
	}
	for _, c := range cases {
		if got := categorizeAttack(c.triggered, c.msg); got != "CC防护" {
			t.Errorf("categorizeAttack(%q) = %q, want CC防护", c.triggered, got)
		}
		if got := stageCategorizeAttack(c.triggered, c.msg); got != "CC防护" {
			t.Errorf("stageCategorizeAttack(%q) = %q, want CC防护", c.triggered, got)
		}
	}
}

func TestHumanFamilyCondition_coversCcRateReject(t *testing.T) {
	// CC 筛选条件必须同时覆盖 human_* 与 cc_rate_reject（否则拒绝事件筛不到）。
	if !strings.Contains(humanFamilyCondition, "cc_rate_reject") {
		t.Fatalf("humanFamilyCondition 必须覆盖 cc_rate_reject，实际: %s", humanFamilyCondition)
	}
	if !strings.Contains(humanFamilyCondition, "human_") {
		t.Fatalf("humanFamilyCondition 必须保留 human_* 覆盖，实际: %s", humanFamilyCondition)
	}
}
