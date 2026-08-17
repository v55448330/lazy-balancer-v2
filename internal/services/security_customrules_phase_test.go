package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// body 条件必须整条链发射 phase:2：REQUEST_BODY 仅在 phase:2 可读，phase:1 的
// body 规则永远不匹配（B-M1）。
func TestEmitCustomRules_bodyConditionEmitsPhase2(t *testing.T) {
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{
		{ID: 1, Name: "纯body", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "body", Operator: "contains", Pattern: "evil"},
		}},
	})
	got := sb.String()
	if !strings.Contains(got, `"id:10001,phase:2,`) {
		t.Fatalf("body condition must emit phase:2 on the starter:\n%s", got)
	}
	if strings.Contains(got, "phase:1") {
		t.Fatalf("body condition must not emit phase:1:\n%s", got)
	}
	if !strings.Contains(got, "REQUEST_BODY") {
		t.Fatalf("body condition must target REQUEST_BODY:\n%s", got)
	}
}

func TestEmitCustomRules_uriOnlyConditionEmitsPhase1(t *testing.T) {
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{
		{ID: 2, Name: "纯uri", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
		}},
	})
	got := sb.String()
	if !strings.Contains(got, `"id:10002,phase:1,`) {
		t.Fatalf("uri-only condition must stay on phase:1:\n%s", got)
	}
}

// 混合 [uri, body] 链：只要任一条件命中 body，整条链（含 continuation 条目）共用
// phase:2 —— coraza 以起始条相位执行整条链，相位不一致的链无法在 phase:2 读体。
func TestEmitCustomRules_mixedChainSharesPhase2(t *testing.T) {
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{
		{ID: 3, Name: "混合链", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/api"},
			{Target: "body", Operator: "contains", Pattern: "inject"},
		}},
	})
	got := sb.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 chained SecRule lines, got %d:\n%s", len(lines), got)
	}
	for i, line := range lines {
		if !strings.Contains(line, "phase:2") || strings.Contains(line, "phase:1") {
			t.Fatalf("chain line %d must carry phase:2 (整条链共用相位):\n%s", i, line)
		}
	}
}

// 旧版单目标内嵌形状此前发射时缺失相位，必须与 conditions 形状同一套相位选择
// （B-M2）：uri → phase:1，body → phase:2。
func TestEmitCustomRules_legacySingleTargetCarriesPhase(t *testing.T) {
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{
		{ID: 4, Name: "旧uri", Enabled: true, Action: "block", Score: 5, Target: "uri", Operator: "contains", Pattern: "/old"},
		{ID: 5, Name: "旧body", Enabled: true, Action: "block", Score: 5, Target: "body", Operator: "contains", Pattern: "legacy"},
	})
	got := sb.String()
	if !strings.Contains(got, `"id:10004,phase:1,`) {
		t.Fatalf("legacy uri rule must emit phase:1:\n%s", got)
	}
	if !strings.Contains(got, `"id:10005,phase:2,`) {
		t.Fatalf("legacy body rule must emit phase:2:\n%s", got)
	}
}
