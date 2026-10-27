package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestEmitCustomRules_conditionLogicANDMatchesLegacyShape(t *testing.T) {
	rule := models.CustomRule{
		ID: 42, Name: "同时满足", Enabled: true, Action: "block", Score: 5,
		Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "body", Operator: "contains", Pattern: "inject"},
		},
	}
	var legacy strings.Builder
	emitCustomRules(&legacy, []models.CustomRule{rule}, 0)
	rule.ConditionLogic = "and"
	var explicit strings.Builder
	emitCustomRules(&explicit, []models.CustomRule{rule}, 0)
	if legacy.String() != explicit.String() {
		t.Fatalf("显式 AND 必须保持既有链式产物:\nlegacy:\n%s\nexplicit:\n%s", legacy.String(), explicit.String())
	}
	if !strings.Contains(explicit.String(), "id:10042") || !strings.Contains(explicit.String(), ",chain") {
		t.Fatalf("AND 必须保持父规则 id 与链式形状:\n%s", explicit.String())
	}
}

func TestEmitCustomRules_conditionLogicOREmitsIndependentRules(t *testing.T) {
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{{
		ID: 42, Name: "任一满足", Enabled: true, Action: "block", Score: 5, ConditionLogic: "or",
		Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "body", Operator: "contains", Pattern: "inject"},
			{Target: "args", Operator: "equals", Pattern: "x"},
		},
	}}, 451)
	got := sb.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Fatalf("OR 三条件必须发射三条独立 SecRule，got %d:\n%s", len(lines), got)
	}
	wantIDs := []string{"id:3642688", "id:3642689", "id:3642690"}
	wantPhases := []string{"phase:1", "phase:2", "phase:1"}
	for i, line := range lines {
		if !strings.Contains(line, wantIDs[i]) || !strings.Contains(line, wantPhases[i]) {
			t.Fatalf("OR 条件 %d 的 id/相位错误: %s", i, line)
		}
		for _, action := range []string{"deny", "status:451", "setvar:tx.inbound_anomaly_score_pl1=+5", "msg:'自定义规则 任一满足 命中'"} {
			if !strings.Contains(line, action) {
				t.Fatalf("OR 条件 %d 未继承父规则动作/评分/归因 %q: %s", i, action, line)
			}
		}
	}
	if strings.Contains(got, ",chain") || strings.Contains(got, "id:10042") || strings.Contains(got, "id:2000000") {
		t.Fatalf("OR 不得 chain、复用父 emit id 或撞排除段:\n%s", got)
	}
}

func TestEmitCustomRules_conditionLogicORSingleAndInvalidShapes(t *testing.T) {
	var single strings.Builder
	emitCustomRules(&single, []models.CustomRule{{
		ID: 44, Name: "单条件 OR", Enabled: true, Action: "log", Score: 5, ConditionLogic: "or",
		Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "/one"}},
	}}, 0)
	lines := strings.Split(strings.TrimSpace(single.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "id:3642816") || strings.Contains(lines[0], ",chain") {
		t.Fatalf("单条件 OR 也必须使用独立分支 id 且不 chain:\n%s", single.String())
	}

	for _, rule := range []models.CustomRule{
		{ID: 45, Name: "非法关系", Enabled: true, Action: "block", Score: 5, ConditionLogic: "xor", Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "/x"}}},
		{ID: 46, Name: "空条件 OR", Enabled: true, Action: "block", Score: 5, ConditionLogic: "or"},
	} {
		var sb strings.Builder
		emitCustomRules(&sb, []models.CustomRule{rule}, 0)
		if sb.Len() != 0 {
			t.Fatalf("非法/空条件规则不得发射: %+v\n%s", rule, sb.String())
		}
	}
}

func TestDecodeCustomRuleEmitID_mapsORBranchesToParent(t *testing.T) {
	for emitID, want := range map[int]int{10042: 42, 3642688: 42, 3642689: 42, 3642816: 44} {
		got, ok := DecodeCustomRuleEmitID(emitID)
		if !ok || got != want {
			t.Fatalf("DecodeCustomRuleEmitID(%d)=(%d,%v), want (%d,true)", emitID, got, ok, want)
		}
	}
	for _, emitID := range []int{10000, 800000, 1000001, 2000000, 3000000} {
		if got, ok := DecodeCustomRuleEmitID(emitID); ok {
			t.Fatalf("DecodeCustomRuleEmitID(%d)=(%d,true), want no parent", emitID, got)
		}
	}
}

func TestSecurityEventsPolicyContainsRule_orBranchesUseParentPolicy(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "blocking", CustomRules: json.RawMessage(`[
		{"id":42,"name":"DB OR","enabled":true,"condition_logic":"or","action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"},{"target":"body","operator":"contains","pattern":"x"}]},
		{"id":0,"name":"旧内嵌 OR","enabled":true,"condition_logic":"or","action":"log","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/legacy"}]}
	]`)}
	for _, id := range []string{"3642688", "3642689", "67000064"} {
		if !securityEventsPolicyContainsRule(policy, id, "") {
			t.Fatalf("OR 分支 %s 必须归因到父规则所在策略", id)
		}
	}
	for _, id := range []string{"10042", "3642690", "67000128"} {
		if securityEventsPolicyContainsRule(policy, id, "") {
			t.Fatalf("非发射分支 %s 不得被策略认领", id)
		}
	}
}

func TestValidateCustomRulesJSON_conditionLogicValidated(t *testing.T) {
	for _, payload := range []string{
		`[{"id":42,"name":"and","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5}]`,
		`[{"id":42,"name":"or","condition_logic":"or","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5}]`,
	} {
		if err := ValidateCustomRulesJSON(payload); err != nil {
			t.Fatalf("合法内嵌条件关系被拒: %v", err)
		}
	}
	if err := ValidateCustomRulesJSON(`[{"id":42,"name":"bad","condition_logic":"xor","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5}]`); err == nil || !strings.Contains(err.Error(), "条件关系") {
		t.Fatalf("内嵌非法 condition_logic 必须拒绝，err=%v", err)
	}
}

func TestEmitCustomRules_orConditionCountBoundPreventsIDCollision(t *testing.T) {
	conditions := make([]models.CustomRuleCondition, customRuleMaxConditions+1)
	for i := range conditions {
		conditions[i] = models.CustomRuleCondition{Target: "uri", Operator: "contains", Pattern: "/x"}
	}
	rules := []models.CustomRule{
		{ID: 41, Name: "超限甲", Enabled: true, Action: "block", Score: 5, ConditionLogic: "or", Conditions: conditions},
		{ID: 42, Name: "超限乙", Enabled: true, Action: "block", Score: 5, ConditionLogic: "or", Conditions: conditions},
	}
	if issue := customRuleEmissionIssue(rules[0]); issue == "" {
		t.Fatal("超过 64 条件必须在发射侧拒绝，避免分支 id 跨父规则碰撞")
	}
	var sb strings.Builder
	emitCustomRules(&sb, rules, 0)
	if sb.Len() != 0 {
		t.Fatalf("超限 OR 规则不得发射重复/越界分支 id:\n%s", sb.String())
	}
	compileForEngineGate(t, sb.String())
}

func TestSecurityEventsPolicyCustomEmitIDs_skippedLegacyRulesDoNotShiftSyntheticIDs(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "blocking", CustomRules: json.RawMessage(`[
		{"id":0,"name":"disabled predecessor","enabled":false,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/off"}]},
		{"id":0,"name":"invalid predecessor","enabled":true,"condition_logic":"xor","action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/bad"}]},
		{"id":0,"name":"enabled OR","enabled":true,"condition_logic":"or","action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/on"}]}
	]`)}
	emitIDs, ok := securityEventsPolicyCustomEmitIDs(policy)
	if !ok {
		t.Fatal("内嵌规则 id 集解析失败")
	}
	if _, hit := emitIDs[67000064]; !hit {
		t.Fatalf("被跳过的旧规则不得占用合成序号，真实 OR 分支 67000064 缺失: %v", emitIDs)
	}
	if _, hit := emitIDs[67000128]; hit {
		t.Fatalf("错误地把被跳过规则计入合成序号: %v", emitIDs)
	}
	if !securityEventsPolicyContainsRule(policy, "67000064", "") {
		t.Fatal("真实 OR 事件必须归因到其所属策略")
	}
}

func TestEngineGate_customRuleConditionLogicCompiles(t *testing.T) {
	customRules := json.RawMessage(`[
		{"id":41,"name":"AND 混合","enabled":true,"condition_logic":"and","action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/and"},{"target":"body","operator":"contains","pattern":"and-body"}]},
		{"id":42,"name":"OR 混合","enabled":true,"condition_logic":"or","action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/or"},{"target":"body","operator":"contains","pattern":"or-body"}]},
		{"id":43,"name":"OR 单条件","enabled":true,"condition_logic":"or","action":"log","score":5,"conditions":[{"target":"args","operator":"equals","pattern":"x"}]},
		{"id":0,"name":"旧内嵌 OR 甲","enabled":true,"condition_logic":"or","action":"pass","score":3,"conditions":[{"target":"uri","operator":"contains","pattern":"/legacy-a"},{"target":"body","operator":"contains","pattern":"legacy-a-body"}]},
		{"id":0,"name":"旧内嵌 OR 乙","enabled":true,"condition_logic":"or","action":"pass","score":3,"conditions":[{"target":"uri","operator":"contains","pattern":"/legacy-b"},{"target":"body","operator":"contains","pattern":"legacy-b-body"}]}
	]`)
	for _, mode := range []string{"blocking", "detection"} {
		t.Run(mode, func(t *testing.T) {
			policy := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: mode, CustomRules: customRules}
			directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
			compileForEngineGate(t, directives)
			if !strings.Contains(directives, "phase:1,deny") || !strings.Contains(directives, "phase:2,deny") {
				t.Fatalf("%s 模式 OR 的 URI/body 分支必须各自按相位发射:\n%s", mode, directives)
			}
		})
	}
}
