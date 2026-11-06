package services

// 自定义规则 headers 目标携带头名（REQUEST_HEADERS:<name>）在 AND 与 OR 两种
// 条件关系下的发射一致性：条件映射必须统一走 customRuleSecTarget 单源——
// 任一形状绕过单源都会把头名静默丢成裸 REQUEST_HEADERS（裸形态匹配全部头的
// 值，按头名判定的拦截规则会自匹配其他头导致误拦面扩大）。字符串形状断言
// 之外，OR+头名的真实渲染产物一并送 coraza v3.8.1 编译门禁（引擎级实证：
// 头名形态同样被引擎接受，形状与编译双断言）。

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

const headerNameProbe = "X-LB-Probe"

func headerNameProbeConditions() []models.CustomRuleCondition {
	return []models.CustomRuleCondition{
		{Target: "headers", Operator: "equals", Pattern: "br", HeaderName: headerNameProbe},
		{Target: "uri", Operator: "contains", Pattern: "/admin"},
	}
}

// AND/OR 两形状 × headers+header_name：发射 target 必须是头名形态，且该规则
// 的发射段不得再出现裸 REQUEST_HEADERS 形态。
func TestEmitCustomRules_headerNameHonoredInAndAndOrShapes(t *testing.T) {
	outByLogic := map[string]string{}
	for logic, id := range map[string]int{"and": 42, "or": 43} {
		var sb strings.Builder
		emitCustomRules(&sb, []models.CustomRule{{
			ID: id, Name: "头名" + strings.ToUpper(logic), Enabled: true, Action: "block", Score: 5,
			ConditionLogic: logic, Conditions: headerNameProbeConditions(),
		}}, 0)
		outByLogic[logic] = sb.String()
	}
	for logic, out := range outByLogic {
		if !strings.Contains(out, "SecRule REQUEST_HEADERS:"+headerNameProbe+" ") {
			t.Fatalf("%s 形状未把 header_name 发射为头名形态:\n%s", strings.ToUpper(logic), out)
		}
		if strings.Contains(out, "SecRule REQUEST_HEADERS \"") {
			t.Fatalf("%s 形状仍发射裸 REQUEST_HEADERS（头名被丢弃）:\n%s", strings.ToUpper(logic), out)
		}
	}
}

// 引擎级实证：OR+headers+头名的真实渲染产物逐字送 coraza 编译；同时钉住
// OR 分支行内 target 为头名形态（裸形态在该规则发射段不再出现）。
func TestEngineGate_orHeaderNameShapeCompiles(t *testing.T) {
	p := &models.SecurityPolicy{
		Mode:             "custom_only",
		AnomalyThreshold: 5,
		CustomRules: json.RawMessage(`[{"id":42,"name":"OR 头名","enabled":true,"condition_logic":"or","action":"block","score":5,"conditions":[` +
			`{"target":"headers","operator":"equals","pattern":"br","header_name":"` + headerNameProbe + `"},` +
			`{"target":"uri","operator":"contains","pattern":"/admin"}]}]`),
	}
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	branches := 0
	for _, line := range strings.Split(directives, "\n") {
		if !strings.Contains(line, "自定义规则 OR 头名 命中") {
			continue
		}
		branches++
		if strings.HasPrefix(strings.TrimSpace(line), "SecRule REQUEST_HEADERS ") {
			t.Fatalf("OR 分支仍发射裸 REQUEST_HEADERS（头名被丢弃）: %s", line)
		}
	}
	if branches != 2 {
		t.Fatalf("OR 两条件应各发射一条分支，got %d:\n%s", branches, directives)
	}
	if !strings.Contains(directives, "SecRule REQUEST_HEADERS:"+headerNameProbe+" ") {
		t.Fatalf("渲染产物未发射头名形态:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}
