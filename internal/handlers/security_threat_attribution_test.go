package handlers

import (
	"slices"
	"testing"
)

// 固定编号 14 是 v2.3.x 威胁情报库预检拦截的历史段。2026-11-25 用户裁定：威胁库
// 不做独立归因，「威胁情报库」不再是触发类型——历史编号 14 的事件并入「IP 访问
// 控制」（与逐策略 ACL deny 链同族），用户通过策略名识别威胁库策略。大屏榜面
// 标签、事件列表触发类型、总览攻击族、筛选族四处口径必须同源。
func TestCategorizeAttack_legacyThreatIntelIDMergesIntoIPACL(t *testing.T) {
	if got := categorizeAttack("14", "威胁情报库拦截"); got != "IP 访问控制" {
		t.Fatalf("categorizeAttack(14)=%q, want IP 访问控制", got)
	}
	if got := triggerTypeForRule("14"); got != "IP 访问控制" {
		t.Fatalf("triggerTypeForRule(14)=%q, want IP 访问控制", got)
	}
	if got := describeThreatRuleNameWithNames("14", nil); got != "IP 访问控制拦截（#14）" {
		t.Fatalf("describeThreatRuleName(14)=%q, want IP 访问控制拦截（#14）", got)
	}
	if got := attackFamilyClassOf("14", ""); got != attackFamilyIPACL {
		t.Fatalf("attackFamilyClassOf(14)=%v, want IP 访问控制族", got)
	}
	// 回归：自定义发射 id 140xxx 不得误入 IP 访问控制族
	if got := categorizeAttack("140012", ""); got == "IP 访问控制" {
		t.Fatalf("categorizeAttack(140012)=%q 不得归 IP 访问控制", got)
	}
	if _, ok := ruleTriggeredFamilyPrefixes["威胁情报库"]; ok {
		t.Fatal("筛选族表不得再有「威胁情报库」")
	}
	if ids := ruleTriggeredFamilyPrefixes["IP 访问控制"]; !slices.Contains(ids, "14") {
		t.Fatalf("IP 访问控制筛选族须包含历史编号 14, got %v", ids)
	}
}

func TestFamilyPrefixCondition_id14ExactMatch(t *testing.T) {
	var ors []string
	var args []any
	appendFamilyPrefixCondition(&ors, &args, "14")
	if len(ors) != 1 || ors[0] != "rule_triggered = ?" || args[0] != "14" {
		t.Fatalf("id:14 族条件须精确匹配, got ors=%v args=%v", ors, args)
	}
}
