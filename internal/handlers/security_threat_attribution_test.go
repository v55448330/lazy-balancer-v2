package handlers

import "testing"

// 威胁情报库（v2.3.x）事件分类与筛选族：id:14 → 「威胁情报库」；
// 筛选族条件为精确匹配（LIKE '14%' 会误并自定义发射 id 14xxxx）。
func TestCategorizeAttack_threatIntelFamily(t *testing.T) {
	if got := categorizeAttack("14", "威胁情报库拦截"); got != "威胁情报库" {
		t.Fatalf("categorizeAttack(14)=%q, want 威胁情报库", got)
	}
	// 回归：自定义发射 id 140xxx 不得误入威胁情报库族
	if got := categorizeAttack("140012", ""); got == "威胁情报库" {
		t.Fatalf("categorizeAttack(140012)=%q 不得归威胁情报库", got)
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
