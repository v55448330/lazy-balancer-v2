package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// ruleTriggeredMultiFilterSQL 的逗号多值契约（S1 场景）：
// 单值与 ruleTriggeredFilterSQL 逐字节一致（向后兼容）；
// 多值逐段复用单段解析后 OR 连接；任一段只能走消息关键词路径时整串回退单输入。
func TestRuleTriggeredMultiFilterSQL_singleValueByteIdentical(t *testing.T) {
	for _, single := range []string{"地域拦截", "942100", "IP 访问控制", "WAF 规则（CRS）", "评分拦截", "sqlmap"} {
		var a1, a2 []any
		got := ruleTriggeredMultiFilterSQL(single, &a1)
		want := ruleTriggeredFilterSQL(single, &a2)
		if got != want {
			t.Errorf("single %q: got %q, want %q (byte-identical)", single, got, want)
		}
		if len(a1) != len(a2) {
			t.Errorf("single %q: args len %d, want %d", single, len(a1), len(a2))
		}
	}
}

func TestRuleTriggeredMultiFilterSQL_multiFamilyOR(t *testing.T) {
	var args []any
	got := ruleTriggeredMultiFilterSQL("地域拦截,自定义规则", &args)
	// 地域拦截 1 个 LIKE 段（8%）+ 自定义规则族 1 个复合 GLOB 段（SC-3：无
	// LIKE 前缀，长度约束条件整体并入，与 categorizeAttack 同口径）
	if n := strings.Count(got, "rule_triggered LIKE ?"); n != 1 {
		t.Errorf("multi family: LIKE fragments=%d, want 1: %q", n, got)
	}
	if !strings.Contains(got, " OR ") || !strings.HasPrefix(got, "(") || !strings.HasSuffix(got, ")") {
		t.Errorf("multi family: must be a parenthesized OR group: %q", got)
	}
	// 自定义规则族的形态条件整体在段内（5 位任意 + ≥7 位以 1 开头）
	if !strings.Contains(got, "GLOB '[0-9][0-9][0-9][0-9][0-9]'") ||
		!strings.Contains(got, "GLOB '1[0-9][0-9][0-9][0-9][0-9][0-9]*'") {
		t.Errorf("multi family: custom-rule family condition missing: %q", got)
	}
}

func TestRuleTriggeredMultiFilterSQL_mixedFamilyAndDigits(t *testing.T) {
	var args []any
	got := ruleTriggeredMultiFilterSQL("地域拦截,942100", &args)
	if !strings.Contains(got, "rule_triggered = ?") {
		t.Errorf("mixed: digit part must keep exact-or-prefix branch: %q", got)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("mixed: parts must be OR-joined: %q", got)
	}
}

func TestRuleTriggeredMultiFilterSQL_unresolvablePartFallsBack(t *testing.T) {
	// 「foo bar」非 family/非数字——整串回退单输入路径（保护含逗号的消息关键词）
	var a1, a2 []any
	got := ruleTriggeredMultiFilterSQL("地域拦截,foo bar", &a1)
	want := ruleTriggeredFilterSQL("地域拦截,foo bar", &a2)
	if got != want {
		t.Errorf("unresolvable part: got %q, want fallback %q", got, want)
	}
}

func TestRuleTriggeredMultiFilterSQL_partialFamilyPrefix(t *testing.T) {
	// 部分前缀段（「评分」命中「评分拦截」family）同样可拆分 OR；
	// 前缀值在 args（SQL 只有占位符），断言 949%/959% 均入参
	var args []any
	got := ruleTriggeredMultiFilterSQL("评分,自定义规则", &args)
	hasArg := func(want string) bool {
		for _, a := range args {
			if a == want {
				return true
			}
		}
		return false
	}
	if !hasArg("949%") || !hasArg("959%") {
		t.Errorf("partial family prefix must put 949%%/959%% into args: %v", args)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("partial family: parts must be OR-joined: %q", got)
	}
}

// SC-3（2026-09-05 安全核心域审计裁定修复）：「自定义规则」筛选 family 必须与
// categorizeAttack 总览口径一致——5 位任意数字 ID（emit=crID+10000）与 ≥7 位
// 以 1 开头的合成 ID（1000000+）归本族；6 位 1xxxxx（CRS 保留段余数、无发射
// 源，总览判「其他」）不得被 LIKE 前缀误并入。以真实 SQLite 判定生成的条件
// 实际命中哪些 ID。
func TestRuleTriggeredFilterSQL_customRuleFamilyMatchesCategorizeAttackScope(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TABLE rule_triggered_family_probe (rule_triggered TEXT)`); err != nil {
		t.Fatal(err)
	}
	probes := []string{
		"10003",   // 5 位自定义（emit=crID+10000）
		"24567",   // 5 位自定义（不以 1 开头）
		"1000001", // 7 位合成（1000000+n）
		"1234567", // 7 位以 1 开头
		"100123",  // 6 位 1xxxxx：CRS 保留段余数，总览判「其他」
		"942100",  // CRS
		"2",       // IP ACL
		"223456",  // 6 位非 1 开头
	}
	for _, id := range probes {
		if _, err := db.DB.Exec(`INSERT INTO rule_triggered_family_probe (rule_triggered) VALUES (?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	// Given：按 family 标签生成筛选条件
	var args []any
	cond := ruleTriggeredFilterSQL("自定义规则", &args)
	// When：对探针 ID 集执行该条件
	matched := map[string]bool{}
	rows, err := db.DB.Query(`SELECT rule_triggered FROM rule_triggered_family_probe WHERE `+cond, args...)
	if err != nil {
		t.Fatalf("query family filter: %v", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		matched[id] = true
	}
	rows.Close()
	// Then：逐 ID 与 categorizeAttack 口径一致
	for _, id := range probes {
		want := categorizeAttack(id, "") == "自定义规则"
		if matched[id] != want {
			t.Errorf("自定义规则 family 匹配 %q=%v, want %v（须与 categorizeAttack 口径一致），条件 %q", id, matched[id], want, cond)
		}
	}
}
