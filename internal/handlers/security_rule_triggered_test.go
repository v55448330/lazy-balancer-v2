package handlers

import (
	"strings"
	"testing"
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
	// 地域拦截 1 前缀 + 自定义规则 10 前缀 = 11 个 LIKE 段，OR 连接
	if n := strings.Count(got, "rule_triggered LIKE ?"); n != 11 {
		t.Errorf("multi family: LIKE fragments=%d, want 11: %q", n, got)
	}
	if !strings.Contains(got, " OR ") || !strings.HasPrefix(got, "(") || !strings.HasSuffix(got, ")") {
		t.Errorf("multi family: must be a parenthesized OR group: %q", got)
	}
	// 自定义规则族的 5 位 GLOB 补段仍在
	if !strings.Contains(got, "GLOB '[0-9][0-9][0-9][0-9][0-9]'") {
		t.Errorf("multi family: custom-rule 5-digit GLOB missing: %q", got)
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
