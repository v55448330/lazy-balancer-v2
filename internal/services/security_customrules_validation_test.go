package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestBuildCorazaDirectives_logActionOmitsScoreSetvar(t *testing.T) {
	// Given a policy whose custom rule action is "log"（仅记录）
	policy := &models.SecurityPolicy{
		Mode: "blocking",
		CustomRules: json.RawMessage(`[{"id":1,"name":"仅记录规则","enabled":true,"action":"log","score":5,"conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/log"}]}]`),
	}
	directives := BuildCorazaDirectives(policy)

	// Then it emits pass,log with a message but NO anomaly-score setvar
	if !strings.Contains(directives, `pass,log,msg:'自定义规则 仅记录规则 命中'`) {
		t.Fatalf("log action must emit pass,log with msg only:\n%s", directives)
	}
	if strings.Contains(directives, "setvar:tx.inbound_anomaly_score_pl1=+5") {
		t.Fatalf("log action must NOT accumulate anomaly score:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_passActionKeepsScoreSetvar(t *testing.T) {
	// Given a policy whose custom rule action is "pass"（放行计分）
	policy := &models.SecurityPolicy{
		Mode: "blocking",
		CustomRules: json.RawMessage(`[{"id":2,"name":"放行计分规则","enabled":true,"action":"pass","score":5,"conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/pass"}]}]`),
	}
	directives := BuildCorazaDirectives(policy)

	// Then it records the event AND accumulates the anomaly score
	if !strings.Contains(directives, `pass,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'自定义规则 放行计分规则 命中'`) {
		t.Fatalf("pass action must accumulate anomaly score:\n%s", directives)
	}
}

func TestValidateCustomRuleConditions_rejectsInvalidTarget(t *testing.T) {
	err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "cookie", Operator: "contains", Pattern: "x"}})
	if err == nil || !strings.Contains(err.Error(), "target 无效") {
		t.Fatalf("invalid target must be rejected, got %v", err)
	}
}

func TestValidateCustomRuleConditions_rejectsInvalidOperator(t *testing.T) {
	err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "matches", Pattern: "x"}})
	if err == nil || !strings.Contains(err.Error(), "operator 无效") {
		t.Fatalf("invalid operator must be rejected, got %v", err)
	}
}

func TestValidateCustomRuleConditions_rejectsControlCharsInPattern(t *testing.T) {
	for _, pat := range []string{"foo\nSecRule X", "foo\tbar", "foo\x01bar", "foo\x7fbar"} {
		err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: pat}})
		if err == nil || !strings.Contains(err.Error(), "控制字符") {
			t.Fatalf("control char %q in pattern must be rejected, got %v", pat, err)
		}
	}
}

func TestValidateCustomRuleConditions_acceptsValid(t *testing.T) {
	if err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "/admin"}}); err != nil {
		t.Fatalf("valid condition must pass, got %v", err)
	}
}

func TestValidateCustomRuleConditions_rejectsEmpty(t *testing.T) {
	err := ValidateCustomRuleConditions(nil)
	if err == nil || !strings.Contains(err.Error(), "至少需要一个匹配条件") {
		t.Fatalf("empty conditions must be rejected, got %v", err)
	}
}

func TestValidateCustomRuleConditions_rejectsTrailingBackslash(t *testing.T) {
	for _, pat := range []string{`C:\`, `C:\\`} {
		err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: pat}})
		if err == nil || !strings.Contains(err.Error(), "反斜杠结尾") {
			t.Fatalf("pattern %q ending with backslash must be rejected, got %v", pat, err)
		}
	}
}

func TestValidateCustomRuleConditions_acceptsMidStringBackslash(t *testing.T) {
	if err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: `abc\def`}}); err != nil {
		t.Fatalf("mid-string backslash must be accepted, got %v", err)
	}
}

func TestValidateCustomRulePattern_operatorAwareTrailingBackslashMessage(t *testing.T) {
	for _, op := range []string{"contains", "equals", "starts_with"} {
		err := validateCustomRulePattern(op, `C:\`)
		if err == nil || !strings.Contains(err.Error(), "改用正则运算符") {
			t.Fatalf("operator %q trailing backslash must suggest switching to regex, got %v", op, err)
		}
	}
	err := validateCustomRulePattern("regex", `C:\`)
	if err == nil || !strings.Contains(err.Error(), "结尾锚定") {
		t.Fatalf("regex trailing backslash must suggest anchor/empty-group, got %v", err)
	}
}

func TestValidateCustomRulesJSON_rejectsPlaceholderEntry(t *testing.T) {
	err := ValidateCustomRulesJSON(`[{"id":1,"name":"占位","enabled":true}]`)
	if err == nil || !strings.Contains(err.Error(), "至少需要一个匹配条件") {
		t.Fatalf("placeholder entry must be rejected, got %v", err)
	}
	if err := ValidateCustomRulesJSON(`[{"id":1,"name":"旧版","enabled":true,"target":"uri","operator":"contains","pattern":"/x"}]`); err != nil {
		t.Fatalf("legacy single-target embedded shape must pass, got %v", err)
	}
}

func TestValidateCustomRulesJSON_acceptsIDArrayAndEmbedded(t *testing.T) {
	if err := ValidateCustomRulesJSON(`[1,2]`); err != nil {
		t.Fatalf("id array must pass, got %v", err)
	}
	if err := ValidateCustomRulesJSON(`[{"id":1,"name":"r","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`); err != nil {
		t.Fatalf("embedded rule must pass, got %v", err)
	}
	if err := ValidateCustomRulesJSON(`[{"id":1,"name":"r","enabled":true,"conditions":[{"target":"bad","operator":"contains","pattern":"/x"}]}]`); err == nil {
		t.Fatalf("embedded rule with invalid target must be rejected")
	}
	if err := ValidateCustomRulesJSON("not-json"); err == nil {
		t.Fatalf("non-JSON custom_rules must be rejected")
	}
}

func TestValidateCustomRuleConditions_rejectsBlankPattern(t *testing.T) {
	// 空或纯空白的 pattern 会生成 @contains "" 之类匹配一切请求的条件，等于全员拦截
	for _, pat := range []string{"", "   "} {
		err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: pat}})
		if err == nil || !strings.Contains(err.Error(), "匹配内容不能为空") {
			t.Fatalf("blank pattern %q must be rejected, got %v", pat, err)
		}
	}
	// 内嵌规则对象路径（ValidateCustomRulesJSON → ValidateCustomRuleConditions）
	if err := ValidateCustomRulesJSON(`[{"id":1,"name":"r","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":""}]}]`); err == nil || !strings.Contains(err.Error(), "匹配内容不能为空") {
		t.Fatalf("embedded blank pattern must be rejected, got %v", err)
	}
	// 旧版单条件形状路径（ValidateCustomRulesJSON → validateCustomRulePattern）
	if err := ValidateCustomRulesJSON(`[{"id":1,"name":"旧版","enabled":true,"target":"uri","operator":"equals","pattern":"  "}]`); err == nil || !strings.Contains(err.Error(), "匹配内容不能为空") {
		t.Fatalf("legacy-shape blank pattern must be rejected, got %v", err)
	}
	// 正常模式不受影响
	if err := ValidateCustomRuleConditions([]models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "/admin"}}); err != nil {
		t.Fatalf("normal pattern must pass, got %v", err)
	}
}

func TestEscapeCorazaPattern_stripsControlCharsAndPreservesLiteralBackslashN(t *testing.T) {
	got := escapeCorazaPattern("a\"b\nc\rd\x00e\\nf")
	if strings.Contains(got, "\n") || strings.Contains(got, "\r") || strings.Contains(got, "\x00") {
		t.Fatalf("real control runes must be stripped, got %q", got)
	}
	if !strings.Contains(got, `\"`) {
		t.Fatalf("quote must be escaped, got %q", got)
	}
	if !strings.Contains(got, `\n`) {
		t.Fatalf("literal two-char \\n sequence must be preserved, got %q", got)
	}
}
