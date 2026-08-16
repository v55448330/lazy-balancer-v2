package services

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestResolvePolicyCustomRules_idsLoadFromDB(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, description, conditions, action, score, enabled) VALUES ('链式验证规则','', '[{"target":"uri","operator":"contains","pattern":"/admin"}]', 'block', 5, 1)`); err != nil {
		t.Fatal(err)
	}
	rules := resolvePolicyCustomRules(json.RawMessage(`[1]`))
	if len(rules) != 1 || rules[0].Name != "链式验证规则" || len(rules[0].Conditions) != 1 {
		t.Fatalf("bad resolution: %+v", rules)
	}
}

func TestResolvePolicyCustomRules_legacyEmbeddedObjects(t *testing.T) {
	rules := resolvePolicyCustomRules(json.RawMessage(`[{"id":2,"name":"内嵌","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"pass","score":1}]`))
	if len(rules) != 1 || rules[0].Name != "内嵌" {
		t.Fatalf("legacy embedded shape not supported: %+v", rules)
	}
}

func TestBuildCorazaDirectives_customRuleDenyOmitsStatusCode(t *testing.T) {
	// Given a blocking policy with a custom block rule carrying a custom status code
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["9"]`),
		CustomRules: json.RawMessage(`[{"id":12,"name":"拒绝规则","enabled":true,"action":"block","score":5,"conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/blocked"}]}]`),
	}

	// When directives are built
	directives := BuildCorazaDirectives(policy)

	// Then the deny action carries no status override; the block page's status governs
	if !strings.Contains(directives, `deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'自定义规则 拒绝规则 命中'`) {
		t.Fatalf("custom deny must carry the anomaly-score setvar without a status override:\n%s", directives)
	}
	if strings.Contains(directives, "status:") {
		t.Fatalf("custom rule action must not emit status::\n%s", directives)
	}
}

func TestBuildCorazaDirectives_userAgentTargetUsesColonNotation(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["9"]`),
		CustomRules:   json.RawMessage(`[{"id":9,"name":"ua","enabled":true,"action":"pass","score":1,"conditions":[{"target":"user_agent","operator":"contains","pattern":"sqlmap"}]}]`),
	}
	directives := BuildCorazaDirectives(policy)
	if !strings.Contains(directives, "REQUEST_HEADERS:User-Agent") {
		t.Fatalf("user_agent target must use colon notation:\n%s", directives)
	}
	if strings.Contains(directives, "REQUEST_HEADERS.User-Agent") {
		t.Fatalf("dot notation rejected by coraza:\n%s", directives)
	}
}

func TestEmitCustomRules_skipsDirtyRuleAmongCleanOnes(t *testing.T) {
	// Given clean rules interleaved with a trailing-backslash rule and an empty-conditions rule
	var sb strings.Builder
	rules := []models.CustomRule{
		{ID: 1, Name: "干净规则", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "/admin"}}},
		{ID: 2, Name: "脏规则", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: `C:\`}}},
		{ID: 3, Name: "空条件规则", Enabled: true, Action: "block", Score: 5},
		{ID: 4, Name: "干净规则二", Enabled: true, Action: "pass", Score: 3, Conditions: []models.CustomRuleCondition{{Target: "args", Operator: "equals", Pattern: "debug=1"}}},
	}

	// When emitted
	emitCustomRules(&sb, rules)
	got := sb.String()

	// Then clean rules are emitted while dirty/empty rules are skipped without failing the whole config
	if !strings.Contains(got, "自定义规则 干净规则 命中") {
		t.Fatalf("first clean rule must be emitted:\n%s", got)
	}
	if !strings.Contains(got, "自定义规则 干净规则二 命中") {
		t.Fatalf("second clean rule must be emitted:\n%s", got)
	}
	if strings.Contains(got, "脏规则") {
		t.Fatalf("trailing-backslash rule must be skipped:\n%s", got)
	}
	if strings.Contains(got, "空条件规则") {
		t.Fatalf("empty-conditions rule must be skipped:\n%s", got)
	}
}

func TestEmitCustomRules_invalidTargetOrOperatorSkipsWholeRule(t *testing.T) {
	// Given：一条含非法 target 的规则、一条含非法 operator 的规则、一条全合法的链式规则
	var sb strings.Builder
	rules := []models.CustomRule{
		{ID: 10, Name: "非法target规则", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "cookie", Operator: "contains", Pattern: "session=1"},
		}},
		{ID: 11, Name: "非法operator规则", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "matches", Pattern: "/admin"},
		}},
		{ID: 12, Name: "合法链式规则", Enabled: true, Action: "block", Score: 3, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/x"},
			{Target: "args", Operator: "contains", Pattern: "a=1"},
		}},
	}

	// When emitted
	emitCustomRules(&sb, rules)
	got := sb.String()

	// Then：非法 target/operator 的规则整条跳过（绝不产生缺 ID 起始条或悬空 chain 的部分发射）
	if strings.Contains(got, "非法target规则") || strings.Contains(got, "非法operator规则") {
		t.Fatalf("invalid target/operator rules must be skipped entirely:\n%s", got)
	}
	if strings.Contains(got, "cookie") || strings.Contains(got, "matches") {
		t.Fatalf("invalid condition must not leak into emission:\n%s", got)
	}
	// And：全合法规则完整发射，两条条件构成完整 chain
	if !strings.Contains(got, "自定义规则 合法链式规则 命中") {
		t.Fatalf("valid rule must be emitted:\n%s", got)
	}
	if !strings.Contains(got, ",chain") {
		t.Fatalf("valid chained rule must carry chain action:\n%s", got)
	}
	if gotCount := strings.Count(got, "SecRule "); gotCount != 2 {
		t.Fatalf("SecRule count=%d, want 2 (only the valid chained rule):\n%s", gotCount, got)
	}
}

// TestEmitCustomRules_invalidRuleLogsSkipAndSparesCleanRules verifies that a
// dirty rule (invalid target/operator) is logged as skipped while clean rules
// produce no skip log line — locking the emission-side log contract.
func TestEmitCustomRules_invalidRuleLogsSkipAndSparesCleanRules(t *testing.T) {
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	// Given dirty rules interleaved with a fully valid chained rule
	var sb strings.Builder
	rules := []models.CustomRule{
		{ID: 10, Name: "非法target规则", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "cookie", Operator: "contains", Pattern: "session=1"},
		}},
		{ID: 11, Name: "非法operator规则", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "matches", Pattern: "/admin"},
		}},
		{ID: 12, Name: "合法链式规则", Enabled: true, Action: "block", Score: 3, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/x"},
			{Target: "args", Operator: "contains", Pattern: "a=1"},
		}},
	}

	// When emitted
	emitCustomRules(&sb, rules)
	logged := logs.String()

	// Then the two dirty rules are logged with their ID/name and the skip marker
	for _, want := range []string{"自定义规则 10(非法target规则)", "自定义规则 11(非法operator规则)", "已跳过发射"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("skip log missing %q:\n%s", want, logged)
		}
	}
	// And the clean chained rule produces no skip log line
	if strings.Contains(logged, "自定义规则 12") || strings.Contains(logged, "合法链式规则") {
		t.Fatalf("clean rule must not be logged as skipped:\n%s", logged)
	}
}
