package services

import (
	"encoding/json"
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
