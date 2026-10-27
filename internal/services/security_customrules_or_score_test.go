package services

import (
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"lazy-balancer-v2/internal/models"
)

// OR 自定义规则的异常分必须按父规则每事务只计一次：分支是四立 SecRule，
// 每个分支都携带 setvar 时，命中 N 个条件就累加 N 倍分——「放行计分」规则会
// 因多条件同时满足越过阈值而变成非预期拦截。评分收敛到父规则级单一评分点
// （分支只置命中标记，评分规则按标记计一次并清除）。
func runCorazaForAnomalyScore(t *testing.T, directives, uri, body string) int {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("引擎必须接受发射产物: %v\n%s", err, directives)
	}
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessConnection("10.0.0.1", 5555, "127.0.0.1", 80)
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	_ = tx.ProcessRequestHeaders()
	if body != "" {
		// URLENCODED 正文处理器按 Content-Type 决定是否解析 ARGS_POST——
		// 缺头时 body 目标族恒空，测试会把「规则没走到」误判成「没计分」。
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		if _, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("process body: %v", err)
	}
	// types.Transaction 接口不含 Variables()；具体实现（*corazawaf.Transaction）
	// 提供插件 API 的 TransactionVariables——测试只需读 TX 值，用最小接口断言。
	txVars, ok := tx.(interface {
		Variables() plugintypes.TransactionVariables
	})
	if !ok {
		t.Fatalf("事务实现不暴露 Variables()，无法读取异常分")
	}
	vals := txVars.Variables().TX().Get("inbound_anomaly_score_pl1")
	if len(vals) == 0 {
		return 0
	}
	score, err := strconv.Atoi(strings.TrimSpace(vals[0]))
	if err != nil {
		t.Fatalf("inbound_anomaly_score_pl1=%q 无法解析: %v", vals[0], err)
	}
	return score
}

func orScoreDirectives(t *testing.T, rules []models.CustomRule) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("SecRuleEngine On\nSecRequestBodyAccess On\n")
	emitCustomRules(&sb, rules, 0)
	return sb.String()
}

func TestEmitCustomRules_orPassScoreCountsParentOnce(t *testing.T) {
	rules := []models.CustomRule{{
		ID: 71, Name: "任一命中计分", Enabled: true, Action: "pass", Score: 5, ConditionLogic: "or",
		Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "uri", Operator: "contains", Pattern: "/secret"},
			{Target: "uri", Operator: "contains", Pattern: "/debug"},
		},
	}}
	directives := orScoreDirectives(t, rules)
	for _, tc := range []struct {
		name, uri string
		want      int
	}{
		{"零条件命中", "/public", 0},
		{"单条件命中", "/admin", 5},
		{"两条件同时命中", "/admin/secret", 5},
		{"三条件同时命中", "/admin/secret/debug", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCorazaForAnomalyScore(t, directives, tc.uri, ""); got != tc.want {
				t.Fatalf("异常分=%d, want %d（父规则每事务只计一次）uri=%s\n%s", got, tc.want, tc.uri, directives)
			}
		})
	}
}

// 混合相位（URI phase:1 + body phase:2）同样只计一次：任一相位先命中即计分，
// 另一相位再命中不得二次累加。
func TestEmitCustomRules_orPassScoreMixedPhasesCountsOnce(t *testing.T) {
	rules := []models.CustomRule{{
		ID: 72, Name: "URI或正文", Enabled: true, Action: "pass", Score: 5, ConditionLogic: "or",
		Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "body", Operator: "contains", Pattern: "inject"},
		},
	}}
	directives := orScoreDirectives(t, rules)
	for _, tc := range []struct {
		name, uri, body string
		want            int
	}{
		{"仅 URI 命中", "/admin", "clean=1", 5},
		{"仅正文命中", "/public", "inject=1", 5},
		{"两相位同时命中", "/admin", "inject=1", 5},
		{"均未命中", "/public", "clean=1", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCorazaForAnomalyScore(t, directives, tc.uri, tc.body); got != tc.want {
				t.Fatalf("异常分=%d, want %d（跨相位不得重复计分）\n%s", got, tc.want, directives)
			}
		})
	}
}

// 发射形状：OR 分支不得各自携带评分 setvar；父规则级的评分点恰好一个。
func TestEmitCustomRules_orPassScoreEmitsSingleScoringPoint(t *testing.T) {
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{{
		ID: 73, Name: "形状", Enabled: true, Action: "pass", Score: 10, ConditionLogic: "or",
		Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/a"},
			{Target: "uri", Operator: "contains", Pattern: "/b"},
		},
	}}, 0)
	got := sb.String()
	if n := strings.Count(got, "inbound_anomaly_score_pl1"); n != 1 {
		t.Fatalf("评分 setvar 出现 %d 次, want 1（分支不得重复计分）:\n%s", n, got)
	}
	if !strings.Contains(got, "+10") {
		t.Fatalf("评分点必须携带父规则分值:\n%s", got)
	}
}
