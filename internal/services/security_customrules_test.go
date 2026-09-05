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
	rules := resolvePolicyCustomRules(json.RawMessage(`[1]`), nil)
	if len(rules) != 1 || rules[0].Name != "链式验证规则" || len(rules[0].Conditions) != 1 {
		t.Fatalf("bad resolution: %+v", rules)
	}
}

func TestResolvePolicyCustomRules_legacyEmbeddedObjects(t *testing.T) {
	rules := resolvePolicyCustomRules(json.RawMessage(`[{"id":2,"name":"内嵌","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"pass","score":1}]`), nil)
	if len(rules) != 1 || rules[0].Name != "内嵌" {
		t.Fatalf("legacy embedded shape not supported: %+v", rules)
	}
}

// Round 34 G: IN 占位符分块——引用数超过单批上限（测试收窄为 2）时全部解析，
// 不再整查询超限失败导致 WAF 自定义规则静默丢失。
func TestResolvePolicyCustomRules_chunkedIDsAcrossBatches(t *testing.T) {
	// Given
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldChunk := policyCustomRuleChunkSize
	policyCustomRuleChunkSize = 2
	t.Cleanup(func() { policyCustomRuleChunkSize = oldChunk })
	for i := 1; i <= 5; i++ {
		if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, description, conditions, action, score, enabled) VALUES (?, '', '[]', 'pass', 1, 1)`, "规则"+string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}

	// When 引用 5 条（跨 3 批查询）
	rules := resolvePolicyCustomRules(json.RawMessage(`[1,2,3,4,5]`), nil)

	// Then 全部解析，无丢失
	if len(rules) != 5 {
		t.Fatalf("len=%d, want 5: %+v", len(rules), rules)
	}
	for i, want := range []string{"规则1", "规则2", "规则3", "规则4", "规则5"} {
		if rules[i].Name != want {
			t.Fatalf("rules[%d].Name=%q, want %q", i, rules[i].Name, want)
		}
	}
}

// Round 35 F-5: 分块查询失败时其 id 不得计入悬空引用日志——此前
// dropped=len(ids)-len(rules) 把「查询失败」误报为「规则已删除」；
// 失败块单独留痕，悬空口径只统计查询成功分块。
func TestResolvePolicyCustomRules_chunkFailureDoesNotInflateDanglingLog(t *testing.T) {
	// Given
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldChunk := policyCustomRuleChunkSize
	policyCustomRuleChunkSize = 2
	t.Cleanup(func() { policyCustomRuleChunkSize = oldChunk })
	// 删表使所有分块查询必然失败（引用 3 条跨 2 批）
	if _, err := db.DB.Exec("DROP TABLE security_custom_rules"); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	// When
	rules := resolvePolicyCustomRules(json.RawMessage(`[1,2,3]`), nil)

	// Then 无规则解析，分块错误单独留痕
	if len(rules) != 0 {
		t.Fatalf("len=%d, want 0", len(rules))
	}
	if !strings.Contains(logs.String(), "分块查询失败") {
		t.Fatalf("chunk failure log missing:\n%s", logs.String())
	}
	// And 悬空日志不得把失败块的 id 计入（0 条悬空，不误导诊断）
	if strings.Contains(logs.String(), "不存在，已跳过") {
		t.Fatalf("dangling log must not fire for failed chunks:\n%s", logs.String())
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
	directives := BuildCorazaDirectives(policy, nil)

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
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "REQUEST_HEADERS:User-Agent") {
		t.Fatalf("user_agent target must use colon notation:\n%s", directives)
	}
	if strings.Contains(directives, "REQUEST_HEADERS.User-Agent") {
		t.Fatalf("dot notation rejected by coraza:\n%s", directives)
	}
}

// TestBuildCorazaDirectives_equalsOperatorEmitsStreq（审计 H1）：equals 语义
// 收紧为大小写敏感精确匹配 @streq——此前误用 @pm（短语匹配：大小写不敏感 +
// 空格分词，「等于 /admin」实际是「包含单词 admin」），与 UI「等于」承诺不符。
func TestBuildCorazaDirectives_equalsOperatorEmitsStreq(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:        "blocking",
		CustomRules: json.RawMessage(`[{"id":11,"name":"等于规则","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"equals","pattern":"/admin"}]}]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, `SecRule REQUEST_URI "@streq /admin"`) {
		t.Fatalf("equals must emit case-sensitive exact match @streq:\n%s", directives)
	}
	if strings.Contains(directives, "@pm") {
		t.Fatalf("@pm must no longer be emitted for equals:\n%s", directives)
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

// N15-F1：多条件链式规则的 setvar 必须绑定到链条末条。coraza v3 在起始条
// 算子命中时立即执行其非破坏性动作（internal/corazawaf/rule.go matchVariable
// 注释「We run non-disruptive actions even if there is no chain match」）——
// 起始条命中而后续条件未命中时链条整体不匹配，但起始条上的 setvar 已累加
// 异常分（幽灵异常分 → 可能触发 949 误拦）。末条命中即整条链命中。
func TestEmitCustomRules_multiConditionSetvarOnLastChainElement(t *testing.T) {
	// Given：一条 block 多条件规则 + 一条 pass 多条件规则 + 一条 log 多条件规则
	var sb strings.Builder
	rules := []models.CustomRule{
		{ID: 20, Name: "链式拦截", Enabled: true, Action: "block", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/admin"},
			{Target: "args", Operator: "contains", Pattern: "a=1"},
		}},
		{ID: 21, Name: "链式计分", Enabled: true, Action: "pass", Score: 3, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "starts_with", Pattern: "/x"},
			{Target: "headers", Operator: "contains", Pattern: "ev"},
		}},
		{ID: 22, Name: "链式记录", Enabled: true, Action: "log", Score: 5, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/y"},
			{Target: "user_agent", Operator: "contains", Pattern: "bot"},
		}},
	}

	// When
	emitCustomRules(&sb, rules)
	got := sb.String()

	// Then：起始条动作串不得携带 setvar（起始条命中而末条未命中时不得泄漏计分）
	for _, starter := range []string{
		`"id:10020,phase:1,deny,log,`,
		`"id:10021,phase:1,pass,log,`,
	} {
		if idx := strings.Index(got, starter); idx >= 0 {
			end := strings.Index(got[idx:], `msg:'`)
			if end < 0 {
				end = strings.Index(got[idx:], `",chain`)
			}
			segment := got[idx : idx+end]
			if strings.Contains(segment, "setvar:") {
				t.Fatalf("multi-condition starter action must not carry setvar (leaks on failed chain):\n%s", got)
			}
		} else {
			t.Fatalf("starter line %q missing:\n%s", starter, got)
		}
	}
	// And：setvar 只出现在链条末条（block 与 pass；log 本就无 setvar）
	wantTail := `"phase:1,setvar:tx.inbound_anomaly_score_pl1=+5"`
	if !strings.Contains(got, wantTail) {
		t.Fatalf("block chain last element must carry the setvar tail:\n%s", got)
	}
	if !strings.Contains(got, `"phase:1,setvar:tx.inbound_anomaly_score_pl1=+3"`) {
		t.Fatalf("pass chain last element must carry the setvar tail:\n%s", got)
	}
	if gotCount := strings.Count(got, "setvar:"); gotCount != 2 {
		t.Fatalf("setvar occurrences=%d, want exactly 2 (block+pass tails, log has none):\n%s", gotCount, got)
	}
	// And：deny/skipAfter 仍留在起始条（coraza 仅在整条链匹配后执行，无泄漏）
	if !strings.Contains(got, `deny,log,msg:'自定义规则 链式拦截 命中',skipAfter:SECURITY_RULES_END,chain"`) {
		t.Fatalf("starter keeps deny/msg/skipAfter without setvar:\n%s", got)
	}
	// And：log 动作末条无附加（无 setvar 可挪）；3 条链式规则各 1 个 chain 动作
	if strings.Count(got, ",chain") != 3 {
		t.Fatalf("expected 3 chained rules (3 chain actions):\n%s", got)
	}
}

// N15-F1 对照组：单条件规则的发射形状不变（setvar 仍在唯一条目上）。
func TestEmitCustomRules_singleConditionSetvarStaysOnRule(t *testing.T) {
	var sb strings.Builder
	rules := []models.CustomRule{
		{ID: 30, Name: "单条件计分", Enabled: true, Action: "pass", Score: 1, Conditions: []models.CustomRuleCondition{
			{Target: "uri", Operator: "contains", Pattern: "/single"},
		}},
	}

	emitCustomRules(&sb, rules)
	got := sb.String()

	want := `"id:10030,phase:1,pass,log,setvar:tx.inbound_anomaly_score_pl1=+1,msg:'自定义规则 单条件计分 命中'"`
	if !strings.Contains(got, want) {
		t.Fatalf("single-condition rule emission shape must stay unchanged:\n%s", got)
	}
}

func TestEmitCustomRules_assignsUniqueSyntheticIDsToLegacyIDLessRules(t *testing.T) {
	// Given：同一策略内两条无 id 的旧版内嵌规则（legacy 0/""-tolerance 数据）
	var sb strings.Builder
	rules := []models.CustomRule{
		{ID: 0, Name: "旧版规则甲", Enabled: true, Action: "block", Score: 5, Target: "uri", Operator: "contains", Pattern: "/a"},
		{ID: 0, Name: "旧版规则乙", Enabled: true, Action: "log", Score: 0, Target: "uri", Operator: "contains", Pattern: "/b"},
	}

	// When：发射
	emitCustomRules(&sb, rules)
	got := sb.String()

	// Then：按序获得不同合成 id（1000000+n），不再共用 id:10000 造成重复 SecRule id
	for _, want := range []string{"id:1000001,phase:1,", "id:1000002,phase:1,"} {
		if !strings.Contains(got, want) {
			t.Fatalf("legacy rule must emit %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "id:10000,") {
		t.Fatalf("legacy rules must not emit duplicate id:10000:\n%s", got)
	}
	// And：两条规则均正常发射（动作串完整）
	if !strings.Contains(got, "自定义规则 旧版规则甲 命中") || !strings.Contains(got, "自定义规则 旧版规则乙 命中") {
		t.Fatalf("both legacy rules must be emitted:\n%s", got)
	}
}
