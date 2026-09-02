package services

// CRS 规则组/排除规则混合选择 + 作用域限定（crs_excluded_rules 双格式 /
// crs_rule_groups 6 位 ID 混合）的读侧归一与发射测试。索引夹具复用
// crs_rule_index_test.go 的 seedCRSRuleIndexFixture（920/942 两组、942 文件
// 含 942100+942550 两条）。

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func scopedExclusionFixture(t *testing.T) {
	t.Helper()
	seedCRSRuleIndexFixture(t)
}

func TestParseCRSExcludedRules_dualFormatAndDegrade(t *testing.T) {
	// 旧 []string → 每条归一 {target, scope:"all"}（顺序与重复保留，发射等价）
	legacy := ParseCRSExcludedRules(`["942100","942100","REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]`)
	if len(legacy) != 3 {
		t.Fatalf("legacy entries = %+v, want 3 (duplicates preserved)", legacy)
	}
	for i, e := range legacy {
		if e.Scope != "all" || e.Target == "" || e.IPs != "" || e.ListRefs != nil {
			t.Fatalf("legacy[%d] = %+v, want normalized {target,all}", i, e)
		}
	}

	// 新 []对象：缺省 scope 补 all；完全相同 {target,scope,ips,listRefs} 去重
	//（listRefs 顺序无关：[2,1] 与 [1,2] 视为同条）
	entries := ParseCRSExcludedRules(`[
		{"target":"42","scope":"ip","ips":"1.1.1.1","listRefs":[2,1]},
		{"target":"42","scope":"ip","ips":"1.1.1.1","listRefs":[1,2]},
		{"target":"942100"},
		{"target":"942100","scope":"all"}
	]`)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2 after dedupe", entries)
	}
	if entries[0].Scope != "ip" || entries[1].Scope != "all" {
		t.Fatalf("scope default fill broken: %+v", entries)
	}

	// 降级不炸：空串/纯空白/既非 []string 也非 []对象（混合数组、对象、裸串）
	// 一律按空处理（nil），绝不返回错误或 panic。
	for _, raw := range []string{"", "   ", "not-json", `{"target":"42"}`, `["942100",{"target":"42"}]`, `[42]`} {
		if got := ParseCRSExcludedRules(raw); got != nil {
			t.Fatalf("Parse(%q) = %+v, want nil (treated as empty)", raw, got)
		}
	}
}

func TestBuildCorazaDirectives_legacyExcludedRulesEmissionUnchanged(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode:             "blocking",
		CRSRuleGroups:    json.RawMessage(`["42"]`),
		CRSExcludedRules: json.RawMessage(`["942100","ABCDEF","942100-abc","REQUEST-942.conf","1-999999","932100-932200"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "SecRuleRemoveById 942100\n") {
		t.Fatal("legal single ID must be emitted (legacy path)")
	}
	if !strings.Contains(directives, "SecRuleRemoveById 932100-932200\n") {
		t.Fatal("legal in-range pair must be emitted (legacy path)")
	}
	for _, illegal := range []string{"ABCDEF", "942100-abc", "REQUEST-942.conf", "1-999999"} {
		if strings.Contains(directives, illegal) {
			t.Fatalf("illegal entry %q must be skipped", illegal)
		}
	}
	if strings.Contains(directives, "ctl:ruleRemoveById") {
		t.Fatal("legacy payload must not emit scoped ctl rules")
	}
}

func TestBuildCorazaDirectives_scopedExclusionExpandsGroupPerID(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode: "blocking",
		CRSExcludedRules: json.RawMessage(
			`[{"target":"42","scope":"ip","ips":"1.1.1.1,2.2.2.2"}]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	// 组 42 在夹具索引中含 942100、942550 两条 → 逐 ID ctl，id 2000001 起顺序唯一
	want := []string{
		`SecRule REMOTE_ADDR "@ipMatch 1.1.1.1,2.2.2.2" "id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"` + "\n",
		`SecRule REMOTE_ADDR "@ipMatch 1.1.1.1,2.2.2.2" "id:2000002,phase:1,pass,nolog,ctl:ruleRemoveById=942550"` + "\n",
	}
	last := -1
	for _, line := range want {
		idx := strings.Index(directives, line)
		if idx < 0 {
			t.Fatalf("missing ctl line %q in:\n%s", line, directives)
		}
		if idx < last {
			t.Fatalf("ctl lines out of order: %q", line)
		}
		last = idx
	}
	if strings.Contains(directives, "SecRuleRemoveById") {
		t.Fatal("scoped payload must not emit config-time SecRuleRemoveById")
	}
}

func TestBuildCorazaDirectives_scopedExclusionMergesIPsAndListDedup(t *testing.T) {
	scopedExclusionFixture(t)
	_, database := newClusterTestService(t)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES ('scoped-src', ?)`,
		`[{"value":"1.1.1.1","remark":""},{"value":"3.3.3.0/24","remark":""}]`)
	if err != nil {
		t.Fatalf("seed ip list: %v", err)
	}
	listID, _ := res.LastInsertId()

	policy := &models.SecurityPolicy{
		Mode: "blocking",
		CRSExcludedRules: json.RawMessage(`[
			{"target":"942100","scope":"ip","ips":" 2.2.2.2 ,1.1.1.1","listRefs":[` + jsonInt(listID) + `]},
			{"target":"942550","scope":"list","listRefs":[` + jsonInt(listID) + `,` + jsonInt(listID) + `]}
		]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	// 条目 1：ips ∪ 列表条目合并去重保序 → 2.2.2.2,1.1.1.1,3.3.3.0/24
	if !strings.Contains(directives,
		`SecRule REMOTE_ADDR "@ipMatch 2.2.2.2,1.1.1.1,3.3.3.0/24" "id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`+"\n") {
		t.Fatalf("entry 1 merged match set wrong:\n%s", directives)
	}
	// 条目 2：同一列表重复引用去重一次；id 跨条目顺序唯一（2000002）
	if !strings.Contains(directives,
		`SecRule REMOTE_ADDR "@ipMatch 1.1.1.1,3.3.3.0/24" "id:2000002,phase:1,pass,nolog,ctl:ruleRemoveById=942550"`+"\n") {
		t.Fatalf("entry 2 merged match set / seq wrong:\n%s", directives)
	}
}

func jsonInt(v int64) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func TestBuildCorazaDirectives_scopedExclusionStaleTargetsSkipped(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode: "blocking",
		CRSExcludedRules: json.RawMessage(`[
			{"target":"999999","scope":"ip","ips":"1.1.1.1"},
			{"target":"99","scope":"list","listRefs":[7]}
		]`),
	}
	// db.DB 未初始化：listRefs 解析为空集 → 两条均跳过（陈旧 ID / 空合并集），
	// 不 panic、不发射任何 ctl 行。
	directives := BuildCorazaDirectives(policy, nil)
	if strings.Contains(directives, "ctl:ruleRemoveById") {
		t.Fatalf("stale targets must be skipped:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_scopedExclusionEmptyListSkipped(t *testing.T) {
	scopedExclusionFixture(t)
	_, database := newClusterTestService(t)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES ('empty-src', '[]')`)
	if err != nil {
		t.Fatalf("seed empty list: %v", err)
	}
	listID, _ := res.LastInsertId()
	policy := &models.SecurityPolicy{
		Mode: "blocking",
		CRSExcludedRules: json.RawMessage(
			`[{"target":"42","scope":"list","listRefs":[` + jsonInt(listID) + `]}]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if strings.Contains(directives, "ctl:ruleRemoveById") {
		t.Fatalf("empty resolved list must skip emission:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_hybridRuleGroupsParentFileSupplement(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["942100"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\n") {
		t.Fatalf("parent file of selected ID must be included:\n%s", directives)
	}
	if !strings.Contains(directives, "SecRuleRemoveById 942550\n") {
		t.Fatalf("unselected sibling ID in parent file must be removed:\n%s", directives)
	}
	if strings.Contains(directives, "SecRuleRemoveById 942100\n") {
		t.Fatalf("selected ID must not be removed:\n%s", directives)
	}
	if strings.Contains(directives, "REQUEST-942-*.conf") {
		t.Fatalf("group 42 not selected — glob include must not appear:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_hybridRuleGroupsGroupCoveredSkipsSupplement(t *testing.T) {
	scopedExclusionFixture(t)
	// 组已选中：glob 覆盖父文件 → 不补 Include、不补删（ID 选择冗余无害）
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["42","942100"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-942-*.conf\n") {
		t.Fatalf("selected group glob must be included:\n%s", directives)
	}
	if strings.Contains(directives, "SecRuleRemoveById") {
		t.Fatalf("group-covered parent file must not trigger removals:\n%s", directives)
	}
	// 同文件全部 ID 被选 → Include 父文件但零补删
	policy.CRSRuleGroups = json.RawMessage(`["942100","942550"]`)
	directives = BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\n") {
		t.Fatalf("parent file must be included when all its IDs selected:\n%s", directives)
	}
	if strings.Contains(directives, "SecRuleRemoveById") {
		t.Fatalf("all IDs selected — no removal expected:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_hybridRuleGroupsStaleIDSkipped(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["999999"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if strings.Contains(directives, "SecRuleRemoveById") {
		t.Fatalf("stale group ID must be skipped:\n%s", directives)
	}
	for _, line := range strings.Split(directives, "\n") {
		if strings.HasPrefix(line, "Include /app/waf/crs/rules/") {
			t.Fatalf("stale-only selection must not include any rules file: %q", line)
		}
	}
}

func TestBuildCorazaDirectives_emptyGroupsKeepAllEffectiveSemantics(t *testing.T) {
	scopedExclusionFixture(t)
	directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"}, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-*.conf\n") {
		t.Fatalf("empty groups must keep REQUEST-only all-effective include:\n%s", directives)
	}
	if strings.Contains(directives, "Include /app/waf/crs/rules/*.conf\n") {
		t.Fatalf("WAFCheckResponse=false must not include RESPONSE files:\n%s", directives)
	}
	directives = BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking", WAFCheckResponse: true}, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/*.conf\n") {
		t.Fatalf("empty groups + response check must keep all-file include:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_groupOnlySelectionEmissionEquivalent(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{Mode: "blocking", CRSRuleGroups: json.RawMessage(`["42"]`)}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-942-*.conf\n") {
		t.Fatalf("pure group selection must keep glob include:\n%s", directives)
	}
	if strings.Contains(directives, "SecRuleRemoveById") || strings.Contains(directives, "rules/REQUEST-942-APPLICATION") {
		t.Fatalf("pure group selection must not emit parent-file include/removals:\n%s", directives)
	}
	policy.WAFCheckResponse = true
	directives = BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "Include /app/waf/crs/rules/RESPONSE-942-*.conf\n") {
		t.Fatalf("response-side glob must survive hybrid rework:\n%s", directives)
	}
}
