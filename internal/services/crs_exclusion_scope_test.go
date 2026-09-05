package services

// CRS 规则组/排除规则混合选择 + 作用域限定（crs_excluded_rules 双格式 /
// crs_rule_groups 6 位 ID 混合）的读侧归一与发射测试。索引夹具复用
// crs_rule_index_test.go 的 seedCRSRuleIndexFixture（920/942 两组、942 文件
// 含 942100+942550 两条）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func scopedExclusionFixture(t *testing.T) {
	t.Helper()
	seedCRSRuleIndexFixture(t)
	seedInfraCRSFiles(t)
}

// seedInfraCRSFiles 提供基础设施三件套（901/949/959）与 crsDirectivesDir——
// F0 存在性门仅在文件在场时发射强制 Include，fixture 缺文件会让门把
// Include 全部跳过、断言集体失真。
func seedInfraCRSFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	for _, name := range []string{"REQUEST-901-INITIALIZATION.conf", "REQUEST-949-BLOCKING-EVALUATION.conf", "RESPONSE-959-BLOCKING-EVALUATION.conf"} {
		if err := os.WriteFile(filepath.Join(rules, name), []byte("# fixture\n"), 0o644); err != nil {
			t.Fatalf("seed infra %s: %v", name, err)
		}
	}
	old := crsDirectivesDir
	crsDirectivesDir = dir
	t.Cleanup(func() { crsDirectivesDir = old })
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
		if !strings.HasPrefix(line, "Include /app/waf/crs/rules/") {
			continue
		}
		// F0：基础设施组（901 初始化/949 评估）强制包含与选组内容无关，放行；
		// 陈旧 ID 不得携带任何攻击组文件进场。
		if strings.Contains(line, "REQUEST-901-INITIALIZATION.conf") || strings.Contains(line, "REQUEST-949-BLOCKING-EVALUATION.conf") {
			continue
		}
		t.Fatalf("stale-only selection must not include any attack-group rules file: %q", line)
	}
}

// F0：选组策略的基础设施组强制包含——未选 01/49/59 时 901 先于被选组、949 殿后
// （响应检查开再加 959）；已选时不重复 Include（重复注册同规则 ID 会编译失败）；
// glob 路径（空选组）不受影响（由 emptyGroups 等价语义测试锁定）。
func TestBuildCorazaDirectives_infraGroupsForceIncluded(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["42"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	idx901 := strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-901-INITIALIZATION.conf")
	idx942 := strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-942-")
	idx949 := strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf")
	if idx901 < 0 || idx942 < 0 || idx949 < 0 {
		t.Fatalf("infra includes missing (901=%d 942=%d 949=%d):\n%s", idx901, idx942, idx949, directives)
	}
	if !(idx901 < idx942 && idx942 < idx949) {
		t.Fatalf("include order must be 901 → selected groups → 949:\n%s", directives)
	}
	if strings.Contains(directives, "RESPONSE-959-BLOCKING-EVALUATION.conf") {
		t.Fatalf("959 must not be included without WAFCheckResponse:\n%s", directives)
	}

	// 响应检查开启 → 959 殿后；已选 01/49/59 组号（M3 读取面剥离——写入面
	// 剥离生效前的存量/带外数据）→ 基础设施组号不再按数组原位发射 glob，
	// 改由强制 Include 按正确次序（901 最前、949/959 殿后）补齐，各恰一次。
	policy.WAFCheckResponse = true
	policy.CRSRuleGroups = json.RawMessage(`["01","42","49","59","80"]`)
	directives = BuildCorazaDirectives(policy, nil)
	for glob, exact := range map[string]string{
		"REQUEST-901-*.conf":  "REQUEST-901-INITIALIZATION.conf",
		"REQUEST-949-*.conf":  "REQUEST-949-BLOCKING-EVALUATION.conf",
		"RESPONSE-959-*.conf": "RESPONSE-959-BLOCKING-EVALUATION.conf",
	} {
		if strings.Contains(directives, "Include /app/waf/crs/rules/"+glob) {
			t.Fatalf("%s must be stripped from selection and force-included exactly instead:\n%s", glob, directives)
		}
		if got := strings.Count(directives, "Include /app/waf/crs/rules/"+exact); got != 1 {
			t.Fatalf("%s force-included %d times, want exactly 1:\n%s", exact, got, directives)
		}
	}
	idx901 = strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-901-INITIALIZATION.conf")
	idx942 = strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-942-")
	idx949 = strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf")
	idx959 := strings.Index(directives, "Include /app/waf/crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf")
	if !(idx901 < idx942 && idx942 < idx949 && idx949 < idx959) {
		t.Fatalf("include order must stay 901 → selected groups → 949 → 959:\n%s", directives)
	}
	// 6 位基础设施 ID（M3 同口径剥离）→ 剥离后由强制 Include 补齐，949 仍恰一次
	policy.CRSRuleGroups = json.RawMessage(`["42","949110"]`)
	directives = BuildCorazaDirectives(policy, nil)
	if got := strings.Count(directives, "Include /app/waf/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"); got != 1 {
		t.Fatalf("949 included %d times after infra-ID strip, want exactly 1:\n%s", got, directives)
	}
}

// TestBuildCorazaDirectives_legacyInfraGroupOrderPreserved（M3）：存量/带外
// crs_rule_groups=["42","01"]（写入面剥离生效前落库）——组号 01 不再按数组原位
// 发射 REQUEST-901-*.conf glob（会排在 942 之后、破坏 901 最前的强制序），而是
// 剥离后由强制 Include 补齐：901 仍最前、949/959 仍殿后。
func TestBuildCorazaDirectives_legacyInfraGroupOrderPreserved(t *testing.T) {
	scopedExclusionFixture(t)
	policy := &models.SecurityPolicy{
		Mode:             "blocking",
		WAFCheckResponse: true,
		CRSRuleGroups:    json.RawMessage(`["42","01"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if strings.Contains(directives, "REQUEST-901-*.conf") {
		t.Fatalf("legacy infra group entry must be stripped, not emitted as glob:\n%s", directives)
	}
	idx901 := strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-901-INITIALIZATION.conf")
	idx942 := strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-942-")
	idx949 := strings.Index(directives, "Include /app/waf/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf")
	idx959 := strings.Index(directives, "Include /app/waf/crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf")
	if idx901 < 0 || idx942 < 0 || idx949 < 0 || idx959 < 0 {
		t.Fatalf("infra includes missing (901=%d 942=%d 949=%d 959=%d):\n%s", idx901, idx942, idx949, idx959, directives)
	}
	if !(idx901 < idx942 && idx942 < idx949 && idx949 < idx959) {
		t.Fatalf("order must be 901 → selected groups → 949 → 959:\n%s", directives)
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

// v2.2.2 契约漂移回归：ips 数组形态（快捷排除/向导 tag 输入）与字符串形态
// 均可解析；序列化恒为数组（前端读侧契约）。
func TestCRSExcludedEntry_IPsDualShapeRoundTrip(t *testing.T) {
	var arrForm CRSExcludedEntry
	if err := json.Unmarshal([]byte(`{"target":"911013","scope":"ip","ips":["203.0.113.99","10.0.0.0/8"],"listRefs":[]}`), &arrForm); err != nil {
		t.Fatalf("array form: %v", err)
	}
	if arrForm.IPs != "203.0.113.99,10.0.0.0/8" {
		t.Fatalf("normalized ips=%q", arrForm.IPs)
	}
	out, err := json.Marshal(arrForm)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"ips":["203.0.113.99","10.0.0.0/8"]`) {
		t.Fatalf("marshal must emit array, got %s", out)
	}
	var strForm CRSExcludedEntry
	if err := json.Unmarshal([]byte(`{"target":"942100","scope":"ip","ips":"1.2.3.4","listRefs":[]}`), &strForm); err != nil {
		t.Fatalf("string form: %v", err)
	}
	if strForm.IPs != "1.2.3.4" {
		t.Fatalf("string form ips=%q", strForm.IPs)
	}
}

// F0-mime：响应检查开启时强制发射 SecResponseBodyMimeType（coraza 零值=空集=
// 响应体永不进规则），关闭时不得出现（避免无谓的响应体缓冲）。
func TestBuildCorazaDirectives_responseBodyMimeTypeEmitted(t *testing.T) {
	scopedExclusionFixture(t)
	on := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "detection", WAFCheckResponse: true, CRSRuleGroups: json.RawMessage(`["51"]`)}, nil)
	if !strings.Contains(on, "SecResponseBodyMimeType text/plain text/html text/xml application/json") {
		t.Fatalf("WAFCheckResponse on must emit SecResponseBodyMimeType:\n%s", on)
	}
	off := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "detection", CRSRuleGroups: json.RawMessage(`["42"]`)}, nil)
	if strings.Contains(off, "SecResponseBodyMimeType") {
		t.Fatalf("WAFCheckResponse off must not emit SecResponseBodyMimeType:\n%s", off)
	}
}

// F0 存量兜底：命中 901 初始化组的存量排除（组号/ID/文件名/跨界区间/作用域形态）
// 在发射面一律跳过——否则它们会在强制 Include 之后把初始化规则重新删除。
func TestBuildCorazaDirectives_storedInitExclusionsSkipped(t *testing.T) {
	scopedExclusionFixture(t)
	for _, target := range []string{`"01"`, `"901200"`, `"REQUEST-901-INITIALIZATION.conf"`, `"900500-902000"`} {
		policy := &models.SecurityPolicy{
			Mode:             "blocking",
			CRSRuleGroups:    json.RawMessage(`["42"]`),
			CRSExcludedRules: json.RawMessage(`[` + target + `]`),
		}
		directives := BuildCorazaDirectives(policy, nil)
		if strings.Contains(directives, "SecRuleRemoveById 901") || strings.Contains(directives, "SecRuleRemoveById 900500-902000") {
			t.Fatalf("stored init exclusion %s must not reach SecRuleRemoveById:\n%s", target, directives)
		}
		if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-901-INITIALIZATION.conf") {
			t.Fatalf("forced 901 include must survive the stored exclusion %s:\n%s", target, directives)
		}
	}
	// scoped（ip 作用域）存量 901 排除同样跳过：不得出现针对 901 的 ctl 展开
	policy := &models.SecurityPolicy{
		Mode:             "blocking",
		CRSRuleGroups:    json.RawMessage(`["42"]`),
		CRSExcludedRules: json.RawMessage(`[{"target":"901200","scope":"ip","ips":"203.0.113.7"}]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if strings.Contains(directives, "ruleRemoveById=901200") {
		t.Fatalf("scoped stored init exclusion must not emit ctl removal:\n%s", directives)
	}
	// 非 901 排除不受影响（回归保护）：942 组号排除照常发射
	policy = &models.SecurityPolicy{
		Mode:             "blocking",
		CRSRuleGroups:    json.RawMessage(`["42"]`),
		CRSExcludedRules: json.RawMessage(`["42"]`),
	}
	directives = BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "SecRuleRemoveById 942000-942999") {
		t.Fatalf("non-init exclusion must still emit:\n%s", directives)
	}
}

// F0 存在性门（CRS 更新风险排查）：基础设施文件缺失时强制 Include 必须跳过
// （coraza 对缺失精确路径 Include 是致命错误，配置加载失败=全站停摆）。
func TestBuildCorazaDirectives_infraIncludeGuardedByExistence(t *testing.T) {
	scopedExclusionFixture(t)
	// 覆盖 fixture 的 crsDirectivesDir 为空目录（rules 下无任何文件）
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := crsDirectivesDir
	crsDirectivesDir = empty
	t.Cleanup(func() { crsDirectivesDir = old })

	policy := &models.SecurityPolicy{
		Mode:             "blocking",
		WAFCheckResponse: true,
		CRSRuleGroups:    json.RawMessage(`["42"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	for _, infra := range []string{"REQUEST-901-INITIALIZATION.conf", "REQUEST-949-BLOCKING-EVALUATION.conf", "RESPONSE-959-BLOCKING-EVALUATION.conf"} {
		if strings.Contains(directives, "Include /app/waf/crs/rules/"+infra) {
			t.Fatalf("missing infra file %s must not be force-included:\n%s", infra, directives)
		}
	}
	// 被选组的 glob Include 不受影响（空匹配仅 warn，无致命路径）
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-942-") {
		t.Fatalf("selected group glob must still emit:\n%s", directives)
	}
}
