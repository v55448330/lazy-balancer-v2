package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁大屏「命中规则」榜应展示可读规则名而非裸 id：事件里 rule_triggered
// 是 coraza SecRule id（阶段 1 预检为合成 id、CRS 为 9xxxxx、自定义规则为
// DB id+10000、限流为 429），直接展示用户无法理解。
func TestGetSecurityThreatScreen_topRulesUseReadableNames(t *testing.T) {
	// Given：四类触发 id 各 1 条事件 + 一条已命名的自定义规则
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seed := func(minutes int, ip, triggered, msg string) {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
			VALUES (?, ?, 'GET', '/a', 'stage1', ?, ?, 'blocked', '')`,
			utcStringAgo(time.Duration(minutes)*time.Minute), ip, triggered, msg); err != nil {
			t.Fatalf("seed event %s: %v", triggered, err)
		}
	}
	// 计数构造 Top3 顺序：800009 ×4 > 2 ×3 > 10018 ×2 > 930130 ×1
	for i := 0; i < 4; i++ {
		seed(30+i, "93.184.216.7", "800009", "地域拦截命中")
	}
	for i := 0; i < 3; i++ {
		seed(30+i, "93.184.216.8", "2", "IP 黑名单拒绝")
	}
	for i := 0; i < 2; i++ {
		seed(30+i, "93.184.216.9", "10018", "自定义规则命中")
	}
	seed(30, "93.184.216.10", "930130", "PHP Injection")
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, conditions, action, enabled) VALUES (18, '测试-阶段3UA', '[]', 'block', 1)`); err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then
	got := map[string]bool{}
	for _, entry := range payload.Data.TopRules {
		got[entry.Name] = true
	}
	want := []string{
		"地域拦截（策略 #9）",
		"IP 访问控制拦截（#2）",
		"测试-阶段3UA（#10018）",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("top_rules 缺少可读标签 %q，实际=%+v", name, payload.Data.TopRules)
		}
	}
	for _, entry := range payload.Data.TopRules {
		if entry.Name == "800009" || entry.Name == "2" || entry.Name == "10018" {
			t.Errorf("top_rules 仍暴露裸 id %q", entry.Name)
		}
	}
	// 第 4 名被 Top3 截断，改用解析器直测 CRS 回退标签（索引目录在测试环境为空）
	if got := describeThreatRuleNameWithNames("930130", nil); got != "CRS 规则（#930130）" {
		t.Errorf("CRS 未命中索引时应回退可读标签，got=%q", got)
	}
}

// 宽窗口下自定义规则键可达 200：标签解析必须一次分块 IN 预取，而不是逐键
// 点查主库（缓存 miss 时的串行查询热点）。
func TestLabeledThreatRuleCounts_prefetchesCustomNames(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	for id, name := range map[int]string{42: "规则甲", 43: "规则乙"} {
		if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, conditions, action, enabled) VALUES (?, ?, '[]', 'block', 1)`, id, name); err != nil {
			t.Fatalf("seed custom rule %d: %v", id, err)
		}
	}
	labeled := labeledThreatRuleCounts(map[string]int{"10042": 3, "10043": 1, "942100": 2, "10099": 4})
	want := map[string]int{
		"规则甲（#10042）":   3,
		"规则乙（#10043）":   1,
		"自定义规则（#10099）": 4,
	}
	for name, count := range want {
		if labeled[name] != count {
			t.Fatalf("labeled[%q]=%d, want %d（all=%+v）", name, labeled[name], count, labeled)
		}
	}
	// 非自定义段键仍走原解析（CRS 索引在测试环境为空 → 回退可读类别标签）
	if labeled["CRS 规则（#942100）"] != 2 {
		t.Fatalf("CRS 回退标签丢失: %+v", labeled)
	}
	// 批量路径不得逐键点查主库（宽窗口 200 键 = 200 次串行查询热点）
	if got := threatRuleNamePointQueriesForTest.Load(); got != 0 {
		t.Fatalf("批量标签解析发起点查 %d 次, want 0", got)
	}
}

// 合成自定义规则 id（1000000+，v2.1.0 前无 id 内嵌规则）没有 DB 行可查，
// 但语义仍属自定义规则族——大屏「命中规则」榜必须给出可读类别标签，且与
// 事件列表 trigger_type 的「WAF·自定义」同族，不得回退成裸数字。
func TestDescribeThreatRuleName_syntheticCustomRuleIsLabeled(t *testing.T) {
	if got := describeThreatRuleNameWithNames("1000001", nil); got != "自定义规则（#1000001）" {
		t.Fatalf("合成自定义 id 标签=%q, want 自定义规则（#1000001）", got)
	}
	// 与事件列表分类同族（避免榜面与列表口径分叉）
	if got := triggerTypeForRule("1000001"); got != "WAF·自定义" {
		t.Fatalf("trigger_type=%q, want WAF·自定义", got)
	}
	// 批量预取路径同样覆盖合成段（customNames 非 nil 时不点查主库）
	labeled := labeledThreatRuleCounts(map[string]int{"1000002": 2})
	if labeled["自定义规则（#1000002）"] != 2 {
		t.Fatalf("合成 id 未进入可读标签维度: %+v", labeled)
	}
	if got := threatRuleNamePointQueriesForTest.Load(); got != 0 {
		t.Fatalf("合成段解析发起点查 %d 次, want 0", got)
	}
}

// id:5 是「绕过模式占位」的信任名单 DetectionOnly 规则（id:3 同族变体）；
// id:14 是 v2.3.x 威胁情报库预检拦截的历史段，2026-11-25 起并入「IP 访问控制」
// ——大屏榜面标签、事件列表触发类型、总览攻击族三面口径必须同源（id→家族
// 单一事实源），历史/导入的 id:5 行一律归信任名单。
func TestThreatRuleFamilyLabels_idFiveAndFourteenAligned(t *testing.T) {
	cases := []struct {
		key, wantDesc, wantTrigger string
	}{
		{"5", "信任名单检测（#5）", "信任名单"},
		{"14", "IP 访问控制拦截（#14）", "IP 访问控制"},
	}
	for _, c := range cases {
		if got := describeThreatRuleNameWithNames(c.key, nil); got != c.wantDesc {
			t.Errorf("describeThreatRuleName(%q)=%q, want %q", c.key, got, c.wantDesc)
		}
		if got := triggerTypeForRule(c.key); got != c.wantTrigger {
			t.Errorf("triggerTypeForRule(%q)=%q, want %q（榜面与事件列表族标签必须一致）", c.key, got, c.wantTrigger)
		}
	}
	if got := attackFamilyClassOf("5", ""); got != attackFamilyTrust {
		t.Errorf("attackFamilyClassOf(5)=%v, want 信任名单族", got)
	}
	if got := attackFamilyClassOf("14", ""); got != attackFamilyIPACL {
		t.Errorf("attackFamilyClassOf(14)=%v, want IP 访问控制族", got)
	}
	// 历史 id:5 行在两个总览视图同口径（旧实现三面分叉：榜面/列表归信任，
	// 攻击族分桶归 IP 访问控制）。
	if got := categorizeAttack("5", ""); got != "信任名单" {
		t.Errorf("categorizeAttack(5)=%q, want 信任名单", got)
	}
	if got := stageCategorizeAttack("5", ""); got != "信任名单" {
		t.Errorf("stageCategorizeAttack(5)=%q, want 信任名单", got)
	}
}

// 固定 id 的族标签必须与事件列表 trigger_type 同词：id:11（请求体解析失败，
// 客户端声明 JSON 却发非法体即可命中）曾在大屏「命中规则」榜显示裸 "11"，
// 而事件列表显示「请求体异常」——同屏两面不一致，排障需自行对回规则文件。
func TestThreatRuleFamilyLabels_bodyAnomalyAligned(t *testing.T) {
	if got, want := describeThreatRuleNameWithNames("11", nil), "请求体异常（#11）"; got != want {
		t.Fatalf("describeThreatRuleName(11)=%q, want %q", got, want)
	}
	if got, want := triggerTypeForRule("11"), "请求体异常"; got != want {
		t.Fatalf("triggerTypeForRule(11)=%q, want %q（榜面与事件列表族标签必须一致）", got, want)
	}
	if got := attackFamilyClassOf("11", ""); got != attackFamilyBodyAnomaly {
		t.Fatalf("attackFamilyClassOf(11)=%v, want 请求体异常族", got)
	}
	// 聚合入口（labeledThreatRuleCounts）同样不得回裸数字。
	labeled := labeledThreatRuleCounts(map[string]int{"11": 2})
	if _, ok := labeled["请求体异常（#11）"]; !ok {
		t.Fatalf("labeledThreatRuleCounts=%v, want 含「请求体异常（#11）」", labeled)
	}
}
