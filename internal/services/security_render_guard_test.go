package services

// 渲染侧带外脏数据防线（写侧/导入门之外的最后一道）：组号重复去重、
// 组号形态门、未知排除 scope 拒绝降级、GeoIP 非法态收严、响应规则与
// 响应检查开关联动、绕过/信任优先级、出站拦截抬码、畸形 body 守卫计分。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/internal/models"
)

// crs_rule_groups 重复组号：渲染必须去重——重复 Include 同一 glob 会让
// coraza 报 duplicated rule id 拒绝整份配置。
func TestRenderCRSGroups_dedupesRepeatedGroupCodes(t *testing.T) {
	seedInfraCRSFiles(t)
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", CRSRuleGroups: json.RawMessage(`["42","42"]`)}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	if got := strings.Count(d, "Include /app/waf/crs/rules/REQUEST-942-*.conf"); got != 1 {
		t.Fatalf("duplicate group must render exactly one Include, got %d:\n%s", got, d)
	}
}

// 渲染侧组号形态门：非两位数字/非 6 位 ID 的条目（带外直写可携带注入
// 载荷）必须跳过而非直拼 Include。
func TestRenderCRSGroups_skipsMalformedGroupCodes(t *testing.T) {
	seedInfraCRSFiles(t)
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", CRSRuleGroups: json.RawMessage("[\"42-*.conf\\nSecRuleEngine Off\\n#\"]")}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	if strings.Contains(d, "SecRuleEngine Off") {
		t.Fatalf("injection-shaped group entry must be skipped, got:\n%s", d)
	}
	// 零匹配 glob 形态同样跳过
	p2 := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", CRSRuleGroups: json.RawMessage(`["9x"]`)}
	d2 := mustDirectives(BuildCorazaDirectives(p2, nil, "", false, 0, "lb_test"))
	if strings.Contains(d2, "REQUEST-99x") {
		t.Fatalf("non-group-code entry must not reach Include glob, got:\n%s", d2)
	}
}

// crs_excluded_rules 未知 scope（带外/旧版快照）：不得静默降级为
// scope=all（全局删规则=保护面静默扩大），跳过该条。
func TestRenderCRSExclusions_unknownScopeNotDemotedToGlobal(t *testing.T) {
	seedInfraCRSFiles(t)
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking",
		CRSExcludedRules: json.RawMessage(`[{"target":"942100","scope":"global"}]`)}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	if strings.Contains(d, "SecRuleRemoveById 942100") {
		t.Fatalf("unknown scope must not degrade to global SecRuleRemoveById, got:\n%s", d)
	}
	// 回归：合法 scope=all 照常发射
	pOK := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking",
		CRSExcludedRules: json.RawMessage(`[{"target":"942100","scope":"all"}]`)}
	dOK := mustDirectives(BuildCorazaDirectives(pOK, nil, "", false, 0, "lb_test"))
	if !strings.Contains(dOK, "SecRuleRemoveById 942100") {
		t.Fatalf("scope=all entry must still emit, got:\n%s", dOK)
	}
}

// GeoIP allow+空名单（写侧 400 的形状，带外直写可绕过）：渲染端 fail-open
// 全放行是最危险方向——fail-visible 拒绝生成。
func TestPrecheckGeoIP_allowWithEmptyListFailsVisible(t *testing.T) {
	p := &models.SecurityPolicy{ID: 77, Name: "g-allow-empty", GeoIPMode: "allow", GeoIPCountries: json.RawMessage(`[]`)}
	if _, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, "lb_test"); err == nil {
		t.Fatal("geoip_mode=allow + 空名单必须拒绝生成（渲染 fail-open 不得静默生效）")
	}
}

// GeoIP 非枚举 mode（带外脏值）：按关闭处理（skip+WARN）而不是按 deny
// 方向静默执行（allowMode=false 默认分支会把 UI 未宣称的方向强加给流量）。
func TestPrecheckGeoIP_unknownModeSkipped(t *testing.T) {
	p := &models.SecurityPolicy{ID: 78, Name: "g-bad-mode", GeoIPMode: "DENY", GeoIPCountries: json.RawMessage(`["CN"]`)}
	d, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, "lb_test")
	if err != nil {
		t.Fatalf("unknown geoip_mode must degrade with WARN, not fail: %v", err)
	}
	if strings.Contains(d, "GeoIP 区域拦截") {
		t.Fatalf("unknown geoip_mode must not emit deny-direction chain, got:\n%s", d)
	}
	// 回归：合法 deny 照常发射
	pOK := &models.SecurityPolicy{ID: 79, Name: "g-ok", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`)}
	dOK, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{pOK}, "lb_test")
	if err != nil || !strings.Contains(dOK, "GeoIP 区域拦截") {
		t.Fatalf("valid deny chain must emit: err=%v\n%s", err, dOK)
	}
}

// 绕过（IP ACL 绕过模式）与信任名单同 IP：绕过=ruleEngine Off 短路是
// 2026-09-15 裁定的语义；coraza ctl 同相位后写覆盖前写，信任名单的
// DetectionOnly 若后发射会把绕过降级为「全评估仅记录」。真实事务断言：
// 同 IP 在绕过+信任双名单时，body 目标（phase:2）自定义拦截规则不得被
// 求值——coraza 的 ruleEngine 检查按相位粒度生效（相位内 ctl 对后续相位
// 起效），phase:2 是区分两种终态的唯一观测面。
func TestEngineGate_bypassBeatsTrustOnSameIP(t *testing.T) {
	customBody := json.RawMessage(`[{"id":12345,"name":"adm","enabled":true,"action":"block","conditions":[{"target":"body","operator":"contains","pattern":"evil"}]}]`)
	compileAndRun := func(t *testing.T, p *models.SecurityPolicy) (interrupted bool, matched22345 bool) {
		t.Helper()
		d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
		var kept []string
		for _, line := range strings.Split(d, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "SecAuditLogType ") ||
				strings.HasPrefix(trimmed, "Include ") || strings.HasPrefix(trimmed, "SecRuleUpdateActionById ") {
				continue
			}
			kept = append(kept, line)
		}
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n")))
		if err != nil {
			t.Fatalf("coraza 引擎拒绝渲染指令: %v\n%s", err, strings.Join(kept, "\n"))
		}
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessConnection("198.51.100.9", 8080, "127.0.0.1", 80)
		tx.ProcessURI("/x", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Host", "x.test")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		tx.AddRequestHeader("Content-Length", "6")
		tx.ProcessRequestHeaders()
		if _, _, err := tx.WriteRequestBody([]byte("x=evil")); err != nil {
			t.Fatal(err)
		}
		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatal(err)
		}
		interrupted = it != nil
		for _, m := range tx.MatchedRules() {
			if m.Rule().ID() == 22345 {
				matched22345 = true
			}
		}
		return interrupted, matched22345
	}

	// 绕过+信任同 IP：绕过必须是事务终态——phase:2 整体不评估
	p := &models.SecurityPolicy{
		AnomalyThreshold: 5, Mode: "blocking",
		IPACLEnabled: true, IPACLMode: "绕过", IPACLList: `["198.51.100.9"]`,
		IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["198.51.100.9"]`),
		CustomRules: customBody,
	}
	// 形状钉：绕过规则必须排在信任 DetectionOnly 之后（后写覆盖前写）
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	idxTrust := strings.Index(d, "ctl:ruleEngine=DetectionOnly")
	idxBypass := strings.Index(d, "ctl:ruleEngine=Off")
	if idxTrust < 0 || idxBypass < 0 || idxBypass < idxTrust {
		t.Fatalf("bypass ctl must be emitted after trust ctl, got:\n%s", d)
	}
	if interrupted, matched := compileAndRun(t, p); interrupted || matched {
		t.Fatalf("绕过+信任双名单：绕过必须完全旁路（ruleEngine Off 终态）——interrupted=%v matchedBodyRule=%v（当前信任 DetectionOnly 覆盖了绕过）", interrupted, matched)
	}

	// 对照一：仅信任名单 → DetectionOnly——phase:2 求值（仅记录）但不拦
	pTrustOnly := &models.SecurityPolicy{
		AnomalyThreshold: 5, Mode: "blocking",
		IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["198.51.100.9"]`),
		CustomRules: customBody,
	}
	if interrupted, matched := compileAndRun(t, pTrustOnly); interrupted || !matched {
		t.Fatalf("信任-only 对照：DetectionOnly 下 body 规则应被求值（仅记录）——interrupted=%v matched=%v", interrupted, matched)
	}

	// 对照二：不在任何名单的 IP……（同 IP 才进名单）改用无名单策略：
	// blocking 下 body 规则真实拦截——证明被测规则本身有效。
	pNoList := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`[]`), CustomRules: customBody}
	if interrupted, matched := compileAndRun(t, pNoList); !interrupted || !matched {
		t.Fatalf("无名单对照：blocking 下 body 拦截规则必须真实中断——interrupted=%v matched=%v", interrupted, matched)
	}
}

// 拦截页归因抬码覆盖出站评估：blockStatus>0 且 waf_check_response=on 时
// 959100 必须与 949110 同款抬码，否则出站拦截落不到配置的阶段 3 拦截页。
func TestRenderBlockStatus_raisesOutboundBlockingEvaluation(t *testing.T) {
	seedInfraCRSFiles(t)
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", WAFCheckResponse: true}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 483, "lb_test"))
	if !strings.Contains(d, `SecRuleUpdateActionById 949110 "deny,status:483"`) {
		t.Fatalf("inbound raise missing (regression), got:\n%s", d)
	}
	if !strings.Contains(d, `SecRuleUpdateActionById 959100 "deny,status:483"`) {
		t.Fatalf("outbound 959100 raise missing when response check on, got:\n%s", d)
	}
	// 回归：响应检查关闭时不抬出站评估（959 文件不会被 Include）
	pOff := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", WAFCheckResponse: false}
	dOff := mustDirectives(BuildCorazaDirectives(pOff, nil, "", false, 483, "lb_test"))
	if strings.Contains(dOff, "959100") {
		t.Fatalf("959100 raise must be gated by waf_check_response, got:\n%s", dOff)
	}
}

// 畸形 body 守卫（id:11）计分必须阈值感知：固定 +5 在阈值 10/15/20 时
// 达不到拦截线，「声明 JSON 发非法 JSON」对全部 body 规则隐身却不拦。
func TestRenderBodyGuard_scoresReachPolicyThreshold(t *testing.T) {
	p := &models.SecurityPolicy{AnomalyThreshold: 10, Mode: "blocking"}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	if !strings.Contains(d, "id:11,phase:2,pass,log,setvar:tx.inbound_anomaly_score_pl1=+10") {
		t.Fatalf("body guard must score by policy threshold (+10), got:\n%s", d)
	}
	// 回归：默认阈值 5 形状不变
	p5 := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}
	d5 := mustDirectives(BuildCorazaDirectives(p5, nil, "", false, 0, "lb_test"))
	if !strings.Contains(d5, "id:11,phase:2,pass,log,setvar:tx.inbound_anomaly_score_pl1=+5") {
		t.Fatalf("default threshold shape changed, got:\n%s", d5)
	}
}

// 「数字-数字」纯数字段不是 CRS 文件名组号：101-942 不得被解释为
// 942 组区间（942000-942999=整组删除 SQLi 规则）。
func TestCRSExcludedEntryEffective_numericSegmentsAreNotFilenames(t *testing.T) {
	if CRSExcludedEntryEffective("101-942") {
		t.Fatal("纯数字段 \"101-942\" 不得映射为文件名组号区间")
	}
	// 回归：6 位区间与真实文件名形态保持合法
	if !CRSExcludedEntryEffective("942000-942999") {
		t.Fatal("显式 6 位区间必须保持合法")
	}
	if !CRSExcludedEntryEffective("REQUEST-942-APPLICATION-ATTACK-SQLI.conf") {
		t.Fatal("真实 CRS 文件名形态必须保持合法")
	}
	// 两位组号在发射侧被映射为 9xx000-9xx999（可发射）——保存门必须同源，
	// 否则 legacy []string 形态的组号条目「保存 400 但已在生效」（新对象格式
	// 走 IsCRSGroupCode 分支，两形态语义分裂）。
	if !CRSExcludedEntryEffective("42") {
		t.Fatal("两位组号必须合法（发射为 942000-942999）")
	}
	if CRSExcludedEntryEffective("4a") {
		t.Fatal("非数字两位记号不得合法")
	}
}

// 响应侧规则 ID + waf_check_response=off：选择零效果，渲染必须跳过
// （而不是 Include 一个永不被评估的 RESPONSE 父文件）。
func TestRenderCRSGroups_responseRuleIDSkippedWhenResponseCheckOff(t *testing.T) {
	seedInfraCRSFiles(t)
	rulesDir := filepath.Join(crsDirectivesDir, "rules")
	if err := os.WriteFile(filepath.Join(rulesDir, "RESPONSE-980-CORRELATION.conf"),
		[]byte("SecAction \"id:980100,phase:4,pass,nolog\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldIdx := CRSRuleIndexDir
	CRSRuleIndexDir = rulesDir
	t.Cleanup(func() { CRSRuleIndexDir = oldIdx })

	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", WAFCheckResponse: false, CRSRuleGroups: json.RawMessage(`["980100"]`)}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	if strings.Contains(d, "RESPONSE-980") {
		t.Fatalf("response rule ID must be skipped when waf_check_response=off, got:\n%s", d)
	}
	// 回归：开启响应检查时照常 Include 父文件
	pOn := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", WAFCheckResponse: true, CRSRuleGroups: json.RawMessage(`["980100"]`)}
	dOn := mustDirectives(BuildCorazaDirectives(pOn, nil, "", false, 0, "lb_test"))
	if !strings.Contains(dOn, "Include /app/waf/crs/rules/RESPONSE-980-CORRELATION.conf") {
		t.Fatalf("response rule parent file must be included when response check on, got:\n%s", dOn)
	}
}

// 引擎级门禁：真实 CRS 夹具树编译渲染产物（Include 不再被过滤）——
// 覆盖重复组号 Include（duplicated rule id 编译拒绝）与 949110/959100
// 抬码对象存在性（SecRuleUpdateActionById 对缺失规则编译报错）。
func TestEngineGate_crsFixtureTreeCompiles(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"crs-setup.conf":                                 "# fixture\n",
		"rules/REQUEST-901-INITIALIZATION.conf":          "SecAction \"id:901001,phase:1,pass,nolog\"\n",
		"rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "SecRule ARGS \"@rx (?i)union.*select\" \"id:942100,phase:2,deny,status:403,log\"\n",
		"rules/REQUEST-949-BLOCKING-EVALUATION.conf":     "SecAction \"id:949110,phase:2,pass,log\"\n",
		"rules/RESPONSE-959-BLOCKING-EVALUATION.conf":    "SecAction \"id:959100,phase:4,pass,log\"\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := crsDirectivesDir
	crsDirectivesDir = root
	t.Cleanup(func() { crsDirectivesDir = old })

	// 重复组号 + 抬码（483 合成码）+ 响应检查开：夹具树全链编译。
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", WAFCheckResponse: true, CRSRuleGroups: json.RawMessage(`["42","42"]`)}
	d := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 483, "lb_test"))
	rewritten := strings.ReplaceAll(d, "/app/waf/crs", root)
	var kept []string
	for _, line := range strings.Split(rewritten, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "SecAuditLogType ") {
			continue
		}
		kept = append(kept, line)
	}
	if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n"))); err != nil {
		t.Fatalf("coraza 引擎拒绝夹具树渲染产物: %v\n--- directives ---\n%s", err, strings.Join(kept, "\n"))
	}
}

// body 目标自定义规则的引擎编译钉（phase:2 + REQUEST_BODY 形状此前只有
// 字符串断言）。
func TestEngineGate_bodyTargetCustomRuleCompiles(t *testing.T) {
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", CustomRules: json.RawMessage(
		`[{"id":3456,"name":"bodyrule","enabled":true,"action":"block","conditions":[{"target":"body","operator":"contains","pattern":"evil"}]}]`)}
	compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test")))
}

// CRS 规则索引缓存键必须含目录路径：同统计量（版本/文件数/最大 mtime/
// 总大小）的不同目录不得命中同一缓存（测试与多目录场景的正确性前提）。
func TestCRSRuleIndexCacheKey_includesDirectory(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	content := []byte("SecAction \"id:942100,phase:2,pass,nolog\"\n")
	for _, dir := range []string{dirA, dirB} {
		path := filepath.Join(dir, "REQUEST-942-X.conf")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, time.Unix(1700000000, 0), time.Unix(1700000000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	old := CRSRuleIndexDir
	defer func() { CRSRuleIndexDir = old }()
	CRSRuleIndexDir = dirA
	keyA := crsRuleIndexCacheKey("v1")
	CRSRuleIndexDir = dirB
	keyB := crsRuleIndexCacheKey("v1")
	if keyA == keyB {
		t.Fatalf("cache key must include directory: both = %q", keyA)
	}
}

// writeIPListFile memo：重复渲染同内容不重复落盘（mtime 不变）；投影文件被
// 外部删除后下一次渲染必须重建（memo 不得造成幽灵引用）。
func TestWriteIPListFile_memoSkipsRewriteButRecoversDelete(t *testing.T) {
	dir := t.TempDir()
	old := IPListDataDir
	IPListDataDir = dir
	t.Cleanup(func() { IPListDataDir = old })

	path1, err := writeIPListFile("memo-scope", []string{"10.0.0.2", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	st1, err := os.Stat(path1)
	if err != nil {
		t.Fatal(err)
	}
	path2, err := writeIPListFile("memo-scope", []string{"10.0.0.1", "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := os.Stat(path2)
	if err != nil {
		t.Fatal(err)
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("同内容重复渲染不得重写投影文件（mtime 必须保持）")
	}
	if err := os.Remove(path1); err != nil {
		t.Fatal(err)
	}
	if _, err := writeIPListFile("memo-scope", []string{"10.0.0.1", "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path1)
	if err != nil {
		t.Fatalf("投影文件被删后必须重建: %v", err)
	}
	if string(data) != "10.0.0.1/32\n10.0.0.2/32\n" {
		t.Fatalf("重建内容 = %q", data)
	}
}
