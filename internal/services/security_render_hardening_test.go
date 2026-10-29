package services

// 安全渲染面硬化（本轮修复）的钉测试：
//   - CRS 树交换窗口内生成必须失败（不得发布无安全链/弱规则集配置）；
//   - crs-setup.conf 缺失不得产生致命 Include；
//   - 单规则路径与生产路径同口径过滤 IPRefMissing 策略；
//   - crs_rule_groups 渲染侧条数上限；
//   - 自定义规则摘要计数复用发射判据；
//   - 库目录注入同步派生规则索引目录、生成级索引令牌与 allow 交集缓存单次求值。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestLoadSecurityPolicyContext_rejectsGenerationDuringCRSTreeSwap(t *testing.T) {
	_, database := newClusterTestService(t)

	// Given 树交换窗口被标记
	leaveWindow := enterCRSTreeSwapWindow()
	t.Cleanup(func() { crsTreeSwapDepth.Store(0) })

	// When 生成期装载安全策略上下文
	_, err := loadSecurityPolicyContext(database)

	// Then 必须显式失败（fail-visible），而不是带着「缺库降级/半棵树」照常生成
	if !errors.Is(err, errCRSTreeSwapInFlight) {
		t.Fatalf("err=%v, want errCRSTreeSwapInFlight（树交换窗口内不得生成配置）", err)
	}

	// And 窗口结束后恢复可用
	leaveWindow()
	if _, err := loadSecurityPolicyContext(database); err != nil {
		t.Fatalf("窗口结束后 loadSecurityPolicyContext 必须恢复: %v", err)
	}
}

// 树交换窗口的嵌套语义：内层退出不得清除外层仍在进行的标记——swap 段内的
// 恢复路径与 seed 内的 replaceDirFrom 都是嵌套进入，内层提前清除会让外层
// 窗口剩余时间里的并发生成读到缺失/部分规则树。
func TestCRSTreeSwapWindow_nestsUntilOutermostExit(t *testing.T) {
	if crsTreeSwapInFlightNow() {
		t.Fatal("前置形态：窗口应关闭（其他用例泄漏了标记）")
	}
	leaveOuter := enterCRSTreeSwapWindow()
	if !crsTreeSwapInFlightNow() {
		t.Fatal("进入窗口后必须报告进行中")
	}
	leaveInner := enterCRSTreeSwapWindow()
	leaveInner()
	if !crsTreeSwapInFlightNow() {
		t.Fatal("内层窗口退出后外层标记必须保持")
	}
	leaveOuter()
	if crsTreeSwapInFlightNow() {
		t.Fatalf("最外层退出后窗口必须关闭，depth=%d", crsTreeSwapDepth.Load())
	}
}

// 生产者侧：树搬移必须在窗口内执行，且退出后不得残留标记（残留会让之后每次
// 配置生成都失败）。搬移经 moveTree 的 osRename 缝观察窗口状态。
func TestRestoreRulesBackup_runsInsideTreeSwapWindow(t *testing.T) {
	root := t.TempDir()
	rulesPath := filepath.Join(root, "crs", "rules")
	bak := crsTransientPath(filepath.Join(root, "crs"), "rules.bak")
	writeTestFile(t, filepath.Join(bak, crsRulesProbeFile), "SecRule bak")
	writeTestFile(t, filepath.Join(rulesPath, "REQUEST-900.conf"), "SecRule live")

	oldRename := osRename
	moves := 0
	osRename = func(src, dst string) error {
		if !crsTreeSwapInFlightNow() {
			t.Errorf("规则树搬移 %s→%s 未处于树交换窗口内（并发生成会读到缺失/部分树）", src, dst)
		}
		moves++
		return os.Rename(src, dst)
	}
	t.Cleanup(func() { osRename = oldRename })

	if !restoreRulesBackup(rulesPath, bak) {
		t.Fatal("完整备份应被还原")
	}
	if moves == 0 {
		t.Fatal("未观察到任何树搬移（用例形态失效）")
	}
	if crsTreeSwapInFlightNow() {
		t.Fatalf("restoreRulesBackup 退出后不得残留窗口标记，depth=%d", crsTreeSwapDepth.Load())
	}
}

// 同族：从节点 waf 包落盘（untarGzTo）替换 live 规则树时也必须在树交换窗口
// 内——RemoveAll(destDir) 与 copyDir 之间 live 缺失/只有部分树，并发生成会
// 发布无安全链或弱化配置。
func TestUntarGzTo_replacesLiveTreeInsideSwapWindow(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "crs")
	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-901.conf", body: []byte("SecRule new")},
	})

	oldRename := osRename
	sawWindow := false
	osRename = func(src, dst string) error {
		if !crsTreeSwapInFlightNow() {
			t.Errorf("规则树 rename %s→%s 未处于树交换窗口内", src, dst)
		}
		sawWindow = true
		return os.Rename(src, dst)
	}
	t.Cleanup(func() { osRename = oldRename })

	if err := untarGzTo(payload, destDir, ""); err != nil {
		t.Fatalf("untar: %v", err)
	}
	if !sawWindow {
		t.Fatal("未观察到 rename 路径（用例形态失效）")
	}
	if crsTreeSwapInFlightNow() {
		t.Fatalf("untarGzTo 退出后不得残留窗口标记，depth=%d", crsTreeSwapDepth.Load())
	}
}

// crs-setup.conf 被带外删除时不得发射精确路径 Include（coraza 对缺失的精确
// 路径是致命错误：整份配置加载失败）。901 初始化仍提供偏执级默认。
func TestBuildCorazaDirectives_skipsMissingCRSSetupInclude(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"REQUEST-901-INITIALIZATION.conf",
		"REQUEST-949-BLOCKING-EVALUATION.conf",
		"RESPONSE-959-BLOCKING-EVALUATION.conf",
	} {
		if err := os.WriteFile(filepath.Join(rules, name), []byte("# fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restore := SetSecurityLibsDirsForTest(dir, filepath.Join(dir, "ip2region.xdb"))
	t.Cleanup(restore)
	resetCRSRuleIndexCacheForHardeningTest(t)

	policy := &models.SecurityPolicy{
		ID: 1, Name: "no-setup", Mode: "blocking", AnomalyThreshold: 5,
		CRSRuleGroups: json.RawMessage(`["42"]`),
	}
	directives, err := BuildCorazaDirectives(policy, nil, "", false, 0, "lb_no_setup")
	if err != nil {
		t.Fatalf("build directives: %v", err)
	}
	if strings.Contains(directives, "crs-setup.conf") {
		t.Fatalf("crs-setup.conf 缺失时不得发射致命 Include:\n%s", directives)
	}
	if !strings.Contains(directives, "REQUEST-901-INITIALIZATION.conf") {
		t.Fatalf("901 初始化必须照常发射:\n%s", directives)
	}

	// 存在时恢复发射（零行为漂移）
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte("# setup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	directives, err = BuildCorazaDirectives(policy, nil, "", false, 0, "lb_no_setup")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(directives, "Include /app/waf/crs/crs-setup.conf") {
		t.Fatalf("crs-setup.conf 存在时必须发射 Include:\n%s", directives)
	}
}

// 单规则路径（规则保存前置校验）必须与生产批量路径同口径跳过 IPRefMissing
// 策略：引用的名单装载失败（畸形 entries）= 生产不渲染，校验也不得虚拟已生效。
func TestGetSecurityPoliciesForRule_filtersIPRefMissing(t *testing.T) {
	_, database := newClusterTestService(t)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES ('broken', '{not-json')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, _ := res.LastInsertId()
	policyRes, err := database.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, ip_whitelist_enabled, ip_whitelist_refs) VALUES ('ref-broken','blocking',1,'stage1',1,?)`, "["+strconv.FormatInt(listID, 10)+"]")
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := policyRes.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_refbroken', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	if got := GetSecurityPoliciesForRule("lb_refbroken"); len(got) != 0 {
		t.Fatalf("policies=%d, want 0（装载失败的策略在生产路径被跳过，单规则路径必须同口径）", len(got))
	}
}

// crs_rule_groups 渲染侧条数上限（写入侧 200）：带外 1 万条组号不得放大成
// 1 万条 Include。夹具必须使用**互异**条目——旧夹具用 250 条全为 "42" 的
// 组号，渲染先截断再去重，去重后恒为 1 行，删掉上限门测试依然绿（断言不可
// 失败）。这里用 80 个互异两位组号 + 130 个互异 6 位规则 ID（各自独占一个
// 父文件、组 90 未选中）共 210 条 > 上限，按是否渲染出第 121 个 ID 的文件
// 与 Include 行数判定截断门。
func TestEmitCRSRuleGroupSelection_capsEntries(t *testing.T) {
	dir := t.TempDir()
	// 130 个互异 6 位 ID，各独占父文件 REQUEST-90-Gnnn.conf（组 90 不在选择内）。
	for i := 1; i <= 130; i++ {
		file := filepath.Join(dir, fmt.Sprintf("REQUEST-90-G%03d.conf", i))
		body := fmt.Sprintf("SecRule ARGS \"@rx x\" \"id:90%04d,phase:2,pass\"\n", i)
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldDir := CRSRuleIndexDir
	CRSRuleIndexDir = dir
	t.Cleanup(func() { CRSRuleIndexDir = oldDir })

	var sb strings.Builder
	groups := make([]string, 0, CRSRuleGroupsMaxEntries+10)
	for i := 1; i <= 80; i++ {
		groups = append(groups, fmt.Sprintf("%02d", i))
	}
	for i := 1; i <= 130; i++ {
		groups = append(groups, fmt.Sprintf("90%04d", i))
	}
	if len(groups) <= CRSRuleGroupsMaxEntries {
		t.Fatalf("夹具无效：条目数 %d 未超过上限 %d", len(groups), CRSRuleGroupsMaxEntries)
	}
	policy := &models.SecurityPolicy{ID: 2, Name: "cap"}
	if err := emitCRSRuleGroupSelection(&sb, policy, groups, lazyCRSRuleIndex()); err != nil {
		t.Fatalf("emitCRSRuleGroupSelection: %v", err)
	}

	out := sb.String()
	includes := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Include ") {
			includes++
		}
	}
	if includes > CRSRuleGroupsMaxEntries {
		t.Fatalf("Include 行数=%d, 上限 %d（渲染侧必须按条目截断）", includes, CRSRuleGroupsMaxEntries)
	}
	// 窗口内（第 1..120 个 ID）父文件必须在场；超窗（121..130）必须缺席。
	for _, i := range []int{1, 120} {
		want := fmt.Sprintf("REQUEST-90-G%03d.conf", i)
		if !strings.Contains(out, want) {
			t.Fatalf("窗口内父文件 %s 缺席（截断过早）:\n%s", want, out)
		}
	}
	for _, i := range []int{121, 122, 123} {
		unwanted := fmt.Sprintf("REQUEST-90-G%03d.conf", i)
		if strings.Contains(out, unwanted) {
			t.Fatalf("超窗父文件 %s 不应被渲染（上限门失效）", unwanted)
		}
	}
}

// 摘要计数必须复用发射判据：存在但会被发射侧跳过的规则（非法分值/撞保留段/
// 禁用）不计数，否则 UI 宣称 N 条自定义防护而引擎零发射。
func TestCountEnabledCustomRulesBatch_countsOnlyEmittable(t *testing.T) {
	_, database := newClusterTestService(t)
	insert := func(name, conditionsJSON string, action string, score, enabled, id int) int {
		t.Helper()
		var res interface{ LastInsertId() (int64, error) }
		var err error
		if id > 0 {
			res, err = database.Exec(`INSERT INTO security_custom_rules (id, name, conditions, action, score, enabled) VALUES (?,?,?,?,?,?)`, id, name, conditionsJSON, action, score, enabled)
		} else {
			res, err = database.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES (?,?,?,?,?)`, name, conditionsJSON, action, score, enabled)
		}
		if err != nil {
			t.Fatal(err)
		}
		v, _ := res.LastInsertId()
		return int(v)
	}
	valid := insert("ok", `[{"target":"uri","operator":"regex","pattern":"^/x$"}]`, "block", 5, 1, 0)
	badScore := insert("bad-score", `[{"target":"uri","operator":"regex","pattern":"^/y$"}]`, "block", 7, 1, 0)
	reserved := insert("reserved-id", `[{"target":"uri","operator":"regex","pattern":"^/z$"}]`, "block", 5, 1, 790000)
	disabled := insert("disabled", `[{"target":"uri","operator":"regex","pattern":"^/w$"}]`, "block", 5, 0, 0)

	raw, _ := json.Marshal([]int{valid, badScore, reserved, disabled})
	policy := &models.SecurityPolicy{ID: 1, CustomRules: raw}
	counts := CountEnabledCustomRulesBatch([]*models.SecurityPolicy{policy})
	if counts[0] != 1 {
		t.Fatalf("count=%d, want 1（仅可发射规则计数；非法分值/保留段/禁用均不计）", counts[0])
	}
	if got := CountEnabledCustomRules(raw); got != 1 {
		t.Fatalf("单策略 count=%d, want 1（与批量路径同判据）", got)
	}
}

// 摘要批量计数必须把 condition_logic 读进发射判据：带外改库/旧版本遗留的
// 非法 condition_logic（写侧/导入门 400，仅带外可达）会让发射侧整条跳过，
// 批量 SQL 漏选该列时判据恒空串 → 计数虚报（UI 宣称 N 条、引擎零发射）。
func TestCountEnabledCustomRulesBatch_skipsInvalidConditionLogic(t *testing.T) {
	_, database := newClusterTestService(t)
	insertWithLogic := func(name, logic string) int {
		t.Helper()
		res, err := database.Exec(`INSERT INTO security_custom_rules (name, conditions, condition_logic, action, score, enabled)
			VALUES (?, '[{"target":"uri","operator":"regex","pattern":"^/x$"}]', ?, 'block', 5, 1)`, name, logic)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return int(id)
	}
	xorID := insertWithLogic("xor-rule", "xor")
	andID := insertWithLogic("and-rule", "and")

	raw, _ := json.Marshal([]int{xorID})
	counts := CountEnabledCustomRulesBatch([]*models.SecurityPolicy{{
		ID: 900001, CustomRules: json.RawMessage(raw),
	}})
	if counts[0] != 0 {
		t.Fatalf("count=%d, want 0（condition_logic=xor 发射侧整条跳过，摘要不得虚报）", counts[0])
	}
	// 合法值（and/or/''）形态不受影响
	raw2, _ := json.Marshal([]int{andID})
	counts = CountEnabledCustomRulesBatch([]*models.SecurityPolicy{{
		ID: 900002, CustomRules: json.RawMessage(raw2),
	}})
	if counts[0] != 1 {
		t.Fatalf("count=%d, want 1（合法 condition_logic 照常计数）", counts[0])
	}
}

// 库目录注入必须同步派生规则索引目录（否则跨包测试的索引指向生产路径→空索引）。
func TestSetSecurityLibsDirsForTest_forwardsRuleIndexDir(t *testing.T) {
	dir := t.TempDir()
	restore := SetSecurityLibsDirsForTest(dir, filepath.Join(dir, "x.xdb"))
	if CRSRuleIndexDir != filepath.Join(dir, "rules") {
		restore()
		t.Fatalf("CRSRuleIndexDir=%q, want %q", CRSRuleIndexDir, filepath.Join(dir, "rules"))
	}
	restore()
	if CRSRuleIndexDir == filepath.Join(dir, "rules") {
		t.Fatalf("restore 未还原 CRSRuleIndexDir")
	}
}

// 生成上下文级索引令牌：一轮生成只求值一次指纹键（逐策略自建惰性链会按
// 规则数放大 ReadDir+全量 stat）。
func TestSecurityPolicyContext_crsRuleIndexEvaluatedOnce(t *testing.T) {
	seedCRSRuleIndexFixture(t)
	_, database := newClusterTestService(t)
	ctx, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatal(err)
	}
	resetCRSRuleIndexCacheForHardeningTest(t)
	before := crsRuleIndexKeyEvals.Load()
	for range 3 {
		_ = ctx.crsRuleIndex()()
	}
	if got := crsRuleIndexKeyEvals.Load() - before; got != 1 {
		t.Fatalf("索引指纹键求值 %d 次, want 1（生成级令牌共享）", got)
	}
}

// allow 交集在生成上下文内按策略集签名复用：同策略集的多条规则只算一次。
func TestSecurityPolicyContext_allowIntersectionCached(t *testing.T) {
	ctx := &securityPolicyContext{allowIntersection: map[string][]string{}}
	calls := 0
	compute := func() []string { calls++; return []string{"10.0.0.0/8"} }
	for range 3 {
		if got := ctx.allowIntersectionCached("7,8", compute); len(got) != 1 {
			t.Fatalf("intersection=%v", got)
		}
	}
	if calls != 1 {
		t.Fatalf("compute calls=%d, want 1（同签名复用）", calls)
	}
	// 签名不同必须重算（不同策略集交集不同）
	ctx.allowIntersectionCached("9", compute)
	if calls != 2 {
		t.Fatalf("compute calls=%d, want 2（签名变化重算）", calls)
	}
	// 空签名（无 allow 策略）不走缓存
	ctx.allowIntersectionCached("", compute)
	if calls != 3 {
		t.Fatalf("compute calls=%d, want 3（空签名直算）", calls)
	}
}

func resetCRSRuleIndexCacheForHardeningTest(t *testing.T) {
	t.Helper()
	crsRuleIndexMu.Lock()
	crsRuleIndexCache, crsRuleIndexKey = nil, ""
	crsRuleIndexMu.Unlock()
}

// crs_excluded_rules 渲染侧条目上限（与 crs_rule_groups 同构的防御深度）：
// 带外/旧快照可绕过写入面 50 条上限，逐条发射会放大配置体积与生成耗时。
// 夹具 60 条互异作用域条目（各 1 个可展开 ID）→ 渲染侧只发射前 50 条。
func TestBuildCorazaDirectives_capsExcludedEntries(t *testing.T) {
	scopedExclusionFixture(t)
	entries := make([]string, 0, CRSExcludedRulesMaxEntries+10)
	for i := 1; i <= CRSExcludedRulesMaxEntries+10; i++ {
		entries = append(entries, fmt.Sprintf(`{"target":"942100","scope":"ip","ips":"10.0.%d.%d"}`, i/250, i%250))
	}
	if len(entries) <= CRSExcludedRulesMaxEntries {
		t.Fatalf("夹具无效：条目数 %d 未超过上限 %d", len(entries), CRSExcludedRulesMaxEntries)
	}
	policy := &models.SecurityPolicy{
		ID: 31, Name: "cap-excluded", AnomalyThreshold: 5, Mode: "blocking",
		CRSExcludedRules: json.RawMessage("[" + strings.Join(entries, ",") + "]"),
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_cap_excluded"))

	ctlLines := 0
	for _, line := range strings.Split(directives, "\n") {
		if strings.Contains(line, "ctl:ruleRemoveById=942100") {
			ctlLines++
		}
	}
	if ctlLines == 0 || ctlLines > CRSExcludedRulesMaxEntries {
		t.Fatalf("作用域排除行数=%d, want 1..%d（渲染侧必须按条目截断）", ctlLines, CRSExcludedRulesMaxEntries)
	}
	compileForEngineGate(t, directives)
}

// 条目上限挡不住组号展开：单条组号 target 会展开为该组全部规则 ID。行预算
// 按展开后的真实行数截断——带外写入不得把生成期行数放大到百万级（生成全程
// 持 CaddyOpLock）。夹具预算缩到 1，组 42 在夹具索引中展开 2 条 → 只发射 1 行。
func TestBuildCorazaDirectives_capsScopedExclusionDirectiveRows(t *testing.T) {
	scopedExclusionFixture(t)
	oldBudget := crsScopedExclusionMaxDirectives
	crsScopedExclusionMaxDirectives = 1
	t.Cleanup(func() { crsScopedExclusionMaxDirectives = oldBudget })

	policy := &models.SecurityPolicy{
		ID: 32, Name: "budget", AnomalyThreshold: 5, Mode: "blocking",
		CRSExcludedRules: json.RawMessage(`[{"target":"42","scope":"ip","ips":"10.1.1.1"}]`),
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_budget"))

	ctlLines := 0
	for _, line := range strings.Split(directives, "\n") {
		if strings.Contains(line, "ctl:ruleRemoveById=") {
			ctlLines++
		}
	}
	if ctlLines != 1 {
		t.Fatalf("组展开行数=%d, want 1（行预算必须截断展开后的实际行数）:\n%s", ctlLines, directives)
	}
	compileForEngineGate(t, directives)
}
