package handlers

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"strconv"

	"lazy-balancer-v2/internal/db"
)

// warmer 已接管时，宽窗口（7d）请求仍须按持久 coverage 补做 24h
// 之外的旧侧分钟——旧实现 warmer 恒固化 24h 且请求路径完全跳过固化，7d
// 窗口的旧侧原始事件永久不进 rollup。
func TestThreatRollup_wideWindowBackfillsUnderWarmer(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	// 30h 前的事件：在 24h 常态窗口之外、7d 窗口之内。
	seedThreatScreenEvent(t, utcStringAgo(30*time.Hour), "93.184.216.7", "942100", "SQL Injection", "blocked")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		threatRollupWarmerWg.Wait()
	})
	StartThreatRollupWarmer(ctx)

	// 回填按有界批推进（单次最多 24h 旧侧）：轮询请求直至旧侧补齐——这正是
	// 「按持久 coverage 续做」的契约（旧实现永不补齐，任何轮次都是 0）。
	var payload threatScreenR79Payload
	for attempt := 0; attempt < 3; attempt++ {
		payload = getThreatScreenR79(t, router, "/security/overview/threat-screen?hours=168")
		if payload.Data.Hours != 168 {
			t.Fatalf("hours=%d, want 168", payload.Data.Hours)
		}
		if payload.Data.TotalEvents >= 1 {
			return
		}
	}
	t.Fatalf("total_events=%d, want >=1（7d 请求须补做 24h 之外的旧侧分钟）", payload.Data.TotalEvents)
}

// warmer 首轮未完成（此处以已取消 ctx 模拟）时不得把「已启动」当作
// 「已有覆盖」——请求路径须沿用懒固化，且响应披露 rollup 就绪/最近成功时间。
func TestThreatRollup_unreadyWarmerFallsBackToLazyFixation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "93.184.216.7", "942100", "SQL Injection", "blocked")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // warmer 立即退出：从未完成首轮
	StartThreatRollupWarmer(ctx)
	threatRollupWarmerWg.Wait()

	payload := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if payload.Data.TotalEvents != 1 {
		t.Fatalf("total_events=%d, want 1（首轮未完成时请求路径须懒固化）", payload.Data.TotalEvents)
	}
	// 最近成功固化时刻由 rollup_last_success 非空断言（下方）承担。
	if payload.Data.RollupLastOK == "" {
		t.Fatalf("rollup_last_success 为空：须披露最近成功固化时间")
	}
	if payload.Data.RollupStale {
		t.Fatalf("rollup_stale=true, want false（刚完成固化）")
	}
}

// 就绪状态陈旧（warmer 持续失败/停摆）时请求路径必须同步固化，
// 不得把旧值伪装成最新 200。
func TestThreatRollup_staleReadinessTriggersRequestFixation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "93.184.216.7", "942100", "SQL Injection", "blocked")

	if p := getThreatScreenR79(t, router, "/security/overview/threat-screen"); p.Data.TotalEvents != 1 {
		t.Fatalf("first total_events=%d, want 1", p.Data.TotalEvents)
	}
	// 模拟「上次成功固化已 10 分钟前」（warmer 停摆），并落一条最新分钟事件。
	threatRollupReadyAt.Store(time.Now().Add(-10 * time.Minute).UnixNano())
	seedThreatScreenEvent(t, utcStringAgo(5*time.Second), "93.184.216.8", "942100", "SQL Injection", "blocked")

	p := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if p.Data.TotalEvents != 2 {
		t.Fatalf("total_events=%d, want 2（就绪陈旧时请求路径须同步固化）", p.Data.TotalEvents)
	}
	if p.Data.RollupStale {
		t.Fatal("rollup_stale=true, want false（本次请求刚完成固化）")
	}
}

// 归属地库代际变化时按空覆盖重固窗口（库恢复后历史空归属地自愈）。
func TestThreatRollup_geoipGenerationChangeRefixesWindow(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(10*time.Minute), "93.184.216.7", "942100", "SQL Injection", "blocked")
	if p := getThreatScreenR79(t, router, "/security/overview/threat-screen"); p.Data.TotalEvents != 1 {
		t.Fatalf("first total_events=%d, want 1", p.Data.TotalEvents)
	}
	// 覆盖区间已固化后新增旧分钟事件（常规轮次不会重固它）。
	seedThreatScreenEvent(t, utcStringAgo(11*time.Minute), "93.184.216.8", "942100", "SQL Injection", "blocked")
	if _, err := db.MetricsDB.Exec(`UPDATE metrics_state SET value='999999' WHERE key=?`, threatRollupGeoIPGenerationKey); err != nil {
		t.Fatal(err)
	}
	p := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if p.Data.TotalEvents != 2 {
		t.Fatalf("total_events=%d, want 2（代际变化后窗口重固，旧分钟新事件纳入）", p.Data.TotalEvents)
	}
}

func TestThreatRollup_geoGenerationPreservesTrimmedMinutes(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, base)
	seedThreatScreenEvent(t, "2026-10-18 11:50:10", "93.184.216.7", "942100", "SQL Injection", "blocked")
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("first rollup: %v", err)
	}
	if got := threatRollupCountForMinute(t, "2026-10-18 11:50"); got != 1 {
		t.Fatalf("initial rollup count=%d, want 1", got)
	}
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatal(err)
	}
	// 未固化旧分钟：11:40 在首次固化的覆盖区间内（按空分钟推进过去），
	// 之后才到的原始事件常规轮次不会重扫。代际变化必须把窗口按空覆盖重固，
	// 从而把它纳入——没有这条，只有「11:50 保留」无法区分「真的重固了」与
	// 「根本没重固、旧行原样躺着」。
	seedThreatScreenEvent(t, "2026-10-18 11:40:10", "93.184.216.9", "942100", "SQL Injection", "blocked")
	if _, err := db.MetricsDB.Exec(`UPDATE metrics_state SET value='999999' WHERE key=?`, threatRollupGeoIPGenerationKey); err != nil {
		t.Fatal(err)
	}
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("refix rollup: %v", err)
	}
	if got := threatRollupCountForMinute(t, "2026-10-18 11:50"); got != 1 {
		t.Fatalf("trimmed minute count=%d after refix, want preserved 1", got)
	}
	if got := threatRollupCountForMinute(t, "2026-10-18 11:40"); got != 1 {
		t.Fatalf("late unfixed minute count=%d after geo generation refix, want 1（窗口必须按空覆盖重固）", got)
	}
}

func TestThreatRollup_trailingRepairBackfillsLateMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	base := time.Date(2026, 10, 18, 12, 5, 30, 0, time.UTC)
	installThreatClock(t, base)
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("first rollup: %v", err)
	}
	seedThreatScreenEvent(t, "2026-10-18 12:02:10", "93.184.216.7", "942100", "SQL Injection", "blocked")
	threatScreenNow = func() time.Time { return base.Add(time.Minute) }
	t.Cleanup(func() { threatScreenNow = func() time.Time { return base } })
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("repair rollup: %v", err)
	}
	if got := threatRollupCountForMinute(t, "2026-10-18 12:02"); got != 1 {
		t.Fatalf("late minute count=%d, want trailing repair 1", got)
	}
}

// top_targets 必须来自分钟 rollup——原始事件被保留策略裁掉后，
// 与 total/国家等卡片仍同窗口。
func TestThreatTopTargets_servedFromRollupAfterRawDeletion(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatLBRule(t, "lb_aaa", "API 服务", "api.example.com")
	// 10-12 分钟前：不在「恒重固」的上一分钟/当前分钟，rollup 固化后不会被后
	// 续重固覆盖。
	for i := 10; i <= 12; i++ {
		seedThreatRuleEvent(t, utcStringAgo(time.Duration(i)*time.Minute), "93.184.216.7", "lb_aaa", "blocked")
	}

	first := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if len(first.Data.TopTargets) != 1 || first.Data.TopTargets[0].Value != 3 {
		t.Fatalf("top_targets=%+v, want 1 项 value=3", first.Data.TopTargets)
	}

	// 原始事件被保留策略（行帽/保留期）裁掉。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatal(err)
	}
	resetThreatScreenCachesForTest()

	second := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if len(second.Data.TopTargets) != 1 || second.Data.TopTargets[0].Value != 3 {
		t.Fatalf("top_targets=%+v, want 1 项 value=3（rollup 已固化，原始行删除不影响窗口口径）", second.Data.TopTargets)
	}
}

// top_targets 必须与其他维度同口径排除保留/私网地址。
func TestThreatTopTargets_excludesReservedSourceIPs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatLBRule(t, "lb_aaa", "API 服务", "api.example.com")
	seedThreatRuleEvent(t, utcStringAgo(10*time.Minute), "192.168.1.5", "lb_aaa", "blocked")
	seedThreatRuleEvent(t, utcStringAgo(11*time.Minute), "::1", "lb_aaa", "blocked")
	seedThreatRuleEvent(t, utcStringAgo(12*time.Minute), "203.0.113.20", "lb_aaa", "blocked") // RFC 5737 段同保留地址排除

	payload := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if len(payload.Data.TopTargets) != 0 {
		t.Fatalf("top_targets=%+v, want 空（保留/私网地址不得进入被攻击目标）", payload.Data.TopTargets)
	}
}

// 已删除规则不得挤掉现存真实目标——须先排除幽灵规则再取前 3。
func TestThreatTopTargets_ghostRulesDoNotCrowdOutExisting(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatLBRule(t, "lb_ok", "现存站点", "ok.example.com")
	// 5 条已删除规则（无 lb_rules 行）计数均高于现存规则。
	for i := range 5 {
		id := "lb_gone_" + string(rune('a'+i))
		for n := range 10 - i {
			seedThreatRuleEvent(t, utcStringAgo(time.Duration(10+n)*time.Minute), "93.184.216.7", id, "blocked")
		}
	}
	seedThreatRuleEvent(t, utcStringAgo(10*time.Minute), "93.184.216.8", "lb_ok", "blocked")

	payload := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if len(payload.Data.TopTargets) != 1 {
		t.Fatalf("top_targets=%+v, want 1 项（现存规则 lb_ok）", payload.Data.TopTargets)
	}
	if payload.Data.TopTargets[0].Name != "现存站点" {
		t.Fatalf("top_targets[0]=%+v, want 现存站点", payload.Data.TopTargets[0])
	}
}

// 限流族是 429 精确 ID——旧实现按 3 字符前缀 + 三个下划线拼成
// LIKE '429___'，永不命中。
func TestRuleTriggeredFilterSQL_rateLimitFamilyExact(t *testing.T) {
	var args []any
	cond := ruleTriggeredFilterSQL("限流", &args)
	if len(args) != 1 || args[0] != "429" {
		t.Fatalf("args=%v, want [429]（限流族=429 精确匹配）", args)
	}
	if cond != "(rule_triggered = ?)" {
		t.Fatalf("cond=%q, want 精确匹配条件", cond)
	}
	// 回归形状：CRS 3 字符前缀族仍锚定 6 位。
	args = nil
	cond = ruleTriggeredFilterSQL("协议异常", &args)
	if len(args) != 1 || args[0] != "920___" {
		t.Fatalf("args=%v, want [920___]（CRS 族仍须长度锚定）", args)
	}
	if cond == "" {
		t.Fatal("协议异常族条件为空")
	}
}

// 显式类型归一清空 refs 后，存在性校验必须使用归一后的 ID 集。
func TestUpdateSecurityPolicy_typeSwitchSkipsStaleRefValidation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	// 被引用的列表行先存在（创建策略时校验通过），随后被删除（禁用期合法）。
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries, created_at, updated_at) VALUES ('临时名单','测试','[]',datetime('now'),datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	listID, _ := res.LastInsertId()

	id := createTestPolicy(t, router, map[string]any{
		"name":             "阶段一转阶段三",
		"policy_type":      "stage1",
		"enabled":          false,
		"ip_acl_enabled":   true,
		"ip_acl_mode":      "deny",
		"ip_acl_list_refs": fmt.Sprintf("[%d]", listID),
	})
	if _, err := db.DB.Exec(`DELETE FROM security_ip_lists WHERE id=?`, listID); err != nil {
		t.Fatal(err)
	}

	// 显式切到 stage3：该类型会清空 ACL/GeoIP 字段，旧 refs 本应失效。
	recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), map[string]any{
		"policy_type":      "stage3",
		"ip_acl_list_refs": fmt.Sprintf("[%d]", listID),
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（归一后 refs 已清空，不应校验旧 ID）", recorder.Code, recorder.Body.String())
	}
	var refs string
	if err := db.DB.QueryRow(`SELECT COALESCE(ip_acl_list_refs,'[]') FROM security_policies WHERE id=?`, id).Scan(&refs); err != nil {
		t.Fatal(err)
	}
	if refs != "[]" {
		t.Fatalf("ip_acl_list_refs=%q, want []", refs)
	}
}

// 爬虫豁免未进入阶段外字段归一——类型往返后不得静默复活。
func TestUpdateSecurityPolicy_crawlerExemptClearedOnStageSwitch(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	// 直接落库（Create 侧地域启用需要已安装 xdb；本测试只钉 Update 归一）。
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, policy_type, geoip_mode, geoip_countries, geoip_crawler_exempt, geoip_crawler_engines, enabled)
		VALUES ('爬虫豁免阶段一', 'stage1', 'deny', '["CN"]', 1, '["googlebot"]', 1)`)
	if err != nil {
		t.Fatal(err)
	}
	id64, _ := res.LastInsertId()
	id := int(id64)

	var exempt int
	if err := db.DB.QueryRow(`SELECT COALESCE(geoip_crawler_exempt,0) FROM security_policies WHERE id=?`, id).Scan(&exempt); err != nil {
		t.Fatal(err)
	}
	if exempt != 1 {
		t.Fatalf("前置态 geoip_crawler_exempt=%d, want 1", exempt)
	}

	recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), map[string]any{"policy_type": "stage3"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(geoip_crawler_exempt,0) FROM security_policies WHERE id=?`, id).Scan(&exempt); err != nil {
		t.Fatal(err)
	}
	if exempt != 0 {
		t.Fatalf("geoip_crawler_exempt=%d, want 0（阶段外字段须随类型归一清空）", exempt)
	}
}

// 自动更新开关必须是指针语义——缺字段/null 不得静默关闭更新。
func TestAutoUpdateSwitches_requireExplicitValue(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.PUT("/security/crs/auto-update", h.UpdateCRSAutoUpdate)
	router.PUT("/security/ip2region/auto-update", h.UpdateIP2RegionAutoUpdate)

	for _, path := range []string{"/security/crs/auto-update", "/security/ip2region/auto-update"} {
		if recorder := putJSON(t, router, path, map[string]any{}); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s 缺字段 status=%d body=%s, want 400", path, recorder.Code, recorder.Body.String())
		}
		if recorder := putJSON(t, router, path, map[string]any{"auto_update": nil}); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s null status=%d body=%s, want 400", path, recorder.Code, recorder.Body.String())
		}
		if recorder := putJSON(t, router, path, map[string]any{"auto_update": false}); recorder.Code != http.StatusOK {
			t.Fatalf("%s 显式 false status=%d body=%s, want 200", path, recorder.Code, recorder.Body.String())
		}
	}
}

func threatRollupTargetCountForMinute(t *testing.T, minute string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_target_rollup WHERE minute=?`, minute).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// Given 旧版本形态：主 rollup 与分钟高水位已存在（增量路径会 no-op），目标
// 维度行与就绪标记缺失；窗口 30h，目标分钟在 26h 前（超出单轮 24h 批上限）。
// When 连续两轮固化。
// Then 第二轮必须延续全量重建补齐目标维度（旧实现 rebuildAll 仅在触发轮为
// 真，第二轮增量 deltaTotal==0 早退 → 目标维度永久缺失且 backfill_incomplete
// 不再披露）；覆盖到达意图起点后意图标记清除。
func TestThreatRollup_persistedRebuildContinuesAcrossCalls(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	base := time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, base)
	eventMinute := base.Add(-26 * time.Hour).Truncate(time.Minute)
	minuteStr := eventMinute.Format("2006-01-02 15:04")
	seedThreatLBRule(t, "lb_rbld", "API 服务", "api.example.com")
	seedThreatRuleEvent(t, eventMinute.Format("2006-01-02 15:04:05"), "93.184.216.7", "lb_rbld", "blocked")
	// 旧版本已固化过该分钟（主 rollup 行）与分钟高水位：无新事件时增量路径
	// 直接 no-op（不写目标维度、不重算归属地）。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count)
		VALUES (?, '', '', 'IP 访问控制', '', 'blocked', 1)`, minuteStr); err != nil {
		t.Fatalf("seed main rollup: %v", err)
	}
	var eventID int64
	if err := db.MetricsDB.QueryRow(`SELECT MAX(id) FROM security_events`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?)`,
		threatRollupEventHighwaterPrefix+minuteStr, strconv.FormatInt(eventID, 10)); err != nil {
		t.Fatalf("seed highwater: %v", err)
	}

	// 首轮：只回填最近 24h，26h 前分钟未到；意图必须已持久化。
	if err := ensureThreatRollup(30); err != nil {
		t.Fatalf("first rollup: %v", err)
	}
	var rebuildFrom string
	if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupRebuildFromKey).Scan(&rebuildFrom); err != nil {
		t.Fatalf("首轮后重建意图未持久化: %v", err)
	}
	if got := threatRollupTargetCountForMinute(t, minuteStr); got != 0 {
		t.Fatalf("首轮不应到达 26h 前分钟，target=%d", got)
	}

	// 第二轮：持久化意图扩展回填下界并继续 fullRebuild。
	if err := ensureThreatRollup(30); err != nil {
		t.Fatalf("second rollup: %v", err)
	}
	if got := threatRollupTargetCountForMinute(t, minuteStr); got != 1 {
		t.Fatalf("target count=%d, want 1（持久化重建必须覆盖单轮批上限之外）", got)
	}
	var remaining int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, threatRollupRebuildFromKey).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("覆盖到达意图起点后必须清除重建标记（remaining=%d）", remaining)
	}
}

// 分批解析必须跨越分块边界：前 500 个候选 id 全是已删除规则的幽灵（计数相同
// 时按 id 升序排在现存规则之前）时，凑满 3 条现存目标的早停逻辑须继续下一批，
// 否则 Top3 少计/漏项（旧实现全量解析，正确但为 3 条结果做 O(distinct) 次
// 主库往返）。
func TestThreatTopTargets_resolvesAcrossChunkBoundary(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatLBRule(t, "lb_ok2", "跨越分块站点", "chunk.example.com")
	// 600 条已删除规则：'lb_ghost_*' 字典序小于 'lb_ok2'，全部落在前 500 个
	// 候选（第一批）或之后，现存规则在第二批才能被解析。
	for i := range 600 {
		seedThreatRuleEvent(t, utcStringAgo(10*time.Minute), "93.184.216.9", fmt.Sprintf("lb_ghost_%04d", i), "blocked")
	}
	seedThreatRuleEvent(t, utcStringAgo(10*time.Minute), "93.184.216.10", "lb_ok2", "blocked")

	payload := getThreatScreenR79(t, router, "/security/overview/threat-screen")
	if len(payload.Data.TopTargets) != 1 {
		t.Fatalf("top_targets=%+v, want 1 项（跨批解析出的现存规则 lb_ok2）", payload.Data.TopTargets)
	}
	if payload.Data.TopTargets[0].Name != "跨越分块站点" {
		t.Fatalf("top_targets[0]=%+v, want 跨越分块站点", payload.Data.TopTargets[0])
	}
}
