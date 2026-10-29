package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// rollup 时间口径（有意设计，勿按「部分分钟」重报）：
//   - warmer 每轮恒固化 currentMinute 的部分分钟；今日计数与大屏总量/分桶/
//     目标维度都包含「当前分钟截至最近一次固化」的事件（滞后 ≤60s）；
//   - recent_rate 例外：固定 5 分钟除数，必须只取完整分钟（见
//     TestGetSecurityThreatScreen_recentRateUsesCompleteMinutesOnly）。
//
// 本用例钉住前一半事实：若将来把三面查询改成「只取完整分钟」，UI 文案
// （含当前分钟，滞后约 1 分钟）必须同步改回——否则文案与数字再次失配。
func TestRollupQueries_includeCurrentPartialMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	now := time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, now)
	lastComplete := now.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := now.Truncate(time.Minute)
	lastStr := lastComplete.Format("2006-01-02 15:04")
	currentStr := currentMinute.Format("2006-01-02 15:04")
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	seedThreatLBRule(t, "lb_partial", "API 服务", "api.example.com")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
		(?, '美国', '', 'SQL注入', '942100', 'blocked', 2),
		(?, '美国', '', 'SQL注入', '942100', 'logged', 1),
		(?, '日本', '', 'XSS', '941100', 'blocked', 5)`,
		lastStr, lastStr, currentStr); err != nil {
		t.Fatalf("seed rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, 'lb_partial', 4), (?, 'lb_partial', 9)`,
		lastStr, currentStr); err != nil {
		t.Fatalf("seed target rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?), (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupCoveredFromKey, dayStart.Format("2006-01-02 15:04"),
		threatRollupWatermarkKey, lastStr); err != nil {
		t.Fatalf("seed rollup state: %v", err)
	}

	// 今日计数：完整分钟 + 当前部分分钟都计入（口径文案已按此陈述）。
	blocked, detected, fromRollup, err := securityOverviewTodayCounts(db.MetricsDB, dayStart, now)
	if err != nil {
		t.Fatalf("today counts: %v", err)
	}
	if !fromRollup {
		t.Fatal("覆盖新鲜时必须走 rollup 口径")
	}
	if blocked != 7 || detected != 1 {
		t.Fatalf("今日计数含当前分钟: blocked=%d detected=%d, want 7/1", blocked, detected)
	}

	// 大屏总量/分桶/目标维度与今日计数同口径（含部分分钟）。
	since := now.Add(-24 * time.Hour).Truncate(time.Minute)
	bucketStarts := []time.Time{since}
	agg, err := threatRollupDimAggregateQuery(db.MetricsDB, since.Format("2006-01-02 15:04"), bucketStarts, dayStart.Format("2006-01-02 15:04"), true)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.total != 8 || agg.blocked != 7 {
		t.Fatalf("大屏总量含当前分钟: total=%d blocked=%d, want 8/7", agg.total, agg.blocked)
	}
	if len(agg.bucketTotals) != 1 || agg.bucketTotals[0] != 8 {
		t.Fatalf("分桶总量必须与总量同口径: %+v", agg.bucketTotals)
	}

	targets, err := threatTopTargets(since.Format("2006-01-02 15:04"), true)
	if err != nil {
		t.Fatalf("top targets: %v", err)
	}
	if len(targets) != 1 || targets[0].Value != 13 {
		t.Fatalf("top_targets 必须与总量同口径: %+v", targets)
	}
}

// 今日计数的 rollup 分支与原始表回退分支必须对同一事件集合给出恒等数值：
// 两分支的谓词套用面一旦分叉，同一卡片会在覆盖水位切换点输出不同数字，
// 且切换时机由水位决定、极难复现。原始表侧同样套攻击面谓词。
func TestSecurityOverviewTodayCounts_rollupAndRawFallbackAgree(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	now := time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	lastComplete := now.Add(-time.Minute).Truncate(time.Minute)
	lastStr := lastComplete.Format("2006-01-02 15:04")
	eventTime := lastComplete.Format("2006-01-02 15:04:05")

	// 事件集合：blocked ×2（普通规则）、logged ×1（普通规则）、
	// logged ×1（爬虫放行族 id 810016）。爬虫放行行不计攻击面。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, action, rule_triggered) VALUES
		(?, 'blocked', '942100'), (?, 'blocked', '942100'),
		(?, 'logged', '942100'), (?, 'logged', '810016')`,
		eventTime, eventTime, eventTime, eventTime); err != nil {
		t.Fatalf("seed events: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, rule, action, count) VALUES
		(?, '942100', 'blocked', 2), (?, '942100', 'logged', 1), (?, '810016', 'logged', 1)`,
		lastStr, lastStr, lastStr); err != nil {
		t.Fatalf("seed rollup: %v", err)
	}

	usable := func(coveredFrom string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?), (?, ?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupCoveredFromKey, coveredFrom,
			threatRollupWatermarkKey, lastStr); err != nil {
			t.Fatalf("seed rollup state: %v", err)
		}
	}

	usable(dayStart.Format("2006-01-02 15:04"))
	rollupBlocked, rollupDetected, fromRollup, err := securityOverviewTodayCounts(db.MetricsDB, dayStart, now)
	if err != nil {
		t.Fatalf("rollup counts: %v", err)
	}
	if !fromRollup {
		t.Fatal("覆盖新鲜时必须走 rollup 口径")
	}

	// 覆盖水位晚于今日起点 → 回退原始表直算。
	usable(dayStart.Add(time.Minute).Format("2006-01-02 15:04"))
	rawBlocked, rawDetected, fromRollup, err := securityOverviewTodayCounts(db.MetricsDB, dayStart, now)
	if err != nil {
		t.Fatalf("raw counts: %v", err)
	}
	if fromRollup {
		t.Fatal("覆盖水位不足时必须回退原始表")
	}
	if rollupBlocked != rawBlocked || rollupDetected != rawDetected {
		t.Fatalf("两分支口径分叉: rollup=%d/%d raw=%d/%d", rollupBlocked, rollupDetected, rawBlocked, rawDetected)
	}
	if rawBlocked != 2 || rawDetected != 1 {
		t.Fatalf("计数口径: blocked=%d detected=%d, want 2/1（爬虫放行不计攻击面）", rawBlocked, rawDetected)
	}
}

// 端点级接线：大屏 handler 的总量与 recent_rate 刻意使用不同时间上界，
// 两者都不许被单方面改动（改动必须成对更新文案与本用例）。
func TestGetSecurityThreatScreen_partialMinuteScopeIsExplicit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	base := time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)
	installThreatClock(t, base)
	lastComplete := base.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := base.Truncate(time.Minute)
	seedThreatScreenEvent(t, lastComplete.Format("2006-01-02 15:04:05"), "93.184.216.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, currentMinute.Add(5*time.Second).Format("2006-01-02 15:04:05"), "93.184.216.8", "942100", "SQL Injection", "blocked")
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	// 单次请求即须含当前部分分钟：首个请求返回落后值再靠重试掩盖，等于
	// 把「请求路径未固化当前分钟」的缺陷藏进轮询间隙。
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Data.TotalEvents != 2 || payload.Data.BlockedEvents != 2 {
		t.Fatalf("首个请求的大屏总量=total %d/blocked %d, want 2/2（含当前部分分钟，滞后 ≤60s，与 UI 文案一致）",
			payload.Data.TotalEvents, payload.Data.BlockedEvents)
	}
}

// 聚合缓存只在窗口覆盖完整时生效（handler 传入 cacheable=!backfill_incomplete）：
// 原始表被保留期/行帽裁剪不再禁用缓存——否则高攻击站点每次 30s 轮询都要重跑
// 窗口内两条聚合（维度 GROUP BY + 逐分钟 GROUP BY），与摄取/固化抢 CPU/IO。
func TestThreatRollupDimAggregateQuery_cachesOnlyWhenWindowCovered(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	since := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
	sinceStr := since.Format("2006-01-02 15:04")
	bucketStarts := []time.Time{since}
	coverage := sinceStr
	seed := func(at time.Time, count int) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute,country,province,family,rule,action,count) VALUES (?,?,?,?,?,?,?)`,
			at.Format("2006-01-02 15:04"), "美国", "", "SQL注入", "942100", "blocked", count); err != nil {
			t.Fatalf("seed rollup: %v", err)
		}
	}
	query := func(cacheable bool) int {
		t.Helper()
		agg, err := threatRollupDimAggregateQuery(db.MetricsDB, sinceStr, bucketStarts, coverage, cacheable)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		return agg.total
	}

	seed(since.Add(time.Minute), 1)
	if got := query(true); got != 1 {
		t.Fatalf("total=%d, want 1", got)
	}
	// 覆盖完整（cacheable=true）：TTL 内命中缓存，行内容变化不影响同键结果。
	seed(since.Add(2*time.Minute), 1)
	if got := query(true); got != 1 {
		t.Fatalf("total=%d, want 1（窗口覆盖完整时同键命中缓存）", got)
	}
	// 覆盖不足（cacheable=false）：既不读也不写缓存——回填中的少计结果不得
	// 被锁在 30s 缓存里，本次查询必须反映全部已固化行。
	seed(since.Add(3*time.Minute), 1)
	if got := query(false); got != 3 {
		t.Fatalf("total=%d, want 3（覆盖不足时不得命中缓存）", got)
	}
	// cacheable=false 不写缓存：此前缓存的旧条目仍在 TTL 内，故覆盖完整的查询
	// 依旧看到旧值，清缓存后才读到全部行。
	if got := query(true); got != 1 {
		t.Fatalf("total=%d, want 1（cacheable=false 不得覆写缓存条目）", got)
	}
	resetThreatScreenCachesForTest()
	if got := query(true); got != 3 {
		t.Fatalf("total=%d, want 3（清缓存后读到全部已固化行）", got)
	}
}

// 宽窗口回填未完成时的 Top3 不得落缓存：部分窗口结果一旦缓存，回填完成后的
// 下一轮轮询（coverageReaches=true、stale=false，不再失效）仍会命中它 ≤60s，
// 而同响应 total/国家已是完整窗口（与聚合查询的 cacheable 门同口径）。
func TestThreatTopTargets_cacheableGateSkipsPartialResults(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	now := time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, now)
	since := now.Add(-24 * time.Hour).Truncate(time.Minute)
	sinceStr := since.Format("2006-01-02 15:04")
	seedThreatLBRule(t, "lb_cache", "缓存站点", "cache.example.com")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, 'lb_cache', 5)`, sinceStr); err != nil {
		t.Fatal(err)
	}

	// cacheable=false：结果不写缓存。
	if _, err := threatTopTargets(sinceStr, false); err != nil {
		t.Fatal(err)
	}
	cached := topTargetsCache.Has(topTargetsCacheKey{metrics: db.MetricsDB, main: db.DB, generation: db.MetricsDBGeneration(), sinceMinute: sinceStr})
	if cached {
		t.Fatal("回填未完成的 Top3 不得落缓存（回填完成后 ≤60s 仍返回部分结果）")
	}
	// 补全后按完整窗口重算：结果反映新增行。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, 'lb_cache', 7)`, now.Format("2006-01-02 15:04")); err != nil {
		t.Fatal(err)
	}
	targets, err := threatTopTargets(sinceStr, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Value != 12 {
		t.Fatalf("完整窗口 Top3=%+v, want 12", targets)
	}
	// cacheable=true：结果落缓存。
	cached = topTargetsCache.Has(topTargetsCacheKey{metrics: db.MetricsDB, main: db.DB, generation: db.MetricsDBGeneration(), sinceMinute: sinceStr})
	if !cached {
		t.Fatal("完整窗口结果必须落缓存")
	}
}
