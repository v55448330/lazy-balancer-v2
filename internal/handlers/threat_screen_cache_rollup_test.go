package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 同步固化会改写窗口内分钟行——读 rollup 分钟行的两份缓存（维度聚合与
// top_targets）必须一起失效。只清前者会让同一次响应的「被攻击目标 Top3」
// 仍返回固化前的数据，与已重算的总量/国家口径短暂分叉。
func TestInvalidateThreatScreenRollupCaches_clearsTopTargets(t *testing.T) {
	resetThreatScreenCachesForTest()
	t.Cleanup(resetThreatScreenCachesForTest)

	targetKey := topTargetsCacheKey{sinceMinute: "2026-10-25 10:00"}
	topTargetsCacheMu.Lock()
	topTargetsCache[targetKey] = topTargetsCacheEntry{
		targets:   []threatTopTarget{{Name: "site-a", Value: 7}},
		expiresAt: time.Now().Add(time.Minute),
	}
	topTargetsCacheMu.Unlock()

	aggKey := threatRollupDimAggregateKey{sinceMinute: "2026-10-25 10:00"}
	threatRollupDimAggregateCacheMu.Lock()
	threatRollupDimAggregateCache[aggKey] = threatRollupDimAggregateEntry{expiresAt: time.Now().Add(time.Minute)}
	threatRollupDimAggregateCacheMu.Unlock()

	invalidateThreatScreenRollupCaches()

	topTargetsCacheMu.Lock()
	_, targetLeft := topTargetsCache[targetKey]
	topTargetsCacheMu.Unlock()
	if targetLeft {
		t.Fatal("固化后 top_targets 缓存必须一并失效（否则同一次响应返回固化前 Top3）")
	}

	threatRollupDimAggregateCacheMu.Lock()
	_, aggLeft := threatRollupDimAggregateCache[aggKey]
	threatRollupDimAggregateCacheMu.Unlock()
	if aggLeft {
		t.Fatal("固化后维度聚合缓存必须失效")
	}
}

func TestThreatScreenCaches_includeMetricsGeneration(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetThreatScreenCachesForTest()
	t.Cleanup(resetThreatScreenCachesForTest)
	oldGeneration := db.MetricsDBGeneration()
	if oldGeneration == "" {
		t.Fatal("test database must have a generation")
	}
	oldKey := topTargetsCacheKey{metrics: db.MetricsDB, main: db.DB, generation: oldGeneration, sinceMinute: "2026-10-25 10:00"}
	markThreatRollupSuccess()
	if !threatRollupUsable() {
		t.Fatal("successful rollup must be usable before rebuild")
	}
	if db.MetricsDB != nil {
		_ = db.MetricsDB.Close()
	}
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("reinitialize metrics db: %v", err)
	}
	newGeneration := db.MetricsDBGeneration()
	if newGeneration == "" || newGeneration == oldGeneration {
		t.Fatalf("generation did not change: old=%q new=%q", oldGeneration, newGeneration)
	}
	newKey := topTargetsCacheKey{metrics: db.MetricsDB, main: db.DB, generation: newGeneration, sinceMinute: oldKey.sinceMinute}
	if oldKey == newKey {
		t.Fatal("cache key must change across metrics generations")
	}
	if threatRollupUsable() {
		t.Fatal("rollup readiness from the old generation must not survive rebuild")
	}
}

// 活跃攻击源缓存 TTL 必须覆盖大屏轮询周期：小于轮询周期时每轮必然
// miss，缓存与代码复杂度为零收益，10 分钟窗口全扫照常每轮发生。
//
// 轮询周期从大屏源码取（web/src/views/security/ThreatScreen.vue 的
// STATS_POLL_MS），不在测试内另存副本：副本会让前端把周期改成 60s 时这里
// 依旧绿（缓存每轮必 miss），正是「期望与实现各持一份」的漂移形态。前端
// 同主题用例反向读本侧 TTL，两侧任一改动都会有一处红。
func TestThreatActiveSourcesCacheTTL_coversPollingInterval(t *testing.T) {
	vue, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "views", "security", "ThreatScreen.vue"))
	if err != nil {
		t.Fatalf("读取大屏源码（轮询周期单源）失败: %v", err)
	}
	match := regexp.MustCompile(`(?m)^\s*const\s+STATS_POLL_MS\s*=\s*(\d+)\s*$`).FindSubmatch(vue)
	if match == nil {
		t.Fatal("大屏源码缺 STATS_POLL_MS 常量声明（跨栈对表需同步本用例）")
	}
	pollMs, err := strconv.Atoi(string(match[1]))
	if err != nil || pollMs <= 0 {
		t.Fatalf("STATS_POLL_MS=%q 非法", match[1])
	}
	polling := time.Duration(pollMs) * time.Millisecond
	if threatActiveSourcesCacheTTL < polling {
		t.Fatalf("threatActiveSourcesCacheTTL=%v, want >= %v（与大屏轮询同周期，否则缓存永不命中）", threatActiveSourcesCacheTTL, polling)
	}
}

// 窗口起点锚点：秒级入参截到分钟（缓存键口径），异形短值原样返回而不得
// 直接 [:16]（带外写库/异形导入的 19 字符以下 event_time 会让处理器 panic）。
func TestThreatMinuteAnchor_guardsShortValues(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-10-25 10:00:00", "2026-10-25 10:00"},
		{"2026-10-25 10:00", "2026-10-25 10:00"},
		{"2027-01-01", "2027-01-01"},
		{"", ""},
	}
	for _, c := range cases {
		if got := threatMinuteAnchor(c.in); got != c.want {
			t.Errorf("threatMinuteAnchor(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// 同屏两份 rollup 读缓存 TTL 必须同源（=前端 30s 轮询周期）：此前 Top3 60s /
// 维度聚合 30s 分叉，warmer 每 60s 推进 rollup 时同一响应里 Top3 与总量最多
// 差 30s 新鲜度（展示口径自相矛盾）。本用例与
// TestThreatActiveSourcesCacheTTL_coversPollingInterval 同主题：改动任一 TTL
// 都会在另一处变红。
func TestThreatScreenRollupCaches_shareTTL(t *testing.T) {
	if topTargetsCacheTTL != threatRollupDimAggregateTTL {
		t.Fatalf("topTargetsCacheTTL=%v, threatRollupDimAggregateTTL=%v, want 同源（同屏同窗口口径）",
			topTargetsCacheTTL, threatRollupDimAggregateTTL)
	}
	if threatRollupDimAggregateTTL > time.Minute {
		t.Fatalf("threatRollupDimAggregateTTL=%v, want <= 1 分钟（大屏轮询复用窗口，不得超出轮询一个数量级）",
			threatRollupDimAggregateTTL)
	}
}

func TestGetSecurityThreatScreen_queryFailureInvalidatesRollupCaches(t *testing.T) {
	// Given：聚合查询可以成功并写缓存，但后续 top_targets 因主库缺表失败。
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatRuleEvent(t, utcStringAgo(time.Minute), "93.184.216.7", "lb_aaa", "blocked")
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatal(err)
	}

	// When：本轮整卡 500。
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}

	// Then：已写入的半轮聚合也必须失效，下一轮不得混用旧聚合与新 Top3。
	threatRollupDimAggregateCacheMu.Lock()
	aggLeft := len(threatRollupDimAggregateCache)
	threatRollupDimAggregateCacheMu.Unlock()
	topTargetsCacheMu.Lock()
	targetsLeft := len(topTargetsCache)
	topTargetsCacheMu.Unlock()
	if aggLeft != 0 || targetsLeft != 0 {
		t.Fatalf("cache entries after 500: aggregate=%d top_targets=%d, want both 0", aggLeft, targetsLeft)
	}
}
