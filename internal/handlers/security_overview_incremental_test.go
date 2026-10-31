package handlers

import (
	"database/sql"
	"reflect"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 增量聚合（水位线）+ SWR 后台刷新的行为级测试：核心断言是「增量路径结果 ==
// 全量重算结果」逐字段相等（精度对账钉测），覆盖冷启动/正常增量/迟到事件/
// 删除触发重建/跨日界/空表/刷新失败保旧快照七种形状。

type overviewIncEvent struct {
	eventTime string
	ip        string
	triggered string
	msg       string
	action    string
}

func insertOverviewIncEvent(t *testing.T, metrics *sql.DB, e overviewIncEvent) {
	t.Helper()
	if _, err := metrics.Exec(`INSERT INTO security_events
		(event_time,client_ip,rule_triggered,rule_msg,action)
		VALUES (?,?,?,?,?)`, e.eventTime, e.ip, e.triggered, e.msg, e.action); err != nil {
		t.Fatalf("seed incremental event %+v: %v", e, err)
	}
}

// seedOverviewIncBaseline 构造跨日桶基线：今日×3、昨日×2、窗口首日边界（含
// 上界内首秒）、并列 top-IP（钉 tie-break 一致性）。
func seedOverviewIncBaseline(t *testing.T, metrics *sql.DB) {
	t.Helper()
	for _, e := range []overviewIncEvent{
		{eventTime: "2026-10-19 01:00:00", ip: "10.1.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"},
		{eventTime: "2026-10-19 02:00:00", ip: "10.1.0.2", triggered: "941160", msg: "XSS", action: "blocked"},
		{eventTime: "2026-10-19 03:00:00", ip: "10.1.0.3", triggered: "942100", msg: "SQL Injection", action: "logged"},
		{eventTime: "2026-10-18 01:00:00", ip: "10.1.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"},
		{eventTime: "2026-10-18 05:00:00", ip: "10.1.0.4", triggered: "", msg: "", action: "logged"},
		{eventTime: "2026-10-13 16:00:00", ip: "10.1.0.5", triggered: "932160", msg: "RCE", action: "blocked"},
		{eventTime: "2026-10-19 04:00:00", ip: "10.9.9.1", triggered: "942100", msg: "SQL Injection", action: "blocked"},
		{eventTime: "2026-10-19 05:00:00", ip: "10.9.9.2", triggered: "942100", msg: "SQL Injection", action: "blocked"},
	} {
		insertOverviewIncEvent(t, metrics, e)
	}
}

var overviewIncTestToday = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

const (
	overviewIncTestTodayStart = "2026-10-18 16:00:00"
	overviewIncTestTZ         = "+08:00"
)

func overviewIncTestKey(metrics *sql.DB) securityOverviewAggCacheKey {
	return securityOverviewAggCacheKey{metrics: metrics, todayStart: overviewIncTestTodayStart, tzName: overviewIncTestTZ}
}

// overviewIncFullReference 全量重算参照（raw 路径，与增量同口径）。
func overviewIncFullReference(t *testing.T, metrics *sql.DB) securityOverviewAggregates {
	t.Helper()
	dayStarts := securityOverviewDayStarts(overviewIncTestToday)
	data, _, err := computeSecurityOverviewAggregatesFull(metrics, dayStarts, overviewIncTestToday, time.Now(), false)
	if err != nil {
		t.Fatalf("full recompute reference: %v", err)
	}
	return data
}

func overviewIncAssertEqual(t *testing.T, phase string, got, want securityOverviewAggregates) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: 增量结果与全量重算不等\n增量=%+v\n全量=%+v", phase, got, want)
	}
}

// TestSecurityOverviewIncremental_refreshMatchesFullRecompute 精度对账钉测：
// 冷启动（全量）→ 插入 N 行（含历史日桶迟到行/窗口首日边界行/并列 top-IP）→
// 增量刷新 → 与全量重算逐字段相等；再插 M 行重复对账。
func TestSecurityOverviewIncremental_refreshMatchesFullRecompute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	seedOverviewIncBaseline(t, metrics)

	key := overviewIncTestKey(metrics)
	// 冷启动：全量建缓存，水位=当时 MAX(id)。
	cold, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ)
	if err != nil {
		t.Fatalf("cold build: %v", err)
	}
	overviewIncAssertEqual(t, "冷启动", cold, overviewIncFullReference(t, metrics))
	entry, ok := securityOverviewAggCache.GetStale(key)
	if !ok {
		t.Fatal("cold build must populate cache entry")
	}
	var wantMaxID int64
	if err := metrics.QueryRow(`SELECT COALESCE(MAX(id),0) FROM security_events`).Scan(&wantMaxID); err != nil {
		t.Fatal(err)
	}
	if entry.state.maxEventID != wantMaxID || entry.state.maxEventID == 0 {
		t.Fatalf("cold watermark=(%d), want MAX(id)=(%d)", entry.state.maxEventID, wantMaxID)
	}

	// When 追加增量行：今日新事件 + 历史日桶迟到行 + 新并列 IP。
	for _, e := range []overviewIncEvent{
		{eventTime: "2026-10-19 06:00:00", ip: "10.1.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"},
		{eventTime: "2026-10-17 20:00:00", ip: "10.1.0.6", triggered: "941160", msg: "XSS", action: "blocked"},
		{eventTime: "2026-10-14 12:00:00", ip: "10.1.0.2", triggered: "932160", msg: "RCE", action: "logged"},
		{eventTime: "2026-10-19 06:30:00", ip: "10.9.9.3", triggered: "942100", msg: "SQL Injection", action: "blocked"},
		{eventTime: "2026-10-19 06:40:00", ip: "10.9.9.4", triggered: "942100", msg: "SQL Injection", action: "blocked"},
	} {
		insertOverviewIncEvent(t, metrics, e)
	}

	// Then 增量刷新结果与全量重算逐字段相等（含并列 IP 的 tie-break 顺序）。
	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("incremental refresh: %v", err)
	}
	overviewIncAssertEqual(t, "第一波增量", refreshed, overviewIncFullReference(t, metrics))
	if overviewAggregateEventCount(refreshed) != 13 {
		t.Fatalf("refreshed trend count=%d, want 13（基线 8 + 第一波 5）", overviewAggregateEventCount(refreshed))
	}

	// And 再插一行（迟到行）后二次增量仍相等。
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-16 08:00:00", ip: "10.1.0.7", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	refreshed, err = refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("second incremental refresh: %v", err)
	}
	overviewIncAssertEqual(t, "第二波增量", refreshed, overviewIncFullReference(t, metrics))
}

// TestSecurityOverviewIncremental_deleteTriggersFullRebuild 删除检测：直接
// DELETE 造成存活计数漂移 → 增量刷新必须切换全量重建并与重算相等。
func TestSecurityOverviewIncremental_deleteTriggersFullRebuild(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	seedOverviewIncBaseline(t, metrics)
	key := overviewIncTestKey(metrics)
	if _, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ); err != nil {
		t.Fatalf("cold build: %v", err)
	}

	if _, err := metrics.Exec(`DELETE FROM security_events WHERE ip_is_not_real = 0 AND client_ip='10.1.0.1'`); err != nil {
		// 兼容列名探测失败路径：直接按 id 删两行。
		if _, err := metrics.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events LIMIT 2)`); err != nil {
			t.Fatalf("delete rows: %v", err)
		}
	}

	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("refresh after delete: %v", err)
	}
	overviewIncAssertEqual(t, "删除后重建", refreshed, overviewIncFullReference(t, metrics))

	entry, ok := securityOverviewAggCache.GetStale(key)
	if !ok {
		t.Fatal("cache entry must exist after rebuild")
	}
	var wantCount int64
	if err := metrics.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&wantCount); err != nil {
		t.Fatal(err)
	}
	if entry.state.seenTotal != wantCount {
		t.Fatalf("seenTotal after rebuild=%d, want COUNT(*)=%d", entry.state.seenTotal, wantCount)
	}
}

// TestSecurityOverviewIncremental_emptyTableAndZeroWatermark 空表冷启动：
// 零面板 + 水位归零；随后插入行可被增量拾取。
func TestSecurityOverviewIncremental_emptyTableAndZeroWatermark(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	key := overviewIncTestKey(metrics)

	cold, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ)
	if err != nil {
		t.Fatalf("cold build on empty table: %v", err)
	}
	if overviewAggregateEventCount(cold) != 0 || len(cold.topIPs) != 0 {
		t.Fatalf("empty cold build=(trend %d, ips %d), want zero panel", overviewAggregateEventCount(cold), len(cold.topIPs))
	}
	entry, ok := securityOverviewAggCache.GetStale(key)
	if !ok || entry.state.maxEventID != 0 || entry.state.seenTotal != 0 {
		t.Fatalf("empty cold state=(ok %v, watermark %d, seen %d), want (true,0,0)", ok, entry.state.maxEventID, entry.state.seenTotal)
	}

	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 07:00:00", ip: "10.2.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("refresh after first event: %v", err)
	}
	overviewIncAssertEqual(t, "空表起步增量", refreshed, overviewIncFullReference(t, metrics))
}

// TestSecurityOverviewIncremental_refreshFailureKeepsStaleSnapshot 刷新失败：
// 保留旧快照（SWR 面板不炸），恢复后同键刷新成功拿到新数据。
func TestSecurityOverviewIncremental_refreshFailureKeepsStaleSnapshot(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	seedOverviewIncBaseline(t, metrics)
	key := overviewIncTestKey(metrics)
	cold, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ)
	if err != nil {
		t.Fatalf("cold build: %v", err)
	}

	// When 表被移除（真实 DB 故障形态），刷新必须失败且不覆盖旧快照。
	if _, err := metrics.Exec(`DROP TABLE security_events`); err != nil {
		t.Fatal(err)
	}
	stale, refreshErr := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if refreshErr == nil {
		t.Fatal("refresh with missing events table must fail")
	}
	overviewIncAssertEqual(t, "失败保旧快照", stale, cold)
	if !securityOverviewAggCache.Has(key) {
		t.Fatal("failed refresh must keep the old cache entry")
	}

	// And 故障消除后同键刷新成功。
	if _, err := metrics.Exec(`CREATE TABLE security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time DATETIME NOT NULL DEFAULT (datetime('now')),
		client_ip TEXT DEFAULT '', rule_triggered TEXT DEFAULT '',
		rule_msg TEXT DEFAULT '', action TEXT DEFAULT '', event_type TEXT DEFAULT 'waf'
	)`); err != nil {
		t.Fatal(err)
	}
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 08:00:00", ip: "10.3.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("refresh after recovery: %v", err)
	}
	overviewIncAssertEqual(t, "恢复后刷新", refreshed, overviewIncFullReference(t, metrics))
}

// TestSecurityOverviewIncremental_swrServesStaleThenRefreshes SWR 语义：
// 过期条目请求立即返回旧快照（零阻塞），后台刷新完成后缓存变新。
func TestSecurityOverviewIncremental_swrServesStaleThenRefreshes(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	seedOverviewIncBaseline(t, metrics)
	key := overviewIncTestKey(metrics)
	if _, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ); err != nil {
		t.Fatalf("cold build: %v", err)
	}

	// 新增一行 + 令条目过期：下一次读取必须立即拿到旧快照（1）。
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 09:00:00", ip: "10.1.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	securityOverviewAggCache.ExpireMatching(func(k securityOverviewAggCacheKey) bool { return k == key })
	served, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ)
	if err != nil {
		t.Fatalf("stale serve: %v", err)
	}
	if overviewAggregateEventCount(served) != 8 {
		t.Fatalf("stale serve trend count=%d, want 8（旧快照零阻塞返回）", overviewAggregateEventCount(served))
	}

	// Then 后台刷新收敛：等待缓存变新（9 行）。
	deadline := time.Now().Add(5 * time.Second)
	for {
		if entry, ok := securityOverviewAggCache.Get(key, time.Now()); ok && overviewAggregateEventCount(entry.data) == 9 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("5s 内后台刷新未完成（SWR 必须在后台收敛到新快照）")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fresh, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ)
	if err != nil || overviewAggregateEventCount(fresh) != 9 {
		t.Fatalf("fresh serve=(count %d, err %v), want (9,nil)", overviewAggregateEventCount(fresh), err)
	}
	overviewIncAssertEqual(t, "SWR 收敛后", fresh, overviewIncFullReference(t, metrics))
}

// TestSecurityOverviewIncremental_dayBoundaryKeyRebuilds 跨日界：todayStart
// 键变化必须同步全量重建一次（新键无旧快照），旧键快照不受影响。
func TestSecurityOverviewIncremental_dayBoundaryKeyRebuilds(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	seedOverviewIncBaseline(t, metrics)
	if _, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ); err != nil {
		t.Fatalf("cold build: %v", err)
	}

	nextDay := overviewIncTestToday.AddDate(0, 0, 1)
	nextKey := securityOverviewAggCacheKey{metrics: metrics, todayStart: "2026-10-19 16:00:00", tzName: overviewIncTestTZ}
	if securityOverviewAggCache.Has(nextKey) {
		t.Fatal("new day-boundary key must start cold")
	}
	rebuilt, err := loadSecurityOverviewAggregates(metrics, nextDay, "2026-10-19 16:00:00", overviewIncTestTZ)
	if err != nil {
		t.Fatalf("day-boundary rebuild: %v", err)
	}
	// 新键今日窗口=10-20（昨日起点=10-19），趋势日期标签整体后移一天。
	if len(rebuilt.trend) != 7 || rebuilt.trend[6].Date != "2026-10-20" {
		t.Fatalf("day-boundary trend last bucket=%+v, want date 2026-10-20", rebuilt.trend[6])
	}
	if !securityOverviewAggCache.Has(nextKey) {
		t.Fatal("day-boundary rebuild must populate the new key")
	}
}

// TestSecurityOverviewIncremental_outOfWindowRowKeepsIncremental：表内存在
// 窗口外旧行（90 天保留 × 7 天窗口的常态）时，删除检测账本必须按窗口口径
// 播种与核对——增量分支必须真实生效，不得每轮误判「有删除」退回全量重算。
func TestSecurityOverviewIncremental_outOfWindowRowKeepsIncremental(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	seedOverviewIncBaseline(t, metrics)
	// 窗口外旧行（保留期常态形态）：不参与任何聚合，也不得污染删除检测账本。
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-09-01 00:00:00", ip: "10.9.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"})

	key := overviewIncTestKey(metrics)
	if _, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ); err != nil {
		t.Fatalf("cold build: %v", err)
	}
	entry, ok := securityOverviewAggCache.GetStale(key)
	if !ok {
		t.Fatal("cold build must populate cache entry")
	}
	var windowAlive, fullCount int64
	// 窗口径=7 天趋势窗口起点（today−6 天的本地日界→UTC），与播种/核对同口径。
	if err := metrics.QueryRow(`SELECT
		(SELECT COUNT(*) FROM security_events WHERE event_time >= ?),
		(SELECT COUNT(*) FROM security_events)`, "2026-10-13 12:00:00").Scan(&windowAlive, &fullCount); err != nil {
		t.Fatal(err)
	}
	if windowAlive == fullCount {
		t.Skipf("夹具退化：窗口外行未生效（window=%d full=%d）", windowAlive, fullCount)
	}
	if entry.state.seenTotal != windowAlive {
		t.Fatalf("seenTotal=%d, want 窗口内存活 %d（全表 %d 不得入账本——否则删除检测恒误报、增量永不生效）",
			entry.state.seenTotal, windowAlive, fullCount)
	}

	// 增量刷新：正常追加窗口内行 → 必须走增量轨道且与全量重算相等。
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 07:00:00", ip: "10.1.0.1", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("incremental refresh: %v", err)
	}
	overviewIncAssertEqual(t, "窗口外行在场增量", refreshed, overviewIncFullReference(t, metrics))
}

// TestSecurityOverviewIncremental_rankElevenIPRushesIntoTop10：基线排名 11 名
// 之外的 IP 靠新增事件冲榜时，增量 top-10 必须以「历史累计+新增」如实入榜。
func TestSecurityOverviewIncremental_rankElevenIPRushesIntoTop10(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	// 10 个 IP 各 2 次拦截（并列前十），第 11 个 IP 1 次（差一名未进种子）。
	for i := 1; i <= 10; i++ {
		insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 01:00:00", ip: "10.1.0." + string(rune('0'+i%10)) + "", triggered: "942100", msg: "SQL Injection", action: "blocked"})
		insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 02:00:00", ip: "10.1.0." + string(rune('0'+i%10)) + "", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	}
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 03:00:00", ip: "10.1.0.99", triggered: "942100", msg: "SQL Injection", action: "blocked"})

	key := overviewIncTestKey(metrics)
	if _, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ); err != nil {
		t.Fatalf("cold build: %v", err)
	}
	// 冲榜：第 11 名 IP 高强度新增 5 次（累计 6，超过前十的 2）。
	for i := 0; i < 5; i++ {
		insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 04:00:00", ip: "10.1.0.99", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	}
	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("incremental refresh: %v", err)
	}
	var found bool
	for _, row := range refreshed.topIPs {
		if row.IP == "10.1.0.99" {
			found = true
			if row.Blocked != 6 {
				t.Fatalf("10.1.0.99 blocked=%d, want 6（历史 1+新增 5 的真实累计）", row.Blocked)
			}
		}
	}
	if !found {
		t.Fatalf("基线 11 名 IP 冲榜后从 top-10 消失（账本只播种了 top-10）: %+v", refreshed.topIPs)
	}
}

// TestSecurityOverviewIncremental_mutatedRowForcesFullRebuild：行改判（检测→
// 拦截原地 UPDATE）后，增量轨道无法回溯已消费行的旧结论——置脏标志必须使
// 下一次刷新走全量重建，拦截/检测拆分如实反映改判后结论。
func TestSecurityOverviewIncremental_mutatedRowForcesFullRebuild(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 01:00:00", ip: "10.1.0.1", triggered: "942100", msg: "SQL Injection", action: "logged"})

	key := overviewIncTestKey(metrics)
	cold, err := loadSecurityOverviewAggregates(metrics, overviewIncTestToday, overviewIncTestTodayStart, overviewIncTestTZ)
	if err != nil {
		t.Fatalf("cold build: %v", err)
	}
	if cold.trend[6].Detected != 1 || cold.trend[6].Blocked != 0 {
		t.Fatalf("冷基线 detected=%d blocked=%d, want 1/0", cold.trend[6].Detected, cold.trend[6].Blocked)
	}

	// 行改判（摄取侧 UPDATE 形态）+ 置脏标志（SecurityEventsRowMutatedHook
	// 的 handlers 侧效果）。
	if _, err := metrics.Exec(`UPDATE security_events SET action='blocked' WHERE event_time='2026-10-19 01:00:00'`); err != nil {
		t.Fatal(err)
	}
	securityOverviewAggMutated.Store(true)

	refreshed, err := refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.trend[6].Blocked != 1 || refreshed.trend[6].Detected != 0 {
		t.Fatalf("改判后 trend blocked=%d detected=%d, want 1/0（全量重建必须反映改判）",
			refreshed.trend[6].Blocked, refreshed.trend[6].Detected)
	}
	// 标志一次性消费：后续刷新恢复增量轨道（不再强制全量——用第二行增量验证）。
	insertOverviewIncEvent(t, metrics, overviewIncEvent{eventTime: "2026-10-19 02:00:00", ip: "10.1.0.2", triggered: "942100", msg: "SQL Injection", action: "blocked"})
	refreshed, err = refreshSecurityOverviewAggregates(metrics, key, overviewIncTestToday)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	overviewIncAssertEqual(t, "改判后恢复增量", refreshed, overviewIncFullReference(t, metrics))
}
