package handlers

// 回退后迟到插入必须仍能进入聚合（两种形态）：
//   - 原始行被保留期/行帽裁剪：全量重算只看得到剩余行，newTotal<oldTotal；
//   - 含旧口径固化行：按当前攻击口径过滤后 kept<oldTotal。
// 两种形态都只能靠「已计入行的最大 id」区分迟到行——普通插入来源的回退保留
// 分钟高水位（增量重固即可合并），原地改判来源的回退把高水位搬进迟到基线
// 后再删键（全量重算仍能按基线合并）。缺任一环，迟到行会在高水位被抹掉后
// 永久既不在 rollup、也不再进入后续增量重扫（大屏与事件列表口径分裂）。

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

const threatRewindMinuteLayout = "2006-01-02 15:04"

// fixThreatRewindMinute 单分钟固化（全量/增量由高水位决定）。
func fixThreatRewindMinute(t *testing.T, m time.Time) {
	t.Helper()
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := threatFixMinuteWithMode(tx, m, false); err != nil {
		_ = tx.Rollback()
		t.Fatalf("fix minute: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func seedThreatRewindWatermark(t *testing.T, minute string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, threatRollupWatermarkKey, minute); err != nil {
		t.Fatal(err)
	}
}

func threatRewindRollupTotals(t *testing.T, minute string) (total int, byAction map[string]int) {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT action, SUM(count) FROM security_event_rollup WHERE minute=? GROUP BY action`, minute)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	byAction = map[string]int{}
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			t.Fatal(err)
		}
		byAction[action] += count
		total += count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return total, byAction
}

func threatRewindStateRows(t *testing.T, key string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// 普通插入来源的回退只回退覆盖水位：分钟高水位必须保留，裁剪分钟上的迟到行
// 由增量重固并入（删除高水位会让 newTotal<oldTotal 分支再也找不到迟到行）。
func TestThreatRollupRewind_insertSourceKeepsLateInsertsOnTrimmedMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Add(5 * time.Second).Format("2006-01-02 15:04:05")

	// Given 该分钟已固化 3 条拦截事件（首固=全量重建，写入事件高水位）。
	for i := range 3 {
		seedThreatScreenEvent(t, eventTime, fmt.Sprintf("93.184.216.%d", i+1), "942100", "SQL Injection", "blocked")
	}
	fixThreatRewindMinute(t, m)
	if got, _ := threatRewindRollupTotals(t, minute); got != 3 {
		t.Fatalf("首固 rollup 总量=%d, want 3", got)
	}
	if threatRewindStateRows(t, services.ThreatRollupEventHighwaterPrefix+minute) != 1 {
		t.Fatal("首固必须先落分钟事件高水位（增量重固的前提）")
	}
	// 行帽/保留期裁掉两条最旧原始行（已固化历史不可再生）。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id ASC LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	// 一条迟到事件（轮转补采）落在已覆盖分钟。
	seedThreatScreenEvent(t, eventTime, "93.184.216.99", "949110", "Inbound Anomaly Score Exceeded", "blocked")
	seedThreatRewindWatermark(t, minute)

	// When 普通插入来源回退（无原地改判分钟）。
	ThreatRollupRewindTo(m, nil)

	// Then 高水位保留 → 下一次固化增量合并迟到行，已裁剪历史不丢。
	if threatRewindStateRows(t, services.ThreatRollupEventHighwaterPrefix+minute) != 1 {
		t.Fatal("普通插入来源的回退不得删除分钟高水位（迟到行 id 单调更大，增量即可覆盖）")
	}
	fixThreatRewindMinute(t, m)
	total, byAction := threatRewindRollupTotals(t, minute)
	if total != 4 {
		t.Fatalf("裁剪+迟到后 rollup 总量=%d, want 4（3 已固化历史 + 1 迟到，%v）", total, byAction)
	}
	if byAction["blocked"] != 4 {
		t.Fatalf("blocked=%d, want 4（迟到行漏计 → 大屏与事件列表口径分裂）", byAction["blocked"])
	}
	// 幂等：再固化一次不重复叠加。
	fixThreatRewindMinute(t, m)
	if got, _ := threatRewindRollupTotals(t, minute); got != 4 {
		t.Fatalf("重复固化后总量=%d, want 4", got)
	}
}

// 原地改判来源的回退删除分钟高水位（改判行 id 不变，增量扫不到）——必须同时
// 留底迟到基线，否则裁剪分钟上的迟到行在全量重算里被 newTotal<oldTotal 分支
// 丢弃，且新落的高水位让后续增量也再扫不到（永久丢失）。
func TestThreatRollupRewind_reclassifySourceKeepsLateInsertsOnTrimmedMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Add(5 * time.Second).Format("2006-01-02 15:04:05")

	// Given 该分钟已固化 3 条拦截 + 1 条检测（旧口径总量 4），高水位=4。
	for i := range 3 {
		seedThreatScreenEvent(t, eventTime, fmt.Sprintf("93.184.216.%d", i+1), "942100", "SQL Injection", "blocked")
	}
	seedThreatScreenEvent(t, eventTime, "93.184.216.9", "942100", "SQL Injection", "logged")
	fixThreatRewindMinute(t, m)
	if total, _ := threatRewindRollupTotals(t, minute); total != 4 {
		t.Fatalf("首固 rollup 总量=%d, want 4", total)
	}
	// 裁掉两条最旧原始行（保留期/行帽），再插入一条迟到拦截。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id ASC LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	seedThreatScreenEvent(t, eventTime, "93.184.216.99", "949110", "Inbound Anomaly Score Exceeded", "blocked")
	seedThreatRewindWatermark(t, minute)

	// When 原地改判来源回退（该分钟需全量重算）。
	ThreatRollupRewindTo(m, []time.Time{m})

	// Then 高水位删除、值搬进迟到基线（=4）；迟到行 id=5 > 基线 → 可合并。
	if threatRewindStateRows(t, services.ThreatRollupEventHighwaterPrefix+minute) != 0 {
		t.Fatal("原地改判来源的回退必须删除该分钟高水位（否则改判结果不会进入 rollup）")
	}
	var baseline string
	if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`,
		services.ThreatRollupLateBaselinePrefix+minute).Scan(&baseline); err != nil {
		t.Fatalf("迟到基线未留底: %v", err)
	}
	if baseline != "4" {
		t.Fatalf("迟到基线=%q, want 4（被删除的高水位值）", baseline)
	}
	fixThreatRewindMinute(t, m)
	total, byAction := threatRewindRollupTotals(t, minute)
	if total != 5 {
		t.Fatalf("裁剪+迟到后 rollup 总量=%d, want 5（4 已固化历史 + 1 迟到，%v）", total, byAction)
	}
	// 迟到基线已消费：后续回退/固化不得再次叠加同一批迟到行。
	if threatRewindStateRows(t, services.ThreatRollupLateBaselinePrefix+minute) != 0 {
		t.Fatal("迟到基线必须在重固事务内消费（残留会让下一次回退重复合并）")
	}
	fixThreatRewindMinute(t, m)
	if got, _ := threatRewindRollupTotals(t, minute); got != 5 {
		t.Fatalf("重复固化后总量=%d, want 5（基线不得重复消费）", got)
	}
}

// 含旧口径固化行（爬虫放行的 logged 仍在 rollup）的分钟：按当前口径过滤后
// kept<oldTotal，同样落到「保留旧行」分支——两种回退来源都必须把迟到行并入，
// 且旧口径行必须被清掉。
func TestThreatRollupRewind_legacyPredicateRowsKeepLateInserts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reclassify func(m time.Time) []time.Time
	}{
		{name: "insert-source", reclassify: func(time.Time) []time.Time { return nil }},
		{name: "reclassify-source", reclassify: func(m time.Time) []time.Time { return []time.Time{m} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			m := time.Date(2026, 10, 19, 11, 59, 0, 0, time.UTC)
			minute := m.Format(threatRewindMinuteLayout)

			// Given 先烧两条事件 id（已计入的历史行，原始行已裁剪）。
			seedThreatScreenEvent(t, m.Add(-2*time.Minute).Format("2006-01-02 15:04:05"),
				"93.184.216.1", "942100", "SQL Injection", "blocked")
			seedThreatScreenEvent(t, m.Add(-2*time.Minute).Format("2006-01-02 15:04:05"),
				"93.184.216.2", "942100", "SQL Injection", "blocked")
			// 旧口径固化行：放行族 logged 1 条 + 正常 blocked 2 条。
			if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
				(?, '', '', '其他', ?, 'logged', 1),
				(?, '', '', 'SQL注入', '942100', 'blocked', 2)`,
				minute, crawlerExemptRulePass, minute); err != nil {
				t.Fatal(err)
			}
			if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, '2')
				ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
				services.ThreatRollupEventHighwaterPrefix+minute); err != nil {
				t.Fatal(err)
			}
			// 一条迟到拦截事件（id=3 > 高水位 2）。
			seedThreatScreenEvent(t, m.Add(10*time.Second).Format("2006-01-02 15:04:05"),
				"93.184.216.99", "949110", "Inbound Anomaly Score Exceeded", "blocked")
			seedThreatRewindWatermark(t, minute)

			// When 回退（来源按子用例）。
			ThreatRollupRewindTo(m, tc.reclassify(m))

			// Then 全量/增量重固都按当前口径清掉放行行，并保留迟到行。
			fixThreatRewindMinute(t, m)
			total, byAction := threatRewindRollupTotals(t, minute)
			if total != 3 || byAction["blocked"] != 3 {
				t.Fatalf("rollup=(total %d, %v), want total=3 全 blocked（迟到行不得丢、旧口径放行行不得留）", total, byAction)
			}
			fixThreatRewindMinute(t, m)
			if got, _ := threatRewindRollupTotals(t, minute); got != 3 {
				t.Fatalf("重复固化后总量=%d, want 3", got)
			}
		})
	}
}

// 回退队列「消费即丢」修复钉测：DB 写失败后已消费的分钟/改判分钟必须回填，
// 否则改判（UPDATE，id 不变）永远不再被全量重算，该分钟口径永久陈旧。
func TestThreatRollupRewind_failureRefillsConsumedQueue(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	seedThreatRewindWatermark(t, m.Format(threatRewindMinuteLayout))
	// 注入失败：metrics_state 不可读 → 水位读取失败（threatRollupRewindToInLock 早退 false）。
	if _, err := db.MetricsDB.Exec(`DROP TABLE metrics_state`); err != nil {
		t.Fatal(err)
	}
	queueThreatRollupRewind(m)
	queueThreatRollupReclassify([]time.Time{m})

	threatRollupMu.Lock()
	applyPendingThreatRollupRewindInLock()
	threatRollupMu.Unlock()

	if got := threatRollupRewindPending.Load(); got != m.Unix() {
		t.Fatalf("失败后回退队列=%d, want %d（已消费条目必须回填）", got, m.Unix())
	}
	if !hasPendingThreatRollupReclassify() {
		t.Fatal("失败后改判分钟必须回填（否则该分钟永不转全量重算）")
	}
	// 清理：回填的全局队列不得泄漏到其他用例。
	threatRollupRewindPending.Store(0)
	_ = takeThreatRollupReclassifyPending()
}

// 直通路径（ThreatRollupRewindTo 抢到锁后直接应用入参）同样必须消费回退
// 返回值：失败即回填。否则水位不回退、原地改判分钟不进全量重算——改判是
// UPDATE（事件 id 不变），增量重固按 id>高水位永远扫不到，该分钟 blocked/
// logged 口径陈旧到下一次代际全量重固（大屏与事件列表同窗口口径分裂）。
func TestThreatRollupRewindTo_directPathRefillsOnFailure(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	// 取近期分钟：窗口外会被 threatRollupRewindMinute 钳到展示下界，断言
	// 目标应取钳制后的同一值（此处取窗口内，避开钳制）。
	m := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Minute)
	seedThreatRewindWatermark(t, m.Format(threatRewindMinuteLayout))
	// 注入失败形态：metrics_state 不可读 → 回退早退 false（与队列路径用例
	// 同一注入方式，不依赖测试缝）。
	if _, err := db.MetricsDB.Exec(`DROP TABLE metrics_state`); err != nil {
		t.Fatal(err)
	}
	threatRollupRewindPending.Store(0)
	_ = takeThreatRollupReclassifyPending()
	t.Cleanup(func() {
		threatRollupRewindPending.Store(0)
		_ = takeThreatRollupReclassifyPending()
	})

	ThreatRollupRewindTo(m, []time.Time{m})

	if got := threatRollupRewindPending.Load(); got != m.Unix() {
		t.Fatalf("直通路径失败后回退队列=%d, want %d（本批重固不得丢弃）", got, m.Unix())
	}
	if !hasPendingThreatRollupReclassify() {
		t.Fatal("直通路径失败后原地改判分钟必须回填（否则该分钟永不转全量重算）")
	}
}

// drain 必须区分「无可消费项/抢不到锁」与「应用成功」：应用失败时队列已被
// applyPending 回填，旧实现却无条件报告「已处理」，ensure 立即 continue 形成
// 无退避、无上限的紧凑重试循环（DB 写锁/BUSY/磁盘满时每轮一次事务 + 一条
// warn，warmer 协程被粘住）。
func TestDrainThreatRollupRewindPending_reportsFailure(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 13, 30, 0, 0, time.UTC)
	seedThreatRewindWatermark(t, m.Format(threatRewindMinuteLayout))
	if _, err := db.MetricsDB.Exec(`DROP TABLE metrics_state`); err != nil {
		t.Fatal(err)
	}
	threatRollupRewindPending.Store(0)
	_ = takeThreatRollupReclassifyPending()
	t.Cleanup(func() {
		threatRollupRewindPending.Store(0)
		_ = takeThreatRollupReclassifyPending()
	})
	queueThreatRollupRewind(m)

	attempted, succeeded := drainThreatRollupRewindPending()
	if !attempted {
		t.Fatal("队列有可消费项时 attempt 必须为真")
	}
	if succeeded {
		t.Fatal("应用失败不得报告成功（ensure 会据此紧凑重试）")
	}
	if got := threatRollupRewindPending.Load(); got != m.Unix() {
		t.Fatalf("失败后回退队列=%d, want %d（必须回填重试）", got, m.Unix())
	}

	// 无待处理项时：attempted=false 且不视为失败。
	threatRollupRewindPending.Store(0)
	if attempted, succeeded := drainThreatRollupRewindPending(); attempted || !succeeded {
		t.Fatalf("空队列: attempted=%v succeeded=%v, want false/true", attempted, succeeded)
	}
}

// 回退持续失败时 ensure 必须有界返回：旧实现 drain 恒报成功 → ensure 紧凑
// 重试永不返回（warmer 协程被粘在循环里，每轮一次事务 + 一条 warn）。
// 用测试缝让 ensure 自身成功、回退持续失败（真实形态是 DB 写锁/BUSY/磁盘满）：
// 缝在第 8 次调用前一律失败、之后成功——旧实现会一路重试到「成功」并返回
// nil，新实现在有界次数内放弃并返回错误。
func TestEnsureThreatRollup_boundedRetriesWhenRewindKeepsFailing(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	oldApply := threatRollupRewindApplyInLock
	oldAttempts := threatRollupRewindApplyAttempts
	oldBackoff := threatRollupRewindApplyBackoff
	t.Cleanup(func() {
		threatRollupRewindApplyInLock = oldApply
		threatRollupRewindApplyAttempts = oldAttempts
		threatRollupRewindApplyBackoff = oldBackoff
		threatRollupRewindPending.Store(0)
		_ = takeThreatRollupReclassifyPending()
	})
	threatRollupRewindApplyAttempts = 2
	threatRollupRewindApplyBackoff = 0
	var calls, successes atomic.Int64
	threatRollupRewindApplyInLock = func(time.Time, []time.Time) bool {
		if calls.Add(1) <= 8 {
			return false
		}
		successes.Add(1)
		return true
	}
	threatRollupRewindPending.Store(0)
	_ = takeThreatRollupReclassifyPending()
	queueThreatRollupRewind(time.Now().UTC().Add(-15 * time.Minute).Truncate(time.Minute))

	err := ensureThreatRollup(1)
	if err == nil {
		t.Fatal("回退持续失败时 ensure 必须返回错误（留待下一轮节拍），不得重试到成功")
	}
	if got := successes.Load(); got != 0 {
		t.Fatalf("有界重试内不得触达「成功」形态（重试次数无上限）: successes=%d", got)
	}
	// 每轮 ensure 最多两处应用（批次间隙合并 + drain），上限 2×attempts。
	if got := calls.Load(); got > int64(2*threatRollupRewindApplyAttempts) {
		t.Fatalf("回退应用次数=%d > %d（重试无上限）", got, 2*threatRollupRewindApplyAttempts)
	}
	if got := threatRollupRewindPending.Load(); got == 0 {
		t.Fatal("失败后队列必须保持回填（下一轮节拍重试）")
	}
}

// 空增量早退：同一分钟连续固化两次时，第二次（窗口内无新行）此前仍会
// 整段重读已固化行再跑一遍全范围聚合（每分钟两遍全扫），结果与
// deltaTotal==0 分支完全相同（只落高水位）。迟到行 id 恒大于已计行，
// 因此「分钟窗口 MAX(id) 不变且无迟到基线」即无新行可合并。
func TestThreatFixMinute_noNewEventsSkipsAggregateScan(t *testing.T) {
	recorder := countingMetricsDB(t)
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := base.Truncate(time.Minute)
	eventTime := minute.Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, eventTime, "93.184.216.8", "941100", "XSS", "blocked")
	fixThreatRewindMinute(t, minute) // 首次：无高水位 → 全量重建

	recorder.reset()
	fixThreatRewindMinute(t, minute) // 第二次：窗口内无新行

	scans := recorder.count(func(query string) bool {
		return strings.Contains(query, "FROM security_events") && strings.Contains(query, "GROUP BY client_ip")
	})
	if scans != 0 {
		t.Fatalf("无新事件的重复固化仍发出 %d 条全范围聚合扫描, want 0（只应更新高水位）", scans)
	}
	// 早退与 deltaTotal==0 分支等价：已固化计数不变。
	if got := threatRollupCountForMinute(t, minute.Format(threatRewindMinuteLayout)); got != 2 {
		t.Fatalf("重复固化后分钟 count=%d, want 2（早退不得丢已固化行）", got)
	}
}

// 正向回归：早退判定不得吞掉迟到插入——同分钟新增行（id 更大）必须照旧合并。
func TestThreatFixMinute_lateEventStillMergesAfterRepeat(t *testing.T) {
	countingMetricsDB(t)
	base := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)
	minute := base.Truncate(time.Minute)
	eventTime := minute.Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "942100", "SQL Injection", "blocked")
	fixThreatRewindMinute(t, minute)
	fixThreatRewindMinute(t, minute) // 无新行的一次重复固化不得提前"封口"

	seedThreatScreenEvent(t, eventTime, "93.184.216.9", "930100", "LFI", "blocked")
	fixThreatRewindMinute(t, minute)

	if got := threatRollupCountForMinute(t, minute.Format(threatRewindMinuteLayout)); got != 2 {
		t.Fatalf("迟到行合入后分钟 count=%d, want 2（早退只对无新行生效）", got)
	}
}

// 持续排队回退时 ensure 必须有界返回：成功/重启两条 continue 路径此前没有
// 迭代上限——队列每轮都有新回退入队（摄取持续补采）或并发回退反复触发重启时，
// 循环永不返回，warmer 协程与请求路径被粘住（每轮一次全量固化事务）。
// 缝「成功但立即重新入队」模拟该形态：有界实现 N 轮后返回 nil 且队列仍有项，
// 无界实现在断言窗口内不返回（由 stop 关闭解除粘住，随后按失败路径返回错误）。
func TestEnsureThreatRollup_boundedIterationsWhenRewindKeepsQueueing(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	oldApply := threatRollupRewindApplyInLock
	oldAttempts := threatRollupRewindApplyAttempts
	oldBackoff := threatRollupRewindApplyBackoff
	t.Cleanup(func() {
		threatRollupRewindApplyInLock = oldApply
		threatRollupRewindApplyAttempts = oldAttempts
		threatRollupRewindApplyBackoff = oldBackoff
		threatRollupRewindPending.Store(0)
		_ = takeThreatRollupReclassifyPending()
	})
	threatRollupRewindApplyAttempts = 2
	threatRollupRewindApplyBackoff = 0
	var calls atomic.Int64
	var stopped atomic.Bool
	threatRollupRewindApplyInLock = func(m time.Time, _ []time.Time) bool {
		calls.Add(1)
		if stopped.Load() {
			// 断言窗口结束：不再回填，让无界实现的失败路径也能退出并清理。
			threatRollupRewindPending.Store(0)
			return false
		}
		queueThreatRollupRewind(m) // 成功但队列永不排空（真实形态：持续补采排队）
		return true
	}
	threatRollupRewindPending.Store(0)
	_ = takeThreatRollupReclassifyPending()
	queueThreatRollupRewind(time.Now().UTC().Add(-15 * time.Minute).Truncate(time.Minute))

	done := make(chan error, 1)
	go func() { done <- ensureThreatRollup(1) }()

	var err error
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		stopped.Store(true)
		<-done
		t.Fatalf("持续排队回退时 ensure 未在限定轮数内返回（迭代无上限）: 已应用 %d 次", calls.Load())
	}
	if err != nil {
		t.Fatalf("有界返回必须是 nil（保留待处理项到下一轮节拍），got %v", err)
	}
	if got := threatRollupRewindPending.Load(); got == 0 {
		t.Fatal("有界返回后待处理项必须保留（下一轮 warmer 节拍继续）")
	}
	// 每轮 ensure 至多「批次间隙 + drain」两处应用；上限 2×attempts 轮。
	if got := calls.Load(); got > int64(4*threatRollupRewindApplyAttempts) {
		t.Fatalf("回退应用次数=%d, want <= %d（迭代轮数无上限）", got, 4*threatRollupRewindApplyAttempts)
	}
}
