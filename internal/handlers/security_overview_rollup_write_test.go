package handlers

// 总览预聚合（IP/规则维度）写入侧钉测：
//   - 固化写入两新表且含保留/私网地址（总览口径与主 rollup 相反——总量必须
//     完整，includes_reserved 披露）；攻击口径谓词同源（爬虫放行 logged 不计入）；
//   - 增量迟到行按 upsert 叠加（不重置）；fullRebuild 整分钟重写（不翻倍）；
//   - 原始行被保留期裁剪形态：保留旧值只并迟到差量；
//   - 原地改判回退的整分钟重固把两新表同步重写（陈旧行清除）；
//   - 升级回填：就绪标记缺失触发重建意图，覆盖底端到达意图起点后置位 '1'
//     且幂等（二次运行不再触发）。

import (
	"strconv"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func overviewIPCountFor(t *testing.T, minute, clientIP, action string) int {
	t.Helper()
	var total int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_ip_rollup WHERE minute=? AND client_ip=? AND action=?`,
		minute, clientIP, action).Scan(&total); err != nil {
		t.Fatal(err)
	}
	return total
}

func overviewRuleCountFor(t *testing.T, minute, ruleTriggered, ruleMsg, action string) int {
	t.Helper()
	var total int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rule_rollup WHERE minute=? AND rule_triggered=? AND rule_msg=? AND action=?`,
		minute, ruleTriggered, ruleMsg, action).Scan(&total); err != nil {
		t.Fatal(err)
	}
	return total
}

func overviewIPTotalForMinute(t *testing.T, minute string) int {
	t.Helper()
	var total int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_ip_rollup WHERE minute=?`, minute).Scan(&total); err != nil {
		t.Fatal(err)
	}
	return total
}

func fixThreatOverviewMinute(t *testing.T, m time.Time, fullRebuild bool) {
	t.Helper()
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := threatFixMinuteWithMode(tx, m, fullRebuild); err != nil {
		_ = tx.Rollback()
		t.Fatalf("fix minute: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// 固化写入：两新表按维度产出计数，保留/私网地址计入总览口径（与主 rollup
// 固化期排除相反），爬虫放行 logged 不计入（攻击口径谓词同源）。
func TestThreatOverviewRollup_fixMinuteWritesIPAndRuleDimensions(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "127.0.0.1", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, eventTime, "10.0.0.8", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, eventTime, "93.184.216.9", crawlerExemptRulePass, "爬虫验证通过", "logged")

	fixThreatOverviewMinute(t, m, false)

	if got := overviewIPCountFor(t, minute, "127.0.0.1", "blocked"); got != 1 {
		t.Fatalf("保留地址 127.0.0.1 计数=%d, want 1（总览口径必须含保留地址）", got)
	}
	if got := overviewIPCountFor(t, minute, "10.0.0.8", "blocked"); got != 1 {
		t.Fatalf("私网地址 10.0.0.8 计数=%d, want 1", got)
	}
	if got := overviewIPCountFor(t, minute, "93.184.216.7", "blocked"); got != 2 {
		t.Fatalf("同键重复事件计数=%d, want 2", got)
	}
	if got := overviewIPCountFor(t, minute, "93.184.216.9", "logged"); got != 0 {
		t.Fatalf("爬虫放行 logged 计数=%d, want 0（攻击口径谓词同源）", got)
	}
	if got := overviewRuleCountFor(t, minute, "942100", "SQL Injection", "blocked"); got != 2 {
		t.Fatalf("规则维度 942100 计数=%d, want 2", got)
	}
	if got := overviewRuleCountFor(t, minute, "941100", "XSS", "blocked"); got != 2 {
		t.Fatalf("规则维度 941100 计数=%d, want 2", got)
	}
	if total := overviewIPTotalForMinute(t, minute); total != 4 {
		t.Fatalf("总览 IP 维度总量=%d, want 4", total)
	}
	// 口径差异钉：同一分钟主 rollup（固化期排除保留/私网）总量=2。
	if got := threatRollupCountForMinute(t, minute); got != 2 {
		t.Fatalf("主 rollup 总量=%d, want 2（固化期排除保留/私网，与总览口径相反）", got)
	}
}

// 增量迟到行按 upsert 叠加（不重置）；fullRebuild 整分钟重写为全量（不翻倍）。
func TestThreatOverviewRollup_incrementalUpsertThenFullRebuild(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "942100", "SQL Injection", "blocked")
	fixThreatOverviewMinute(t, m, false)
	if got := overviewIPCountFor(t, minute, "93.184.216.7", "blocked"); got != 1 {
		t.Fatalf("首固计数=%d, want 1", got)
	}
	// 同分钟迟到行 → 增量 upsert 叠加，不重置。
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "942100", "SQL Injection", "blocked")
	fixThreatOverviewMinute(t, m, false)
	if got := overviewIPCountFor(t, minute, "93.184.216.7", "blocked"); got != 2 {
		t.Fatalf("增量叠加后计数=%d, want 2", got)
	}
	seedThreatScreenEvent(t, eventTime, "93.184.216.8", "941100", "XSS", "blocked")
	fixThreatOverviewMinute(t, m, false)
	if got := overviewIPTotalForMinute(t, minute); got != 3 {
		t.Fatalf("第二次增量后总量=%d, want 3", got)
	}
	// fullRebuild：整分钟重写为全量，不翻倍。
	fixThreatOverviewMinute(t, m, true)
	if got := overviewIPTotalForMinute(t, minute); got != 3 {
		t.Fatalf("fullRebuild 后总量=%d, want 3（整分钟重写，不得叠加翻倍）", got)
	}
	if got := overviewIPCountFor(t, minute, "93.184.216.7", "blocked"); got != 2 {
		t.Fatalf("fullRebuild 后 93.184.216.7 计数=%d, want 2", got)
	}
	if got := overviewRuleCountFor(t, minute, "941100", "XSS", "blocked"); got != 1 {
		t.Fatalf("fullRebuild 后规则维度计数=%d, want 1", got)
	}
}

// 原始行已被保留期裁剪（newTotal-lateTotal<oldTotal）：与主 rollup 同策略
// ——保留旧值，只并迟到行差量（整分钟重写会丢掉已固化历史）。
func TestThreatOverviewRollup_prunedRowsKeepOldAndMergeLateOnly(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, eventTime, "93.184.216.8", "941100", "XSS", "blocked")
	fixThreatOverviewMinute(t, m, false)
	// 保留期/行帽裁掉全部原始行（已固化历史不可再生），再补一条迟到行。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatal(err)
	}
	seedThreatScreenEvent(t, eventTime, "93.184.216.9", "930100", "LFI", "blocked")
	fixThreatOverviewMinute(t, m, true)

	if got := overviewIPCountFor(t, minute, "93.184.216.7", "blocked"); got != 1 {
		t.Fatalf("裁剪形态旧值 93.184.216.7=%d, want 1（保留旧行，不得整分钟重写）", got)
	}
	if got := overviewIPCountFor(t, minute, "93.184.216.8", "blocked"); got != 1 {
		t.Fatalf("裁剪形态旧值 93.184.216.8=%d, want 1", got)
	}
	if got := overviewIPCountFor(t, minute, "93.184.216.9", "blocked"); got != 1 {
		t.Fatalf("裁剪形态迟到行 93.184.216.9=%d, want 1（差量 upsert）", got)
	}
	if got := overviewRuleCountFor(t, minute, "930100", "LFI", "blocked"); got != 1 {
		t.Fatalf("裁剪形态迟到规则行=%d, want 1", got)
	}
	// 幂等：再次全量重固同样落在保留分支，旧值不得重复叠加。
	fixThreatOverviewMinute(t, m, true)
	if got := overviewIPTotalForMinute(t, minute); got != 3 {
		t.Fatalf("重复固化后总量=%d, want 3", got)
	}
}

// 原地改判来源回退删除分钟高水位 → 整分钟重固：两新表必须同步重写
// （陈旧行清除，而非增量叠加残留）。
func TestThreatOverviewRollup_reclassifyRewindRewritesMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Add(5 * time.Second).Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "93.184.216.7", "942100", "SQL Injection", "blocked")
	fixThreatOverviewMinute(t, m, false)
	// 预置陈旧总览行（client_ip 已不在事件中）——重固必须是整分钟重写。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_ip_rollup (minute, client_ip, action, count) VALUES (?, '203.0.113.99', 'blocked', 7)`, minute); err != nil {
		t.Fatal(err)
	}
	// 回退前提：分钟已被固化（有覆盖水位）——未固化时回退直接返回，改判
	// 由首次全量固化天然覆盖。
	seedThreatRewindWatermark(t, minute)
	ThreatRollupRewindTo(m, []time.Time{m})
	fixThreatOverviewMinute(t, m, false)
	if got := overviewIPCountFor(t, minute, "93.184.216.7", "blocked"); got != 1 {
		t.Fatalf("重固后计数=%d, want 1", got)
	}
	if got := overviewIPCountFor(t, minute, "203.0.113.99", "blocked"); got != 0 {
		t.Fatalf("陈旧总览行未随整分钟重固清除（count=%d）", got)
	}
}

// 升级回填：就绪标记缺失 → 首轮触发重建意图（覆盖重置），覆盖底端到达
// 意图起点后置位 '1' 并清除意图；历史已固化分钟的总览行被回填补齐；
// 幂等：置位后二次运行不再触发。
func TestEnsureThreatRollup_overviewRollupUpgradeBackfill(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, base)
	threatRollupRequestedHours.Store(0)
	t.Cleanup(func() { threatRollupRequestedHours.Store(0) })
	seedThreatRollupCoveredWindow(t, base, 24*7)
	// 升级形态：就绪标记缺失（覆盖窗fixture模拟已就绪系统，此处删键回退旧库）。
	if _, err := db.MetricsDB.Exec(`DELETE FROM metrics_state WHERE key=?`, threatRollupOverviewReadyKey); err != nil {
		t.Fatal(err)
	}
	// 36h 前已固化分钟：主 rollup 行 + 分钟高水位 + 原始事件，两新表无行
	// （旧版本固化产物）。覆盖窗宣称已覆盖——无升级触发时增量路径永不补写。
	eventTime := base.Add(-36 * time.Hour)
	eventMinute := eventTime.Truncate(time.Minute)
	minuteStr := eventMinute.Format(threatRewindMinuteLayout)
	seedThreatScreenEvent(t, eventTime.Format("2006-01-02 15:04:05"), "93.184.216.7", "942100", "SQL Injection", "blocked")
	var eventID int64
	if err := db.MetricsDB.QueryRow(`SELECT MAX(id) FROM security_events`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, family, rule, action, count) VALUES (?, '', '', 'SQL 注入', 'blocked', 1)`, minuteStr); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?)`,
		services.ThreatRollupEventHighwaterPrefix+minuteStr, strconv.FormatInt(eventID, 10)); err != nil {
		t.Fatal(err)
	}

	// 首轮：触发重建意图（覆盖重置），总览标记不得置位（回填未完成）。
	if err := ensureThreatRollup(24); err != nil {
		t.Fatal(err)
	}
	var intent int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, services.ThreatRollupRebuildFromKey).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	if intent != 1 {
		t.Fatal("首轮后重建意图未持久化（总览升级回填必须由 rebuild_from 驱动到覆盖底端）")
	}
	var ready string
	err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupOverviewReadyKey).Scan(&ready)
	if err == nil && ready == "1" {
		t.Fatal("回填未完成就置位总览就绪标记（读侧会提前停用 raw 回退）")
	}

	// 续做：覆盖底端逐轮推进，到达意图起点后置位 '1' 并清除意图。
	converged := false
	for range 12 {
		if err := ensureThreatRollup(24); err != nil {
			t.Fatal(err)
		}
		if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupOverviewReadyKey).Scan(&ready); err == nil && ready == "1" {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatalf("回填未收敛（overview_rollup_ready=%q），24 批/轮 × 12 轮应覆盖 7 天窗口", ready)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, services.ThreatRollupRebuildFromKey).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	if intent != 0 {
		t.Fatal("覆盖到达意图起点后必须清除重建标记")
	}
	// 历史已固化分钟的总览行被回填补齐（含保留地址口径的事件计数）。
	if got := overviewIPCountFor(t, minuteStr, "93.184.216.7", "blocked"); got != 1 {
		t.Fatalf("回填后历史分钟总览行=%d, want 1", got)
	}
	if got := overviewRuleCountFor(t, minuteStr, "942100", "SQL Injection", "blocked"); got != 1 {
		t.Fatalf("回填后历史分钟规则行=%d, want 1", got)
	}

	// 幂等：二次运行不再触发（意图不得重建，历史行不得翻倍）。
	if err := ensureThreatRollup(24); err != nil {
		t.Fatal(err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, services.ThreatRollupRebuildFromKey).Scan(&intent); err != nil {
		t.Fatal(err)
	}
	if intent != 0 {
		t.Fatal("就绪标记置位后二次运行不得再触发重建意图")
	}
	if got := overviewIPCountFor(t, minuteStr, "93.184.216.7", "blocked"); got != 1 {
		t.Fatalf("幂等运行后历史分钟总览行=%d, want 1", got)
	}
}
