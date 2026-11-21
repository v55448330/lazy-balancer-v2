package notify

// audit152/153 修复批回归（notify 域）：聚合器锁外读与首条单发、日报按用户
// send_time 分槽（含宽限届满/is_test 水位）、昨日窗口本地日历日、认证计数按日
// 分桶（含时区变更清理边界）、邮件正文转义与日报 Content-Type 跟随渲染格式、
// MCP 推送前置通道过滤、峰值请求差分（含首样本无基线）、自动封禁窗口口径、
// TOP 攻击源去重、配置读错误上抛、API 密钥到期时间宽容解析（含 UTC 换算）。
//
// 测试顺序说明：本文件不使用 t.Parallel——其中若干用例改写 time.Local /
// db.DB / 推送 hook 等包级状态，必须独占执行。

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// testLocShanghai 测试用配置时区（与 TZ=Asia/Shanghai 同形，不依赖宿主 TZ）。
func testLocShanghai(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("load Asia/Shanghai: %v", err)
	}
	return loc
}

// withLocalLocation 临时把 time.Local 指到 loc（=TZ=Asia/Shanghai 进程形态；
// 日报日历日时区未注入时取 time.Local）。
func withLocalLocation(t *testing.T, loc *time.Location) {
	t.Helper()
	old := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = old })
}

// newDailyTestDBs 三库最小形状（main/metrics/audit）：覆盖 CollectDailyData 的
// 全部查询点，缺表会让查询静默返错、把断言变成假绿。
func newDailyTestDBs(t *testing.T) {
	t.Helper()
	open := func(name string) *sql.DB {
		d, err := sql.Open("sqlite", t.TempDir()+"/"+name)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		return d
	}
	oldMain, oldMetrics, oldAudit := db.DB, db.MetricsDB, db.AuditDB
	mainDB, metricsDB, auditDB := open("main.db"), open("metrics.db"), open("audit.db")
	db.DB, db.MetricsDB, db.AuditDB = mainDB, metricsDB, auditDB
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = oldMain, oldMetrics, oldAudit
		mainDB.Close()
		metricsDB.Close()
		auditDB.Close()
	})

	ddl := []string{
		`CREATE TABLE notification_daily (user_id INTEGER PRIMARY KEY, config TEXT NOT NULL DEFAULT '', updated_at TEXT)`,
		`CREATE TABLE notification_deliveries (
			id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
			event_type TEXT NOT NULL, level TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL,
			body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0, error TEXT DEFAULT '', created_at TEXT NOT NULL,
			sent_at DATETIME, is_test INTEGER NOT NULL DEFAULT 0, retry_channel_ids TEXT NOT NULL DEFAULT '',
			node TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE notification_channels (
			id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
			style_config TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE autoban_recidivism (identity TEXT PRIMARY KEY, offense_count INTEGER NOT NULL DEFAULT 0,
			last_ban_at TEXT NOT NULL DEFAULT '', escalated_duration TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE cert_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT DEFAULT '',
			status TEXT DEFAULT '', expires_at TEXT DEFAULT '')`,
		`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master INTEGER DEFAULT 1)`,
		`INSERT INTO global_config (id, is_master) VALUES (1, 1)`,
		`CREATE TABLE task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT DEFAULT '',
			started_at TEXT DEFAULT '', status TEXT DEFAULT '')`,
		`CREATE TABLE auto_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT '',
			status TEXT DEFAULT '')`,
		`CREATE TABLE security_crs_version (id INTEGER PRIMARY KEY, version TEXT DEFAULT '')`,
		`CREATE TABLE security_ip2region_version (id INTEGER PRIMARY KEY, version TEXT DEFAULT '')`,
		`CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
			expires_at DATETIME, is_enabled INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE mcp_tool_stats (date TEXT NOT NULL, tool TEXT NOT NULL, key_id INTEGER NOT NULL DEFAULT 0,
			calls INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(100) NOT NULL,
			mode VARCHAR(10) NOT NULL DEFAULT 'slave', ip_address VARCHAR(45) NOT NULL,
			port INTEGER DEFAULT 8000, is_approved BOOLEAN DEFAULT FALSE, status VARCHAR(20) DEFAULT 'offline')`,
		`CREATE TABLE cluster_node_daily_stats (date TEXT NOT NULL, node TEXT NOT NULL,
			stats_json TEXT NOT NULL DEFAULT '{}', updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (date, node))`,
	}
	for _, q := range ddl {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatalf("main DDL %q: %v", q, err)
		}
	}
	metricsDDL := []string{
		`CREATE TABLE security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_time TEXT NOT NULL,
			rule_name TEXT DEFAULT '', client_ip TEXT DEFAULT '', uri TEXT DEFAULT '',
			event_type TEXT DEFAULT '', action TEXT DEFAULT '')`,
		`CREATE TABLE metrics_history (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT,
			timestamp TEXT NOT NULL, requests_total INTEGER DEFAULT 0,
			bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0)`,
	}
	for _, q := range metricsDDL {
		if _, err := db.MetricsDB.Exec(q); err != nil {
			t.Fatalf("metrics DDL %q: %v", q, err)
		}
	}
	if _, err := db.AuditDB.Exec(`CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,
		action TEXT DEFAULT '', resource TEXT DEFAULT '', detail TEXT DEFAULT '',
		created_at TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatalf("audit DDL: %v", err)
	}
}

func mustExec(t *testing.T, d *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := d.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// ensureBusStoppedForTest 停掉分发循环并清空队列：让 Publish 走「队列未装配」
// 丢弃分支（droppedCount），从而可观测「是否发布了事件」；不注册 cleanup
// （避免 close 已关闭 stopCh），后续用 resetNotifyBusForTest 的测试会自建新通道。
func ensureBusStoppedForTest(t *testing.T) {
	t.Helper()
	if started.Load() {
		Stop()
		awaitLoopExit(t)
		started.Store(false)
	}
	stopOnce = sync.Once{}
	queue = nil
	droppedCount.Store(0)
}

// ---- NOTIF-152-01 聚合器：首个拦截判定必须在锁内 --------------------------

// TestRecordBlockedEventNoUnlockedRead 并发摄取 + 窗口 flush：旧实现在 Unlock
// 之后读 blockedCurrent.count——flush 已把指针置 nil（nil 解引用）或轮换到
// 新窗口（迟到事件被当首条重发）。此测试以 -race 捕获数据竞争（RED 证据）。
func TestRecordBlockedEventNoUnlockedRead(t *testing.T) {
	resetBlockedStateForTest(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				RecordBlockedEvent("r1")
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				flushBlockedWindow()
			}
		}
	}()
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
	resetBlockedStateForTest(t)
}

// TestRecordBlockedEventFirstOnlyPublishPerWindow 无并发、可观测断言：同一窗口
// 内只有首条拦截立即发布一次（后续进聚合），窗口 flush 再追加一条汇总。
// 旧实现的锁外首条判定在「flush 置 nil / 窗口轮换」竞态下会重发首条——本用例
// 与 TestRecordBlockedEventNoUnlockedRead（需 -race 才有 RED 证据）互补：
// 后者是压测，本用例是确定性的行为钉（NOTIF153-10）。
// 发布器曾是形参（publish func(Event)）但从未被调用——本用例传 no-op 仍观察到
// 真实发布；该死缝已删除，断言只能经包级总线状态（DroppedCount）建立。
func TestRecordBlockedEventFirstOnlyPublishPerWindow(t *testing.T) {
	resetBlockedStateForTest(t)
	ensureBusStoppedForTest(t) // queue=nil：Publish 走丢弃计数，可观测「发布了几条」
	before := DroppedCount()
	RecordBlockedEvent("r1")
	RecordBlockedEvent("r1")
	RecordBlockedEvent("r2")
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("同窗口三次拦截发布 %d 条, want 1（仅首条立即告警）", got)
	}
	flushBlockedWindow()
	if got := DroppedCount() - before; got != 2 {
		t.Fatalf("窗口 flush 后累计发布 %d 条, want 2（首条 + 汇总）", got)
	}
	// flush 已清空窗口：再次 flush 无发布。
	flushBlockedWindow()
	if got := DroppedCount() - before; got != 2 {
		t.Fatalf("空窗口 flush 发布了事件（累计 %d 条, want 2）", got)
	}
	resetBlockedStateForTest(t)
}

// NOTIF154-P3-01：cross-midnight 槽——23:58 槽的 5 分钟宽限窗跨零点，次日
// 00:02 排程按昨日槽触发；投递侧 dailySlotDue 必须用同一槽（此前按今日
// 23:58 判定为未到期 → 0 投递并在宽限窗内重复空跑）。
func TestDailySlotCandidateCrossMidnight(t *testing.T) {
	loc := testLocShanghai(t)
	day := func(d, hh, mm int) time.Time { return time.Date(2026, 11, d, hh, mm, 0, 0, loc) }
	if slot, ok := DailySlotCandidate(day(20, 0, 2), "23:58", loc); !ok || !slot.Equal(day(19, 23, 58)) {
		t.Fatalf("00:02 的 23:58 槽 = %v/%v, want 昨日 23:58 且到期", slot, ok)
	}
	if slot, ok := DailySlotCandidate(day(20, 9, 4), "09:00", loc); !ok || !slot.Equal(day(20, 9, 0)) {
		t.Fatalf("09:04 的 09:00 槽 = %v/%v, want 当日 09:00 且到期", slot, ok)
	}
	if _, ok := DailySlotCandidate(day(20, 9, 6), "09:00", loc); ok {
		t.Fatal("超宽限 09:06 不得判定到期")
	}
	if _, ok := DailySlotCandidate(day(20, 23, 0), "23:58", loc); ok {
		t.Fatal("槽前 23:00 不得判定到期")
	}
}

// 端到端：00:02 的 23:58 槽必须真实投递一份日报，同槽重复触发不重复发。
func TestDeliverDailyForAllCrossMidnightSlot(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	newDailyTestDBs(t)
	mustExec(t, db.DB, `INSERT INTO notification_daily (user_id, config) VALUES
		(21, '{"enabled":true,"send_time":"23:58"}')`)
	ctx := withDailySlotScope(context.Background())
	at := time.Date(2026, 11, 20, 0, 2, 0, 0, time.Local) // 19 日 23:58 槽宽限内
	if _, err := DeliverDailyForAll(ctx, at); err != nil {
		t.Fatalf("跨零点定时日报: %v", err)
	}
	if got := dailyRows(t, 21); got != 1 {
		t.Fatalf("跨零点槽投递份数=%d, want 1（排程按昨日槽触发，投递侧必须同源）", got)
	}
	if _, err := DeliverDailyForAll(ctx, at); err != nil {
		t.Fatalf("同槽重复触发: %v", err)
	}
	if got := dailyRows(t, 21); got != 1 {
		t.Fatalf("同槽重复触发后份数=%d, want 1", got)
	}
}

// SEC154-P3-01：聚合文案按窗口实际跨度生成——ticker 相位与首个事件无关，
// 窗口可能只开启几秒，固定断言「5 分钟内」会夸大攻击持续时间。
func TestBlockedAggregateBodyUsesActualWindowSpan(t *testing.T) {
	short := &blockedWindowState{start: time.Now().Add(-2 * time.Second), count: 80,
		topRule: map[string]int{"SQLi": 80}}
	evt := blockedAggregateEvent(short)
	if strings.Contains(evt.Body, "5 分钟") {
		t.Fatalf("短窗口文案仍断言 5 分钟: %q", evt.Body)
	}
	if !strings.Contains(evt.Body, "秒内拦截 80 次") {
		t.Fatalf("短窗口文案未含实际跨度: %q", evt.Body)
	}
	if evt.Fields["1"] == "5" {
		t.Fatalf("Fields[1] 仍是固定 5 分钟: %v", evt.Fields)
	}
	full := &blockedWindowState{start: time.Now().Add(-blockedWindow), count: 80,
		topRule: map[string]int{"SQLi": 80}}
	if got := blockedAggregateEvent(full).Body; !strings.Contains(got, "5 分钟内拦截 80 次") {
		t.Fatalf("满窗文案=%q, want 5 分钟", got)
	}
}

func resetBlockedStateForTest(t *testing.T) {
	t.Helper()
	blockedMu.Lock()
	blockedCurrent = nil
	blockedMu.Unlock()
}

// ---- NOTIF-152-02 日报 per-user send_time 分槽 ------------------------------

// TestDeliverDailyForAllScheduledPerUserSlot 定时路径（ctx 带日报任务 ID）只投
// 各自 send_time 槽到期的用户；手动触发（无任务 ID）保持全员强发。
func TestDeliverDailyForAllScheduledPerUserSlot(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	newDailyTestDBs(t)
	mustExec(t, db.DB, `INSERT INTO notification_daily (user_id, config) VALUES
		(11, '{"enabled":true,"send_time":"09:00"}'),
		(12, '{"enabled":true,"send_time":"10:00"}')`)

	// 定时路径标记由 DailyReportRun 在 trigger=auto 时注入（与手动执行区分）。
	ctx := withDailySlotScope(withTaskID(context.Background(), "notification-daily-report"))
	at9 := time.Date(2026, 11, 20, 9, 0, 30, 0, time.Local)

	if _, err := DeliverDailyForAll(ctx, at9); err != nil {
		t.Fatalf("09:00 定时日报: %v", err)
	}
	if got := dailyRows(t, 11); got != 1 {
		t.Fatalf("09:00 用户 11 投递份数=%d, want 1", got)
	}
	if got := dailyRows(t, 12); got != 0 {
		t.Fatalf("09:00 用户 12（10:00 槽）不应投递，得 %d 份", got)
	}

	// 同槽重复触发不得重复投递（同轮重入/多一次 tick）。
	if _, err := DeliverDailyForAll(ctx, at9); err != nil {
		t.Fatalf("09:00 重复触发: %v", err)
	}
	if got := dailyRows(t, 11); got != 1 {
		t.Fatalf("同槽重复触发后用户 11 份数=%d, want 1", got)
	}

	at10 := time.Date(2026, 11, 20, 10, 0, 20, 0, time.Local)
	if _, err := DeliverDailyForAll(ctx, at10); err != nil {
		t.Fatalf("10:00 定时日报: %v", err)
	}
	if got := dailyRows(t, 12); got != 1 {
		t.Fatalf("10:00 用户 12 投递份数=%d, want 1", got)
	}
	if got := dailyRows(t, 11); got != 1 {
		t.Fatalf("10:00 不应重复投递用户 11，得 %d 份", got)
	}

	// 宽限届满（now-slot > 5min）不再追溯：11 的 09:00 槽在 09:06 必须跳过
	// （NOTIF153-11 未覆盖分支）。
	at906 := time.Date(2026, 11, 20, 9, 6, 0, 0, time.Local)
	if _, err := DeliverDailyForAll(ctx, at906); err != nil {
		t.Fatalf("09:06 定时日报: %v", err)
	}
	if got := dailyRows(t, 11); got != 1 {
		t.Fatalf("超宽限槽被补发：用户 11 份数=%d, want 1", got)
	}

	// is_test=1 的测试发送不压槽水位：用户 13 的 09:00 槽前只有一次测试发送，
	// 定时轮仍须真实投递（dailySlotDue 的水位只认 is_test=0）。
	mustExec(t, db.DB, `INSERT INTO notification_daily (user_id, config) VALUES (13, '{"enabled":true,"send_time":"09:00"}')`)
	mustExec(t, db.DB, `INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, is_test, created_at)
		VALUES (13, ?, 'info', '每日日报（测试）', '{}', 'sent', 1, 1, '2026-11-20 09:00:00')`, EvtDailyReport)
	if _, err := DeliverDailyForAll(ctx, time.Date(2026, 11, 20, 9, 1, 0, 0, time.Local)); err != nil {
		t.Fatalf("09:01 定时日报: %v", err)
	}
	if got := dailyRows(t, 13); got != 1 {
		t.Fatalf("is_test 测试发送压住了槽水位：用户 13 定时投递份数=%d, want 1", got)
	}

	// 手动触发（管理端「立即发送全员日报」）保持全员：不受 send_time 槽约束。
	at15 := time.Date(2026, 11, 20, 15, 0, 0, 0, time.Local)
	if _, err := DeliverDailyForAll(context.Background(), at15); err != nil {
		t.Fatalf("手动全员日报: %v", err)
	}
	if dailyRows(t, 11) != 2 || dailyRows(t, 12) != 2 {
		t.Fatalf("手动触发应各再投 1 份，得 11=%d 12=%d", dailyRows(t, 11), dailyRows(t, 12))
	}
}

func dailyRows(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries
		WHERE user_id=? AND event_type=? AND is_test=0`, userID, EvtDailyReport).Scan(&n); err != nil {
		t.Fatalf("count daily rows: %v", err)
	}
	return n
}

// ---- NOTIF-152-03 昨日窗口=本地日历日 --------------------------------------

// TestCollectDailyDataLocalCalendarDay 09:00（+08:00）采集昨日：窗口必须是本地
// 日历日 [11-19 00:00, 11-20 00:00) 半开区间，而不是 UTC 截断日。
func TestCollectDailyDataLocalCalendarDay(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	newDailyTestDBs(t)
	rows := []struct{ at, ip string }{
		{"2026-11-18 15:59:59", "10.0.0.1"}, // 本地 11-18 23:59:59 → 窗口前
		{"2026-11-18 16:00:00", "10.0.0.2"}, // 本地 11-19 00:00:00 → 窗口内（含）
		{"2026-11-19 15:59:59", "10.0.0.3"}, // 本地 11-19 23:59:59 → 窗口内
		{"2026-11-19 16:00:00", "10.0.0.4"}, // 本地 11-20 00:00:00 → 窗口外（不含）
	}
	for _, r := range rows {
		mustExec(t, db.MetricsDB, `INSERT INTO security_events (event_time, action, client_ip) VALUES (?, 'blocked', ?)`, r.at, r.ip)
	}
	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.Local)
	d, err := CollectDailyData(context.Background(), now)
	if err != nil {
		t.Fatalf("CollectDailyData: %v", err)
	}
	if d.Date != "2026-11-19" {
		t.Fatalf("日期标签=%q, want 2026-11-19（本地日历日）", d.Date)
	}
	// 计数相同不代表窗口相同（旧实现偏移 8 小时也能凑出 2 条）——按 IP 集合钉钉子。
	if d.Requests != 2 {
		t.Fatalf("窗口请求数=%d, want 2（本地日历日半开区间）", d.Requests)
	}
	if !strings.Contains(d.TopIPs, "10.0.0.2") || !strings.Contains(d.TopIPs, "10.0.0.3") {
		t.Fatalf("窗口内 IP 缺失：%q（want 含 10.0.0.2 与 10.0.0.3）", d.TopIPs)
	}
	if strings.Contains(d.TopIPs, "10.0.0.1") || strings.Contains(d.TopIPs, "10.0.0.4") {
		t.Fatalf("窗口外 IP 被计入：%q（不应含 10.0.0.1 / 10.0.0.4）", d.TopIPs)
	}
}

// ---- NOTIF-152-04 认证计数按日分桶（跨日不覆盖） ---------------------------

// TestAuthCountersBucketByDate 同一进程内跨两天累加：昨日桶在次日仍可读，
// 日报读昨日标签不会被今天的事件清零/覆盖。
func TestAuthCountersBucketByDate(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	authCounters.mu.Lock()
	authCounters.days = nil
	authCounters.mu.Unlock()
	t.Cleanup(func() {
		authCounters.mu.Lock()
		authCounters.days = nil
		authCounters.mu.Unlock()
	})
	day1 := time.Date(2026, 11, 19, 10, 0, 0, 0, time.Local)
	day2 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.Local)
	noteAuthEventAt(EvtLoginSuccess, day1)
	noteAuthEventAt(EvtLoginSuccess, day1)
	noteAuthEventAt(EvtLoginFailed, day1)
	noteAuthEventAt(EvtMFAVerifyFailed, day1)
	noteAuthEventAt(EvtLoginFailed, day2)
	noteAuthEventAt(EvtLoginFailed, day2)

	ok, fail, mfa := readAuthCounters("2026-11-19")
	if ok != 2 || fail != 1 || mfa != 1 {
		t.Fatalf("昨日桶=%d/%d/%d, want 2/1/1", ok, fail, mfa)
	}
	ok, fail, mfa = readAuthCounters("2026-11-20")
	if ok != 0 || fail != 2 || mfa != 0 {
		t.Fatalf("今日桶=%d/%d/%d, want 0/2/0", ok, fail, mfa)
	}
	// 有界：只保留昨天及更晚的桶（更早的桶被清理），且昨日桶内容不被次日
	// 写入改动（此前用 `_, _, _ = readAuthCounters(...)` 空语句，昨日桶在次日
	// 写入后是否仍完整从未被断言）。
	if ok2, fail2, mfa2 := readAuthCounters("2026-11-19"); ok2 != 2 || fail2 != 1 || mfa2 != 1 {
		t.Fatalf("次日写入后昨日桶=%d/%d/%d, want 2/1/1（不得被清理/覆盖）", ok2, fail2, mfa2)
	}
	if got := authCountersDaysLen(); got != 2 {
		t.Fatalf("认证计数桶数=%d, want 2（今天+昨天；更早桶已清理）", got)
	}
}

// TestAuthCountersTimezoneShiftKeepsNewerBucket 清理边界（NOTIF153 P3 计数桶
// 跨时区）：设置页切时区会让本地日期标签整体前移——在「旧时区今天」写入的桶
// 在新时区下标签是明天，旧实现的 {date, date-1} 白名单会把它当陈旧数据删掉，
// 昨日/当日报告读数从 0 起算。保留 ≥昨天（含未来标签）后桶不再丢失。
func TestAuthCountersTimezoneShiftKeepsNewerBucket(t *testing.T) {
	authCounters.mu.Lock()
	authCounters.days = nil
	authCounters.mu.Unlock()
	t.Cleanup(func() {
		authCounters.mu.Lock()
		authCounters.days = nil
		authCounters.mu.Unlock()
	})
	// 东八区 11-20 00:30 → 桶 "2026-11-20"。
	withLocalLocation(t, testLocShanghai(t))
	noteAuthEventAt(EvtLoginSuccess, time.Date(2026, 11, 20, 0, 30, 0, 0, time.Local))
	noteAuthEventAt(EvtLoginSuccess, time.Date(2026, 11, 20, 0, 40, 0, 0, time.Local))
	// 切到 UTC-10（跨日西移）：同一时刻本地标签回退到 "2026-11-19"。
	honolulu, err := time.LoadLocation("Pacific/Honolulu")
	if err != nil {
		t.Fatalf("load Pacific/Honolulu: %v", err)
	}
	withLocalLocation(t, honolulu)
	noteAuthEventAt(EvtLoginFailed, time.Date(2026, 11, 19, 20, 0, 0, 0, time.Local))
	if ok, _, _ := readAuthCounters("2026-11-20"); ok != 2 {
		t.Fatalf("时区西移后新时区下「明天」标签桶被删（成功计数=%d, want 2）", ok)
	}
	if _, fail, _ := readAuthCounters("2026-11-19"); fail != 1 {
		t.Fatalf("新时区下的今天桶失败计数=%d, want 1", fail)
	}
	if got := authCountersDaysLen(); got != 2 {
		t.Fatalf("桶数=%d, want 2（未来标签桶保留，仍受有界约束）", got)
	}
}

func authCountersDaysLen() int {
	authCounters.mu.Lock()
	defer authCounters.mu.Unlock()
	return len(authCounters.days)
}

// ---- LNK-task-152-01 API 密钥到期时间宽容解析 ----------------------------

func TestParseAPIKeyExpiryDriverForms(t *testing.T) {
	cases := []struct{ raw, wantUTC string }{
		{"2026-11-19 16:00:00+00:00", "2026-11-19 16:00:00"}, // glebarez 读回形态
		{"2026-11-19 16:00:00", "2026-11-19 16:00:00"},       // 历史裸墙钟（按 UTC）
		{"2026-11-19T16:00:00Z", "2026-11-19 16:00:00"},      // RFC3339
		{"2026-11-19T16:00:00", "2026-11-19 16:00:00"},       // 无时区 T 形态
		// 带偏移必须按偏移换算 UTC（16:00+08:00 = 08:00Z）。此前该用例 wantUTC=""
		// 只断「解析成功」，带偏移值被解析成错误时区仍全绿（NOTIF153-12）。
		{"2026-11-19 16:00:00.000+08:00", "2026-11-19 08:00:00"},
	}
	for _, c := range cases {
		got, ok := parseAPIKeyExpiry(c.raw)
		if !ok {
			t.Fatalf("解析失败：%q", c.raw)
		}
		if got.UTC().Format(dailyTimeLayout) != c.wantUTC {
			t.Fatalf("%q → %s, want UTC %s", c.raw, got.UTC().Format(dailyTimeLayout), c.wantUTC)
		}
	}
	// 裸墙钟按 UTC 解释（与旧实现 time.Parse 语义一致，防存量数据到期日漂移）：
	// 位置必须是 UTC，而不是进程本地时区。
	if got, ok := parseAPIKeyExpiry("2026-11-19 16:00:00"); !ok {
		t.Fatalf("裸墙钟解析失败")
	} else if got.Location() != time.UTC || !got.Equal(time.Date(2026, 11, 19, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("裸墙钟=%s（loc=%v），want 2026-11-19T16:00:00Z", got, got.Location())
	}
	if _, ok := parseAPIKeyExpiry("不是时间"); ok {
		t.Fatalf("垃圾输入不应解析成功")
	}
	if _, ok := parseAPIKeyExpiry(""); ok {
		t.Fatalf("空串不应解析成功")
	}
}

func TestAPIKeyExpiryDaysCalendarCeil(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	now := time.Date(2026, 11, 19, 16, 0, 0, 0, time.Local)
	cases := []struct {
		exp  time.Time
		want int
	}{
		{time.Date(2026, 11, 19, 23, 30, 0, 0, time.Local), 0}, // 今天到期
		{time.Date(2026, 11, 20, 0, 30, 0, 0, time.Local), 1},  // 明日凌晨=1 天
		{time.Date(2026, 11, 26, 0, 30, 0, 0, time.Local), 7},  // 7 个日历日
		{time.Date(2026, 11, 18, 12, 0, 0, 0, time.Local), -1}, // 已过期
		{time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC), 1},     // UTC 输入按本地日换算（16:00+08）
	}
	for _, c := range cases {
		if got := apiKeyExpiryDays(c.exp, now); got != c.want {
			t.Fatalf("exp=%s → %d 天, want %d", c.exp, got, c.want)
		}
	}
}

// ---- SYSH-152-14 GetDailyConfig 错误上抛 ----------------------------------

func TestGetDailyConfigDistinguishesErrors(t *testing.T) {
	// 表缺失=真实读失败，必须上抛（旧实现把任何错误都当「无行=默认」）。
	database := newNotifyTestDB(t)
	if _, err := GetDailyConfig(1); err == nil {
		t.Fatalf("表缺失时 GetDailyConfig 返回 nil error（故障被伪装成默认配置）")
	}
	// 表存在但无行=默认配置，不报错。
	mustExec(t, database, `CREATE TABLE notification_daily (user_id INTEGER PRIMARY KEY, config TEXT NOT NULL DEFAULT '', updated_at TEXT)`)
	cfg, err := GetDailyConfig(1)
	if err != nil {
		t.Fatalf("无行应回落默认：%v", err)
	}
	if !cfg.Enabled || cfg.SendTime != "09:00" {
		t.Fatalf("默认配置=%+v, want enabled+09:00", cfg)
	}
}

// ---- NOTIF-152-05 事件邮件正文一律转义 ------------------------------------

func TestWrapEmailHTMLEscapesEventBody(t *testing.T) {
	body := `外部输入 <a href="http://evil.example/x">点我</a> <script>alert(1)</script>`
	got := wrapEmailHTML(Message{EventType: EvtLoginFailed, Level: string(LevelWarn), Title: "登录失败"},
		"登录失败", body, time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC))
	if strings.Contains(got, `<a href="http://evil.example/x">`) || strings.Contains(got, "<script>") {
		t.Fatalf("事件正文未经转义直接进 HTML：\n%s", got)
	}
	if !strings.Contains(got, "&lt;a href=") || !strings.Contains(got, "&lt;script&gt;") {
		t.Fatalf("事件正文应转义为实体：\n%s", got)
	}
}

// ---- NOTIF153-02 日报邮件 Content-Type 跟随实际渲染格式 --------------------

// TestEmailDailyReportContentTypeFollowsRenderedFormat 日报格式选成 markdown/
// text/json 时，正文里的未转义 '<script>' 只能以 text/plain 发送；只有实际
// 渲染格式为 html 才按 text/html。格式来源与 renderDailyForChannelFormat
// 同源（经 Message.ContentFormat 传到 Sender）。
func TestEmailDailyReportContentTypeFollowsRenderedFormat(t *testing.T) {
	cases := []struct {
		name       string
		format     string
		wantCT     string
		wantScript bool // 正文应原样含 <script>（text/plain 上下文里是字面文本）
	}{
		{name: "markdown 日报按纯文本发送", format: "markdown", wantCT: "text/plain; charset=UTF-8", wantScript: true},
		{name: "json 日报按纯文本发送", format: "json", wantCT: "text/plain; charset=UTF-8"},
		{name: "html 日报按 text/html 发送", format: "html", wantCT: "text/html; charset=UTF-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newNotifySettingsDB(t)
			srv := newFakeSMTPServer(t)
			host, port, _ := net.SplitHostPort(srv.addr())
			if err := SetSettings(map[string]string{
				KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com",
			}); err != nil {
				t.Fatalf("写入 SMTP 设置失败: %v", err)
			}
			payload := `{"date":"2026-11-20","items":["top_ips"],"values":{"top_ips":"<script>alert(1)</script>"},"formats":{"email":"` + tc.format + `"}}`
			body, format := renderDailyForChannelFormat(Message{EventType: EvtDailyReport, Body: payload}, "email", "")
			if format != tc.format {
				t.Fatalf("渲染格式=%q, want %q（格式决序单源）", format, tc.format)
			}
			if err := sendToChannel(context.Background(), "email", `{"email":"ops@example.com"}`,
				Message{EventType: EvtDailyReport, Level: "info", Title: "每日日报", Body: body, ContentFormat: format}); err != nil {
				t.Fatalf("sendToChannel(email): %v", err)
			}
			_, _, data := srv.capture()
			if !strings.Contains(data, "Content-Type: "+tc.wantCT) {
				t.Fatalf("Content-Type ≠ %q：\n%s", tc.wantCT, data)
			}
			decoded := decodeMailBodyForTest(t, data)
			if tc.wantScript && !strings.Contains(decoded, "<script>alert(1)</script>") {
				t.Fatalf("纯文本日报正文丢失原始内容（应原样保留为字面文本）：\n%s", decoded)
			}
			if tc.format != "html" && strings.Contains(data, "Content-Type: text/html") {
				t.Fatalf("非 html 日报被按 HTML 发送（注入面重新打开）")
			}
		})
	}
}

// decodeMailBodyForTest 取 RFC822 正文（首个空行后 base64）解码还原。
func decodeMailBodyForTest(t *testing.T, data string) string {
	t.Helper()
	var b64 strings.Builder
	inBody := false
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if inBody && line != "" {
			b64.WriteString(line)
			continue
		}
		if line == "" {
			inBody = true
		}
	}
	body, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		t.Fatalf("正文 base64 解码失败: %v", err)
	}
	return string(body)
}

// ---- NOTIF-152-06 MCP 推送前置通道过滤 ------------------------------------

// TestDispatchSkipsPushForExplicitEmptyChannels 显式空选接收通道（channel_ids='[]'）
// 的用户不再收 MCP 实时推送（与通道投递同源三态）；普通订阅用户照常推送。
func TestDispatchSkipsPushForExplicitEmptyChannels(t *testing.T) {
	ensureBusStoppedForTest(t)
	database := newNotifyTestDB(t)
	// user 1：显式空选（不投递任何通道）；user 2：普通显式订阅（无通道选择=全部）。
	mustExec(t, database, `INSERT INTO notification_channels (user_id, type, target) VALUES (1,'webhook','http://x'), (2,'webhook','http://y')`)
	mustExec(t, database, `INSERT INTO notification_subscriptions (user_id, event_type, min_level, channel_ids) VALUES
		(1, ?, 'info', '[]'), (2, ?, 'info', '')`, EvtLoginFailed, EvtLoginFailed)

	var mu sync.Mutex
	got := map[int64]int{}
	RegisterPushHook(func(uid int64, _ Message) {
		mu.Lock()
		got[uid]++
		mu.Unlock()
	})
	t.Cleanup(func() { RegisterPushHook(nil) })

	evt := Event{Type: EvtLoginFailed, Level: LevelWarn, Fields: map[string]string{"1": "u", "2": "bad", "3": "1.2.3.4"}}
	dispatch(evt)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n2 := got[2]
		mu.Unlock()
		if n2 > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if got[1] != 0 {
		t.Fatalf("显式空选通道的用户仍收到 MCP 推送（%d 次）", got[1])
	}
	if got[2] != 1 {
		t.Fatalf("普通订阅用户 MCP 推送次数=%d, want 1", got[2])
	}
}

// ---- NOTIF-152-08 峰值请求=窗口差分（非累计计数器原值） --------------------

func TestCollectDailyDataPeakQPSFromCounterDiff(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	newDailyTestDBs(t)
	// 全局行（rule_id IS NULL）累计计数器：窗内增量 30/60/50，末点归零重计 20。
	// 时间戳为 UTC 墙钟串（security_events/metrics_history 的存储口径）；本地
	// 11-19 00:00 = UTC 11-18 16:00。
	seeds := []struct {
		ts  string
		val int64
	}{
		{"2026-11-18 15:59:30", 100}, // 窗口前基线
		{"2026-11-18 16:00:00", 130},
		{"2026-11-18 16:00:30", 190},
		{"2026-11-18 16:01:00", 240},
		{"2026-11-18 16:01:30", 20}, // /load 归零：差分取当前值
	}
	for _, s := range seeds {
		mustExec(t, db.MetricsDB, `INSERT INTO metrics_history (rule_id, timestamp, requests_total) VALUES (NULL, ?, ?)`, s.ts, s.val)
	}
	// 规则级行（rule_id 非空）是同一流量的明细拆分，不得与全局行重复计入。
	mustExec(t, db.MetricsDB, `INSERT INTO metrics_history (rule_id, timestamp, requests_total) VALUES ('lb_a', '2026-11-18 16:05:00', 9000)`)

	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.Local)
	d, err := CollectDailyData(context.Background(), now)
	if err != nil {
		t.Fatalf("CollectDailyData: %v", err)
	}
	if d.PeakQPS != 60 {
		t.Fatalf("峰值请求/窗=%d, want 60（相邻全局采样差分最大值）", d.PeakQPS)
	}
}

// TestCollectDailyDataPeakQPSFirstSampleWithoutBaseline 窗口首样本无窗口前基线
// 时不产增量：累计计数器首样本的值本身跨越窗口之前的历史，计入即为假峰值
// （NOTIF153 P3 峰值差分首样本基线；生产逻辑已按此实现，此前无测试覆盖）。
func TestCollectDailyDataPeakQPSFirstSampleWithoutBaseline(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	newDailyTestDBs(t)
	seeds := []struct {
		ts  string
		val int64
	}{
		{"2026-11-18 16:00:00", 130}, // 窗口首样本：无基线 → 不产增量
		{"2026-11-18 16:00:30", 190}, // +60
		{"2026-11-18 16:01:00", 10},  // /load 归零：+10（取当前值）
	}
	for _, s := range seeds {
		mustExec(t, db.MetricsDB, `INSERT INTO metrics_history (rule_id, timestamp, requests_total) VALUES (NULL, ?, ?)`, s.ts, s.val)
	}
	d, err := CollectDailyData(context.Background(), time.Date(2026, 11, 20, 9, 0, 0, 0, time.Local))
	if err != nil {
		t.Fatalf("CollectDailyData: %v", err)
	}
	if d.PeakQPS != 60 {
		t.Fatalf("峰值请求/窗=%d, want 60（首样本不产增量；不得把累计值 130 当峰值）", d.PeakQPS)
	}
}

// ---- NOTIF-152-09 自动封禁次数：窗口上界 + 与 UI 同源 ---------------------

func TestCollectDailyDataAutobanUsesAuditWindow(t *testing.T) {
	withLocalLocation(t, testLocShanghai(t))
	newDailyTestDBs(t)
	// 与 UI（services.AutobanBannedToday）同源：audit_log action='自动封禁'。
	// 逐 IP 行各计 1；单轮上限的省略量取汇总行前缀后的整数。
	mustExec(t, db.AuditDB, `INSERT INTO audit_log (action, detail, created_at) VALUES
		('自动封禁', 'IP：1.1.1.1 命中：50 次/5 分钟 时长：10 分钟', '2026-11-19 03:00:00'),
		('自动封禁', '汇总：其余 3 个 IP 省略逐条记录（本轮共 4 个 IP，逐条上限 1；完整名单见预置 IP 列表）', '2026-11-19 04:00:00'),
		('自动封禁', 'IP：2.2.2.2 命中：50 次/5 分钟 时长：10 分钟', '2026-11-20 03:00:00'),
		('自动封禁', 'IP：3.3.3.3 命中：50 次/5 分钟 时长：10 分钟', '2026-11-18 03:00:00'),
		('自动解封', 'IP：4.4.4.4', '2026-11-19 05:00:00')`)
	// 累犯表行：旧口径（无上界、累计 last_ban_at）会把它算进昨日。
	mustExec(t, db.DB, `INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at) VALUES
		('9.9.9.9', 2, '2026-11-20 03:00:00')`)

	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.Local)
	d, err := CollectDailyData(context.Background(), now)
	if err != nil {
		t.Fatalf("CollectDailyData: %v", err)
	}
	if d.Autobans != 4 {
		t.Fatalf("自动封禁次数=%d, want 4（窗内逐 IP 1 条 + 汇总 3 个省略；窗外与其它动作不计）", d.Autobans)
	}
}

// ---- NOTIF-152-10 top_ip 出清单 + 存量配置容错 ----------------------------

func TestDailyItemsDropLegacyTopIP(t *testing.T) {
	for _, id := range DailyItemIDs {
		if id == "top_ip" {
			t.Fatalf("DailyItemIDs 仍含已合并的 top_ip（应与 top_ips 去重）")
		}
	}
	newNotifyTestDB(t)
	mustExec(t, db.DB, `CREATE TABLE notification_daily (user_id INTEGER PRIMARY KEY, config TEXT NOT NULL DEFAULT '', updated_at TEXT)`)
	mustExec(t, db.DB, `INSERT INTO notification_daily (user_id, config) VALUES
		(21, '{"enabled":true,"send_time":"09:00","items":["requests","top_ip","top_ips"]}')`)
	cfg, err := GetDailyConfig(21)
	if err != nil {
		t.Fatalf("GetDailyConfig: %v", err)
	}
	for _, id := range cfg.Items {
		if id == "top_ip" {
			t.Fatalf("存量配置里的 top_ip 未做迁移容错：items=%v", cfg.Items)
		}
	}
	if len(cfg.Items) != 2 {
		t.Fatalf("items=%v, want 保留 requests/top_ips 两项", cfg.Items)
	}
}

// ---- LNK-task-152-01 API 密钥到期时间宽容解析 ----------------------------

// TestCheckAPIKeyExpiryParsesDriverTimezoneForm glebarez 驱动读 DATETIME 列回来
// 的形态是「2026-11-19 16:00:00+00:00」（带时区后缀）；旧解析只试裸布局与
// RFC3339，带空格+时区的形态直接跳过 → 临期预警静默不发。
func TestCheckAPIKeyExpiryParsesDriverTimezoneForm(t *testing.T) {
	ensureBusStoppedForTest(t) // queue=nil：Publish 走丢弃计数，可观测「是否发布」
	newDailyTestDBs(t)
	exp := time.Now().Add(3 * 24 * time.Hour).Format("2006-01-02 15:04:05+00:00")
	mustExec(t, db.DB, `INSERT INTO api_keys (name, expires_at, is_enabled) VALUES ('k1', ?, 1)`, exp)
	before := DroppedCount()
	if err := CheckAPIKeyExpiry(); err != nil {
		t.Fatalf("CheckAPIKeyExpiry: %v", err)
	}
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("glebarez 形态到期时间未解析（发布 %d 条预警, want 1）", got)
	}
}
