package services

// 回归：通知日报排程槽语义。
//
// 引擎契约（internal/taskengine/engine.go Scheduled 分支）：求值后立即判定
// due = now.After(槽)；NextSlotFn 返回未来槽永远不会触发。因此槽函数必须
// 「宽限窗内返回最近的已到期槽（≤now），否则返回下一个未来槽」。旧实现以
// now+1min 为基准取未来槽，槽前 30s 前导窗的第一次重算就把当日槽推到次日，
// due 恒 false —— 定时日报永不投递。
//
// 第二个用例用真实引擎 tick 驱动：fake 时钟取 real-90s、send_time 由它派生
// （槽=该分钟边界，必然 ≤real now 且在宽限内），从而确定性验证「到点触发」
// 与「同一槽只投一次」两条引擎契约，不依赖宿主墙钟时刻。

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func mustLoadLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return loc
}

func TestDailyReportSlotSemantics(t *testing.T) {
	sh := mustLoadLoc(t, "Asia/Shanghai")
	day := func(d, hh, mm, ss int) time.Time { return time.Date(2026, 11, d, hh, mm, ss, 0, sh) }
	cases := []struct {
		name  string
		now   time.Time
		times []string
		want  time.Time
	}{
		{
			// 引擎前导窗（槽-30s）第一次重算：必须留在当日槽，否则 due 永假。
			name: "前导窗 08:59:30 返回当日 09:00（不是次日）",
			now:  day(20, 8, 59, 30), times: []string{"09:00"}, want: day(20, 9, 0, 0),
		},
		{
			// 槽已到期：返回 ≤now 的槽，引擎 now.After(槽)=true ⇒ 本 tick 投递。
			name: "09:00:01 槽已到期（≤now，due 成立）",
			now:  day(20, 9, 0, 1), times: []string{"09:00"}, want: day(20, 9, 0, 0),
		},
		{
			name: "宽限内 09:00:30 仍返回当日槽（引擎 schedDoneSlot 防重）",
			now:  day(20, 9, 0, 30), times: []string{"09:00"}, want: day(20, 9, 0, 0),
		},
		{
			name: "超出 5min 宽限 09:06 推进次日（昨日摘要不再追溯）",
			now:  day(20, 9, 6, 0), times: []string{"09:00"}, want: day(21, 9, 0, 0),
		},
		{
			name: "多用户槽 10:00 → 下一个未来槽 18:00",
			now:  day(20, 10, 0, 0), times: []string{"09:00", "18:00"}, want: day(20, 18, 0, 0),
		},
		{
			name: "多用户槽 前导窗取最早槽 09:00",
			now:  day(20, 8, 59, 30), times: []string{"09:00", "18:00"}, want: day(20, 9, 0, 0),
		},
		{
			// 宽限窗跨零点：23:58 槽在次日 00:02 仍须触发。
			name: "跨零点 00:02 仍返回昨日 23:58 槽",
			now:  day(20, 0, 2, 0), times: []string{"23:58"}, want: day(19, 23, 58, 0),
		},
		{
			name: "宽限内取最近槽（09:00/09:03，now 09:03:20）",
			now:  day(20, 9, 3, 20), times: []string{"09:00", "09:03"}, want: day(20, 9, 3, 0),
		},
		{
			name: "空槽集合回退 09:00",
			now:  day(20, 8, 0, 0), times: nil, want: day(20, 9, 0, 0),
		},
		{
			name: "非法槽全部跳过回退 09:00",
			now:  day(20, 8, 0, 0), times: []string{"abc", "25:99"}, want: day(20, 9, 0, 0),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dailyReportSlotAt(c.now, c.times, sh)
			if !got.Equal(c.want) {
				t.Fatalf("slot(%s, %v) = %s, want %s", c.now.Format("2006-01-02 15:04:05"), c.times, got, c.want)
			}
			if got.Location() != sh {
				t.Fatalf("槽时区=%v, want 配置时区 %v（NOTIF153-04 同源）", got.Location(), sh)
			}
		})
	}

	// 引擎 due 表达式（与 engine.go Scheduled 分支同式）：前导窗尚未 due，
	// 跨过槽之后 due 成立——旧实现（返回次日槽）两者都恒假。
	lead := dailyReportSlotAt(day(20, 8, 59, 30), []string{"09:00"}, sh)
	if day(20, 8, 59, 30).After(lead) {
		t.Fatalf("前导窗不应已到期")
	}
	after := dailyReportSlotAt(day(20, 9, 0, 1), []string{"09:00"}, sh)
	if !day(20, 9, 0, 1).After(after) {
		t.Fatalf("09:00:01 的槽必须满足引擎 due=now.After(槽)：slot=%s", after)
	}
}

// TestNextDailyReportSlotUsesConfiguredTimezone：槽数学必须与
// 投递侧 dailySlotDue 用同一配置时区，而不是进程 TZ。
func TestNextDailyReportSlotUsesConfiguredTimezone(t *testing.T) {
	tokyo := mustLoadLoc(t, "Asia/Tokyo")
	// UTC 00:02 = 东京 09:02：按配置时区（东京）日历，09:00 槽 2 分钟前到期
	// 仍在宽限内；按进程 UTC 日历则会算成「明日 09:00」（隔日偏差）。
	nowUTC := time.Date(2026, 11, 20, 0, 2, 0, 0, time.UTC) // 东京 09:02
	got := dailyReportSlotAt(nowUTC, []string{"09:00"}, tokyo)
	want := time.Date(2026, 11, 20, 9, 0, 0, 0, tokyo)
	if !got.Equal(want) {
		t.Fatalf("配置时区槽=%s, want %s（按东京日历，而非 UTC 日界）", got, want)
	}
}

// TestNotificationDailyReportEngineFiresScheduledSlot 真实引擎驱动
// 的端到端钉）：Scheduled 任务经 tick 在到期槽触发一次，同一槽不重复投递。
func TestNotificationDailyReportEngineFiresScheduledSlot(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	te := taskengine.NewEngine(taskengine.Options{TickInterval: 5 * time.Millisecond})
	t.Cleanup(te.Stop)

	// fake 时钟落后 90s：send_time 取其分钟边界 ⇒ 槽恒 ≤ real now 且在 5min
	// 宽限内（确定性触发，不依赖宿主墙钟落在哪个时刻）。
	baseNow := time.Now()
	fakeNow := func() time.Time { return baseNow.Add(-90 * time.Second) }
	sendTime := fakeNow().Format("15:04")
	loc := CurrentLocation()

	var runs atomic.Int32
	mustRegisterTask(te, taskengine.Descriptor{
		ID: "notification-daily-report-test", Family: "notification",
		Name: "通知日报排程钉测", Category: "通知",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleAny,
		NextSlotFn: func() time.Time { return dailyReportSlotAt(fakeNow(), []string{sendTime}, loc) },
		Run: func(taskengine.RunContext) error {
			runs.Add(1)
			return nil
		},
	})
	te.StartLoop("notification-daily-report-test")

	waitForCond(t, 3*time.Second, func() bool { return runs.Load() >= 1 })
	if got := runs.Load(); got != 1 {
		t.Fatalf("首个到期槽执行次数=%d, want 1", got)
	}
	// 同一槽仍由 NextSlotFn 返回（宽限内）——引擎 schedDoneSlot 必须拒绝重投。
	time.Sleep(200 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("同一槽被重复投递：执行次数=%d, want 1", got)
	}
}

// TestScheduledFutureSlotDoesNotFire 引擎契约对照（旧实现的失败形态）：返回
// 未来槽的 Scheduled 任务不得触发——这正是 的根因形态。
func TestScheduledFutureSlotDoesNotFire(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	te := taskengine.NewEngine(taskengine.Options{TickInterval: 5 * time.Millisecond})
	t.Cleanup(te.Stop)
	var runs atomic.Int32
	mustRegisterTask(te, taskengine.Descriptor{
		ID: "future-slot-probe", Family: "notification", Name: "未来槽对照",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleAny,
		NextSlotFn: func() time.Time { return time.Now().Add(time.Minute) },
		Run:        func(taskengine.RunContext) error { runs.Add(1); return nil },
	})
	te.StartLoop("future-slot-probe")
	time.Sleep(200 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("未来槽任务被执行 %d 次（引擎 due=now.After(槽) 永不成立）", got)
	}
}

// TestNodeStatsSlotSemantics 从节点统计上报槽（每日 00:05，宽限语义与日报
// 同源）：宽限窗内返回已到期槽（≤now ⇒ 引擎 due 成立），否则返回下一未来槽。
// 旧实现恒返回严格未来槽，引擎 due=now.After(槽) 恒假——任务永不执行。
func TestNodeStatsSlotSemantics(t *testing.T) {
	sh := mustLoadLoc(t, "Asia/Shanghai")
	day := func(d, hh, mm, ss int) time.Time { return time.Date(2026, 11, d, hh, mm, ss, 0, sh) }
	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{name: "槽前 00:04:59 返回当日 00:05（未来槽）", now: day(20, 0, 4, 59), want: day(20, 0, 5, 0)},
		{name: "槽点 00:05:00 返回当日 00:05（<=now，due 成立）", now: day(20, 0, 5, 0), want: day(20, 0, 5, 0)},
		{name: "槽后 00:05:01 仍在宽限内返回当日 00:05", now: day(20, 0, 5, 1), want: day(20, 0, 5, 0)},
		{name: "宽限边缘 00:05:59 仍返回当日 00:05", now: day(20, 0, 5, 59), want: day(20, 0, 5, 0)},
		{name: "超出宽限 00:06 返回次日 00:05", now: day(20, 0, 6, 0), want: day(21, 0, 5, 0)},
		{name: "中午返回次日 00:05（最早未来槽）", now: day(20, 12, 0, 0), want: day(21, 0, 5, 0)},
		{name: "深夜 23:59 返回次日 00:05", now: day(20, 23, 59, 0), want: day(21, 0, 5, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nodeStatsSlotAt(c.now, sh)
			if !got.Equal(c.want) {
				t.Fatalf("slot(%s) = %s, want %s", c.now.Format("2006-01-02 15:04:05"), got, c.want)
			}
			if got.Location() != sh {
				t.Fatalf("槽时区=%v, want 配置时区 %v", got.Location(), sh)
			}
			// 引擎 due 表达式（与 engine.go Scheduled 分支同式）：宽限窗内、且已过
			// 槽点（tick 在槽点之后）时必须成立。
			if withinGrace := c.now.After(c.want) && c.now.Sub(c.want) < nodeStatsSlotGrace; withinGrace && !c.now.After(got) {
				t.Fatalf("宽限内槽 %s 不满足引擎 due=now.After(槽)（now=%s）——任务永不执行", got, c.now)
			}
		})
	}
}

// TestNodeStatsSlotUsesConfiguredTimezone 槽数学按配置时区日历，而非进程 TZ。
func TestNodeStatsSlotUsesConfiguredTimezone(t *testing.T) {
	tokyo := mustLoadLoc(t, "Asia/Tokyo")
	// UTC 15:02 = 东京次日 00:02：按东京日历 00:05 槽在未来 3 分钟。
	nowUTC := time.Date(2026, 11, 21, 15, 2, 0, 0, time.UTC)
	want := time.Date(2026, 11, 22, 0, 5, 0, 0, tokyo)
	if got := nodeStatsSlotAt(nowUTC, tokyo); !got.Equal(want) {
		t.Fatalf("配置时区槽=%s, want %s（按东京日历而非 UTC 日界）", got, want)
	}
}

// TestNodeStatsReportEngineFiresScheduledSlot 真实引擎驱动：RoleSlaveOnly 任务
// 在从角色引擎上按节点统计槽触发一次，同一槽不重复执行（P1 死因之二——
// 槽恒未来——已由槽语义用例钉死，本用例钉引擎端到端可达）。
func TestNodeStatsReportEngineFiresScheduledSlot(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	te := taskengine.NewEngine(taskengine.Options{TickInterval: 5 * time.Millisecond})
	t.Cleanup(te.Stop)
	te.SetRole(false) // 从节点角色：RoleSlaveOnly 任务可调度

	loc := CurrentLocation()
	// fake 时钟退一日：节点统计槽（固定 00:05）在 fake 日历下必然 ≤ real now，
	// 引擎 due 恒成立——确定性触发，不依赖宿主墙钟落在哪个时刻。
	fakeNow := func() time.Time { return time.Now().AddDate(0, 0, -1) }
	var runs atomic.Int32
	mustRegisterTask(te, taskengine.Descriptor{
		ID: "notification-node-stats-report-test", Family: "notification",
		Name: "节点统计上报排程钉测", Category: "通知",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleSlaveOnly,
		NextSlotFn: func() time.Time { return nodeStatsSlotAt(fakeNow(), loc) },
		Run: func(taskengine.RunContext) error {
			runs.Add(1)
			return nil
		},
	})
	te.StartLoop("notification-node-stats-report-test")

	waitForCond(t, 3*time.Second, func() bool { return runs.Load() >= 1 })
	if got := runs.Load(); got != 1 {
		t.Fatalf("首个到期槽执行次数=%d, want 1", got)
	}
	time.Sleep(200 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("同一槽被重复执行：次数=%d, want 1（schedDoneSlot 防重）", got)
	}
}

// TestNodeStatsReportFailureRetriedWithinGrace 统计上报失败由引擎在同一槽重投
// （失败轮不推进槽 + Scheduled 退避兜底）——槽宽限化后瞬时故障/重启窗口内的
// 当日块仍能补报，无需任务体自建重试或事件侧 spool。
func TestNodeStatsReportFailureRetriedWithinGrace(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	te := taskengine.NewEngine(taskengine.Options{TickInterval: 5 * time.Millisecond})
	t.Cleanup(te.Stop)
	te.SetRole(false)
	loc := CurrentLocation()
	fakeNow := func() time.Time { return time.Now().AddDate(0, 0, -1) }
	var runs atomic.Int32
	var succeeded atomic.Bool
	mustRegisterTask(te, taskengine.Descriptor{
		ID: "notification-node-stats-retry-test", Family: "notification",
		Name: "节点统计上报失败重投钉测", Category: "通知",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleSlaveOnly,
		NextSlotFn: func() time.Time { return nodeStatsSlotAt(fakeNow(), loc) },
		Run: func(taskengine.RunContext) error {
			if runs.Add(1) == 1 {
				return errors.New("主节点瞬时不可达")
			}
			succeeded.Store(true)
			return nil
		},
	})
	te.StartLoop("notification-node-stats-retry-test")

	waitForCond(t, 5*time.Second, func() bool { return succeeded.Load() })
	if got := runs.Load(); got < 2 {
		t.Fatalf("失败轮未在同一槽重投：执行次数=%d, want >=2", got)
	}
}
