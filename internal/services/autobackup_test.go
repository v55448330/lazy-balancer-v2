package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// —— autoBackupDueSlot 纯函数矩阵 ——

func TestAutoBackupDueSlot_daily(t *testing.T) {
	// Given: 当日 15:04,槽 03:00(已过)
	loc := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 9, 20, 15, 4, 0, 0, loc)

	// When
	slot, ok := autoBackupDueSlot(now, "daily", "03:00", 1, loc)

	// Then: 槽=当日 03:00
	want := time.Date(2026, 9, 20, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_dailyBeforeSlotFallsToYesterday(t *testing.T) {
	// Given: 当日 01:59,槽 03:00(未到)
	loc := time.UTC
	now := time.Date(2026, 9, 20, 1, 59, 0, 0, loc)

	// When
	slot, ok := autoBackupDueSlot(now, "daily", "03:00", 1, loc)

	// Then: 槽=前一日 03:00
	want := time.Date(2026, 9, 19, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_weekly(t *testing.T) {
	// Given: 周三 10:00,weekly day=1(周一)03:00
	loc := time.UTC
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, loc) // 2026-09-23 是周三
	if now.Weekday() != time.Wednesday {
		t.Fatalf("夹具自检失败: %s 不是周三", now.Weekday())
	}

	// When
	slot, ok := autoBackupDueSlot(now, "weekly", "03:00", 1, loc)

	// Then: 最近过去的周一 03:00 = 2026-09-21
	want := time.Date(2026, 9, 21, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_weeklyBeforeSlotFallsToPrevWeek(t *testing.T) {
	// Given: 周一 02:00,weekly day=1(周一)03:00(本轮未到)
	loc := time.UTC
	now := time.Date(2026, 9, 21, 2, 0, 0, 0, loc) // 周一

	// When
	slot, ok := autoBackupDueSlot(now, "weekly", "03:00", 1, loc)

	// Then: 上一周一 03:00 = 2026-09-14
	want := time.Date(2026, 9, 14, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_weeklySundayDay7(t *testing.T) {
	// Given: 周一 10:00,weekly day=7(周日)03:00 → 最近的过去周日=昨天
	loc := time.UTC
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, loc) // 周一

	// When
	slot, ok := autoBackupDueSlot(now, "weekly", "03:00", 7, loc)

	// Then: 2026-09-20(周日)03:00
	want := time.Date(2026, 9, 20, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_monthly(t *testing.T) {
	// Given: 15 日 12:00,monthly day=1 03:00
	loc := time.UTC
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, loc)

	// When
	slot, ok := autoBackupDueSlot(now, "monthly", "03:00", 1, loc)

	// Then: 本月 1 日 03:00
	want := time.Date(2026, 9, 1, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_monthlyBeforeSlotFallsToPrevMonth(t *testing.T) {
	// Given: 9 月 1 日 01:00,monthly day=15 03:00(本月 15 日未到)
	loc := time.UTC
	now := time.Date(2026, 9, 1, 1, 0, 0, 0, loc)

	// When
	slot, ok := autoBackupDueSlot(now, "monthly", "03:00", 15, loc)

	// Then: 上月(8 月)15 日 03:00
	want := time.Date(2026, 8, 15, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestAutoBackupDueSlot_monthlyClampsShortMonth(t *testing.T) {
	loc := time.UTC
	tests := []struct {
		name string
		now  time.Time
		day  int
		want time.Time
	}{
		// day=31 在 2 月收敛到月末 28;now 取 28 日午后使本月槽成为最近过去槽
		//（未收敛时 time.Date(2,31) 归一溢出到 3 月 → 回落 1 月 31,断言失败）
		{name: "nonleap february clamps to 28", now: time.Date(2026, 2, 28, 12, 0, 0, 0, loc), day: 31, want: time.Date(2026, 2, 28, 3, 0, 0, 0, loc)},
		// 闰年 2 月收敛到 29:2028 闰年,3 月 1 日 01:00 → 2 月 29 03:00
		{name: "leap february clamps to 29", now: time.Date(2028, 3, 1, 1, 0, 0, 0, loc), day: 30, want: time.Date(2028, 2, 29, 3, 0, 0, 0, loc)},
		// 4 月 30 日后,day=31 收敛 4 月 30(本月已过 03:00)
		{name: "april clamps to 30", now: time.Date(2026, 4, 30, 12, 0, 0, 0, loc), day: 31, want: time.Date(2026, 4, 30, 3, 0, 0, 0, loc)},
		// 4 月 1 日 01:00,day=31 → 上月 3 月 31 03:00
		{name: "prev month clamp", now: time.Date(2026, 4, 1, 1, 0, 0, 0, loc), day: 31, want: time.Date(2026, 3, 31, 3, 0, 0, 0, loc)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, ok := autoBackupDueSlot(tt.now, "monthly", "03:00", tt.day, loc)
			if !ok {
				t.Fatal("ok=false, want true")
			}
			if !slot.Equal(tt.want) {
				t.Fatalf("slot=%v, want %v", slot, tt.want)
			}
		})
	}
}

func TestAutoBackupDueSlot_nonUTCTimezone(t *testing.T) {
	// Given: now 取 UTC 2026-09-19 20:30(=上海 2026-09-20 04:30),槽按 loc 计算
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("时区数据库不可用: %v", err)
	}
	now := time.Date(2026, 9, 19, 20, 30, 0, 0, time.UTC)

	// When
	slot, ok := autoBackupDueSlot(now, "daily", "03:00", 1, loc)

	// Then: 上海 2026-09-20 03:00(当日槽,本地已过)
	want := time.Date(2026, 9, 20, 3, 0, 0, 0, loc)
	if !ok {
		t.Fatal("ok=false, want true")
	}
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
	if _, offset := slot.Zone(); offset != 8*3600 {
		t.Fatalf("slot offset=%d, want +8h(上海)", offset)
	}
}

func TestAutoBackupDueSlot_invalidInputs(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, loc)
	tests := []struct {
		name  string
		freq  string
		hhmm  string
		day   int
		valid bool
	}{
		{name: "unknown frequency", freq: "hourly", hhmm: "03:00", day: 1, valid: false},
		{name: "empty frequency", freq: "", hhmm: "03:00", day: 1, valid: false},
		{name: "hour out of range", freq: "daily", hhmm: "24:00", day: 1, valid: false},
		{name: "minute out of range", freq: "daily", hhmm: "03:60", day: 1, valid: false},
		{name: "malformed time", freq: "daily", hhmm: "0300", day: 1, valid: false},
		{name: "empty time", freq: "daily", hhmm: "", day: 1, valid: false},
		{name: "zero day monthly", freq: "monthly", hhmm: "03:00", day: 0, valid: false},
		{name: "negative day monthly", freq: "monthly", hhmm: "03:00", day: -1, valid: false},
		// monthly day>28 不是 dueSlot 的非法输入——写侧 PUT 限定 1-28,
		// dueSlot 对超出值防御性收敛到月末(见 monthlyClampsShortMonth)
		{name: "zero day weekly", freq: "weekly", hhmm: "03:00", day: 0, valid: false},
		{name: "day beyond 7 weekly", freq: "weekly", hhmm: "03:00", day: 8, valid: false},
		{name: "valid weekly day 7", freq: "weekly", hhmm: "23:59", day: 7, valid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := autoBackupDueSlot(now, tt.freq, tt.hhmm, tt.day, loc)
			if ok != tt.valid {
				t.Fatalf("ok=%v, want %v", ok, tt.valid)
			}
		})
	}
}

// —— autoBackupTick(DB + 执行器注入)——

func setupAutoBackupTestDB(t *testing.T) {
	t.Helper()
	setupIsolatedDB(t)
	// 固定调度时区为 UTC,隔离 CurrentLocation 的全局态；cleanup 必须恢复
	// 调用前时区（CurrentLocation 是包级全局态，-shuffle 下写死不恢复会串味）。
	previousLocation := CurrentLocation().String()
	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatalf("configure UTC location: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ConfigureLocation(previousLocation)
	})
}

func setAutoBackupTestExecutor(t *testing.T, calls *[]string, err error) {
	t.Helper()
	SetAutoBackupExecutor(func(ctx context.Context, trigger, operator string, engineRunID int64) error {
		*calls = append(*calls, trigger+":"+operator)
		return err
	})
	t.Cleanup(func() { SetAutoBackupExecutor(nil) })
}

func TestAutoBackupScheduled_startedAtBoundaries(t *testing.T) {
	boundaries := []struct {
		name      string
		startedAt time.Time
		wantSlot  time.Time
	}{
		{name: "before_slot", startedAt: time.Date(2026, 9, 20, 2, 59, 59, 999000000, time.UTC), wantSlot: time.Date(2026, 9, 19, 3, 0, 0, 0, time.UTC)},
		{name: "at_slot", startedAt: time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC), wantSlot: time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)},
		{name: "after_slot", startedAt: time.Date(2026, 9, 20, 3, 0, 0, 1000000, time.UTC), wantSlot: time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)},
	}
	outcomes := []struct {
		name       string
		execErr    error
		cancel     bool
		wantErr    error
		advanceRun bool
	}{
		{name: "success", advanceRun: true},
		{name: "executor_failure", execErr: context.DeadlineExceeded, wantErr: context.DeadlineExceeded, advanceRun: true},
		{name: "canceled", execErr: context.Canceled, cancel: true, wantErr: context.Canceled},
	}
	for _, boundary := range boundaries {
		for _, outcome := range outcomes {
			t.Run(boundary.name+"/"+outcome.name, func(t *testing.T) {
				setupAutoBackupTestDB(t)
				if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00', auto_backup_last_run=NULL WHERE id=1`); err != nil {
					t.Fatal(err)
				}
				var calls []string
				setAutoBackupTestExecutor(t, &calls, outcome.execErr)
				ctx := context.Background()
				if outcome.cancel {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}

				err := runAutoBackupScheduledAt(ctx, 0, boundary.startedAt)

				if !errors.Is(err, outcome.wantErr) {
					t.Fatalf("run error=%v, want %v", err, outcome.wantErr)
				}
				if len(calls) != 1 || calls[0] != "schedule:system" {
					t.Fatalf("calls=%v, want single schedule:system", calls)
				}
				var lastRun *string
				if queryErr := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); queryErr != nil {
					t.Fatal(queryErr)
				}
				if !outcome.advanceRun {
					if lastRun != nil {
						t.Fatalf("last_run=%q, want NULL after cancellation", *lastRun)
					}
					return
				}
				if lastRun == nil {
					t.Fatal("last_run=NULL, want fixed startedAt slot")
				}
				got, parseErr := time.Parse(time.RFC3339, *lastRun)
				if parseErr != nil {
					t.Fatalf("last_run=%q is not RFC3339: %v", *lastRun, parseErr)
				}
				if !got.Equal(boundary.wantSlot) {
					t.Fatalf("last_run=%v, want %v", got, boundary.wantSlot)
				}
			})
		}
	}
}

func TestAutoBackupNextSlot_disabledReturnsZero(t *testing.T) {
	// Given: 未启用
	setupAutoBackupTestDB(t)

	// When
	_, ok := nextAutoBackupSlot(time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC))

	// Then
	if ok {
		t.Fatal("未启用应无槽（引擎零调度）")
	}
}

func TestAutoBackupNextSlot_coveredStepsToFuture(t *testing.T) {
	// Given: last_run 恰等于最近槽（已跑过本槽）
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00', auto_backup_last_run='2026-09-20T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	slot, ok := nextAutoBackupSlot(time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC))

	// Then: 步进到明日槽（未来时刻——引擎睡到点）
	if !ok {
		t.Fatal("已启用应有下一槽")
	}
	if want := time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC); !slot.Equal(want) {
		t.Fatalf("slot=%v, want 明日 %v", slot, want)
	}
}

func TestAutoBackupNextSlot_catchesUpPastSlot(t *testing.T) {
	// Given: 停机跨槽——last_run=昨日槽, now 已过今日槽
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00', auto_backup_last_run='2026-09-19T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	slot, ok := nextAutoBackupSlot(time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC))

	// Then: 返回过去槽（≤now——引擎到点立即触发=跨停机窗口补跑）
	if !ok {
		t.Fatal("漏跑应有追补槽")
	}
	if want := time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC); !slot.Equal(want) {
		t.Fatalf("slot=%v, want 最近漏跑槽 %v", slot, want)
	}
}

func TestAutoBackupScheduled_nilExecutorReturnsError(t *testing.T) {
	// Given: 执行器未装配（启动装配窗口）。
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	SetAutoBackupExecutor(nil)
	t.Cleanup(func() { SetAutoBackupExecutor(nil) })

	// When/Then：必须返回可见错误而非记录成功；last_run 仍不推进。
	if err := runAutoBackupScheduled(context.Background(), 0); err == nil {
		t.Fatal("未装配执行器不得静默记录成功")
	}
	var lastRun *string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); err != nil {
		t.Fatal(err)
	}
	if lastRun != nil {
		t.Fatalf("last_run=%q, want NULL(未装配不推进)", *lastRun)
	}
}

// monthly day 带外写入 29-31（集群快照直写不校验）时，短月
// 「已执行→步进」会回退到已执行的过去槽：nextAutoBackupSlot 返回不晚于 now
// 且不晚于水位线的时刻，引擎每 tick 重跑备份并刷 task_runs。
// 读侧须把 day 收敛到写侧允许区间（越界回退默认 1——与 handlers 读侧
// 同口径，保证「UI 显示的即生效值」）。
func TestAutoBackupNextSlot_outOfRangeMonthlyDayDoesNotRepeatExecutedSlot(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='monthly',
		auto_backup_time='03:00', auto_backup_day=31, auto_backup_last_run='2026-02-28T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC)

	slot, ok := nextAutoBackupSlot(now)
	if !ok {
		t.Fatal("已启用应有下一槽")
	}
	if !slot.After(now) {
		t.Fatalf("next slot=%v 不晚于 now=%v：day 越界把步进回退到已执行的过去槽（引擎每 tick 重跑备份）", slot, now)
	}
	if want := time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC); !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v（day 越界回退默认 1）", slot, want)
	}
}

// （回归形状）：weekly day 越界（0 或 >7）此前让 autoBackupDueSlot
// ok=false → 调度面零槽（任务静默停摆）。读侧收敛到可调度区间后必须有槽。
func TestAutoBackupNextSlot_outOfRangeWeeklyDayStillSchedules(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='weekly',
		auto_backup_time='03:00', auto_backup_day=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC)

	slot, ok := nextAutoBackupSlot(now)
	if !ok {
		t.Fatal("weekly day 越界不得让调度面零槽（任务静默停摆）")
	}
	// 未跑过 → 返回最近过去槽：weekly day=0 归一为周一，now=2026-02-28（周六）
	// ⇒ 2026-02-23 03:00 UTC。钉具体时刻而非仅「≤now」——零值/任意过去时刻
	// 同样满足形态断言，矩阵这一格会失去区分力（调度器会每分钟都到点）。
	if want := time.Date(2026, 2, 23, 3, 0, 0, 0, time.UTC); !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v（weekly day 越界回退周一 03:00）", slot, want)
	}
	if slot.After(now) {
		t.Fatalf("slot=%v 应 ≤now（未执行过时返回最近槽）", slot)
	}
}

// 月度「已执行→步进」必须以最近槽为起点：以 now 步进时，1/31、3/31、5/31、
// 8/31、10/31 的 AddDate(0,1,0) 会归一到下下月（1/31+1 月=3/3），回落到已
// 执行月份之后的第二个月，设置页把下个月槽整月显示为跳过。day∈{1,2,3} 时
// 恰落入该窗口；day≥4 因当月槽仍早于 step 而侥幸正确——矩阵同时钉住两端。
func TestAutoBackupNextSlot_monthEndStepsToAdjacentMonth(t *testing.T) {
	cases := []struct {
		year, month int
		day         int
	}{
		{2026, 1, 1}, {2026, 1, 2}, {2026, 1, 3}, {2026, 1, 28},
		{2026, 3, 1}, {2026, 3, 2}, {2026, 3, 3}, {2026, 3, 28},
		{2026, 5, 1}, {2026, 5, 2}, {2026, 5, 3}, {2026, 5, 28},
		{2026, 8, 1}, {2026, 8, 2}, {2026, 8, 3}, {2026, 8, 28},
		{2026, 10, 1}, {2026, 10, 2}, {2026, 10, 3}, {2026, 10, 28},
	}
	for _, tc := range cases {
		name := time.Date(tc.year, time.Month(tc.month), 1, 0, 0, 0, 0, time.UTC).Format("2006-01")
		t.Run(fmt.Sprintf("%s-day%d", name, tc.day), func(t *testing.T) {
			setupAutoBackupTestDB(t)
			executed := time.Date(tc.year, time.Month(tc.month), tc.day, 3, 0, 0, 0, time.UTC)
			if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='monthly',
				auto_backup_time='03:00', auto_backup_day=?, auto_backup_last_run=? WHERE id=1`, tc.day, executed.Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			now := time.Date(tc.year, time.Month(tc.month), autoBackupDaysInMonth(tc.year, time.Month(tc.month)), 12, 0, 0, 0, time.UTC)

			slot, ok := nextAutoBackupSlot(now)
			if !ok {
				t.Fatal("monthly 已启用必须有下一槽")
			}
			nextMonth := time.Date(tc.year, time.Month(tc.month), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
			want := time.Date(nextMonth.Year(), nextMonth.Month(), tc.day, 3, 0, 0, 0, time.UTC)
			if !slot.Equal(want) {
				t.Fatalf("月末步进 slot=%v, want 紧邻下一月槽 %v（不得跳月）", slot, want)
			}
		})
	}
}

// 回归：daily/weekly 从槽步进后仍落在紧邻下一周期槽（不得因改为 due 起点
// 而原地踏步或多跳）。
func TestAutoBackupNextSlot_dailyWeeklyStepFromExecutedSlot(t *testing.T) {
	cases := []struct {
		name string
		freq string
		day  int
		now  time.Time
		want time.Time
	}{
		{
			name: "daily", freq: "daily", day: 1,
			now:  time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC),
			want: time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC),
		},
		{
			name: "weekly", freq: "weekly", day: 1,
			now:  time.Date(2026, 9, 22, 15, 0, 0, 0, time.UTC),
			want: time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupAutoBackupTestDB(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency=?,
				auto_backup_time='03:00', auto_backup_day=?, auto_backup_last_run=? WHERE id=1`,
				tc.freq, tc.day, "2026-09-21T03:00:00Z"); err != nil {
				t.Fatal(err)
			}

			slot, ok := nextAutoBackupSlot(tc.now)
			if !ok {
				t.Fatal("已启用必须有下一槽")
			}
			if !slot.Equal(tc.want) {
				t.Fatalf("slot=%v, want %v", slot, tc.want)
			}
		})
	}
}

func TestAutoBackupNextSlotDailyWeeklyAcrossDSTFallback(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	cases := []struct {
		name    string
		freq    string
		day     int
		lastRun string
		now     time.Time
		want    time.Time
	}{
		{
			name: "daily", freq: "daily", day: 1,
			lastRun: "2026-10-24T03:30:00+02:00",
			now:     time.Date(2026, 10, 24, 12, 0, 0, 0, loc),
			want:    time.Date(2026, 10, 25, 3, 30, 0, 0, loc),
		},
		{
			name: "weekly", freq: "weekly", day: 7,
			lastRun: "2026-10-18T03:30:00+02:00",
			now:     time.Date(2026, 10, 20, 9, 0, 0, 0, loc),
			want:    time.Date(2026, 10, 25, 3, 30, 0, 0, loc),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupAutoBackupTestDB(t)
			if _, err := ConfigureLocation("Europe/Berlin"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency=?,
				auto_backup_time='03:30', auto_backup_day=?, auto_backup_last_run=? WHERE id=1`, tc.freq, tc.day, tc.lastRun); err != nil {
				t.Fatal(err)
			}
			slot, ok := nextAutoBackupSlot(tc.now)
			if !ok {
				t.Fatal("enabled schedule must have a next slot")
			}
			if !slot.Equal(tc.want) {
				t.Fatalf("slot=%s, want %s", slot.Format(time.RFC3339), tc.want.Format(time.RFC3339))
			}
		})
	}
}

// 自动备份开关读失败必须留痕（首报一次）：引擎先求值 EnabledFn 再求值
// NextSlotFn，EnabledFn 读错即 LoopOn=false 短路——nextAutoBackupSlot 的
// schedule-read-auto-backup 告警永远不会被求值，静默 fail-closed 让「库故障」
// 与「用户关闭」在任务面完全同形。同类静默 reader（threat/crawler 总闸）同断言。
func TestAutoBackupEnabled_logsReadFailureOnceAndRecovers(t *testing.T) {
	setupAutoBackupTestDB(t)
	isolateMetricsState(t)
	originalWriter := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	// When：主库查询恒失败 ×2
	healthy := db.DB
	swapBrokenDB(t)
	broken := db.DB
	if enabled, known := AutoBackupEnabledState(); known && enabled {
		t.Fatal("读失败必须 fail-closed（视为关）")
	}
	if globalTaskAutoUpdateEnabled("threat") {
		t.Fatal("读失败必须 fail-closed（视为关）")
	}
	AutoBackupEnabledState()
	globalTaskAutoUpdateEnabled("threat")

	// Then：每类只首报一次（状态转换口径，30s×2880 行/天的历史形态）
	if count := strings.Count(logs.String(), "读取配置失败（schedule-read-auto-backup-enabled）"); count != 1 {
		t.Fatalf("auto-backup 开关读失败日志次数=%d, want 1（状态转换去重）: %s", count, logs.String())
	}
	if count := strings.Count(logs.String(), "读取配置失败（schedule-read-threat-auto-update）"); count != 1 {
		t.Fatalf("threat 总闸读失败日志次数=%d, want 1: %s", count, logs.String())
	}

	// When：库恢复。Then：恢复分支留一条 info，稳定期零噪音。
	db.DB = healthy
	AutoBackupEnabledState()
	globalTaskAutoUpdateEnabled("threat")
	AutoBackupEnabledState()
	globalTaskAutoUpdateEnabled("threat")
	if count := strings.Count(logs.String(), "读取配置已恢复（schedule-read-auto-backup-enabled）"); count != 1 {
		t.Fatalf("恢复日志次数=%d, want 1: %s", count, logs.String())
	}
	if count := strings.Count(logs.String(), "读取配置已恢复（schedule-read-threat-auto-update）"); count != 1 {
		t.Fatalf("threat 恢复日志次数=%d, want 1: %s", count, logs.String())
	}

	// When：恢复后再次失败。Then：去重状态机复位，必须重新首报一次。
	db.DB = broken
	AutoBackupEnabledState()
	if count := strings.Count(logs.String(), "读取配置失败（schedule-read-auto-backup-enabled）"); count != 2 {
		t.Fatalf("再次失败后告警次数=%d, want 2（恢复后必须重新首报）: %s", count, logs.String())
	}
}

// 水位线写失败必须让本轮失败：槽不推进时引擎只在「failed 且槽未推进」才退避，
// 返回 success 会让默认 1s tick 每秒重投一次完整备份（每次一行 task_runs）。
func TestAutoBackupScheduled_failsWhenWatermarkUpdateFails(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 只让 global_config 的 UPDATE 失败（读路径不受影响）
	if _, err := db.DB.Exec(`CREATE TRIGGER ab_fail_watermark BEFORE UPDATE ON global_config BEGIN SELECT RAISE(ABORT, 'injected watermark failure'); END;`); err != nil {
		t.Fatal(err)
	}
	var calls []string
	setAutoBackupTestExecutor(t, &calls, nil)

	// When：备份业务本身成功
	err := runAutoBackupScheduledAt(context.Background(), 0, time.Date(2026, 9, 20, 3, 0, 0, 1000000, time.UTC))

	// Then：本轮必须返回错误（让引擎退避），且执行器只跑一次
	if err == nil {
		t.Fatal("水位线写失败必须让本轮返回 error（否则引擎无退避、每秒重投完整备份）")
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%v, want 单次执行", calls)
	}
	var lastRun *string
	if qerr := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); qerr != nil {
		t.Fatal(qerr)
	}
	if lastRun != nil {
		t.Fatalf("last_run=%q, want 未推进（UPDATE 失败）", *lastRun)
	}
}

// 排程参数非法（本版本不认识的频率、非两位补零的时刻）此前零槽零日志：
// 任务监控全绿、无失败行、无告警，自动备份永久停摆。必须按状态转换留痕一次
// （首报 warn、重复不刷屏），恢复合法值后记一条 info。
func TestNextAutoBackupSlot_invalidScheduleParamsLeaveTrace(t *testing.T) {
	setupAutoBackupTestDB(t)
	isolateMetricsState(t)
	now := time.Date(2026, 9, 22, 15, 0, 0, 0, time.UTC)
	logs := captureLogf(t)

	// 不认识的频率：零槽 + 首报一次。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='hourly',
		auto_backup_time='03:00', auto_backup_last_run=NULL WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if slot, ok := nextAutoBackupSlot(now); ok {
		t.Fatalf("非法频率必须零槽（不执行），got %v", slot)
	}
	nextAutoBackupSlot(now)
	if count := strings.Count(logs.String(), "自动备份排程参数非法"); count != 1 {
		t.Fatalf("非法频率告警次数=%d, want 1（状态转换去重）: %s", count, logs.String())
	}

	// 非两位补零的时刻同样非法，且不重复刷屏。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_frequency='daily', auto_backup_time='3:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, ok := nextAutoBackupSlot(now); ok {
		t.Fatal("非两位补零时刻必须零槽")
	}
	if count := strings.Count(logs.String(), "自动备份排程参数非法"); count != 1 {
		t.Fatalf("同类非法参数告警次数=%d, want 1（不得每轮刷屏）: %s", count, logs.String())
	}

	// 恢复合法值：有槽 + 一条恢复 info。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if slot, ok := nextAutoBackupSlot(now); !ok || slot.IsZero() {
		t.Fatalf("恢复合法参数后必须有槽，got %v ok=%v", slot, ok)
	}
	if count := strings.Count(logs.String(), "自动备份排程参数已恢复合法"); count != 1 {
		t.Fatalf("恢复日志次数=%d, want 1: %s", count, logs.String())
	}
}

// 带外写入的非法水位线（非 RFC3339）：读侧按「从未跑过」立即补跑，推进 SQL
// 必须同判据——`datetime(非法值)` 为 NULL 时条件恒不成立、Exec 却成功，
// 水位线永不推进 ⇒ 每个 tick 重跑一次完整备份（写 task_runs 行 + 备份文件）。
func TestAutoBackupScheduled_advancesOutOfBandInvalidWatermark(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00', auto_backup_last_run='legacy-not-a-timestamp'
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var calls []string
	setAutoBackupTestExecutor(t, &calls, nil)

	// When
	startedAt := time.Date(2026, 9, 20, 3, 0, 0, 1000000, time.UTC)
	if err := runAutoBackupScheduledAt(context.Background(), 0, startedAt); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Then 1：非法值被真实槽覆盖（读侧判据「非法=未跑过」在写侧同样成立）。
	if len(calls) != 1 {
		t.Fatalf("calls=%v, want 单次执行", calls)
	}
	var lastRun string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); err != nil {
		t.Fatalf("read last_run: %v", err)
	}
	got, perr := time.Parse(time.RFC3339, lastRun)
	if perr != nil {
		t.Fatalf("last_run=%q 仍为非法形态：非法水位线必须按「未跑过」被覆盖", lastRun)
	}

	// Then 2：覆盖后下一槽在未来——不再每 tick 判到期重跑全量备份。
	now := startedAt
	slot, ok := nextAutoBackupSlot(now)
	if !ok {
		t.Fatal("ok=false, want 未来槽（水位线已推进）")
	}
	if !slot.After(now) {
		t.Fatalf("slot=%v 不晚于 now=%v：水位线未推进，调度器会每 tick 重跑全量备份", slot, now)
	}
	if slot.Before(got) {
		t.Fatalf("slot=%v 早于已写水位线 %v", slot, got)
	}
}

// 平面格式水位线落在「Go 读侧判据」与「SQL 写守卫判据」的夹缝。可复现形态
// 是空格分隔 + 时区后缀（SQLite datetime 家族合法、datetime('now')/带外工具
// 直写可达）：glebarez 驱动回读只归一 T 分隔形态，空格形态原样回来——
// 读侧 time.Parse(RFC3339) 失败 ⇒ 按「从未跑过」每 tick 重跑全量备份；写守卫
// 的 datetime() 却解析成功且晚于目标槽 ⇒ 推进条件恒不成立——水位线既不推进
// 也不自愈（纯平面无时区形态会被驱动回读归一成 RFC3339，不构成夹缝）。
// 判据单源（parseAutoBackupWatermark，读侧接受 SQLite datetime 文本按 UTC）
// + 写侧 CAS 后：已覆盖槽立即让位、下一槽落在未来，且下一轮真实执行把库值
// 改写为 RFC3339。
func TestAutoBackupScheduled_plainFormatWatermarkCoveredAndSelfHeals(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00', auto_backup_last_run='2026-09-20 03:00:07 +00:00'
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var calls []string
	setAutoBackupTestExecutor(t, &calls, nil)

	// Then 1：平面值按 UTC 解析 ⇒ 今日槽（03:00:00）已被 03:00:07 覆盖，
	// 下一槽必须在未来（修复前返回今日已过去的 03:00 槽 ⇒ 每 tick 重跑）。
	now := time.Date(2026, 9, 20, 3, 0, 8, 0, time.UTC)
	slot, ok := nextAutoBackupSlot(now)
	if !ok {
		t.Fatal("ok=false, want 未来槽")
	}
	if !slot.After(now) {
		t.Fatalf("slot=%v 不晚于 now=%v：平面水位线未被认领，调度器每 tick 重跑全量备份", slot, now)
	}

	// Then 2：下一轮真实执行（明日槽晚于平面水位线）照常推进，库值改写为
	// RFC3339——写守卫与读侧同判据，不再被平面值卡死。
	startedAt := time.Date(2026, 9, 21, 3, 0, 10, 0, time.UTC)
	if err := runAutoBackupScheduledAt(context.Background(), 0, startedAt); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls=%v, want 单次执行", calls)
	}
	var lastRun string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); err != nil {
		t.Fatalf("read last_run: %v", err)
	}
	written, perr := time.Parse(time.RFC3339, lastRun)
	if perr != nil {
		t.Fatalf("last_run=%q 仍为平面/非法形态：写守卫必须与读侧同判据推进", lastRun)
	}
	if want := time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC); !written.Equal(want) {
		t.Fatalf("last_run=%v, want 本轮槽 %v", written, want)
	}
	if slot, ok := nextAutoBackupSlot(startedAt); !ok || !slot.After(startedAt) {
		t.Fatalf("slot=%v ok=%v: 改写后下一槽必须在未来", slot, ok)
	}
}
