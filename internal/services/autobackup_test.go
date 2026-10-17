package services

import (
	"context"
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
	// Given: 9 月 1 日 01:00,monthly day=1 03:00(本月未到)
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
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	// 固定调度时区为 UTC,隔离 CurrentLocation 的全局态
	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatalf("configure UTC location: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ConfigureLocation("UTC")
	})
}

func setAutoBackupTestExecutor(t *testing.T, calls *[]string, err error) {
	t.Helper()
	SetAutoBackupExecutor(func(trigger, operator string, engineRunID int64) error {
		*calls = append(*calls, trigger+":"+operator)
		return err
	})
	t.Cleanup(func() { SetAutoBackupExecutor(nil) })
}

func TestAutoBackupScheduled_execsAndAdvancesLastRun(t *testing.T) {
	// Given: 引擎在排程槽调用（v2.0 Scheduled）——runAutoBackupScheduled 直接执行
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var calls []string
	setAutoBackupTestExecutor(t, &calls, nil)

	// When
	if err := runAutoBackupScheduled(0); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Then: trigger=schedule, 操作者恒为 system, last_run=当日最近槽
	if len(calls) != 1 || calls[0] != "schedule:system" {
		t.Fatalf("calls=%v, want single schedule:system", calls)
	}
	var lastRun string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); err != nil {
		t.Fatalf("read last_run: %v", err)
	}
	got, err := time.Parse(time.RFC3339, lastRun)
	if err != nil {
		t.Fatalf("last_run 非 RFC3339 形态 %q: %v", lastRun, err)
	}
	// 最近槽=测试运行当日 03:00（UTC）——只需断言形态与时点结构
	if got.Hour() != 3 || got.Minute() != 0 {
		t.Fatalf("last_run=%v, want 当日 03:00 槽", got)
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

func TestAutoBackupScheduled_advancesLastRunEvenWhenExecutorFails(t *testing.T) {
	// Given: 执行器失败——last_run 仍推进(失败已落 failed 行,不重试风暴)
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var calls []string
	setAutoBackupTestExecutor(t, &calls, context.DeadlineExceeded)

	// When
	_ = runAutoBackupScheduled(0)

	// Then
	if len(calls) != 1 {
		t.Fatalf("calls=%v, want single attempt", calls)
	}
	var lastRun string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); err != nil {
		t.Fatalf("read last_run: %v", err)
	}
	if got, _ := time.Parse(time.RFC3339, lastRun); got.IsZero() || got.Hour() != 3 {
		t.Fatalf("last_run=%s, want 当日 03:00 槽(失败也推进)", lastRun)
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
	if err := runAutoBackupScheduled(0); err == nil {
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
