package services

import (
	"context"
	"slices"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 规则库定时调度（星期多选 + 时间，时区遵循基础设置）：NextScheduledSlot 纯函数
// 形状矩阵 + 三库「保存排程/开关/成功路径/tick 预写」的重排口径。

func useShanghaiLocation(t *testing.T) *time.Location {
	t.Helper()
	loc, err := ConfigureLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation("UTC") })
	return loc
}

func allWeek() []int { return []int{1, 2, 3, 4, 5, 6, 7} }

// 2026-08-11 是周二（+08 本地日历）。

func TestNextScheduledSlot_sameDayBeforeSlot(t *testing.T) {
	// Given 当日（周二）未到排程点
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 11, 3, 0, 0, 0, loc)

	// When
	slot := NextScheduledSlot(now, allWeek(), "04:00", loc)

	// Then 取当日槽
	want := time.Date(2026, 8, 11, 4, 0, 0, 0, loc)
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestNextScheduledSlot_sameDayAfterSlot(t *testing.T) {
	// Given 当日已过排程点
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 11, 5, 0, 0, 0, loc)

	// When
	slot := NextScheduledSlot(now, allWeek(), "04:00", loc)

	// Then 取次日槽
	want := time.Date(2026, 8, 12, 4, 0, 0, 0, loc)
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestNextScheduledSlot_skipsUnselectedWeekdays(t *testing.T) {
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 11, 5, 0, 0, 0, loc) // 周二 05:00

	// When 仅选周三
	slot := NextScheduledSlot(now, []int{3}, "04:00", loc)

	// Then 取周三槽（今日虽过点但未选）
	want := time.Date(2026, 8, 12, 4, 0, 0, 0, loc)
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}

	// When 仅选周二（今日已过点）
	slot = NextScheduledSlot(now, []int{2}, "04:00", loc)

	// Then 跨周回绕到下周二
	want = time.Date(2026, 8, 18, 4, 0, 0, 0, loc)
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestNextScheduledSlot_weekendWrap(t *testing.T) {
	// Given 周五过点，仅选周一
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 14, 5, 0, 0, 0, loc) // 周五

	// When
	slot := NextScheduledSlot(now, []int{1}, "04:00", loc)

	// Then 跨周末回绕到下周一
	want := time.Date(2026, 8, 17, 4, 0, 0, 0, loc)
	if !slot.Equal(want) {
		t.Fatalf("slot=%v, want %v", slot, want)
	}
}

func TestNextScheduledSlot_timezoneSensitive(t *testing.T) {
	// Given UTC 周二 20:30 = 上海周三 04:30（本地日历已跨日且过点）
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 11, 20, 30, 0, 0, time.UTC)

	// When
	slot := NextScheduledSlot(now, allWeek(), "04:00", loc)

	// Then 取上海周四 04:00 = UTC 周三 20:00（落库 UTC 与本地墙面相差 8h）
	wantUTC := time.Date(2026, 8, 12, 20, 0, 0, 0, time.UTC)
	if !slot.UTC().Equal(wantUTC) {
		t.Fatalf("slot.UTC()=%v, want %v", slot.UTC(), wantUTC)
	}
	if slot.In(loc).Hour() != 4 || slot.In(loc).Minute() != 0 {
		t.Fatalf("slot local wall=%v, want 04:00", slot.In(loc))
	}
}

func TestNextScheduledSlot_emptyOrInvalidDaysFallbackAllWeek(t *testing.T) {
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 11, 5, 0, 0, 0, loc)
	want := time.Date(2026, 8, 12, 4, 0, 0, 0, loc)

	for name, days := range map[string][]int{
		"空集":   {},
		"全非法值": {0, 8, -3},
		"含非法值": {3, 99}, // 3 有效 → 周三槽，不兜底
	} {
		slot := NextScheduledSlot(now, days, "04:00", loc)
		if name == "含非法值" {
			if w := time.Date(2026, 8, 12, 4, 0, 0, 0, loc); !slot.Equal(w) {
				t.Fatalf("%s: slot=%v, want %v（非法值过滤后按有效值）", name, slot, w)
			}
			continue
		}
		if !slot.Equal(want) {
			t.Fatalf("%s: slot=%v, want %v（兜底全周）", name, slot, want)
		}
	}
}

func TestNextScheduledSlot_invalidTimeFallback0400(t *testing.T) {
	loc := useShanghaiLocation(t)
	now := time.Date(2026, 8, 11, 3, 0, 0, 0, loc)
	want := time.Date(2026, 8, 11, 4, 0, 0, 0, loc)

	for _, hhmm := range []string{"25:99", "9:00", "bad", ""} {
		if slot := NextScheduledSlot(now, allWeek(), hhmm, loc); !slot.Equal(want) {
			t.Fatalf("hhmm=%q: slot=%v, want %v（非法时间兜底 04:00）", hhmm, slot, want)
		}
	}
}

func TestScheduleDaysParseFormat(t *testing.T) {
	if got := ParseScheduleDays("1,2,3,4,5,6,7"); !slices.Equal(got, allWeek()) {
		t.Fatalf("ParseScheduleDays full=%v", got)
	}
	// 去重 + 排序 + 非法值过滤
	if got := ParseScheduleDays("5,2,2,0,9,x"); !slices.Equal(got, []int{2, 5}) {
		t.Fatalf("ParseScheduleDays mixed=%v, want [2 5]", got)
	}
	if got := ParseScheduleDays(""); len(got) != 0 {
		t.Fatalf("ParseScheduleDays empty=%v, want []", got)
	}
	if got := FormatScheduleDays([]int{5, 2, 2}); got != "2,5" {
		t.Fatalf("FormatScheduleDays=%q, want %q", got, "2,5")
	}
	// NormalizeScheduleDays：非法过滤后非空才有效（端点校验同用）
	if got := NormalizeScheduleDays([]int{0, 8}); len(got) != 0 {
		t.Fatalf("NormalizeScheduleDays invalid=%v, want empty", got)
	}
	if got := NormalizeScheduleDays([]int{7, 1, 7}); !slices.Equal(got, []int{1, 7}) {
		t.Fatalf("NormalizeScheduleDays=%v, want [1 7]", got)
	}
}

// readVersionSchedule 读版本表排程三列（测试断言助手）。
func readVersionSchedule(t *testing.T, table string) (days, hhmm, nextUpdate string) {
	t.Helper()
	err := db.DB.QueryRow(`SELECT COALESCE(schedule_days,''), COALESCE(schedule_time,''), COALESCE(next_update,'') FROM `+table+` WHERE id=1`).
		Scan(&days, &hhmm, &nextUpdate)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func parseSlotUTC(t *testing.T, raw string) time.Time {
	t.Helper()
	for _, layout := range []string{crsTimeLayout, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC()
		}
	}
	t.Fatalf("next_update=%q 不可解析", raw)
	return time.Time{}
}

func TestSetCRSSchedule_persistsAndRearms(t *testing.T) {
	// Given 已播种的 CRS 版本行
	newTestCRSManager(t)
	loc := useShanghaiLocation(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	want := NextScheduledSlot(time.Now().UTC(), []int{2}, "04:30", loc)

	// When 保存排程（仅周二 04:30）
	if err := SetCRSSchedule([]int{2}, "04:30"); err != nil {
		t.Fatalf("SetCRSSchedule: %v", err)
	}

	// Then 排程列落库 + next_update 重排为下一个周二 04:30（UTC）
	days, hhmm, nextUpdate := readVersionSchedule(t, "security_crs_version")
	if days != "2" || hhmm != "04:30" {
		t.Fatalf("schedule=(%q,%q), want (2,04:30)", days, hhmm)
	}
	if got := parseSlotUTC(t, nextUpdate); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want %v", got, want.UTC())
	}
	if got := parseSlotUTC(t, nextUpdate).In(loc); got.Weekday() != time.Tuesday {
		t.Fatalf("next_update weekday=%v, want Tuesday", got.Weekday())
	}
}

func TestSetCRSSchedule_rejectsInvalid(t *testing.T) {
	newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)

	if err := SetCRSSchedule([]int{0, 9}, "04:30"); err == nil {
		t.Fatal("全非法星期应报错")
	}
	if err := SetCRSSchedule(nil, "04:30"); err == nil {
		t.Fatal("空星期集应报错")
	}
	if err := SetCRSSchedule([]int{2}, "25:99"); err == nil {
		t.Fatal("非法时间应报错")
	}
	// 行不受影响
	days, _, _ := readVersionSchedule(t, "security_crs_version")
	if days != "1,2,3,4,5,6,7" {
		t.Fatalf("schedule_days=%q, want 默认未变", days)
	}
}

func TestSetIP2RegionSchedule_persistsAndRearms(t *testing.T) {
	newTestIP2RegionManager(t)
	loc := useShanghaiLocation(t)
	seedIP2RegionVersionRow(t, "commit-abc", true)
	want := NextScheduledSlot(time.Now().UTC(), []int{6}, "23:15", loc)

	if err := SetIP2RegionSchedule([]int{6}, "23:15"); err != nil {
		t.Fatalf("SetIP2RegionSchedule: %v", err)
	}

	days, hhmm, nextUpdate := readVersionSchedule(t, "security_ip2region_version")
	if days != "6" || hhmm != "23:15" {
		t.Fatalf("schedule=(%q,%q), want (6,23:15)", days, hhmm)
	}
	if got := parseSlotUTC(t, nextUpdate); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want %v", got, want.UTC())
	}
}

func TestSetThreatSchedule_persistsAndRearmsEnabledSources(t *testing.T) {
	// Given 三源：ustc 失败退避中，其余启用且非失败
	newClusterTestService(t)
	loc := useShanghaiLocation(t)
	backoff := time.Now().UTC().Add(time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', consecutive_failures=1, next_update=? WHERE name='ustc'`, backoff); err != nil {
		t.Fatal(err)
	}
	want := NextScheduledSlot(time.Now().UTC(), []int{3}, "05:00", loc)
	// When
	if err := SetThreatSchedule([]int{3}, "05:00"); err != nil {
		t.Fatalf("SetThreatSchedule: %v", err)
	}

	// Then global_config 排程列落库
	var days, hhmm string
	if err := db.DB.QueryRow(`SELECT COALESCE(threat_schedule_days,''), COALESCE(threat_schedule_time,'') FROM global_config WHERE id=1`).Scan(&days, &hhmm); err != nil {
		t.Fatal(err)
	}
	if days != "3" || hhmm != "05:00" {
		t.Fatalf("threat schedule=(%q,%q), want (3,05:00)", days, hhmm)
	}
	// 启用且非失败源重排到槽位；失败源保留退避排程
	for _, name := range []string{"firehol_l1", "et_compromised"} {
		var next string
		if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name=?`, name).Scan(&next); err != nil {
			t.Fatal(err)
		}
		if got := parseSlotUTC(t, next); !got.Equal(want.UTC()) {
			t.Fatalf("%s next_update=%v, want %v", name, got, want.UTC())
		}
	}
	var ustcNext string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&ustcNext); err != nil {
		t.Fatal(err)
	}
	if ustcNext != backoff {
		t.Fatalf("失败源 next_update=%q, want 保留退避 %q", ustcNext, backoff)
	}
}

func TestSetThreatSchedule_rejectsInvalid(t *testing.T) {
	newClusterTestService(t)
	if err := SetThreatSchedule(nil, "04:00"); err == nil {
		t.Fatal("空星期集应报错")
	}
	if err := SetThreatSchedule([]int{1}, "bad"); err == nil {
		t.Fatal("非法时间应报错")
	}
}

// —— 既有「+24h」写点改走排程槽的行为钉 ——

func TestSetCRSAutoUpdate_enableUsesConfiguredSchedule(t *testing.T) {
	newTestCRSManager(t)
	loc := useShanghaiLocation(t)
	seedCRSVersionRow(t, "v4.14.0", false)
	if err := SetCRSSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}
	want := NextScheduledSlot(time.Now().UTC(), []int{2}, "04:30", loc)

	// When 开启自动更新
	if err := SetCRSAutoUpdate(true); err != nil {
		t.Fatal(err)
	}

	// Then next_update=排程槽（而非旧的 now+24h）
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	got := parseSlotUTC(t, nextUpdate)
	if !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want 排程槽 %v", got, want.UTC())
	}
}

func TestSetIP2RegionAutoUpdate_enableUsesConfiguredSchedule(t *testing.T) {
	newTestIP2RegionManager(t)
	loc := useShanghaiLocation(t)
	seedIP2RegionVersionRow(t, "commit-abc", false)
	if err := SetIP2RegionSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}
	want := NextScheduledSlot(time.Now().UTC(), []int{2}, "04:30", loc)

	if err := SetIP2RegionAutoUpdate(true); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if got := parseSlotUTC(t, nextUpdate); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want 排程槽 %v", got, want.UTC())
	}
}

func TestCRSSchedulerTick_prewritesConfiguredSlot(t *testing.T) {
	// Given 自动更新开、无 next_update、排程=周四 06:00
	m := newTestCRSManager(t)
	loc := useShanghaiLocation(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if err := SetCRSSchedule([]int{4}, "06:00"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET next_update='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) // 周二（上海 20:00）
	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v4.15.0", nil
	}

	// When 首个 tick（只排程不启动）
	m.schedulerTick(now, nil)

	// Then 预写=周四 06:00 槽且不启动更新
	if fetchCalled {
		t.Fatal("first tick should only schedule, not run")
	}
	want := NextScheduledSlot(now, []int{4}, "06:00", loc)
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if got := parseSlotUTC(t, nextUpdate); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want %v", got, want.UTC())
	}
}

func TestCRSUpdate_successReschedulesToConfiguredSlot(t *testing.T) {
	// Given 排程=周二 04:30，更新结果「已是最新」（成功无下载路径）
	m := newTestCRSManager(t)
	loc := useShanghaiLocation(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if err := SetCRSSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }

	// When
	m.run("manual")

	// Then 成功路径把 next_update 重排到槽位（而非 datetime('now','+24 hours')）
	want := NextScheduledSlot(time.Now().UTC(), []int{2}, "04:30", loc)
	_, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("status=%q, want success", status)
	}
	if got := parseSlotUTC(t, nextUpdate); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want 排程槽 %v", got, want.UTC())
	}
}

func TestIP2RegionUpdate_successReschedulesToConfiguredSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	loc := useShanghaiLocation(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if err := SetIP2RegionSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }

	m.run("manual")

	want := NextScheduledSlot(time.Now().UTC(), []int{2}, "04:30", loc)
	_, status, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("status=%q, want success", status)
	}
	if got := parseSlotUTC(t, nextUpdate); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want 排程槽 %v", got, want.UTC())
	}
}

func TestMarkSourceSuccess_usesConfiguredSchedule(t *testing.T) {
	// Given 威胁库排程=周五 07:15
	newClusterTestService(t)
	loc := useShanghaiLocation(t)
	if err := SetThreatSchedule([]int{5}, "07:15"); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	want := NextScheduledSlot(time.Now().UTC(), []int{5}, "07:15", loc)

	// When 源成功落库
	markSourceSuccess(id, 10, time.Now().UTC().Format(crsTimeLayout))

	// Then next_update=排程槽（而非 now+24h）
	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE id=?`, id).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if got := parseSlotUTC(t, next); !got.Equal(want.UTC()) {
		t.Fatalf("next_update=%v, want 排程槽 %v", got, want.UTC())
	}
}
