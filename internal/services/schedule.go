package services

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 规则库定时调度（v2.3.x）：CRS/IP2Region/威胁情报库三个更新任务的排程从固定
// 24h 间隔改为「星期多选 + 时间」可配置——DB 存逗号串星期（1=周一…7=周日，
// 默认全选=每天）与 HH:MM（默认 04:00），槽位按基础设置时区（CurrentLocation）
// 的本地日历计算、UTC 落库。到期判定仍走 next_update<=now 不变，变的只是
// 「重排时写什么」。失败退避优先：失败后 1h/指数退避的 next_update 覆写排程槽
// （先恢复服务，下个成功后再回到排程节奏）；威胁库保存排程时失败源保留退避
// 不重排。手动「立即更新」不受影响（成功路径同样按排程槽重排）。

const (
	defaultScheduleDays = "1,2,3,4,5,6,7"
	defaultScheduleTime = "04:00"
)

// NormalizeScheduleDays 归一写侧输入：过滤非法值、去重、升序；结果为空表示
// 输入无有效星期（调用方按校验失败拒绝）。
func NormalizeScheduleDays(days []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(days))
	for _, d := range days {
		if d < 1 || d > 7 || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// ParseScheduleDays 解析 DB 逗号串星期集（非法值过滤、去重、升序）。
func ParseScheduleDays(s string) []int {
	var raw []int
	for _, part := range strings.Split(s, ",") {
		if d, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			raw = append(raw, d)
		}
	}
	return NormalizeScheduleDays(raw)
}

// FormatScheduleDays 序列化星期集为逗号串（与 ParseScheduleDays 互逆）。
func FormatScheduleDays(days []int) string {
	norm := NormalizeScheduleDays(days)
	parts := make([]string, 0, len(norm))
	for _, d := range norm {
		parts = append(parts, strconv.Itoa(d))
	}
	return strings.Join(parts, ",")
}

// ValidScheduleHHMM 校验 "HH:MM"（24 小时制，补零两位）——端点 400 判定用。
func ValidScheduleHHMM(hhmm string) bool {
	_, _, ok := parseAutoBackupHHMM(hhmm)
	return ok
}

// NextScheduledSlot 计算 now 之后的下一个排程槽：候选=loc 本地日历的 hh:mm，
// 当日在星期集内且候选>now 则取当日，否则向后扫描至多 8 天取首个命中。
// days 空/全非法 → 兜底全周；hhmm 非法 → 兜底 04:00。返回值带 loc 时区，
// 落库端取 .UTC()。
func NextScheduledSlot(now time.Time, days []int, hhmm string, loc *time.Location) time.Time {
	hour, minute, ok := parseAutoBackupHHMM(hhmm)
	if !ok {
		hour, minute = 4, 0
	}
	set := map[int]bool{}
	for _, d := range NormalizeScheduleDays(days) {
		set[d] = true
	}
	if len(set) == 0 {
		for d := 1; d <= 7; d++ {
			set[d] = true
		}
	}
	local := now.In(loc)
	base := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	for i := 0; i < 8; i++ {
		day := base.AddDate(0, 0, i)
		iso := int(day.Weekday())
		if iso == 0 {
			iso = 7
		}
		if !set[iso] {
			continue
		}
		// 墙面分量重组：跨 DST 时槽位仍落在本地 hh:mm（AddDate 直接加时长会漂移）
		slot := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, loc)
		if slot.After(now) {
			return slot
		}
	}
	// 兜底全周时 8 天扫描必有命中；零值=防御不可达
	return time.Time{}
}

// validateScheduleInput 写侧统一校验（服务层纵深防御；端点先做同口径 400 判定）。
func validateScheduleInput(days []int, hhmm string) ([]int, error) {
	norm := NormalizeScheduleDays(days)
	if len(norm) == 0 {
		return nil, fmt.Errorf("至少选择一天")
	}
	if !ValidScheduleHHMM(hhmm) {
		return nil, fmt.Errorf("时间格式无效（HH:MM）")
	}
	return norm, nil
}

// normalizeScheduleRow 读取端归一：空/非法值回落默认（与 newColumns 默认对齐）。
func normalizeScheduleRow(daysRaw, hhmm string) ([]int, string) {
	days := ParseScheduleDays(daysRaw)
	if len(days) == 0 {
		days = ParseScheduleDays(defaultScheduleDays)
	}
	if !ValidScheduleHHMM(hhmm) {
		hhmm = defaultScheduleTime
	}
	return days, hhmm
}

// versionTableSchedule 读版本表（CRS/IP2Region）排程两列。
func versionTableSchedule(table string) ([]int, string) {
	var daysRaw, hhmm string
	if err := db.DB.QueryRow(`SELECT COALESCE(schedule_days,''), COALESCE(schedule_time,'') FROM `+table+` WHERE id=1`).Scan(&daysRaw, &hhmm); err != nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	return normalizeScheduleRow(daysRaw, hhmm)
}

// versionTableNextSlot 版本表「重排时写什么」的统一答案（UTC 落库串）。
func versionTableNextSlot(table string, now time.Time) string {
	days, hhmm := versionTableSchedule(table)
	return NextScheduledSlot(now, days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
}

// CRSSchedule 返回 CRS 更新任务排程（GET 载荷）。
func CRSSchedule() ([]int, string) { return versionTableSchedule("security_crs_version") }

// IP2RegionSchedule 返回 IP2Region 更新任务排程（GET 载荷）。
func IP2RegionSchedule() ([]int, string) { return versionTableSchedule("security_ip2region_version") }

// ThreatSchedule 读威胁库任务级排程（global_config 两列；与 threat_auto_update
// 同表先例——任务级设置不落逐源表）。
func ThreatSchedule() ([]int, string) {
	var daysRaw, hhmm string
	if err := db.DB.QueryRow(`SELECT COALESCE(threat_schedule_days,''), COALESCE(threat_schedule_time,'') FROM global_config WHERE id=1`).Scan(&daysRaw, &hhmm); err != nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	return normalizeScheduleRow(daysRaw, hhmm)
}

// threatNextSlot 威胁库任务级排程槽（UTC 落库串）。
func threatNextSlot(now time.Time) string {
	days, hhmm := ThreatSchedule()
	return NextScheduledSlot(now, days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
}

// setVersionTableSchedule 版本表排程保存 + 保存即重排（auto_update 关闭时也
// 重排——「下次更新」如实展示，调度器仍受开关门控）。
func setVersionTableSchedule(table, seedVersion string, days []int, hhmm string) error {
	norm, err := validateScheduleInput(days, hhmm)
	if err != nil {
		return err
	}
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO `+table+` (id, version, auto_update) VALUES (1, ?, TRUE)`, seedVersion); err != nil {
		return fmt.Errorf("初始化版本记录: %w", err)
	}
	// F49-2（第 49 轮审计）：失败退避 pending 的行保留退避排程（先恢复服务，
	// 下个成功后回到排程节奏）——与 SetThreatSchedule 的失败源保留同口径。
	next := NextScheduledSlot(time.Now().UTC(), norm, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE `+table+` SET schedule_days=?, schedule_time=?, next_update=IIF(COALESCE(update_status,'')='failed', next_update, ?) WHERE id=1`,
		FormatScheduleDays(norm), hhmm, next); err != nil {
		return fmt.Errorf("保存定时更新设置: %w", err)
	}
	return nil
}

// SetCRSSchedule 保存 CRS 更新排程（星期集 + 时间）并重排 next_update。
func SetCRSSchedule(days []int, hhmm string) error {
	return setVersionTableSchedule("security_crs_version", CRSBundledVersion, days, hhmm)
}

// SetIP2RegionSchedule 保存 IP2Region 更新排程并重排 next_update。
func SetIP2RegionSchedule(days []int, hhmm string) error {
	return setVersionTableSchedule("security_ip2region_version", "unknown", days, hhmm)
}

// SetThreatSchedule 保存威胁库任务级排程（global_config）并重排启用且非失败
// 源的 next_update；失败源保留退避排程（先恢复服务，下个成功后回到排程节奏）。
func SetThreatSchedule(days []int, hhmm string) error {
	norm, err := validateScheduleInput(days, hhmm)
	if err != nil {
		return err
	}
	next := NextScheduledSlot(time.Now().UTC(), norm, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_schedule_days=?, threat_schedule_time=?, updated_at=datetime('now') WHERE id=1`,
		FormatScheduleDays(norm), hhmm); err != nil {
		return fmt.Errorf("保存定时更新设置: %w", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE update_enabled=1 AND COALESCE(update_status,'') != 'failed'`, next); err != nil {
		return fmt.Errorf("重排威胁库源更新计划: %w", err)
	}
	return nil
}
