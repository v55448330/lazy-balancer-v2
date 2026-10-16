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
// 的本地日历计算、UTC 落库。到期判定走 next_update<=now。
// 2026-09-25 用户裁定（排程语义重构）：①任务必须真正按设置的日期+时间触发
// ——next_update 恒为排程槽（真实触发时间），失败退避不再改写它（原 1h/指数
// 退避覆写机制撤除）；②失败重试在当前任务内完成（见下方 updateMaxAttempts），
// 日志记「第 x 次，共 x 次」；重试耗尽后任务落定 failed，下一运行=下一排程槽。

const (
	defaultScheduleDays = "1,2,3,4,5,6,7"
	defaultScheduleTime = "04:00"
)

// 排程槽推进门共享 SQL 片段（SEC-C-2，第 70 轮审计）：仅 auto 触发且现存
// 槽空/过期才推进——手动触发不动预约、未来槽不回拨。此前同一谓词在
// CRS/IP2Region/威胁情报三族 8 处内联重复（历史同型漏同步两起），此处收敛
// 为单一事实源；参数序恒为「触发来源（?='auto'）、下一槽值（?）」。
// 分族前缀：版本表族（CRS/IP2Region）在谓词前叠加 auto_update=1 门；
// 威胁源族无 auto_update 列（启用门走 WHERE update_enabled=1 重排，见
// scheduleThreatSources），不加该前缀。advanceVersionSlotIfDue 的
// IIF(auto_update=1, ?, next_update) 是另一形态（触发门由调用方
// advanceSlotIfAuto 前置，此处只判 auto_update），刻意不并入。
const (
	// slotAdvanceGateSQL 推进门核心谓词（两族共用）。
	slotAdvanceGateSQL = `?='auto' AND (COALESCE(next_update,'')='' OR next_update<=datetime('now'))`
	// versionTableSlotAdvanceSQL 版本表族（security_crs_version/
	// security_ip2region_version）的 next_update 赋值片段。
	versionTableSlotAdvanceSQL = `next_update=IIF(auto_update=1 AND ` + slotAdvanceGateSQL + `, ?, next_update)`
	// threatSlotAdvanceSQL 威胁源族（security_threat_sources）的
	// next_update 赋值片段。
	threatSlotAdvanceSQL = `next_update=IIF(` + slotAdvanceGateSQL + `, ?, next_update)`
)

// parseUTCSlot 解析 DB 存的 UTC 排程串为 time.Time（crsTimeLayout 与
// RFC3339 双形态——与 localDisplayUTC 同口径）。
func parseUTCSlot(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{crsTimeLayout, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

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

// versionTableNextUpdate 读版本表当前排程槽（空串=未排程）——TASK-L1 同批，
// 引擎 NextSlotFn 的 DB 直读数据源（不经管理器实例）。
func versionTableNextUpdate(table string) string {
	// B1-8（第 74 轮）：nil 库守卫——NextSlotFn fail-closed（零值槽）。
	if db.DB == nil {
		return ""
	}
	var s string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE id=1`).Scan(&s); err != nil {
		return ""
	}
	return s
}

// versionTableNextSlot 版本表「重排时写什么」的统一答案（UTC 落库串）。
func versionTableNextSlot(table string, now time.Time) string {
	days, hhmm := versionTableSchedule(table)
	return NextScheduledSlot(now, days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
}

// versionTableAutoUpdateEnabled 读版本表自动更新开关（读错 fail-closed）。
func versionTableAutoUpdateEnabled(table string) bool {
	if db.DB == nil {
		return false
	}
	var enabled int
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_update,1) FROM ` + table + ` WHERE id=1`).Scan(&enabled); err != nil {
		return false
	}
	return enabled == 1
}

// CRSSchedule 返回 CRS 更新任务排程（GET 载荷）。
func CRSSchedule() ([]int, string) { return versionTableSchedule("security_crs_version") }

// IP2RegionSchedule 返回 IP2Region 更新任务排程（GET 载荷）。
func IP2RegionSchedule() ([]int, string) { return versionTableSchedule("security_ip2region_version") }

// globalTaskSchedule 读任务级排程（global_config 两列；threat/crawler 共用
// 同一读取与归一逻辑，列前缀隔离配置）。
func globalTaskSchedule(prefix string) ([]int, string) {
	var daysRaw, hhmm string
	query := `SELECT COALESCE(` + prefix + `_schedule_days,''), COALESCE(` + prefix + `_schedule_time,'') FROM global_config WHERE id=1`
	if err := db.DB.QueryRow(query).Scan(&daysRaw, &hhmm); err != nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	return normalizeScheduleRow(daysRaw, hhmm)
}

// ThreatSchedule 读威胁库任务级排程（global_config 两列；与 threat_auto_update
// 同表先例——任务级设置不落逐源表）。
func ThreatSchedule() ([]int, string) { return globalTaskSchedule("threat") }

// CrawlerSchedule 读爬虫地址库独立排程（不共享 threat_* 配置）。
func CrawlerSchedule() ([]int, string) { return globalTaskSchedule("crawler") }

// threatNextSlot 威胁库任务级排程槽（UTC 落库串）。
func threatNextSlot(now time.Time) string {
	days, hhmm := ThreatSchedule()
	return NextScheduledSlot(now, days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
}

// crawlerNextSlot 爬虫地址库独立排程槽（UTC 落库串）。
func crawlerNextSlot(now time.Time) string {
	days, hhmm := CrawlerSchedule()
	return NextScheduledSlot(now, days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
}

// earliestEnabledSourceUpdate 返回启用源最早排程槽（空=无排程）。
// sourceTable 仅由包内固定传入，不接受外部输入。
func earliestEnabledSourceUpdate(sourceTable string) string {
	if db.DB == nil {
		return ""
	}
	var next string
	if err := db.DB.QueryRow(`SELECT MIN(COALESCE(NULLIF(next_update,''), '9999')) FROM ` + sourceTable + ` WHERE update_enabled=1`).Scan(&next); err != nil || next == "9999" {
		return ""
	}
	return next
}

func earliestThreatNextUpdate() string {
	return earliestEnabledSourceUpdate("security_threat_sources")
}

func earliestCrawlerNextUpdate() string {
	return earliestEnabledSourceUpdate("security_crawler_sources")
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
	// 2026-09-25 用户裁定：失败退避撤除——一律重排到新槽（原 F49-2 失败行保留
	// 退避的 IIF 守卫随退避机制一并移除）。
	next := NextScheduledSlot(time.Now().UTC(), norm, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE `+table+` SET schedule_days=?, schedule_time=?, next_update=? WHERE id=1`,
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

// setGlobalTaskSchedule 保存任务级排程并事务化重排启用源 next_update。
// 配置列前缀与源表由内部调用方固定传入，不接受外部输入。
func setGlobalTaskSchedule(prefix, sourceTable string, days []int, hhmm string) error {
	norm, err := validateScheduleInput(days, hhmm)
	if err != nil {
		return err
	}
	next := NextScheduledSlot(time.Now().UTC(), norm, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("开启排程事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后为 no-op
	query := `UPDATE global_config SET ` + prefix + `_schedule_days=?, ` + prefix + `_schedule_time=?, updated_at=datetime('now') WHERE id=1`
	if _, err := tx.Exec(query, FormatScheduleDays(norm), hhmm); err != nil {
		return fmt.Errorf("保存定时更新设置: %w", err)
	}
	if _, err := tx.Exec(`UPDATE `+sourceTable+` SET next_update=? WHERE update_enabled=1`, next); err != nil {
		return fmt.Errorf("重排规则库源更新计划: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交排程事务: %w", err)
	}
	return nil
}

// SetThreatSchedule 保存威胁库任务级排程（global_config）并重排全部启用源的
// next_update（2026-09-25 用户裁定：失败源不再保留退避，一律重排到新槽）。
// LBS-B-U1（第 69 轮）：两步写事务化——跨表双写曾各自独立提交，第二步失败
// 留「排程已改、槽位照旧」中间态；现失败整体回滚报错。
func SetThreatSchedule(days []int, hhmm string) error {
	return setGlobalTaskSchedule("threat", "security_threat_sources", days, hhmm)
}

// SetCrawlerSchedule 保存爬虫地址库独立排程并重排全部启用爬虫源。
func SetCrawlerSchedule(days []int, hhmm string) error {
	return setGlobalTaskSchedule("crawler", "security_crawler_sources", days, hhmm)
}
