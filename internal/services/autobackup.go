package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 自动备份（v2.0 Scheduled 标准）：引擎在 nextAutoBackupSlot 排程槽调用
// runAutoBackupScheduled。追补/去重=槽位与 last_run 比对（停机跨槽自动补跑
// 一次；失败也推进 last_run，防重试风暴）。执行体由 handlers 包注入
// （services→handlers 直接依赖会成环，装配点在 main.go）。
var (
	autoBackupExecMu   sync.Mutex
	autoBackupExecutor func(ctx context.Context, trigger, operator string, engineRunID int64) error
)

// WriteAutoBackupFileSynced 复用服务层持久化原子落盘单源：唯一临时文件、
// 文件 fsync、rename、父目录 fsync，最终权限 0600。handlers 不另造 tmp+rename
// 平行实现；失败时单源 helper 负责清理临时文件。
func WriteAutoBackupFileSynced(path string, data []byte) error {
	return writeFileAtomicSynced(path, data, 0o600)
}

// SetAutoBackupExecutor 注入备份执行器（main.go 装配 handlers 实现；nil 解除）。
// ctx 由引擎 Run 上下文透传：demote/停止时在途备份
// 必须可被取消，而非跑完并记 success。
func SetAutoBackupExecutor(fn func(ctx context.Context, trigger, operator string, engineRunID int64) error) {
	autoBackupExecMu.Lock()
	autoBackupExecutor = fn
	autoBackupExecMu.Unlock()
}

// AutoBackupEnabled 读自动备份业务开关（读错 fail-closed）。
// 读错必须留痕：引擎先求值 EnabledFn 再求值 NextSlotFn（engine.go），失败即
// LoopOn=false 短路——nextAutoBackupSlot 里已有的 schedule-read-auto-backup
// 告警永远不会被求值，静默 fail-closed 让「库故障」与「用户关闭」在任务面
// 完全同形（零执行、零失败行、零日志）。状态转换口径（首报 warn + 恢复 info）
// 与同族排程读取单源。
func AutoBackupEnabled() bool {
	enabled, known := AutoBackupEnabledState()
	return known && enabled
}

// AutoBackupEnabledState 三态读取自动备份开关：known=false 表示不可判定
// （库不可读/未初始化）。调度对齐只对 known=true 落动作——读失败保持上一次
// 生效的调度态，等周期性重试收敛；tick 侧 EnabledFn 仍用二态 fail-closed。
func AutoBackupEnabledState() (enabled, known bool) {
	if db.DB == nil {
		return false, false
	}
	var v int
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0) FROM global_config WHERE id=1`).Scan(&v); err != nil {
		logScheduleReadFailure("schedule-read-auto-backup-enabled", err)
		return false, false
	}
	logScheduleReadRecovered("schedule-read-auto-backup-enabled")
	return v == 1, true
}

// autoBackupConfigWriter 是 *sql.DB / *sql.Tx 的最小写面（开关写入单源）。
type autoBackupConfigWriter interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// writeAutoBackupEnabled 开关+启用水位线写入的唯一实现（DB 直写与设置页事务
// 共用；off→on 保留既有水位线语义——停用期不追补）。
func writeAutoBackupEnabled(w autoBackupConfigWriter, enabled bool) error {
	var previous int
	if err := w.QueryRow(`SELECT COALESCE(auto_backup_enabled,0) FROM global_config WHERE id=1`).Scan(&previous); err != nil {
		return err
	}
	if _, err := w.Exec(`UPDATE global_config SET auto_backup_enabled=?, updated_at=datetime('now') WHERE id=1`, enabled); err != nil {
		return err
	}
	if previous == 0 && enabled {
		if _, err := w.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, time.Now().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}

// SetAutoBackupEnabledTx 在调用方事务内写业务开关与启用水位线
// 设置页「四列设置 + 开关」必须同事务——修复前设置先落库、开关后写，开关
// 失败返回 500 但设置已生效）。事务提交后由调用方经 SyncAutoBackupTaskLoop
// 同步引擎调度。
//
// 生产写侧唯一入口：本包不再提供自开事务的 SetAutoBackupEnabled（生产引用
// 为零、仅测试消费，且绕过调用方事务边界——测试请直接用本函数 + 事务）。
func SetAutoBackupEnabledTx(tx *sql.Tx, enabled bool) error {
	return writeAutoBackupEnabled(tx, enabled)
}

// SyncAutoBackupTaskLoop 事务提交后同步自动备份调度（启用态即开/关循环）。
func SyncAutoBackupTaskLoop(enabled bool) { applyBusinessTaskLoop("auto-backup", enabled) }

func currentAutoBackupExecutor() func(ctx context.Context, trigger, operator string, engineRunID int64) error {
	autoBackupExecMu.Lock()
	defer autoBackupExecMu.Unlock()
	return autoBackupExecutor
}

// parseAutoBackupHHMM 解析 "HH:MM"（24 小时制，补零两位）。
func parseAutoBackupHHMM(hhmm string) (hour, minute int, ok bool) {
	parts := strings.Split(hhmm, ":")
	if len(parts) != 2 || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return 0, 0, false
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// autoBackupDaysInMonth 返回 y 年 m 月天数。
func autoBackupDaysInMonth(year int, month time.Month) int {
	return time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, -1).Day()
}

// autoBackupDueSlot 返回 ≤now 的最近调度槽（按 loc 时区计算）。
// freq: daily/weekly/monthly；hhmm: "HH:MM"；day: weekly 1=周一…7=周日、
// monthly 写侧限定 1-28（dueSlot 对超出值防御性收敛到月末，防 29-31 在
// 短月缺失）。day 仅被 weekly/monthly 消费，daily 不校验。非法输入 ok=false。
func autoBackupDueSlot(now time.Time, freq, hhmm string, day int, loc *time.Location) (time.Time, bool) {
	hour, minute, ok := parseAutoBackupHHMM(hhmm)
	if !ok {
		return time.Time{}, false
	}
	// 槽的年月日/星期按 loc 的本地日历取值——now 自带时区与 loc 不同时,
	// 直接取 now.Year()/Weekday() 会算错日期(如 UTC 周六 20:30 = 上海周日)
	local := now.In(loc)
	switch freq {
	case "daily":
		slot := time.Date(local.Year(), local.Month(), local.Day(), hour, minute, 0, 0, loc)
		if slot.After(now) {
			slot = slot.AddDate(0, 0, -1)
		}
		return slot, true
	case "weekly":
		if day < 1 || day > 7 {
			return time.Time{}, false
		}
		// 本包 day 1=周一…7=周日 → Go Weekday（周日=0）
		targetGoWeekday := day % 7
		todaySlot := time.Date(local.Year(), local.Month(), local.Day(), hour, minute, 0, 0, loc)
		back := (int(local.Weekday()) - targetGoWeekday + 7) % 7
		slot := todaySlot.AddDate(0, 0, -back)
		if slot.After(now) {
			slot = slot.AddDate(0, 0, -7)
		}
		return slot, true
	case "monthly":
		// 写侧（PUT 校验）限定 1-28；此处对超出值防御性收敛到月末而非拒绝
		//（存量行/带外写库形态不致调度停摆）
		if day < 1 {
			return time.Time{}, false
		}
		slot := time.Date(local.Year(), local.Month(), min(day, autoBackupDaysInMonth(local.Year(), local.Month())), hour, minute, 0, 0, loc)
		if slot.After(now) {
			firstOfPrev := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc).AddDate(0, -1, 0)
			slot = time.Date(firstOfPrev.Year(), firstOfPrev.Month(), min(day, autoBackupDaysInMonth(firstOfPrev.Year(), firstOfPrev.Month())), hour, minute, 0, 0, loc)
		}
		return slot, true
	default:
		return time.Time{}, false
	}
}

// autoBackupDayHigh 返回各频率 auto_backup_day 的合法上限（weekly 1=周一…7=周日；
// daily/monthly 1-28——29-31 在短月没有对应日）。与 handlers 写侧/读侧同名
// helper 同值；services 不能 import handlers（依赖成环），此处是调度侧单源。
func autoBackupDayHigh(freq string) int {
	if freq == "weekly" {
		return 7
	}
	return 28
}

// normalizeAutoBackupDay 把读到的 day 收敛到 1..autoBackupDayHigh(freq)，越界
// 回退 DB 默认 1——与 handlers 读侧 「越界存量值回退默认」同口径，保证
// 「UI 显示的即生效值」。
func normalizeAutoBackupDay(freq string, day int) int {
	if day < 1 || day > autoBackupDayHigh(freq) {
		return 1
	}
	return day
}

// autoBackupSettingsRow 调度器消费的 global_config 设置快照。
type autoBackupSettingsRow struct {
	enabled bool
	freq    string
	hhmm    string
	day     int
	lastRun *time.Time
}

func loadAutoBackupSettings() (autoBackupSettingsRow, error) {
	var row autoBackupSettingsRow
	var lastRun sql.NullString
	// nil 库守卫（生产不可达）——EnabledFn/NextSlotFn 消费方
	// fail-closed（err 路径=已停止/零值槽）。
	if db.DB == nil {
		return row, sql.ErrConnDone
	}
	err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0), COALESCE(auto_backup_frequency,'daily'),
		COALESCE(auto_backup_time,'03:00'), COALESCE(auto_backup_day,1), auto_backup_last_run
		FROM global_config WHERE id=1`).
		Scan(&row.enabled, &row.freq, &row.hhmm, &row.day, &lastRun)
	if err != nil {
		return row, err
	}
	// 读侧收敛 day 到写侧允许区间（weekly 1-7、
	// daily/monthly 1-28）。带外写入的 29-31（集群快照直写不校验）会让
	// monthly「已执行→步进」在短月回退到已执行的过去槽——水位线不再推进，
	// 引擎每 tick 重跑备份；weekly 越界则让 autoBackupDueSlot ok=false，调度面
	// 零槽（任务静默停摆）。越界回退默认 1，与 handlers 读侧同口径。
	row.day = normalizeAutoBackupDay(row.freq, row.day)

	if lastRun.Valid && lastRun.String != "" {
		if parsed, perr := time.Parse(time.RFC3339, lastRun.String); perr == nil {
			row.lastRun = &parsed
		} else {
			// 非法形态按「未跑过」处理——下一个到期槽立即补跑，不静默停摆。
			// 写侧 advanceAutoBackupWatermark 的推进条件必须同判据（非法值可被
			// 覆盖），否则水位线永不推进、每个 tick 重跑一次全量备份。
			Logf("warn", "自动备份：auto_backup_last_run 形态非法 %q（按未运行处理）", lastRun.String)
		}
	}
	return row, nil
}

// nextAutoBackupSlot 计算自动备份的下一执行槽（复用 autoBackupDueSlot
// 逐槽推进语义；禁用或参数非法返回 false）。
func nextAutoBackupSlot(now time.Time) (time.Time, bool) {
	// nil 库守卫与 schedule.go 各族同口径（无库脚手架形态静默零槽，不留痕）。
	if db.DB == nil {
		return time.Time{}, false
	}
	row, err := loadAutoBackupSettings()
	// 读失败按零槽返回但必须留痕（此前静默——库故障窗口
	// 自动备份「静默停摆」，任务监控全绿）。成功路径补恢复 info。
	if err != nil {
		logScheduleReadFailure("schedule-read-auto-backup", err)
		return time.Time{}, false
	}
	logScheduleReadRecovered("schedule-read-auto-backup")
	if !row.enabled {
		return time.Time{}, false
	}
	loc := CurrentLocation()
	due, ok := autoBackupDueSlot(now.In(loc), row.freq, row.hhmm, row.day, loc)
	if !ok {
		// 参数非法（本版本不认识的频率，或非两位补零的时刻形态）此前直接零槽：
		// 任务监控全绿、无失败行、无日志，自动备份永久停摆。按状态转换留痕一次，
		// 恢复合法值后记恢复。
		if lvl := logStateTransition("schedule-auto-backup-invalid", true); lvl != "" {
			Logf(lvl, "自动备份排程参数非法（frequency=%q time=%q day=%d），自动备份不会执行；请改为 daily/weekly/monthly 与两位补零的 HH:MM", row.freq, row.hhmm, row.day)
		}
		return time.Time{}, false
	}
	if lvl := logStateTransition("schedule-auto-backup-invalid", false); lvl != "" {
		Logf(lvl, "自动备份排程参数已恢复合法")
	}
	if !due.After(now.In(loc)) {
		// 漏跑追补：最近过去的槽未被 last_run 覆盖 → 返回该槽（≤now——
		// v2.0 Scheduled 引擎到点立即触发=跨停机窗口补跑）
		if row.lastRun == nil || due.After(*row.lastRun) {
			return due, true
		}
		// 已执行——从「已执行的槽」而非 now 步进（曾恒 +24h——weekly/monthly
		// 时追不上下一槽，下次执行恒显示过去时刻）。从槽步进还消除了月末日历
		// 归一溢出：1/31.AddDate(0,1,0)=3/3 → 回落 3 月槽，2 月槽消失；
		// due 恒为当月合法槽（day 已在读侧收敛到 1..28），+1 月不会溢出。
		step := due.Add(24 * time.Hour)
		switch row.freq {
		case "weekly":
			step = due.Add(7 * 24 * time.Hour)
		case "monthly":
			step = due.AddDate(0, 1, 0)
		}
		due, ok = autoBackupDueSlot(step, row.freq, row.hhmm, row.day, loc)
	}
	return due, ok
}

// NextAutoBackupSlot 返回调度器自身使用的下一执行槽（含 last_run 漏跑补跑
// 判定）。设置页只读展示复用同一入口，不再用未保存表单复制一套推算逻辑。
func NextAutoBackupSlot(now time.Time) (time.Time, bool) {
	return nextAutoBackupSlot(now)
}

// runAutoBackupScheduled 定时任务执行体（v2.0 Scheduled 标准——引擎在排程
// 槽调用；追补/去重判定在 NextSlotFn=nextAutoBackupSlot）。成败均推进
// last_run（失败已由执行器落 failed 行+审计，防重试风暴）。
func runAutoBackupScheduled(ctx context.Context, engineRunID int64) error {
	return runAutoBackupScheduledAt(ctx, engineRunID, time.Now())
}

// runAutoBackupScheduledAt 是定时执行体的显式开始时刻路径。生产入口在调用时
// 固定 startedAt；调用方也可用已知的引擎触发时刻驱动同一条执行与记账链。
func runAutoBackupScheduledAt(ctx context.Context, engineRunID int64, startedAt time.Time) error {
	exec := currentAutoBackupExecutor()
	if exec == nil {
		return errors.New("自动备份执行器未就绪")
	}
	// 水位线槽必须在执行**开始前**固定。补跑跨槽边界结束（如 02:58
	// 启动补昨日 03:00、03:00:10 结束）时用完成时刻重算会写到尚未执行的今日槽，
	// nextAutoBackupSlot 判定「已跑」并步进到明日——当日备份静默漏跑。
	execErr := exec(ctx, "schedule", "system", engineRunID) // engineRunID=引擎已记行——执行器跳过自记（单写方）
	if ctx.Err() != nil {
		// 取消（角色降级/引擎停止）不等于本槽已完成：推进水位线会把漏掉的
		// 备份槽记作已执行，恢复后不再补跑。
		return execErr
	}
	// 水位线写失败必须让本轮返回 error：槽不推进 ⇒ 引擎判定「失败且槽未推进」
	// 才退避，否则默认 1s tick 下每秒重投一次完整备份（每条一行 task_runs）。
	// 口径：备份业务本身可能已成功，失败信号表达的是「本槽未被记账」——
	// 面板短暂 failed 优于每秒重跑全文备份；下次成功记账即恢复正常。
	advanceErr := advanceAutoBackupWatermark(startedAt)
	return errors.Join(execErr, advanceErr)
}

// autoBackupWatermarkSlot 返回本次执行应写入水位线的槽：以触发
// 时刻 startedAt 计算 ≤startedAt 的最近调度槽（=引擎实际触发/补跑的槽），
// 且仅当该槽晚于既有水位线（不倒退、不重复入账）。
func autoBackupWatermarkSlot(startedAt time.Time) (time.Time, bool) {
	row, err := loadAutoBackupSettings()
	if err != nil {
		return time.Time{}, false
	}
	loc := CurrentLocation()
	due, ok := autoBackupDueSlot(startedAt.In(loc), row.freq, row.hhmm, row.day, loc)
	if !ok {
		return time.Time{}, false
	}
	if row.lastRun != nil && !due.After(*row.lastRun) {
		return time.Time{}, false
	}
	return due, true
}

// advanceAutoBackupWatermark 把水位线推进到本次实际执行的槽；SQL 侧同样带
// 「仅前进」守卫（并发手动/定时执行的更晚槽不被回退）。返回错误供调用方
// 让本轮失败（触发引擎退避），不再是只 warn 的尽力而为。
func advanceAutoBackupWatermark(startedAt time.Time) error {
	slot, ok := autoBackupWatermarkSlot(startedAt)
	if !ok {
		// 无需推进（无槽/已覆盖）：不是失败。
		return nil
	}
	formatted := slot.Format(time.RFC3339)
	// 「是否已跑过」的判据与读侧 loadAutoBackupSettings 同源：NULL/空串/非法形态
	// 一律按「从未跑过」处理，允许被本槽覆盖。datetime(非法值) 为 NULL，若只写
	// `datetime(last_run) < datetime(?)`，带外非法值会让条件恒不成立、Exec 仍成功
	// ⇒ 水位线永不推进，调度器每个 tick 判到期并重跑一次完整备份。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1 AND (auto_backup_last_run IS NULL OR auto_backup_last_run='' OR datetime(auto_backup_last_run) IS NULL OR datetime(auto_backup_last_run) < datetime(?))`, formatted, formatted); err != nil {
		Logf("warn", "自动备份：更新 auto_backup_last_run 失败: %v", err)
		return fmt.Errorf("更新自动备份水位线（槽 %s）失败: %w", formatted, err)
	}
	return nil
}
