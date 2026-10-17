package services

import (
	"database/sql"
	"errors"
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
	autoBackupExecutor func(trigger, operator string, engineRunID int64) error
)

// SetAutoBackupExecutor 注入备份执行器（main.go 装配 handlers 实现；nil 解除）。
func SetAutoBackupExecutor(fn func(trigger, operator string, engineRunID int64) error) {
	autoBackupExecMu.Lock()
	autoBackupExecutor = fn
	autoBackupExecMu.Unlock()
}

// AutoBackupEnabled 读自动备份业务开关（读错 fail-closed）。
func AutoBackupEnabled() bool {
	if db.DB == nil {
		return false
	}
	var enabled int
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0) FROM global_config WHERE id=1`).Scan(&enabled); err != nil {
		return false
	}
	return enabled == 1
}

// SetAutoBackupEnabled 写自动备份业务开关并同步任务调度；off→on 保留
// 既有水位线语义（停用期不追补），与设置页保存同口径。
func SetAutoBackupEnabled(enabled bool) error {
	var previous int
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0) FROM global_config WHERE id=1`).Scan(&previous); err != nil {
		return err
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=?, updated_at=datetime('now') WHERE id=1`, enabled); err != nil {
		return err
	}
	if previous == 0 && enabled {
		if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, time.Now().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	syncTaskLoop("auto-backup", enabled)
	return nil
}

func currentAutoBackupExecutor() func(trigger, operator string, engineRunID int64) error {
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
	// B1-8（第 74 轮）：nil 库守卫（生产不可达）——EnabledFn/NextSlotFn 消费方
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
	if lastRun.Valid && lastRun.String != "" {
		if parsed, perr := time.Parse(time.RFC3339, lastRun.String); perr == nil {
			row.lastRun = &parsed
		} else {
			// 非法形态按「未跑过」处理——下一个到期槽立即补跑，不静默停摆
			Logf("warn", "自动备份：auto_backup_last_run 形态非法 %q（按未运行处理）", lastRun.String)
		}
	}
	return row, nil
}

// nextAutoBackupSlot 计算自动备份的下一执行槽（复用 autoBackupDueSlot
// 逐槽推进语义；禁用或参数非法返回 false）。
func nextAutoBackupSlot(now time.Time) (time.Time, bool) {
	row, err := loadAutoBackupSettings()
	if err != nil || !row.enabled {
		return time.Time{}, false
	}
	loc := CurrentLocation()
	due, ok := autoBackupDueSlot(now.In(loc), row.freq, row.hhmm, row.day, loc)
	if !ok {
		return time.Time{}, false
	}
	if !due.After(now.In(loc)) {
		// 漏跑追补：最近过去的槽未被 last_run 覆盖 → 返回该槽（≤now——
		// v2.0 Scheduled 引擎到点立即触发=跨停机窗口补跑）
		if row.lastRun == nil || due.After(*row.lastRun) {
			return due, true
		}
		// 已执行——步进到下一未来槽
		// （R63-P2-4：曾恒 +24h——weekly/monthly 时追不上下一槽，下次执行恒显示过去时刻）
		step := now.In(loc).Add(24 * time.Hour)
		switch row.freq {
		case "weekly":
			step = now.In(loc).Add(7 * 24 * time.Hour)
		case "monthly":
			step = now.In(loc).AddDate(0, 1, 0)
		}
		due, ok = autoBackupDueSlot(step, row.freq, row.hhmm, row.day, loc)
	}
	return due, ok
}

// runAutoBackupScheduled 定时任务执行体（v2.0 Scheduled 标准——引擎在排程
// 槽调用；追补/去重判定在 NextSlotFn=nextAutoBackupSlot）。成败均推进
// last_run（失败已由执行器落 failed 行+审计，防重试风暴）。
func runAutoBackupScheduled(engineRunID int64) error {
	exec := currentAutoBackupExecutor()
	if exec == nil {
		return errors.New("自动备份执行器未就绪")
	}
	execErr := exec("schedule", "system", engineRunID) // engineRunID=引擎已记行——执行器跳过自记（单写方）
	row, err := loadAutoBackupSettings()
	if err == nil {
		if dueSlot, ok := autoBackupDueSlot(time.Now(), row.freq, row.hhmm, row.day, CurrentLocation()); ok {
			if _, uerr := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, dueSlot.Format(time.RFC3339)); uerr != nil {
				Logf("warn", "自动备份：更新 auto_backup_last_run 失败: %v", uerr)
			}
		}
	}
	return execErr
}
