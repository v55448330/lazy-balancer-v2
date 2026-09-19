package services

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 自动备份调度器（v2.3.x）：仅主节点启动（main.go isMaster 分支装配），1 分钟
// tick。到期判定为纯函数 autoBackupDueSlot——返回 ≤now 的最近调度槽；tick 比对
// global_config.auto_backup_last_run，「last_run 为空或 dueSlot 晚于 last_run」
// 即执行并置 last_run=dueSlot（停机跨槽自动补跑一次；失败也推进，防止每分钟
// 重试风暴——失败已落 auto_backups.failed 行与审计）。执行体由 handlers 包注入
// （services→handlers 直接依赖会成环，装配点在 main.go）。
var (
	autoBackupMu     sync.Mutex
	autoBackupCancel context.CancelFunc
	autoBackupDone   chan struct{}

	autoBackupExecMu     sync.Mutex
	autoBackupExecutor   func(trigger, operator string) error
	autoBackupTickWindow = time.Minute
)

// SetAutoBackupExecutor 注入备份执行器（main.go 装配 handlers 实现；nil 解除）。
func SetAutoBackupExecutor(fn func(trigger, operator string) error) {
	autoBackupExecMu.Lock()
	autoBackupExecutor = fn
	autoBackupExecMu.Unlock()
}

func currentAutoBackupExecutor() func(trigger, operator string) error {
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

// autoBackupTick 执行单轮到期判定：未启用/未到期/参数非法均安全跳过。
func autoBackupTick(now time.Time) {
	row, err := loadAutoBackupSettings()
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			Logf("warn", "自动备份：读取设置失败（本轮跳过）: %v", err)
		}
		return
	}
	if !row.enabled {
		return
	}
	dueSlot, ok := autoBackupDueSlot(now, row.freq, row.hhmm, row.day, CurrentLocation())
	if !ok {
		Logf("warn", "自动备份：调度参数非法（freq=%s time=%s day=%d，本轮跳过）", row.freq, row.hhmm, row.day)
		return
	}
	if row.lastRun != nil && !dueSlot.After(*row.lastRun) {
		return
	}
	exec := currentAutoBackupExecutor()
	if exec == nil {
		return
	}
	if err := exec("schedule", "system"); err != nil {
		Logf("error", "自动备份执行失败: %v", err)
	}
	// 成败均推进 last_run——失败已由执行器落 failed 行+审计，此处防重试风暴
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, dueSlot.Format(time.RFC3339)); err != nil {
		Logf("warn", "自动备份：更新 auto_backup_last_run 失败: %v", err)
	}
}

// autoBackupWorkerDone 返回当前 worker 的 done 通道（未运行为 nil；测试用）。
func autoBackupWorkerDone() <-chan struct{} {
	autoBackupMu.Lock()
	defer autoBackupMu.Unlock()
	return autoBackupDone
}

// StartAutoBackupScheduler 启动 1 分钟调度循环（已在运行则幂等 no-op）。
// 启动即先跑一轮 tick——重启后跨槽的备份立即补跑。
func StartAutoBackupScheduler(ctx context.Context) {
	autoBackupMu.Lock()
	if autoBackupDone != nil {
		autoBackupMu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	autoBackupCancel = cancel
	autoBackupDone = done
	autoBackupMu.Unlock()

	go func() {
		defer func() {
			close(done)
			autoBackupMu.Lock()
			if autoBackupDone == done {
				autoBackupCancel = nil
				autoBackupDone = nil
			}
			autoBackupMu.Unlock()
		}()
		autoBackupTick(time.Now())
		ticker := time.NewTicker(autoBackupTickWindow)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				autoBackupTick(time.Now())
			}
		}
	}()
}

// StopAutoBackupScheduler 终止调度循环并等待退出；未运行为 no-op。
func StopAutoBackupScheduler() {
	autoBackupMu.Lock()
	cancel := autoBackupCancel
	done := autoBackupDone
	autoBackupCancel = nil
	autoBackupDone = nil
	autoBackupMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
