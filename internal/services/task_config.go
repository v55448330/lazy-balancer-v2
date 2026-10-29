package services

import (
	"fmt"

	"lazy-balancer-v2/internal/db"
)

// setGlobalTaskAutoUpdate 写任务级自动更新总闸（global_config 列前缀隔离），
// 并直接驱动对应 StartLoop/StopLoop（业务开关是调度唯一事实源）。
//
// 写侧与版本表族（setVersionTableAutoUpdate）同形：先 INSERT OR IGNORE 补建
// 单行再写标志，并校验 RowsAffected>0。裸 UPDATE 在 global_config 缺行时影响
// 0 行仍返回 nil——开关响应成功、库中无记录、EnabledFn 读 ErrNoRows fail-closed
// 致调度面永不投递（三方不一致且任务监控全绿）。
func setGlobalTaskAutoUpdate(prefix string, enabled bool) error {
	// 同族 DB 入口（engine History/RunOverview、taskmonitor collectCertJobRows、
	// taskrun.taskRunStartedAt）一律先判 nil：装配缺失/测试构造下降级为错误，
	// 而不是 nil 指针 panic。
	if db.DB == nil {
		return fmt.Errorf("更新规则库自动更新开关: 数据库未初始化")
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("更新规则库自动更新开关: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后为 no-op
	if _, err := tx.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		return fmt.Errorf("补建全局配置行: %w", err)
	}
	res, err := tx.Exec(`UPDATE global_config SET `+prefix+`_auto_update=?, updated_at=datetime('now') WHERE id=1`, enabled)
	if err != nil {
		return fmt.Errorf("更新规则库自动更新开关: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取规则库自动更新开关写入结果: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("更新规则库自动更新开关: 未写入任何行")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交规则库自动更新开关: %w", err)
	}
	id, known := businessTaskIDForAutoUpdatePrefix(prefix)
	if !known {
		return fmt.Errorf("更新规则库自动更新开关: 未登记的自动更新前缀 %q", prefix)
	}
	// 调度应用走与业务驱动整轮对齐共用的互斥（setter 与对齐交错的
	// 「库新/loop 旧」错态没有重试纠正路径）；应用值在锁内按库实态读取，
	// 本参数仅作读失败回退。前缀→任务 ID 单源查表（businessTaskDrivers），
	// 未知前缀响亮报错，不再按「前缀即任务 ID」兜底应用。
	applyBusinessTaskLoop(id, enabled)
	return nil
}

// globalTaskAutoUpdateEnabled 读任务级总闸（读错 fail-closed=视为关）。
// 与 AutoBackupEnabled 同族口径：读错必须留痕，否则库故障与「用户关闭」在
// 任务面完全同形（静默停摆、零失败行）。调度门（tick 侧 EnabledFn）使用本
// 二态口径——读错只影响本轮，下一 tick 重新求值即恢复。
func globalTaskAutoUpdateEnabled(prefix string) bool {
	enabled, known := globalTaskAutoUpdateState(prefix)
	return known && enabled
}

// globalTaskAutoUpdateState 三态读取任务级总闸：known=false 表示启用状态
// 不可判定（库不可读/未初始化）。业务驱动任务的调度对齐必须区分「确认关闭」
// 与「读不到」——后者保持上一次生效的调度态并等待周期性重试，不得把一次
// 读失败固化成独立的调度关闭态（此后 tick 连 EnabledFn 都不再求值）。
func globalTaskAutoUpdateState(prefix string) (enabled, known bool) {
	if db.DB == nil {
		return false, false
	}
	var v int
	key := "schedule-read-" + prefix + "-auto-update"
	if err := db.DB.QueryRow(`SELECT COALESCE(` + prefix + `_auto_update,1) FROM global_config WHERE id=1`).Scan(&v); err != nil {
		logScheduleReadFailure(key, err)
		return false, false
	}
	logScheduleReadRecovered(key)
	return v != 0, true
}
