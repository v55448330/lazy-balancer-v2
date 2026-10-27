package services

// 逐任务调度开关持久化（节点本地）。
//
// 背景：任务引擎的 loopEnabled 纯内存；若只靠「启动时无条件 StartLoop 默认
// 清单」，用户显式停止的任务会在进程重启/角色翻转后复活并跑首轮，违背
// 「用户明确停止不得被启动复活」的引擎标准。
//
// 事实源边界：
//   - 业务驱动任务（threat/crs/ip2region/crawlerbot-update/auto-backup/
//     autoban）：业务开关即调度开关，唯一事实源是业务表字段；本表不写、
//     套用时跳过（防第二事实源）。
//   - 非业务驱动且非 Oneshot 的循环/常驻/定时任务：用户经任务监控
//     Toggle/Control 显式改变调度后写本表；内部自动唤醒（证书入队等）只
//     影响运行态，不得改写偏好。
//   - 无记录：保持 InitTaskEngine 的默认启动清单（现行默认）。
//
// 节点本地：本表不进集群快照也不进配置备份/导入（备份表清单显式枚举）。

import (
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// RecordTaskLoopPref 记录用户显式启停偏好（幂等 upsert）。
// 业务驱动任务拒绝写入——业务字段是唯一事实源。
func RecordTaskLoopPref(taskID string, enabled bool) error {
	if db.DB == nil {
		return fmt.Errorf("任务调度偏好：数据库未初始化")
	}
	if IsBusinessDrivenTask(taskID) {
		return fmt.Errorf("任务调度偏好：%s 为业务驱动任务，调度由业务开关决定", taskID)
	}
	// updated_at 与任务域其余时间列同源（配置时区墙钟，见 taskengine 的
	// engineNowStr 口径）；此前用 SQLite `datetime('now')`（UTC），跨表对账/
	// 导出时与同域时间列偏差一个时区。
	updatedAt := time.Now().In(CurrentLocation()).Format("2006-01-02 15:04:05")
	_, err := db.DB.Exec(`INSERT INTO task_loop_prefs (task_id, enabled, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(task_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at`,
		taskID, boolToInt(enabled), updatedAt)
	return err
}

// loadTaskLoopPrefs 读取全部偏好为映射（task_id -> enabled）。读取失败返回空
// 映射（按默认启动清单运行）；调用方不得把它当作「全部关闭」。
// 单任务版 loadTaskLoopPref 仅测试消费（生产零调用）
// 已删除——测试一律经本函数取单键。
func loadTaskLoopPrefs() map[string]bool {
	prefs := map[string]bool{}
	if db.DB == nil {
		return prefs
	}
	rows, err := db.DB.Query(`SELECT task_id, enabled FROM task_loop_prefs`)
	if err != nil {
		Logf("warn", "任务调度偏好读取失败，按默认启动清单运行: %v", err)
		return prefs
	}
	defer rows.Close()
	for rows.Next() {
		var taskID string
		var enabled int
		if err := rows.Scan(&taskID, &enabled); err != nil {
			Logf("warn", "任务调度偏好行解析失败，已跳过: %v", err)
			continue
		}
		prefs[taskID] = enabled != 0
	}
	if err := rows.Err(); err != nil {
		Logf("warn", "任务调度偏好遍历失败: %v", err)
	}
	return prefs
}

// applyTaskLoopPrefs 把已读取的持久化偏好套用到刚从默认清单启动的引擎：
//   - enabled=0 → StopLoop（覆盖默认启动）
//   - enabled=1 → StartLoop（恢复默认关闭的任务，如 cert-waiting-ca）
//
// prefs 由调用方经 loadTaskLoopPrefs 一次性读取传入——
// 此前函数内部二次查询同一表（装配期两份读取可能看到不同快照，且重复 I/O）。
// 业务驱动任务与 Oneshot 任务跳过；未注册任务（版本差异残留行）跳过。
// 幂等：重复调用结果一致。
func applyTaskLoopPrefs(te *taskengine.Engine, prefs map[string]bool) {
	if te == nil {
		return
	}
	stale := make([]string, 0, len(prefs))
	for taskID, enabled := range prefs {
		if IsBusinessDrivenTask(taskID) {
			continue // 业务字段唯一事实源
		}
		meta, ok := te.Lookup(taskID)
		if !ok {
			// 注册表外的残留行（升级删任务/改名后的历史行）：此前静默跳过却
			// 每次启动加载，属域外状态——启动期清理（失败只 warn，偏好表非
			// 关键路径）。
			stale = append(stale, taskID)
			continue
		}
		if meta.Kind == taskengine.KindOneshot {
			continue
		}
		if enabled {
			te.StartLoop(taskID)
		} else {
			te.StopLoop(taskID)
		}
	}
	purgeStaleTaskLoopPrefs(stale)
}

// purgeStaleTaskLoopPrefs 删除注册表外任务的调度偏好残行（启动期一次性）。
func purgeStaleTaskLoopPrefs(taskIDs []string) {
	if len(taskIDs) == 0 || db.DB == nil {
		return
	}
	for _, taskID := range taskIDs {
		if _, err := db.DB.Exec(`DELETE FROM task_loop_prefs WHERE task_id=?`, taskID); err != nil {
			Logf("warn", "清理未注册任务的调度偏好失败（%s）: %v", taskID, err)
			continue
		}
		Logf("info", "已清理未注册任务的调度偏好残留（%s）", taskID)
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
