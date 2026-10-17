package services

// U10-F02（第 78 轮）：逐任务调度开关持久化（节点本地）。
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
	_, err := db.DB.Exec(`INSERT INTO task_loop_prefs (task_id, enabled, updated_at)
		VALUES (?, ?, datetime('now'))
		ON CONFLICT(task_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at`,
		taskID, boolToInt(enabled))
	return err
}

// loadTaskLoopPref 读取单任务偏好；found=false 表示从未记录。
func loadTaskLoopPref(taskID string) (enabled bool, found bool) {
	if db.DB == nil {
		return false, false
	}
	var value int
	if err := db.DB.QueryRow(`SELECT enabled FROM task_loop_prefs WHERE task_id=?`, taskID).Scan(&value); err != nil {
		return false, false
	}
	return value != 0, true
}

// loadTaskLoopPrefs 读取全部偏好为映射（task_id -> enabled）。读取失败返回空
// 映射（按默认启动清单运行）；调用方不得把它当作「全部关闭」。
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

// applyTaskLoopPrefs 把持久化偏好套用到刚从默认清单启动的引擎：
//   - enabled=0 → StopLoop（覆盖默认启动）
//   - enabled=1 → StartLoop（恢复默认关闭的任务，如 cert-waiting-ca）
//
// 业务驱动任务与 Oneshot 任务跳过；未注册任务（版本差异残留行）跳过。
// 幂等：重复调用结果一致。
func applyTaskLoopPrefs(te *taskengine.Engine) {
	if te == nil || db.DB == nil {
		return
	}
	rows, err := db.DB.Query(`SELECT task_id, enabled FROM task_loop_prefs`)
	if err != nil {
		Logf("warn", "任务调度偏好读取失败，按默认启动清单运行: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var taskID string
		var enabled int
		if err := rows.Scan(&taskID, &enabled); err != nil {
			Logf("warn", "任务调度偏好行解析失败，已跳过: %v", err)
			continue
		}
		if IsBusinessDrivenTask(taskID) {
			continue // 业务字段唯一事实源
		}
		meta, ok := te.Lookup(taskID)
		if !ok || meta.Kind == taskengine.KindOneshot {
			continue
		}
		if enabled != 0 {
			te.StartLoop(taskID)
		} else {
			te.StopLoop(taskID)
		}
	}
	if err := rows.Err(); err != nil {
		Logf("warn", "任务调度偏好遍历失败: %v", err)
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
