package services

import (
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

const (
	// updateMaxAttempts 任务内重试：同一任务内对失败步骤最多尝试 3 次
	// （1 初始 + 2 重试），重试等待见 updateAttemptWaits。
	updateMaxAttempts = 3
)

// updateAttemptWaits 第 N 次失败后的重试等待（30s/60s）。
var updateAttemptWaits = []time.Duration{30 * time.Second, 60 * time.Second}

// updateRetrySleep 重试等待（测试可替换为即时返回）。
var updateRetrySleep = func(d time.Duration) { time.Sleep(d) }

// runWithInTaskRetry 在同一任务内重试失败步骤：第 N 次失败后经 onWait 回调
// （调用方落「等待 Ns 重试，第 x 次，共 x 次」日志），等待后重试；耗尽返回最后错误。
func runWithInTaskRetry(op func() error, onWait func(nextAttempt int, wait time.Duration, err error)) error {
	var err error
	for attempt := 1; ; attempt++ {
		if err = op(); err == nil || attempt >= updateMaxAttempts {
			return err
		}
		wait := updateAttemptWaits[attempt-1]
		onWait(attempt+1, wait, err)
		updateRetrySleep(wait)
	}
}

// updateRunStillMaster 运行中角色复核（demote 在途中止判定）——
// 与三库起点角色复查同一 SQL 口径（COALESCE(is_master,1)；查询失败按非主
// 节点→跳过语义，宁停勿写）。
func updateRunStillMaster() bool {
	// U10-F11：与同族 B1-8 口径一致——nil 库 fail-closed（按非主节点）。
	if db.DB == nil {
		return false
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return false
	}
	return true
}

// taskRunStartedAt 取任务引擎预插行的 started_at（配置时区墙钟）并归一
// 为 UTC 存储；前端 formatDate 再按配置时区显示，与任务监控展示同一时刻。
// 直接调用（rc=nil/RunID=0）或行不可读时回退当前 UTC。
func taskRunStartedAt(rc *taskengine.RunContext) string {
	// U10-F11：与同族 B1-8 口径一致——nil 库直接回退当前 UTC（不 panic）。
	if db.DB == nil {
		return time.Now().UTC().Format(crsTimeLayout)
	}
	if rc != nil && rc.RunID > 0 {
		var started string
		if err := db.DB.QueryRow(`SELECT started_at FROM task_runs WHERE id=?`, rc.RunID).Scan(&started); err == nil && started != "" {
			if instant, err := time.ParseInLocation(crsTimeLayout, started, CurrentLocation()); err == nil {
				return instant.UTC().Format(crsTimeLayout)
			}
		}
	}
	return time.Now().UTC().Format(crsTimeLayout)
}
