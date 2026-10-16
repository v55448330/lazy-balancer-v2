package services

import (
	"time"

	"lazy-balancer-v2/internal/db"
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
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return false
	}
	return true
}
