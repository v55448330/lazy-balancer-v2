package services

import (
	"context"
	"errors"
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

// updateRetrySleep 重试等待（测试可替换为即时返回）。父 ctx 取消会立即
// 中断等待；返回 nil 表示等待完整结束，可进入下一次尝试。
var updateRetrySleep = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runWithInTaskRetry 在同一任务内重试失败步骤：第 N 次失败后经 onWait 回调
// （调用方落「等待 Ns 重试，第 x 次，共 x 次」日志），等待后重试；耗尽返回最后错误。
// 父 runCtx 取消在每次操作后、等待前与等待中均优先返回，不得把手动取消
// 当成瞬断再尝试。这里只检查父 ctx，不把源级 DeadlineExceeded 错当取消。
func runWithInTaskRetry(ctx context.Context, op func() error, onWait func(nextAttempt int, wait time.Duration, err error)) error {
	var err error
	for attempt := 1; ; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		err = op()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err == nil || attempt >= updateMaxAttempts {
			return err
		}
		wait := updateAttemptWaits[attempt-1]
		onWait(attempt+1, wait, err)
		if err := updateRetrySleep(ctx, wait); err != nil {
			return err
		}
	}
}

// updateRunRole 运行期角色三态：(是否主节点, 角色是否已判定)——起点角色门、
// demote 在途中止复核、取消归因共用同一 SQL 口径（COALESCE(is_master,1)）。
// 角色读故障必须是「不可判定」而非并入「非主节点」——否则 DB 瞬断会被误报成
// 「节点已降级」（源行终态与审计失真），或被当作从节点静默跳过本轮（任务监控
// 恒 success 掩盖 DB 异常）。消费口径：!known → 返回错误/记 failed（任务
// 可见）+ warn 留痕；known && !master → 从节点跳过语义（宁停勿写不变）。
func updateRunRole() (bool, bool) {
	// 单次快照：判定与使用同一句柄——两次读 db.DB 之间被置 nil（关库/停引擎
	// 竞态）时 RoleOf 会带着 nil 句柄进入并 panic。
	database := db.DB
	if database == nil {
		return false, false
	}
	isMaster, err := RoleOf(context.Background(), database)
	if err != nil {
		return false, false
	}
	return isMaster, true
}

// errRunRoleUndecidable 角色不可判定（DB 读失败）哨兵——成功写路径复核
// （updateRunWriteGate）的「不可判定」分支返回值：消费方按失败落定
// （task_runs/任务监控可见），不得并入「降级」（skipped）或「手动取消」。
var errRunRoleUndecidable = errors.New("角色读取失败，无法判定本节点是否主节点")

// updateRunWriteGate 成功写路径前的角色+取消复核（与 crsinstall
// observeCancelAfterSwap 同族三态口径，威胁/爬虫/自动封禁成功写路径共用）：
// 下载/评估完成到写库/收敛之间存在毫秒级降级窗口——从节点继续写主库打破
// 只读不变量（现有钉测只覆盖下载期取消，本门补成功路径窗）。语义：
//   - 角色不可判定（DB 读失败）→ errRunRoleUndecidable：不写不收敛，按失败落定；
//   - 已知从节点（已降级）→ taskengine.ErrTaskSkipped：不写不收敛（从节点零写）；
//   - 主节点且 ctx 已取消 → ctx.Err()（手动取消）；nil ctx 视为未取消。
func updateRunWriteGate(ctx context.Context) error {
	if isMaster, known := updateRunRole(); !known {
		return errRunRoleUndecidable
	} else if !isMaster {
		return taskengine.ErrTaskSkipped
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

// taskRunStartedAt 取任务引擎预插行的 started_at（配置时区墙钟）并归一
// 为 UTC 存储；前端 formatDate 再按配置时区显示，与任务监控展示同一时刻。
// 直接调用（rc=nil/RunID=0）或行不可读时回退当前 UTC。
func taskRunStartedAt(rc *taskengine.RunContext) string {
	// 与同族口径一致——nil 库直接回退当前 UTC（不 panic）；单次快照，
	// 判定与查询共用同一句柄（两次读 db.DB 之间被置 nil 会让 QueryRow panic）。
	database := db.DB
	if database == nil {
		return time.Now().UTC().Format(crsTimeLayout)
	}
	if rc != nil && rc.RunID > 0 {
		var started string
		if err := database.QueryRow(`SELECT started_at FROM task_runs WHERE id=?`, rc.RunID).Scan(&started); err == nil && started != "" {
			if instant, err := time.ParseInLocation(crsTimeLayout, started, CurrentLocation()); err == nil {
				return instant.UTC().Format(crsTimeLayout)
			}
		}
	}
	return time.Now().UTC().Format(crsTimeLayout)
}
