package services

// 运行日志尺寸刷新 worker 的重启路径必须有界：旧 worker 卡在 DB busy_timeout
// 时不得无界挂起刷新链启动——超时放弃等待并 warn，新实例照常接续（新实例的
// 首次刷新可经 runtimeLogSizeMB 观测，不需要 StartLogRotate 返回 done 通道）。

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// installStuckLogRotateWorker 安装「永不退出」的旧 worker 形态（done 永不关闭，
// 等价于 refresh 阻塞在 DB busy_timeout 的生产形态），返回释放函数。
func installStuckLogRotateWorker(t *testing.T) chan struct{} {
	t.Helper()
	stuck := make(chan struct{})
	runtimeLogSizeRefresh.Lock()
	runtimeLogSizeRefresh.cancel = func() {}
	runtimeLogSizeRefresh.done = stuck
	runtimeLogSizeRefresh.Unlock()
	t.Cleanup(func() { StopLogRotateWithin(2 * time.Second) })
	return stuck
}

func TestLogRotateRestart_abandonsStuckWorkerWithinBudget(t *testing.T) {
	initServicesDB(t)
	logs := captureServiceLog(t)
	installStuckLogRotateWorker(t)

	// When 旧 worker 永不退出时重启刷新链。
	begin := time.Now()
	StartLogRotate(context.Background())
	elapsed := time.Since(begin)

	// Then 等待被预算截断（约 1s），不无界挂起。
	if elapsed > 3*time.Second {
		t.Fatalf("重启等待耗时 %s，超出有界预算（%s）", elapsed, logRotateRestartWaitMax)
	}
	if elapsed < logRotateRestartWaitMax/2 {
		t.Fatalf("重启等待耗时 %s，未等待预算即放弃（%s）", elapsed, logRotateRestartWaitMax)
	}
	if warns := countLogLines(logs, "未在重启预算"); warns != 1 {
		t.Fatalf("放弃等待 warn lines=%d, want 1; logs=%s", warns, logs.String())
	}

	// Then 新实例已接管：可正常停止（旧 worker 永不退出的形态不得被沿用）。
	if !StopLogRotateWithin(2 * time.Second) {
		t.Fatal("重启后的 worker 必须在预算内退出（新实例已接管）")
	}
}

func TestStartLogRotate_refreshesThresholdObservably(t *testing.T) {
	initServicesDB(t)
	StopLogRotateWithin(2 * time.Second)
	t.Cleanup(func() {
		StopLogRotateWithin(2 * time.Second)
		runtimeLogSizeMB.Store(100)
	})
	if _, err := db.DB.Exec(`UPDATE global_config SET runtime_log_size_mb=7 WHERE id=1`); err != nil {
		t.Fatalf("seed runtime log size: %v", err)
	}
	runtimeLogSizeMB.Store(100)

	// When 启动刷新链（无 done 通道可等——结果必须经阈值本身观测）。
	StartLogRotate(context.Background())

	// Then 首次刷新落库值，写侧消费的阈值随之生效。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtimeLogSizeMB.Load() == 7 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("runtimeLogSizeMB=%d，首次刷新未在超时内落库", runtimeLogSizeMB.Load())
}
