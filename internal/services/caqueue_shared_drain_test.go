package services

import (
	"testing"
	"time"
)

// PauseAndDrain 的所有队列必须共享一个排空截止时间。逐队列各自等
// caQueueDrainTimeout 会让 N 个 provider 的最坏等待变成 N×30s——配置导入在取
// caddyOpMu 之前调用本函数，该窗口内全部配置写请求排队。与
// CancelJobsForRule、暂停部署回调同口径：共享截止。
//
// 队列状态直接构造（loop 已退出、在途 executions 不归还），不起真实 loop 与
// DB——避免收尾 goroutine 触碰后续测试的库句柄。
func TestCAQueueManager_PauseAndDrain_sharesSingleDrainDeadline(t *testing.T) {
	oldTimeout := caQueueDrainTimeout
	caQueueDrainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { caQueueDrainTimeout = oldTimeout })

	certificateServiceMu.Lock()
	oldService := certificateService
	certificateService = nil
	certificateServiceMu.Unlock()
	t.Cleanup(func() {
		certificateServiceMu.Lock()
		certificateService = oldService
		certificateServiceMu.Unlock()
	})

	queues := make(map[int]*caQueue, 3)
	constructed := make([]*caQueue, 0, 3)
	for id := 1; id <= 3; id++ {
		queue := &caQueue{
			active: make(map[int]struct{}),
			cancel: func() {},
		}
		// 在途执行体不响应取消：三队列的 executions.Wait 都不会返回。
		queue.executions.Add(1)
		queues[id] = queue
		constructed = append(constructed, queue)
	}
	manager := &CAQueueManager{queues: queues, active: true}
	t.Cleanup(func() {
		for _, queue := range constructed {
			queue.executions.Done()
		}
	})

	// When
	start := time.Now()
	drained := manager.PauseAndDrain()
	elapsed := time.Since(start)

	// Then：未排空，且总等待 ≈ 单倍截止（3×100ms 串行会 ≥300ms）
	if drained {
		t.Fatal("PauseAndDrain drained=true, want false（在途执行未退出）")
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("PauseAndDrain elapsed=%v, want < 200ms（共享截止而非逐队列 100ms 串行）", elapsed)
	}
}
