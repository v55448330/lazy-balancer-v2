package handlers

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// startCertQueueDispatchForTest 让测试里的 CA 队列真正执行：
// 生产唯一驱动方是 cert-issuance daemon 的 RunTicker；测试未装配引擎，
// 因此显式以同一实现驱动派发（100ms 节拍 + 入队唤醒）。
func startCertQueueDispatchForTest(t *testing.T) {
	t.Helper()
	qm := services.GetCAQueueManager()
	if qm == nil {
		t.Fatal("CA 队列未初始化")
	}
	ctx, cancel := context.WithCancel(context.Background())
	qm.StartDispatchForTest(ctx)
	t.Cleanup(cancel)
}
