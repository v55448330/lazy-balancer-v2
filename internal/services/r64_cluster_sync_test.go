package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
)

// R64 A-N4：Halted 终态的状态机语义锁定——Start() 对 Halted 是 no-op（缺口本
// 体），Resume() 是唯一出口。SetClusterMode 重新注册路径在 BecomeSlave 后补调
// Resume（handlers/cluster_mode.go）依赖此语义：令牌撤销/schema 不匹配 halt 后，
// 重新注册必须能拉起新循环进入注册轮询，否则从节点静默永久脱同步。
func TestSyncService_halted_startNoOp_resumeRestarts(t *testing.T) {
	_, database := newClusterTestService(t)
	svc := NewSyncService(database, &config.Config{NodeName: "t", Port: 8000}, NewCaddyService("http://127.0.0.1:1"))
	t.Cleanup(svc.Stop)

	// 白盒注入 halt 终态（生产由 token 撤销/schema 不匹配的 run 循环置位，
	// finishRun 保留 Halted 并清空 cancel/done——与此处手工构造等价）
	svc.state.Store(uint32(syncStateHalted))

	// Start()（BecomeSlave→StartSync→Start 路径）对 Halted 必须 no-op——
	// 这是 A-N4 缺口的前提行为，锁定防止语义漂移
	svc.Start()
	if got := syncLifecycleState(svc.state.Load()); got != syncStateHalted {
		t.Fatalf("Start() on Halted must be no-op, state=%v", got)
	}
	svc.mu.Lock()
	cancelAfterStart := svc.cancel
	svc.mu.Unlock()
	if cancelAfterStart != nil {
		t.Fatal("Start() on Halted must not launch a run loop")
	}

	// Resume()（重新注册路径补调）必须拉起新循环并离开 Halted
	svc.Resume()
	if got := syncLifecycleState(svc.state.Load()); got == syncStateHalted {
		t.Fatal("Resume() must leave Halted state（重新注册后循环应重启进入注册轮询）")
	}
	svc.mu.Lock()
	cancelAfterResume := svc.cancel
	svc.mu.Unlock()
	if cancelAfterResume == nil {
		t.Fatal("Resume() must launch a new run loop")
	}

	// 稳定性：Stop 后再次 Resume 不应panic/复活（幂等安全边界）
	svc.Stop()
	done := make(chan struct{})
	go func() { defer close(done); svc.Resume() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Resume after Stop must not hang")
	}
}
