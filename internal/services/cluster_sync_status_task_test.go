package services

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

func TestClusterSyncStatusMirrorProjectsHaltedSlave(t *testing.T) {
	previous := TaskEngine()
	engine := taskengine.NewEngine(taskengine.Options{StartPaused: true})
	SetTaskEngineForTest(engine)
	t.Cleanup(func() {
		SetTaskEngineForTest(previous)
		engine.Stop()
		SetSyncLifecycleHaltedProbe(nil)
	})

	engine.SetRole(false)
	SetSyncLifecycleHaltedProbe(func() bool { return true })
	if got := clusterSyncStatusMirror(); got != string(TaskStatusFailed) {
		t.Fatalf("halted slave status=%q, want failed", got)
	}

	engine.SetRole(true)
	if got := clusterSyncStatusMirror(); got != "" {
		t.Fatalf("master status=%q, want no slave sync mirror", got)
	}

	engine.SetRole(false)
	SetSyncLifecycleHaltedProbe(func() bool { return false })
	if got := clusterSyncStatusMirror(); got != "" {
		t.Fatalf("healthy slave status=%q, want execution-state fallback", got)
	}
}

// ResumeSyncIfUserEnabled 门控三形状：用户停止态不复活、开启态委托 Resume、
// 引擎未装配（测试/嵌入）委托 Resume。handler 重新注册/手动同步的复活唯一
// 入口——裸 Resume 会把服务层「切从保持停止」守门结果推翻（同步在无调度
// 状态运行，与「切从后不会同步」审计矛盾）。
func TestResumeSyncIfUserEnabled_gatesUserStoppedState(t *testing.T) {
	te := newWireTestEngine(t)
	var calls int
	resume := func() { calls++ }

	// 开启态：委托。
	ResumeSyncIfUserEnabled(resume)
	if calls != 1 {
		t.Fatalf("开启态 resume 调用=%d, want 1", calls)
	}
	// 用户停止态：不委托。
	te.StopLoop("cluster-sync")
	ResumeSyncIfUserEnabled(resume)
	if calls != 1 {
		t.Fatalf("用户停止态 resume 调用=%d, want 保持 1（不得复活）", calls)
	}
	// 重新开启：恢复委托。
	te.StartLoop("cluster-sync")
	ResumeSyncIfUserEnabled(resume)
	if calls != 2 {
		t.Fatalf("重新开启后 resume 调用=%d, want 2", calls)
	}
}

func TestResumeSyncIfUserEnabled_nilEngineDelegates(t *testing.T) {
	previous := TaskEngine()
	SetTaskEngineForTest(nil)
	t.Cleanup(func() { SetTaskEngineForTest(previous) })
	var calls int
	ResumeSyncIfUserEnabled(func() { calls++ })
	if calls != 1 {
		t.Fatalf("引擎未装配时 resume 调用=%d, want 1（委托不阻断）", calls)
	}
}

// 用户停止 → BecomeSlave（gated 不复活）→ 门控入口 Resume：Halted 同步循环
// 保持停止，loop_on=false 与「切从后不会同步」审计不再矛盾（handler 裸
// Resume 曾把 Halted 拉起成无调度运行态）。
func TestBecomeSlave_userStoppedHaltedSyncStaysStoppedThroughResumeGate(t *testing.T) {
	_, database := newClusterTestService(t)
	probe := &roleLifecycleProbe{}
	te := wireClusterLifecycleEngineForTest(t, probe, false)
	waitForCond(t, 2*time.Second, func() bool { return probe.syncStarts.Load() == 1 })

	// 用户停止 cluster-sync 调度。
	te.StopLoop("cluster-sync")
	waitForCond(t, 2*time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "cluster-sync" && !meta.Running {
				return true
			}
		}
		return false
	})

	service := NewClusterService(database, "")
	t.Cleanup(func() { unregisterClusterService(service) })
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	if meta, ok := te.Lookup("cluster-sync"); !ok || meta.LoopOn {
		t.Fatalf("前置不成立：loopOn=%v（用户停止态未保持）", meta.LoopOn)
	}
	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='同步停止' AND detail LIKE '%切从后不会同步%'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("前置不成立：gated 审计=%d 行, want 1", audits)
	}

	// Halted 终态注入（生产由令牌撤销/schema 不匹配置位；白盒等价）。
	sync := NewSyncService(database, &config.Config{NodeName: "gate", Port: 8000}, NewCaddyService("http://127.0.0.1:1"))
	t.Cleanup(sync.Stop)
	t.Cleanup(func() { unregisterSyncDrainer(sync) })
	sync.state.Store(uint32(syncStateHalted))

	// handler 语义：BecomeSlave 返回后经门控入口复活。
	ResumeSyncIfUserEnabled(sync.Resume)

	if !sync.IsHalted() {
		t.Fatal("用户停止态经门控入口仍复活了 Halted 循环——同步在无调度状态运行")
	}
	if meta, ok := te.Lookup("cluster-sync"); !ok || meta.LoopOn {
		t.Fatalf("门控复活改写了调度开关: %+v", meta)
	}
}
