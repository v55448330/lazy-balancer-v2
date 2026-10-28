package services

// 测试目标：集群角色翻转只经 TaskEngine().SetRole；master-only 任务在从节点
// 不得手动调度，升主后由引擎恢复调度，无管理器或旧调度器旁路。
// 钉法：引擎在场+三管理器全 nil（newWireTestEngine 装配不含管理器）+注册
// RoleMasterOnly 探针任务，经角色门 Trigger 的返回值判定引擎角色。
// 夹具次序：newWireTestEngine 会 db.Initialize 换库，ClusterService 直接构造
// 在换库后的 db.DB 上，不再二次 Initialize。

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// registerRoleProbeTask 注册 RoleMasterOnly 触发型探针（Run 空体），返回经
// 角色门探测引擎角色的闭包：nil=引擎视本节点为主节点。
func registerRoleProbeTask(t *testing.T, te *taskengine.Engine) func() error {
	t.Helper()
	if err := te.Register(taskengine.Descriptor{
		ID: "role-probe", Family: "test", Name: "角色探针",
		Category: "系统", Kind: taskengine.KindOneshot,
		RunsOn: taskengine.RoleMasterOnly,
		Run:    func(rc taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatalf("register probe: %v", err)
	}
	return func() error { return te.Trigger("role-probe", "manual", "test") }
}

func TestBecomeSlave_flipsEngineRoleWithManagersNil(t *testing.T) {
	te := newWireTestEngine(t)
	probe := registerRoleProbeTask(t, te)
	if err := probe(); err != nil {
		t.Fatalf("given: 主节点态探针触发应通过角色门: %v", err)
	}

	service := NewClusterService(db.DB, "")
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}

	if err := probe(); err == nil {
		t.Fatal("降级（三管理器全 nil）后 master-only 探针必须被角色门拒绝（旧行为：引擎角色未翻转 → 触发成功 → 必红）")
	}
}

func TestPromote_flipsEngineRoleWithManagersNil(t *testing.T) {
	te := newWireTestEngine(t)
	// 库态种子先于引擎角色：IsMaster 读库判重（引擎 SetRole(false) 不落库）；
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("seed slave db state: %v", err)
	}
	te.SetRole(false) // 从节点态种子
	probe := registerRoleProbeTask(t, te)
	if err := probe(); err == nil {
		t.Fatal("given: 从节点态探针必须被角色门拒绝")
	}

	service := NewClusterService(db.DB, "")
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	if err := probe(); err != nil {
		t.Fatalf("升主（三管理器全 nil）后 master-only 探针应通过角色门: %v", err)
	}
}

type roleLifecycleProbe struct {
	acmeStarts atomic.Int32
	syncStarts atomic.Int32
}

// wireClusterLifecycleEngineForTest 在当前 DB 上装配证书/同步 daemon，
// 不重置测试数据；角色切换只能经引擎调用生命周期 hook。

func (p *roleLifecycleProbe) StartACME() { p.acmeStarts.Add(1) }
func (p *roleLifecycleProbe) StopACME()  {}
func (p *roleLifecycleProbe) StartSync() { p.syncStarts.Add(1) }
func (p *roleLifecycleProbe) StopSync()  {}

func TestPromote_lifecycleStartsOnlyThroughEngine(t *testing.T) {
	// Given：从节点态引擎 + 同时接到 ClusterService 与 daemon hook 的生命周期探针。
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(false)
	probe := &roleLifecycleProbe{}
	SetCertIssuanceLifecycleHooks(probe.StartACME, probe.StopACME)
	SetSyncLifecycleHooks(probe.StartSync, probe.StopSync)
	t.Cleanup(func() {
		SetCertIssuanceLifecycleHooks(nil, nil)
		SetSyncLifecycleHooks(nil, nil)
	})
	service := NewClusterService(db.DB, "")

	// When：升主。
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Then：StartACME 只能由 cert-issuance daemon 调一次，不得再有直调旁路。
	// 固定 Sleep(100ms) 换成条件等待 + 短窗稳定性断言（高负载下
	// 固定窗口既可能提前（flaky 假绿）也可能空等）。
	waitForCond(t, 2*time.Second, func() bool { return probe.acmeStarts.Load() == 1 })
	assertCounterStable(t, &probe.acmeStarts, 1, 100*time.Millisecond)
}

func TestBecomeSlave_lifecycleStartsOnlyThroughEngine(t *testing.T) {
	// Given：主节点态引擎 + 同步生命周期探针。
	newWireTestEngine(t)
	probe := &roleLifecycleProbe{}
	SetCertIssuanceLifecycleHooks(probe.StartACME, probe.StopACME)
	SetSyncLifecycleHooks(probe.StartSync, probe.StopSync)
	t.Cleanup(func() {
		SetCertIssuanceLifecycleHooks(nil, nil)
		SetSyncLifecycleHooks(nil, nil)
	})
	service := NewClusterService(db.DB, "")

	// When：降级。
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}

	// Then：StartSync 只能由 cluster-sync daemon 的新代调用一次
	// 条件等待替代固定 Sleep，再短窗确认无迟到的第二次直调）。
	waitForCond(t, 2*time.Second, func() bool { return probe.syncStarts.Load() == 1 })
	assertCounterStable(t, &probe.syncStarts, 1, 100*time.Millisecond)
}

// assertCounterStable 短窗轮询确认计数在窗口内恒为 want——条件等待只能证明
// 「某一时刻达到 want」，迟到/重复调用需窗口内稳定性断言才能捕获。
func assertCounterStable(t *testing.T, counter *atomic.Int32, want int32, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if got := counter.Load(); got != want {
			t.Fatalf("计数在观察窗口内变为 %d，want 稳定 %d（重复调用）", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPromote_preservesClusterSyncStopped(t *testing.T) {
	// Given：cluster-sync 被用户明确停止。
	_, database := newClusterTestService(t)
	probe := &roleLifecycleProbe{}
	te := wireClusterLifecycleEngineForTest(t, probe, false)
	waitForCond(t, 2*time.Second, func() bool { return probe.syncStarts.Load() == 1 })
	te.StopLoop("cluster-sync")
	waitForCond(t, 2*time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "cluster-sync" && !meta.Running {
				return true
			}
		}
		return false
	})
	probe.syncStarts.Store(0)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	service := NewClusterService(database, "")

	// When：升主成功。
	if err := service.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Then：保持停止，不得因 StartLoop 复活或调用 StartSync。
	if meta, ok := te.Lookup("cluster-sync"); ok && meta.LoopOn {
		t.Fatal("Promote 覆盖了 cluster-sync 用户停止态")
	}
	if got := probe.syncStarts.Load(); got != 0 {
		t.Fatalf("停止的 cluster-sync 被启动 %d 次, want 0", got)
	}
}

func TestPromote_failurePreservesClusterSyncStopped(t *testing.T) {
	// Given：cluster-sync 停止 + 提升事务必然失败。
	_, database := newClusterTestService(t)
	probe := &roleLifecycleProbe{}
	te := wireClusterLifecycleEngineForTest(t, probe, false)
	waitForCond(t, 2*time.Second, func() bool { return probe.syncStarts.Load() == 1 })
	te.StopLoop("cluster-sync")
	waitForCond(t, 2*time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "cluster-sync" && !meta.Running {
				return true
			}
		}
		return false
	})
	probe.syncStarts.Store(0)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_promotion BEFORE UPDATE OF is_master ON global_config
		WHEN NEW.is_master=1 BEGIN SELECT RAISE(ABORT, 'reject promotion'); END`); err != nil {
		t.Fatal(err)
	}
	service := NewClusterService(database, "")

	// When：提升失败并回退。
	if err := service.Promote(context.Background()); err == nil {
		t.Fatal("promotion unexpectedly succeeded")
	}

	// Then：失败回退同样保持停止。
	if meta, ok := te.Lookup("cluster-sync"); ok && meta.LoopOn {
		t.Fatal("Promote 失败回退覆盖了 cluster-sync 用户停止态")
	}
	if got := probe.syncStarts.Load(); got != 0 {
		t.Fatalf("停止的 cluster-sync 被启动 %d 次, want 0", got)
	}
}
