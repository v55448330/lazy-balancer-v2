package services

// （不再内部二次查表） / 装配暂停与 BootSync 后恢复调度的结构钉。

import (
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// 表二次查询，传入快照被无视（此测试传「库中不存在」的偏好行，行为必须
// 按快照生效）。单任务版 loadTaskLoopPref 已删除，测试经 loadTaskLoopPrefs
// 取单键。
func TestApplyTaskLoopPrefs_consumesProvidedSnapshot(t *testing.T) {
	te := newWireTestEngine(t)
	meta, ok := te.Lookup("log-cleanup")
	if !ok || !meta.LoopOn {
		t.Fatalf("装配默认应开启 log-cleanup 调度, ok=%v loopOn=%v", ok, meta.LoopOn)
	}
	// 快照中的偏好行不在 task_loop_prefs 表内（旧实现内部重查 → 空映射 → 无效）。
	if prefs := loadTaskLoopPrefs(); len(prefs) != 0 {
		t.Fatalf("基线表应为空, got %v", prefs)
	}
	applyTaskLoopPrefs(te, map[string]bool{"log-cleanup": false})
	if meta, _ := te.Lookup("log-cleanup"); meta.LoopOn {
		t.Fatal("applyTaskLoopPrefs 必须消费调用方快照（旧实现内部重查表会无视该偏好）")
	}
}

// InitTaskEngine 装配期调度暂停、BootSync 完成后恢复——直接观察
// 引擎公开执行门，不再读取源码文本。暂停门与 tick 共用 schedPaused，BootSync
// 的 startup 触发是该暂停期唯一豁免。
func TestInitTaskEngine_pausesTickUntilBootSyncDone(t *testing.T) {
	setupIsolatedDB(t)
	t.Cleanup(StopTaskEngine)
	bootEntered := make(chan struct{})
	releaseBoot := make(chan struct{})
	SetConfigLoadRerun(func(string) error {
		close(bootEntered)
		<-releaseBoot
		return nil
	})
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	// 装配期服务屏障：常驻族（cert-issuance）的 Run 体起步即接管部署面
	// （StartACME→CA 队列/部署重试）。配置载入完成前必须被屏障挡住。
	lifecycleStarted := make(chan struct{}, 1)
	SetCertIssuanceLifecycleHooks(func() {
		select {
		case lifecycleStarted <- struct{}{}:
		default:
		}
	}, func() {})
	t.Cleanup(func() { SetCertIssuanceLifecycleHooks(nil, nil) })
	initDone := make(chan *taskengine.Engine, 1)
	go func() { initDone <- InitTaskEngine("", t.TempDir()+"/app.log") }()

	select {
	case <-bootEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("BootSync did not reach configLoadRerun")
	}
	// BootSync 未完成 = 配置未载入：证书签发生命周期不得已接管部署面。
	select {
	case <-lifecycleStarted:
		t.Fatal("配置载入完成前启动了证书签发生命周期（常驻族越过装配屏障）")
	case <-time.After(200 * time.Millisecond):
	}
	te := TaskEngine()
	if te == nil {
		t.Fatal("engine must be registered before BootSync")
	}
	if err := te.Trigger("config-watchdog", "manual", "test"); !errors.Is(err, taskengine.ErrSchedulingPaused) {
		t.Fatalf("execution during BootSync err=%v, want ErrSchedulingPaused", err)
	}

	close(releaseBoot)
	select {
	case te = <-initDone:
	case <-time.After(2 * time.Second):
		t.Fatal("InitTaskEngine did not finish after BootSync release")
	}
	// 屏障在 BootSync 后解除：被延迟的证书生命周期已兑现，屏障无残留
	// （深度泄漏会让后续导入/队列恢复永久停在「只登记意图」状态）。
	if configImportHoldActive() {
		t.Fatal("InitTaskEngine 返回后装配屏障未释放（depth>0）")
	}
	select {
	case <-lifecycleStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("配置载入完成后证书签发生命周期未被兑现（屏障只延迟不丢弃）")
	}
	// 看门狗整轮未判定现在会返回错误（Caddy admin 不可达=未判定），
	// 本用例断言的是「BootSync 后调度已恢复」，故注入可用的假 Caddy admin，
	// 使 Trigger 的成功/失败只反映调度门状态。
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	oldURL := watchdogAdminURLValue
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	if err := te.Trigger("config-watchdog", "manual", "test"); err != nil {
		t.Fatalf("execution after BootSync must be resumed: %v", err)
	}
}
