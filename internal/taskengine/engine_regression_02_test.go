package taskengine

// BootSync 前暂停 tick / 在途排空 API / demote×pendingRestart

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Stop 的 cancel 遍历与 runNow 的 cancel 登记交错。确定性编排
// （in-package 直调 runNow）：测试持 roleMu 写锁——runNow 已过 stopped 检查
// 并阻塞在 roleMu.RLock（cancel 未登记）；随后 Stop 置 stopped、cancel 遍历
// 见 r.cancel==nil 跳过、阻塞在 runWG.Wait；放开 roleMu 后旧实现裸登记并
// 全程未取消跑完，修复后临界区内复核 stopped 即取消（Run 落 cancelled）。
func TestEngine_StopRacingRunNowCancelsInFlight(t *testing.T) {
	for round := range 5 {
		e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
		var uncancelled atomic.Int32
		if err := e.Register(Descriptor{ID: "t-race", Family: "t", Name: "竞态", Kind: KindPeriodic,
			RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Hour },
			Run: func(rc RunContext) error {
				select {
				case <-rc.Ctx.Done():
					return rc.Ctx.Err()
				case <-time.After(200 * time.Millisecond):
					uncancelled.Add(1) // 全程未收到取消而跑完——竞态漏取消
					return nil
				}
			}}); err != nil {
			t.Fatal(err)
		}
		// roleMu 写锁必须受控释放：waitForEngine 等待失败（t.Fatalf→Goexit）
		// 时若裸持锁退出，runNow 永久阻塞在 RLock、Stop 永久阻塞在
		// runWG.Wait，t.Cleanup(e.Stop) 一并挂死。正常路径与清理路径经
		// 同一 sync.Once 解锁（只解一次，双路径不重复 Unlock）。
		var unlockOnce sync.Once
		t.Cleanup(func() { unlockOnce.Do(func() { e.roleMu.Unlock() }) })
		e.roleMu.Lock() // 阻挡 runNow 的角色门（stopped 检查已通过、cancel 未登记）
		runDone := make(chan error, 1)
		go func() { _, err := e.runNow("t-race", "manual", ""); runDone <- err }()
		waitForEngine(t, "runNow 抵达角色门", time.Second, func() bool { return e.inFlight.Load() == 1 })
		stopDone := make(chan struct{})
		go func() { e.Stop(); close(stopDone) }()
		waitForEngine(t, "Stop 标记引擎停止", time.Second, e.IsStopped)
		unlockOnce.Do(func() { e.roleMu.Unlock() })
		if err := <-runDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("第 %d 轮：runNow err=%v, want context.Canceled", round, err)
		}
		<-stopDone
		if latest := e.LatestRun("t-race"); latest == nil || latest.Status != "cancelled" {
			t.Fatalf("第 %d 轮：终态=%+v, want cancelled", round, latest)
		}
		if uncancelled.Load() != 0 {
			t.Fatalf("第 %d 轮：Stop 完成后仍有 Run 全程未被取消而跑完（Stop×runNow 竞态漏取消）", round)
		}
	}
}

// （门内化钉）：slave 角色下直调 tryStartDaemon 内部入口（绕过 StartLoop
// 预检）必须被内化角色门拒绝——旧实现无门内复查，master-only daemon 在
// slave 上被拉起。
func TestEngine_TryStartDaemonRefusedOnSlave(t *testing.T) {
	e := NewEngine(Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	if err := e.Register(Descriptor{ID: "d-master", Family: "t", Name: "主节点常驻", Kind: KindDaemon,
		RunsOn: RoleMasterOnly, RestartOnRoleFlip: true,
		Run: func(rc RunContext) error { <-rc.Ctx.Done(); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(false) // slave
	r := regOf(t, e, "d-master")
	r.mu.Lock()
	r.loopEnabled = true
	r.mu.Unlock()
	e.tryStartDaemon(r, true) // 内部入口直调——角色门必须在 CAS 临界区内
	if e.IsRunning("d-master") {
		t.Fatal("master-only daemon 不得在 slave 上经 tryStartDaemon 启动")
	}
}

// （全链路竞态钉）：master-only daemon 运行中连续 demote→promote→demote
// （promote 在旧代退出清理前栽 pendingRestart），旧实现的退出清理以陈旧角色
// 快照内联登记新代——demote 的 cancel 遍历未及新登记，daemon 在 slave 存活。
// 修复后换代经 tryStartDaemon 以新鲜角色复核，终态恒不运行。
func TestEngine_DemotePendingRestartNoSlaveDaemon(t *testing.T) {
	for round := range 50 {
		e := NewEngine(Options{TickInterval: time.Hour})
		var entries atomic.Int32
		if err := e.Register(Descriptor{ID: "d-flip", Family: "t", Name: "翻转常驻", Kind: KindDaemon,
			RunsOn: RoleMasterOnly, RestartOnRoleFlip: true,
			Run: func(rc RunContext) error {
				entries.Add(1)
				<-rc.Ctx.Done()
				return nil
			}}); err != nil {
			t.Fatal(err)
		}
		e.StartLoop("d-flip")
		waitForEngine(t, "首代 daemon 启动", 2*time.Second, func() bool { return entries.Load() >= 1 })
		e.SetRole(false) // demote：取消旧代
		e.SetRole(true)  // promote（旧代清理未落定）：栽 pendingRestart
		e.SetRole(false) // 再次 demote——旧实现的新代登记逃出本次 cancel 遍历
		// 终态收敛：slave 上不得有存活的 master-only daemon（IsRunning 的
		// loopOn&&roleAllows 分支在 slave 恒 false，即真实 running 态）。
		deadline := time.Now().Add(2 * time.Second)
		for e.IsRunning("d-flip") && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		leaked := e.IsRunning("d-flip")
		e.Stop()
		if leaked {
			t.Fatalf("第 %d 轮：demote×pendingRestart 竞态在 slave 上拉起 master-only daemon", round)
		}
	}
}

// StartPaused 引擎的 tick 不投递周期任务；ResumeScheduling 后恢复。
func TestEngine_StartPausedDefersTickUntilResume(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour, StartPaused: true})
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "p-paused", Family: "t", Name: "暂停", Kind: KindPeriodic,
		RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Millisecond },
		Run: func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("p-paused")
	e.tick()
	e.tick()
	if runs.Load() != 0 {
		t.Fatal("装配暂停期 tick 不得投递周期任务（BootSync 前置不变量）")
	}
	e.ResumeScheduling()
	e.tick() // tick 经 goroutine 投递
	waitForEngine(t, "恢复后首轮投递", 2*time.Second, func() bool { return runs.Load() >= 1 })
}

// BootSync 任务在装配暂停期照常同步执行（暂停只作用于 tick 投递）。
func TestEngine_BootSyncRunsWhilePaused(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour, StartPaused: true})
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "boot-task", Family: "t", Name: "启动", Kind: KindOneshot,
		RunsOn: RoleAny, BootSync: true,
		Run: func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.RunBootSyncTasks()
	if runs.Load() != 1 {
		t.Fatalf("BootSync 必须在装配暂停期照常执行, runs=%d", runs.Load())
	}
}

// StatusFn 闭包 panic 在 Lookup/DescribeAll 隔离为空镜像（与
// IntervalFn/NextSlotFn/EnabledFn 同口径），不得杀死整页聚合。
func TestEngine_StatusFnPanicIsolated(t *testing.T) {
	e := newTestEngine(t)
	if err := e.Register(Descriptor{ID: "s-panic", Family: "t", Name: "镜像panic", Kind: KindPeriodic,
		RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Hour },
		StatusFn: func() string { panic("status boom") },
		Run:      func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	m, ok := e.Lookup("s-panic")
	if !ok {
		t.Fatal("Lookup 应命中")
	}
	if m.StatusMirror != "" {
		t.Fatalf("StatusFn panic 须隔离为空镜像, got %q", m.StatusMirror)
	}
	found := false
	for _, meta := range e.DescribeAll() { // 不得 panic
		if meta.ID == "s-panic" {
			found = true
			if meta.StatusMirror != "" {
				t.Fatalf("DescribeAll 中 StatusFn panic 须隔离为空镜像, got %q", meta.StatusMirror)
			}
		}
	}
	if !found {
		t.Fatal("DescribeAll 应含 s-panic")
	}
}

// 不得经 runNow 上抛给手动触发链。
func TestEngine_RunNowNextSlotFnPanicIsolated(t *testing.T) {
	e := newTestEngine(t)
	if err := e.Register(Descriptor{ID: "sch-panic", Family: "t", Name: "槽panic", Kind: KindScheduled,
		RunsOn:     RoleAny,
		NextSlotFn: func() time.Time { panic("slot boom") },
		Run:        func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RunSync("sch-panic", "manual", ""); err != nil {
		t.Fatalf("NextSlotFn panic 不得使执行失败: %v", err)
	}
}

// nil 库句柄下终态写入不得 panic（引擎终态写路径 updateTaskRunTerminal 的
// 函数同形防护；legacy RecordRunFinish 直写旁路已按 task-engine 标准 v2.2
// 删除——task_runs 唯一写方=引擎，终态保护断言随迁本路径）。
func TestEngine_TerminalWriteNilDBNoPanic(t *testing.T) {
	old := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = old })
	updateTaskRunTerminal(1, "success", 1, "")
	updateTaskRunTerminal(1, "failed", 1, "boom")
}

// CancelInFlightRuns 取消全部在途非常驻 Run（导入前排空），常驻族
// 不在排空范围。
func TestEngine_CancelInFlightRuns(t *testing.T) {
	e := newTestEngine(t)
	periodicStarted := make(chan struct{})
	if err := e.Register(Descriptor{ID: "p-inflight", Family: "t", Name: "在途", Kind: KindPeriodic,
		RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Hour },
		Run: func(rc RunContext) error {
			close(periodicStarted)
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}
	daemonStarted := make(chan struct{})
	if err := e.Register(Descriptor{ID: "d-inflight", Family: "t", Name: "常驻在途", Kind: KindDaemon,
		RunsOn: RoleAny,
		Run: func(rc RunContext) error {
			close(daemonStarted)
			<-rc.Ctx.Done()
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = e.RunSync("p-inflight", "manual", "") }()
	<-periodicStarted
	e.StartLoop("d-inflight")
	<-daemonStarted
	if n := e.CancelInFlightRuns(); n != 1 {
		t.Fatalf("CancelInFlightRuns 应仅取消 1 个在途非常驻 Run, got %d", n)
	}
	if !e.IsRunning("d-inflight") {
		t.Fatal("常驻族不在排空范围（取消即停摆，生命周期归角色门/启停）")
	}
	waitForEngine(t, "在途 Run 取消落定", 2*time.Second, func() bool { return !e.IsTaskInFlight("p-inflight") })
}
