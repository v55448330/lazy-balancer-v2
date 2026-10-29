package taskengine

// Scheduled 派发 admission 窗口——tick 在 due&&eligible
// 判定后以 go runNow 异步派发，admission（reserveRun）不复核 loopEnabled/槽
// 状态；StopLoop/业务关闭落在「判定后、reserve 前」时任务仍启动一次，与
// 「已停止」契约矛盾。Periodic 已有 reservePeriodicRun 同族收口，本文件钉
// Scheduled 的同型语义：admission 与派发判定同步完成 + reserve 复核
// loopEnabled/槽未到期/Kind。

import (
	"sync/atomic"
	"testing"
	"time"
)

// 目标形状①：tick 返回时 Scheduled admission 已同步完成（running 占位可见）。
// 若 admission 由派发 goroutine 承担（旧形态），tick 返回时 running=false；
// 同步 admission（新形态）则必为 true。
func TestEngine_ScheduledAdmissionCompletesSynchronouslyInTick(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var runs, slotCalls atomic.Int32
	runReleased := make(chan struct{})
	slotEntered := make(chan struct{})
	allowSlotReturn := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-runReleased:
		default:
			close(runReleased)
		}
	})
	const id = "t-sched-admission-sync"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "定时 admission 同步", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			if slotCalls.Add(1) == 1 {
				close(slotEntered)
				<-allowSlotReturn
			}
			return time.Now().Add(-time.Second)
		},
		Run: func(RunContext) error {
			runs.Add(1)
			<-runReleased
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)

	tickDone := make(chan struct{})
	go func() {
		e.tick()
		close(tickDone)
	}()
	waitForEngineSignal(t, "tick 进入 NextSlotFn", slotEntered)
	// 在槽闭包返回后持住 admission 所需的 e.mu：同步 admission 的 tick
	// 必须阻塞；旧的异步 go runNow 形态会让 tick 先返回，确定性地暴露回归。
	e.mu.Lock()
	close(allowSlotReturn)
	select {
	case <-tickDone:
		e.mu.Unlock()
		t.Fatal("admission 持锁期间 tick 已返回——admission 仍由派发 goroutine 承担")
	case <-time.After(200 * time.Millisecond):
	}
	e.mu.Unlock()
	waitForEngineSignal(t, "同步 admission tick 返回", tickDone)

	r := regOf(t, e, id)
	r.mu.Lock()
	running := r.running
	r.mu.Unlock()
	if !running {
		t.Fatal("tick 返回时 admission 未完成（running=false）")
	}
	close(runReleased)
	waitForEngine(t, "admission 在途轮排空", 2*time.Second, func() bool { return e.inFlight.Load() == 0 })
	if got := runs.Load(); got != 1 {
		t.Fatalf("到期槽执行次数=%d, want 1", got)
	}
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("到期槽 task_runs=%d, want 1", got)
	}
}

// 目标形状②：停止态 Scheduled admission（拒绝哨兵/计数回收/runWG 排空/
// 零落行）与 Periodic 同表驱动单源——见 engine_periodic_gate_test.go
// TestEngine_ReserveRunRejectsStoppedLoop 的 scheduled 子用例。

// 目标形状③：admission 复核槽仍到期——窗口内槽被并发改写（手动触发/上一轮
// 完成后 executeRun 尾部重算到未来）时按陈旧判定投递会立即多跑一次。
// 畸形形状：对非 Scheduled 任务调用 reserveScheduledRun 同样拒绝。
func TestEngine_ReserveScheduledRunRechecksSlotAndKind(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	const id = "t-sched-slot-recheck"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "槽复核", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return time.Now().Add(-time.Second) },
		Run:        func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop(id)
	r := regOf(t, e, id)

	now := time.Now()
	r.mu.Lock()
	r.nextScheduledTime = now.Add(-time.Second)
	r.mu.Unlock()
	res, err := e.reserveScheduledRun(id, now)
	if err != nil || res == nil {
		t.Fatalf("到期槽 admission err=%v res=%p, want nil/非空", err, res)
	}
	res.release()

	// 槽被改写为未到期：拒绝且不占位。
	r.mu.Lock()
	r.nextScheduledTime = now.Add(time.Hour)
	r.mu.Unlock()
	res, err = e.reserveScheduledRun(id, now)
	if res != nil || err != errScheduledNotDue {
		t.Fatalf("未到期槽 res=%p err=%v, want nil/errScheduledNotDue", res, err)
	}
	// 槽清空（业务未配置排程）：同口径拒绝。
	r.mu.Lock()
	r.nextScheduledTime = time.Time{}
	r.mu.Unlock()
	res, err = e.reserveScheduledRun(id, now)
	if res != nil || err != errScheduledNotDue {
		t.Fatalf("空槽 res=%p err=%v, want nil/errScheduledNotDue", res, err)
	}
	if got := e.inFlight.Load(); got != 0 {
		t.Fatalf("拒绝后 inFlight=%d, want 0", got)
	}

	// 畸形：Periodic 任务不得经 Scheduled admission 占位。
	const pid = "t-sched-kind-mismatch"
	if err := e.Register(Descriptor{
		ID: pid, Family: "t", Name: "类型错配", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop(pid)
	res, err = e.reserveScheduledRun(pid, now)
	if res != nil || err != errScheduledLoopDisabled {
		t.Fatalf("Periodic 任务 Scheduled admission res=%p err=%v, want nil/errScheduledLoopDisabled", res, err)
	}
}

// 回归形状：StopLoop 先于 tick 时本就不得派发（eligible 判定拦截）——
// 修复不得改变该既有语义。
func TestEngine_ScheduledStoppedLoopDoesNotDispatch(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var runs atomic.Int32
	const id = "t-sched-stopped-tick"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "停止后 tick", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return time.Now().Add(-time.Second) },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	e.StopLoop(id)

	e.tick()
	time.Sleep(50 * time.Millisecond) // 放行任何被派发的 goroutine
	if got := runs.Load(); got != 0 {
		t.Fatalf("StopLoop 后 tick 执行次数=%d, want 0", got)
	}
	if got := countRuns(t, id); got != 0 {
		t.Fatalf("StopLoop 后 task_runs=%d, want 0", got)
	}
}
