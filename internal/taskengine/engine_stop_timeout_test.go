package taskengine

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func cleanupStopTimeoutEngine(t *testing.T, e *Engine, release func()) {
	t.Helper()
	release()
	// 若断言在 Stop 前失败，也在此关闭 schedStop；已停止时该调用幂等。
	e.StopWithTimeout(20 * time.Millisecond)
	select {
	case <-e.schedDone:
	case <-time.After(2 * time.Second):
		t.Error("释放阻塞后调度循环仍未退出")
	}
	drained := make(chan struct{})
	go func() {
		e.runWG.Wait()
		e.daemonWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Error("释放阻塞后 Run/daemon 仍未排空")
	}
}

func TestEngine_StopWithTimeoutSchedulerOnlySkipsEmptyUnsettledWarning(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: 5 * time.Millisecond})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	releaseInterval := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseInterval) }) }
	t.Cleanup(func() { cleanupStopTimeoutEngine(t, e, release) })
	if err := e.Register(Descriptor{
		ID: "t-stop-scheduler-only", Family: "t", Name: "仅调度阻塞", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration {
			enteredOnce.Do(func() { close(entered) })
			<-releaseInterval
			return time.Hour
		},
		Run: func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-stop-scheduler-only")
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("调度闭包未进入")
	}
	logs := captureEngineLog(t)

	e.StopWithTimeout(25 * time.Millisecond)

	got := logs.String()
	if !strings.Contains(got, "引擎停止等待调度循环退出超时") {
		t.Fatalf("缺少真实调度超时告警: %s", got)
	}
	if strings.Contains(got, "引擎停止等待在途任务超时") {
		t.Fatalf("没有 Run/daemon 在途却记录在途超时告警: %s", got)
	}
	if ids := e.unsettledTaskIDs(); len(ids) != 0 {
		t.Fatalf("测试前提破坏：存在未落定任务 %v", ids)
	}
}

func TestEngine_StopWithTimeoutSchedulerRunDaemonShareOneBudget(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: 5 * time.Millisecond})
	schedulerEntered := make(chan struct{})
	var schedulerEnteredOnce sync.Once
	runEntered := make(chan struct{})
	daemonEntered := make(chan struct{})
	releaseScheduler := make(chan struct{})
	releaseRun := make(chan struct{})
	releaseDaemon := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseScheduler)
			close(releaseRun)
			close(releaseDaemon)
		})
	}
	t.Cleanup(func() { cleanupStopTimeoutEngine(t, e, release) })
	for _, d := range []Descriptor{
		{
			ID: "t-stop-shared-scheduler", Family: "t", Name: "共享预算调度", Kind: KindPeriodic, RunsOn: RoleAny,
			IntervalFn: func() time.Duration {
				schedulerEnteredOnce.Do(func() { close(schedulerEntered) })
				<-releaseScheduler
				return time.Hour
			},
			Run: func(RunContext) error { return nil },
		},
		{
			ID: "t-stop-shared-run", Family: "t", Name: "共享预算 Run", Kind: KindPeriodic, RunsOn: RoleAny,
			IntervalFn: func() time.Duration { return time.Nanosecond },
			Run: func(RunContext) error {
				close(runEntered)
				<-releaseRun // 刻意不消费取消，验证有界停止
				return nil
			},
		},
		{
			ID: "t-stop-shared-daemon", Family: "t", Name: "共享预算 daemon", Kind: KindDaemon, RunsOn: RoleAny,
			Run: func(RunContext) error {
				close(daemonEntered)
				<-releaseDaemon // 刻意不消费取消，验证有界停止
				return nil
			},
		},
	} {
		if err := e.Register(d); err != nil {
			t.Fatal(err)
		}
	}
	e.StartLoop("t-stop-shared-daemon")
	select {
	case <-daemonEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon 未进入在途态")
	}
	e.StartLoop("t-stop-shared-run")
	select {
	case <-runEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Run 未进入在途态")
	}
	e.StartLoop("t-stop-shared-scheduler")
	select {
	case <-schedulerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler 未进入阻塞闭包")
	}
	logs := captureEngineLog(t)

	const timeout = 150 * time.Millisecond
	started := time.Now()
	e.StopWithTimeout(timeout)
	elapsed := time.Since(started)
	if elapsed >= timeout+50*time.Millisecond {
		t.Fatalf("scheduler+Run+daemon 等待耗时=%s，超过共享预算+调度余量 %s", elapsed, timeout+50*time.Millisecond)
	}
	got := logs.String()
	if !strings.Contains(got, "引擎停止等待调度循环退出超时") || !strings.Contains(got, "引擎停止等待在途任务超时") {
		t.Fatalf("同场真实超时缺少一条告警: %s", got)
	}
	for _, id := range []string{"t-stop-shared-run", "t-stop-shared-daemon"} {
		if !strings.Contains(got, id) {
			t.Fatalf("未落定任务告警缺少 %s: %s", id, got)
		}
	}
}
