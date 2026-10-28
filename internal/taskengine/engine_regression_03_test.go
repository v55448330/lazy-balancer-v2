package taskengine

import (
	"sync/atomic"
	"testing"
	"time"
)

// 调度退出信号（schedDone）：tick 在调度 goroutine 内同步调用装配方闭包
// （生产 IntervalFn/NextSlotFn 为 DB 直读），闭包阻塞时 scheduleLoop 永不退出；
// StopWithTimeout 必须把 schedDone 与在途 Run/daemon 纳入同一预算。
func TestEngine_StopWithTimeoutBoundsBlockedSchedulerClosure(t *testing.T) {
	e := newTestEngine(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	if err := e.Register(Descriptor{ID: "t-stop-slow-closure", Family: "t", Name: "慢调度闭包", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release // 模拟 DB 锁/驱动挂起的调度闭包
			return time.Minute
		},
		Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-stop-slow-closure")
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("tick 未进入 IntervalFn")
	}

	done := make(chan struct{})
	go func() { e.StopWithTimeout(200 * time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("StopWithTimeout 对阻塞的调度闭包无界等待——schedDone 未纳入 timeout 预算")
	}
}

// EnabledFn=false 时 IntervalFn（生产形态为 DB 查询）不得再每 tick 执行，
// 与 Scheduled 分支「EnabledFn=false 整分支跳过」的省读设计对齐。
func TestEngine_EnabledFnFalseSkipsPeriodicIntervalEvaluation(t *testing.T) {
	e := newTestEngine(t)
	var intervalCalls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-enp-skip-interval", Family: "t", Name: "业务门省读", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { intervalCalls.Add(1); return 20 * time.Millisecond },
		EnabledFn:  func() bool { return false },
		Run:        func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-enp-skip-interval")
	time.Sleep(300 * time.Millisecond)
	if n := intervalCalls.Load(); n != 0 {
		t.Fatalf("EnabledFn=false 期间 IntervalFn 不得求值（每 tick DB 读取空转），got %d 次", n)
	}
	if n := countRuns(t, "t-enp-skip-interval"); n != 0 {
		t.Fatalf("EnabledFn=false 期间不得调度落行，got %d 行", n)
	}
}

// 畸形形状：EnabledFn panic 经 safeBool fail-closed 为 false——IntervalFn
// 同样不得求值、零调度零落行（panic 不传导到调度 goroutine）。
func TestEngine_EnabledFnPanicSkipsPeriodicIntervalEvaluation(t *testing.T) {
	e := newTestEngine(t)
	var intervalCalls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-enp-panic", Family: "t", Name: "业务门 panic", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { intervalCalls.Add(1); return 20 * time.Millisecond },
		EnabledFn:  func() bool { panic("boom") },
		Run:        func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-enp-panic")
	time.Sleep(300 * time.Millisecond)
	if n := intervalCalls.Load(); n != 0 {
		t.Fatalf("EnabledFn panic（fail-closed false）期间 IntervalFn 不得求值，got %d 次", n)
	}
	if n := countRuns(t, "t-enp-panic"); n != 0 {
		t.Fatalf("EnabledFn panic 期间不得调度落行，got %d 行", n)
	}
	if e.IsStopped() {
		t.Fatal("EnabledFn panic 不得终止引擎")
	}
}
