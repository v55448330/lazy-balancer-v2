package taskengine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// RunTicker 是唯一许可的高频常驻执行形态（task-engine 标准 v2.2 §0.2）：
// 立即首跑（bootstrap）+ 固定节拍 + 唤醒合并，ctx 取消即停，fn panic 隔离。
// 本组用例钉死四条契约：立即执行 / 间隔执行 / 唤醒立即执行（合并）/ 取消退出 /
// panic 隔离后继续跑。

func TestRunTicker_bootstrapRunsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunTicker(ctx, time.Hour, nil, func(context.Context) { runs.Add(1) })
	}()
	// bootstrap 必须立即首跑，不等到第一个 interval（1h）到期。
	waitForEngine(t, "RunTicker bootstrap 首跑", 2*time.Second, func() bool { return runs.Load() == 1 })
	cancel()
	<-done
	if got := runs.Load(); got != 1 {
		t.Fatalf("首跑后运行次数=%d, want 1（interval 未到期不得再跑）", got)
	}
}

func TestRunTicker_ticksAtInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	go RunTicker(ctx, 15*time.Millisecond, nil, func(context.Context) { runs.Add(1) })
	waitForEngine(t, "interval 节拍累计≥3 轮", 2*time.Second, func() bool { return runs.Load() >= 3 })
}

func TestRunTicker_wakeTriggersImmediateRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	var runs atomic.Int32
	go RunTicker(ctx, time.Hour, wake, func(context.Context) { runs.Add(1) })
	waitForEngine(t, "bootstrap 首跑", 2*time.Second, func() bool { return runs.Load() == 1 })
	wake <- struct{}{}
	// 唤醒必须立即触发一轮，不等 1h interval。
	waitForEngine(t, "唤醒立即执行", 2*time.Second, func() bool { return runs.Load() == 2 })
}

func TestRunTicker_wakeCoalesces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	var runs atomic.Int32
	release := make(chan struct{})
	go RunTicker(ctx, time.Hour, wake, func(context.Context) {
		runs.Add(1)
		if runs.Load() == 1 {
			<-release // 首轮挂起：期间到达的唤醒必须合并，不得堆积成连跑
		}
	})
	waitForEngine(t, "bootstrap 首跑", 2*time.Second, func() bool { return runs.Load() == 1 })
	// 连发 3 次唤醒：通道缓冲 1 + 非阻塞投递，只保留 1 个待消费信号。
	for range 3 {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	close(release)
	waitForEngine(t, "合并后仅再跑一轮", 2*time.Second, func() bool { return runs.Load() == 2 })
	time.Sleep(30 * time.Millisecond)
	if got := runs.Load(); got != 2 {
		t.Fatalf("唤醒合并失效：运行次数=%d, want 2（堆积信号不得连跑）", got)
	}
}

func TestRunTicker_returnsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunTicker(ctx, time.Hour, wake, func(context.Context) {})
	}()
	waitForEngine(t, "bootstrap 首跑", 2*time.Second, func() bool { return true })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 RunTicker 未返回")
	}
}

func TestRunTicker_recoversPanicAndKeepsTicking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	go RunTicker(ctx, 10*time.Millisecond, nil, func(context.Context) {
		if calls.Add(1) == 1 {
			panic("boom")
		}
	})
	// panic 必须被隔离：daemon 不退出，下一轮节照常执行。
	waitForEngine(t, "panic 隔离后继续节拍", 2*time.Second, func() bool { return calls.Load() >= 2 })
}

func TestRunTicker_nonPositiveIntervalFallsBackToOneSecond(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	go RunTicker(ctx, 0, nil, func(context.Context) { runs.Add(1) })
	waitForEngine(t, "bootstrap 首跑", 2*time.Second, func() bool { return runs.Load() == 1 })
	// interval<=0 兜底 1s 并记一次 warn：不得静默空转（无节拍）也不得热循环。
	waitForEngine(t, "兜底 1s 节拍出现第二轮", 3*time.Second, func() bool { return runs.Load() >= 2 })
}
