package taskengine

// CancelHook 隔离守卫：CancelHook 是装配方闭包（生产为 manager 取消），
// 曾裸调——一次 panic 会顺着 Cancel 抛进调用方 goroutine，且
// cancelHookRunning 永不复位：该任务此后所有 Cancel 被「钩子运行中」门拒绝，
// 新一轮占位也被 ReserveRun 的同一条门永久挡死（静默停摆）。

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngine_CancelHookPanicIsolatedAndReleasesGate(t *testing.T) {
	e := newTestEngine(t)
	const id = "t-chk-panic"
	var hookCalls atomic.Int32
	started := make(chan struct{}, 2)
	firstDone := make(chan error, 1)
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "钩子 panic", Kind: KindOneshot, Cancelable: true,
		CancelHook: func() bool {
			if hookCalls.Add(1) == 1 {
				panic("cancel hook boom")
			}
			return true
		},
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)

	go func() { firstDone <- e.Trigger(id, "manual", "") }()
	waitForEngineSignal(t, "首轮启动", started)

	// When 钩子 panic 的 Cancel
	// Then 不得抛给调用方，且按「取消未生效」返回（panic 不是生效证据）。
	if ok := e.Cancel(id); ok {
		t.Fatal("panic 的 CancelHook 不得被当作取消成功（本轮上下文未取消）")
	}
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("钩子调用次数=%d, want 1", got)
	}

	// Then cancelHookRunning 已复位：第二次 Cancel 能再次进入钩子并生效。
	if ok := e.Cancel(id); !ok {
		t.Fatal("CancelHook panic 后 cancelHookRunning 未复位（该任务 Cancel 永久失效）")
	}
	if got := hookCalls.Load(); got != 2 {
		t.Fatalf("第二次 Cancel 未进入钩子（调用次数=%d）", got)
	}
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("取消生效后在途轮未结束")
	}

	// Then 占位门（running||cancelHookRunning）不残留：新一轮可正常占位。
	secondDone := make(chan error, 1)
	go func() { secondDone <- e.Trigger(id, "manual", "") }()
	waitForEngineSignal(t, "第二轮启动", started)
	if ok := e.Cancel(id); !ok {
		t.Fatal("第二轮取消应成功")
	}
	select {
	case err := <-secondDone:
		// 取消生效的在途轮按取消终态返回（取消原因经 ctx 传导）。
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrRunCancelled) {
			t.Fatalf("第二轮返回意外错误: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("第二轮未结束")
	}
}
