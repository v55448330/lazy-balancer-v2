package taskengine

// TASK-L2（第 69 轮 P2）：Register 对 Kind 与 Fn 配套的校验——Periodic 缺
// IntervalFn 会在 tick 处 nil 调用 panic 崩进程；Scheduled 缺 NextSlotFn 静默
// 停摆。注册期响亮拒绝。

import (
	"strings"
	"testing"
	"time"
)

func TestRegister_rejectsPeriodicWithoutIntervalFn(t *testing.T) {
	e := NewEngine(Options{})
	err := e.Register(Descriptor{ID: "no-interval", Family: "x", Kind: KindPeriodic, Run: func(RunContext) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "IntervalFn") {
		t.Fatalf("periodic without IntervalFn must be rejected, got %v", err)
	}
}

func TestRegister_rejectsScheduledWithoutNextSlotFn(t *testing.T) {
	e := NewEngine(Options{})
	err := e.Register(Descriptor{ID: "no-slot", Family: "x", Kind: KindScheduled, Run: func(RunContext) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "NextSlotFn") {
		t.Fatalf("scheduled without NextSlotFn must be rejected, got %v", err)
	}
}

// 回归：配套合法的注册照常接受。
func TestRegister_acceptsWellFormedKinds(t *testing.T) {
	e := NewEngine(Options{})
	if err := e.Register(Descriptor{ID: "ok-p", Family: "x", Kind: KindPeriodic, IntervalFn: func() time.Duration { return time.Minute }, Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatalf("well-formed periodic must pass: %v", err)
	}
	if err := e.Register(Descriptor{ID: "ok-s", Family: "x", Kind: KindScheduled, NextSlotFn: func() time.Time { return time.Time{} }, Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatalf("well-formed scheduled must pass: %v", err)
	}
	if err := e.Register(Descriptor{ID: "ok-d", Family: "x", Kind: KindDaemon, Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatalf("daemon must pass: %v", err)
	}
}
