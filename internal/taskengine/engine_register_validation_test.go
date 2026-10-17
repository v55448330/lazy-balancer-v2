package taskengine

import (
	"sync/atomic"
	"testing"
	"time"
)

func validRegisterDescriptor() Descriptor {
	return Descriptor{
		ID: "valid", Family: "test", Name: "valid", Category: "测试",
		Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return time.Second },
		Run:        func(RunContext) error { return nil },
	}
}

func TestEngineRegister_rejectsInvalidKind(t *testing.T) {
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	d.Kind = Kind("bogus")
	if err := e.Register(d); err == nil {
		t.Fatal("未知 Kind 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsInvalidRunsOn(t *testing.T) {
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	d.RunsOn = Role("bogus")
	if err := e.Register(d); err == nil {
		t.Fatal("未知 RunsOn 必须响亮拒绝，不得按 any 放行")
	}
}

func TestEngineRegister_rejectsBootSyncNonOneshot(t *testing.T) {
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	d.BootSync = true
	if err := e.Register(d); err == nil {
		t.Fatal("BootSync 仅允许 Oneshot，其他 Kind 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsMissingKind(t *testing.T) {
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	d.Kind = ""
	if err := e.Register(d); err == nil {
		t.Fatal("Kind 缺失必须响亮拒绝，不得静默降级为 Oneshot")
	}
}

func TestEngineRegister_rejectsDuplicateID(t *testing.T) {
	// Given：同引擎内已有一个有效任务。
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	if err := e.Register(d); err != nil {
		t.Fatal(err)
	}
	// When/Then：同 ID 再注册必须失败，不得覆盖原描述符、历史与日志身份。
	if err := e.Register(d); err == nil {
		t.Fatal("重复 ID 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsMissingName(t *testing.T) {
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	d.Name = ""
	if err := e.Register(d); err == nil {
		t.Fatal("空 Name 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsNilRun(t *testing.T) {
	e := NewEngine(Options{})
	d := validRegisterDescriptor()
	d.Run = nil
	if err := e.Register(d); err == nil {
		t.Fatal("nil Run 必须响亮拒绝，不得注册后空指针")
	}
}

func TestEngine_nonPositivePeriodicIntervalDisablesLoopWithoutRun(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			// Given：动态 IntervalFn 返回非正周期（注册期不得调用该函数）。
			e := newTestEngine(t)
			var runs atomic.Int32
			d := validRegisterDescriptor()
			d.IntervalFn = func() time.Duration { return interval }
			d.Run = func(RunContext) error { runs.Add(1); return nil }
			if err := e.Register(d); err != nil {
				t.Fatalf("注册只校验 IntervalFn 存在，不应调用动态函数: %v", err)
			}
			e.StartLoop(d.ID)
			// When：tick 求值发现非法周期。
			e.tick()
			// Then：停止该任务调度且 Run 未执行，不得形成忙循环。
			for _, meta := range e.DescribeAll() {
				if meta.ID == d.ID && meta.LoopOn {
					t.Errorf("非正周期 %v 后 LoopOn=true，任务会持续忙调度", interval)
				}
			}
			if runs.Load() != 0 {
				t.Errorf("非正周期 %v 仍执行 Run %d 次", interval, runs.Load())
			}
		})
	}
}
