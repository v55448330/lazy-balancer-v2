package taskengine

import (
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
