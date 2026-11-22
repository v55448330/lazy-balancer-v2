package taskengine

import (
	"errors"
	"testing"
	"time"
)

// 所有任务类型的终态都要带任务类型与任务名进入通知钩子；成功/失败都要发。
func TestTaskTerminalHookCarriesKindAndName(t *testing.T) {
	e := newTestEngine(t)
	old := TaskTerminalHook
	TaskTerminalHook = nil
	t.Cleanup(func() { TaskTerminalHook = old })

	type gotEvent struct {
		id, name, kind, status, message string
	}
	var got []gotEvent
	TaskTerminalHook = func(id, name, kind, status, message string) {
		got = append(got, gotEvent{id, name, kind, status, message})
	}

	if err := e.Register(Descriptor{
		ID: "t-ok", Family: "t", Name: "成功任务", Category: "测试", Kind: KindOneshot,
		Run: func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RunSync("t-ok", "manual", "tester"); err != nil {
		t.Fatalf("success run: %v", err)
	}
	if len(got) != 1 || got[0].id != "t-ok" || got[0].name != "成功任务" || got[0].kind != "触发任务" || got[0].status != "success" {
		t.Fatalf("成功终态事件=%+v, want t-ok/成功任务/触发任务/success", got)
	}

	if err := e.Register(Descriptor{
		ID: "t-fail", Family: "t", Name: "失败任务", Category: "测试", Kind: KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { return errors.New("boom") },
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RunSync("t-fail", "manual", "tester"); err == nil {
		t.Fatal("失败任务 RunSync 应返回错误")
	}
	if len(got) != 2 || got[1].name != "失败任务" || got[1].kind != "周期任务" || got[1].status != "failed" || got[1].message != "boom" {
		t.Fatalf("失败终态事件=%+v, want 失败任务/周期任务/failed/boom", got)
	}
}
