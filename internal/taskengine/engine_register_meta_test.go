package taskengine

// Register 的事件元数据写入次序：终态事件（通知正文）的任务名/类型取自注册时
// 写入的 taskEventMeta。被准入门拒绝的注册（重复 ID / 引擎已停止）不得改动
// 它——此前元数据写在准入门之前，重复注册会用在册任务从未有过的名称/类型
// 覆盖它，停止态拒绝则留下无消费方的孤儿项。

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Given 在册任务已持有事件元数据（名称/类型）。
// When 同 ID 的另一个描述符被准入门以「重复注册」拒绝。
// Then 在册任务的事件元数据不得被被拒描述符改写——终态事件仍带在册描述符的
// 名称与类型。
func TestEngine_RejectedDuplicateRegisterKeepsEventMeta(t *testing.T) {
	e := newTestEngine(t)
	old := TaskTerminalHook
	TaskTerminalHook = nil
	t.Cleanup(func() { TaskTerminalHook = old })
	var events []string
	TaskTerminalHook = func(id, name, kind, status, message string) {
		events = append(events, name+"|"+kind+"|"+status)
	}

	// Given
	mustRegisterTaskForTest(t, e, Descriptor{ID: "t-meta-dup", Family: "t", Name: "在册任务", Kind: KindOneshot,
		Run: func(RunContext) error { return nil }})

	// When：名称/类型都不同的描述符撞同一 ID
	err := e.Register(Descriptor{ID: "t-meta-dup", Family: "t", Name: "被拒描述符", Kind: KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "重复注册") {
		t.Fatalf("重复注册应被准入门拒绝, got %v", err)
	}

	// Then：在册任务照常执行，终态事件带的是在册描述符的名称与类型
	if _, err := e.RunSync("t-meta-dup", "manual", "tester"); err != nil {
		t.Fatalf("在册任务仍应可执行: %v", err)
	}
	if len(events) != 1 || events[0] != "在册任务|触发任务|success" {
		t.Fatalf("终态事件=%v, want [在册任务|触发任务|success]（被拒注册不得改写事件元数据）", events)
	}
}

// Given 引擎已停止。
// When 迟到的注册被准入门以 ErrEngineStopped 拒绝。
// Then 不得留下无消费方的事件元数据孤儿项。
func TestEngine_RejectedStoppedRegisterLeavesNoEventMeta(t *testing.T) {
	e := newTestEngine(t)
	e.Stop()
	const id = "t-meta-stopped"

	// When
	err := e.Register(Descriptor{ID: id, Family: "t", Name: "迟到注册", Kind: KindOneshot,
		Run: func(RunContext) error { return nil }})
	if !errors.Is(err, ErrEngineStopped) {
		t.Fatalf("已停止引擎的注册 err=%v, want ErrEngineStopped", err)
	}

	// Then
	if _, ok := taskEventMeta.Load(id); ok {
		// 判负后清掉孤儿项，不把本用例的残留留给同进程后续用例。
		taskEventMeta.Delete(id)
		t.Fatalf("被停止态拒绝的注册留下了事件元数据孤儿项 %q", id)
	}
}
