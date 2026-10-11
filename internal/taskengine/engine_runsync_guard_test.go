package taskengine

// U1-P4-4（第 67 轮）：RunSync 与 Trigger 守卫不对称——Trigger 拒绝 KindDaemon
// 手动触发（engine.go「常驻任务不支持手动触发（启停即可）」），RunSync 无同型
// 守卫，常驻任务被 handler 直调可绕过 startDaemon 生命周期与常驻循环双跑。
// B 批裁定语义：常驻任务仅引擎调度（StartLoop/StopLoop 启停即可）。

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Given KindDaemon 描述符。
// When RunSync 直调。
// Then 返回与 Trigger 同型拒绝错误，且 Run 体未被执行（不与常驻循环双跑）。
func TestRunSync_rejectsDaemonKind(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-rsd", Family: "t", Name: "常驻D", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error { runs.Add(1); return nil }})
	e.SetRole(true)

	_, err := e.RunSync("t-rsd", "manual", "tester")
	if err == nil || !strings.Contains(err.Error(), "常驻任务") {
		t.Fatalf("RunSync 应拒绝常驻任务（与 Trigger 同型守卫），得到 err=%v", err)
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("常驻任务 Run 体不得经 RunSync 执行，执行次数=%d", got)
	}
}

// Given MasterOnly 描述符 + 引擎为从节点角色。
// When RunSync 直调。
// Then 返回「该操作仅允许在主节点执行」（与 Trigger 同型口径），Run 体未执行。
func TestRunSync_masterOnlyRejectedOnSlave(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-rsm", Family: "t", Name: "主仅M", Kind: KindScheduled, MasterOnly: true,
		// TASK-L2（第 69 轮）配套：Scheduled 注册必须带 NextSlotFn（远期槽——
		// tick 不触发，本测试只验 RunSync 角色门）。
		NextSlotFn: func() time.Time { return time.Now().Add(time.Hour) },
		Run:        func(rc RunContext) error { runs.Add(1); return nil }})
	e.SetRole(false) // 从节点

	_, err := e.RunSync("t-rsm", "manual", "tester")
	if err == nil || !strings.Contains(err.Error(), "主节点") {
		t.Fatalf("从节点 RunSync 应拒绝 MasterOnly 任务，得到 err=%v", err)
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("从节点上 MasterOnly 任务 Run 体不得执行，执行次数=%d", got)
	}
}

// 回归：Oneshot 任务 RunSync 正常执行（守卫不误伤既有直调入口——auto-backup
// 同形态：非 Daemon、非 MasterOnly bool）。
func TestRunSync_oneshotStillExecutes(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-rso", Family: "t", Name: "单次O", Kind: KindOneshot, ManualRun: true,
		Run: func(rc RunContext) error { runs.Add(1); return nil }})
	e.SetRole(true)

	runID, err := e.RunSync("t-rso", "manual", "tester")
	if err != nil {
		t.Fatalf("Oneshot RunSync 应正常执行，得到 err=%v", err)
	}
	if runID <= 0 {
		t.Fatalf("RunSync 应返回有效 runID，得到 %d", runID)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("Oneshot Run 体应恰执行一次，得到 %d", got)
	}
}
