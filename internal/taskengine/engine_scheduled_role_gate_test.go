package taskengine

// Scheduled 分支的角色门前置：从节点（角色不符）每个 tick 不得求值
// EnabledFn/NextSlotFn——二者是装配方闭包（生产为 DB 直读），此前先求值再在
// due 判定里筛角色，从节点每 tick 白付两次查询。门前置后从节点零 DB 读、
// 零槽缓存落值；promote 后下一 tick 立即恢复求值并投递到期槽。

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEngine_ScheduledRoleGateSkipsSlotEvaluation(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	const id = "t-sched-role-gate"
	var slotEvals, enabledEvals, runs atomic.Int32
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "角色门槽求值", Kind: KindScheduled, RunsOn: RoleMasterOnly,
		NextSlotFn: func() time.Time {
			slotEvals.Add(1)
			return time.Now().Add(-time.Second)
		},
		EnabledFn: func() bool {
			enabledEvals.Add(1)
			return true
		},
		Run: func(RunContext) error {
			runs.Add(1)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(false) // 从节点
	e.StartLoop(id)

	for range 5 {
		e.tick()
	}
	if got := slotEvals.Load(); got != 0 {
		t.Fatalf("从节点 NextSlotFn 求值 %d 次, want 0（角色门未前置——每 tick 白付 DB 读）", got)
	}
	if got := enabledEvals.Load(); got != 0 {
		t.Fatalf("从节点 EnabledFn 求值 %d 次, want 0（角色门未前置）", got)
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("从节点执行 %d 次, want 0", got)
	}
	if n := countRuns(t, id); n != 0 {
		t.Fatalf("从节点 task_runs=%d, want 0", n)
	}

	// promote：下一 tick 立即恢复求值并投递到期槽（无需等残余节拍）。
	e.SetRole(true)
	e.tick()
	waitForEngine(t, "promote 后执行并排空", 2*time.Second, func() bool { return runs.Load() == 1 && e.inFlight.Load() == 0 })
	if got := slotEvals.Load(); got < 1 {
		t.Fatalf("promote 后 NextSlotFn 求值 %d 次, want >=1", got)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("promote 后到期槽执行 %d 次, want 1", got)
	}
}
