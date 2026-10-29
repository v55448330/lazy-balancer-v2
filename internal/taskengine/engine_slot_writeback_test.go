package taskengine

// Scheduled 在途轮回写的并发改写复核：executeRun 尾部以 NextSlotFn 求值结果
// 回写槽缓存前，必须复核缓存未被并发改写（与 tick 求值回写同款 CAS）。

import (
	"sync"
	"testing"
	"time"
)

// Given Scheduled 到期槽在途轮（Run 体阻塞），轮内显式复位排程进度且业务
// 重排落定新槽（模拟 ResetScheduleProgress 与随后的重排求值先于轮结束完成），
// NextSlotFn 读到的仍是旧到期槽（DB 投影滞后窗口）。
// When 在途轮结束，executeRun 尾部回写槽缓存。
// Then 并发落定的新槽不被回滚——陈旧求值不得把新槽打回过去（旧行为无条件
// 覆盖，下一 tick 按旧槽重投=重复执行）。
func TestExecuteRun_writebackRespectsConcurrentSlotRewrite(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	e.SetRole(true)
	dueSlot := time.Now().Add(-time.Minute)
	newSlot := time.Now().Add(time.Hour)
	started := make(chan struct{})
	release := make(chan struct{})
	// 清理兜底与正常路径共用一次 close（Fatal 退出时放行阻塞的 Run 体）。
	var releaseOnce sync.Once
	releaseRun := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseRun)
	if err := e.Register(Descriptor{
		ID: "t-slot-rewrite", Family: "t", Name: "回写复核", Kind: KindScheduled, RunsOn: RoleAny,
		// 求值滞后窗口：轮结束时 DB 仍读到旧槽（会滚回旧值的形态）。
		NextSlotFn: func() time.Time { return dueSlot },
		Run: func(RunContext) error {
			close(started)
			<-release
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-slot-rewrite")

	// 预置到期槽（模拟 tick 已求值武装）。
	r := regOf(t, e, "t-slot-rewrite")
	r.mu.Lock()
	r.nextScheduledTime = dueSlot
	r.mu.Unlock()

	runDone := make(chan error, 1)
	go func() { runDone <- e.Trigger("t-slot-rewrite", "manual", "") }()
	<-started

	// 在途轮结束前：显式复位 + 业务重排落定新槽。
	e.ResetScheduleProgress("t-slot-rewrite")
	r.mu.Lock()
	r.nextScheduledTime = newSlot
	r.mu.Unlock()

	releaseRun()
	if err := <-runDone; err != nil {
		t.Fatalf("在途轮 err=%v", err)
	}

	if slot := fieldSnapshot(t, e, "t-slot-rewrite").slot; !slot.Equal(newSlot) {
		t.Fatalf("并发落定的新槽被在途轮回写滚回 %v, want %v", slot, newSlot)
	}
}
