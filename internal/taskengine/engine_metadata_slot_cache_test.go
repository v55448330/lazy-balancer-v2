package taskengine

// 元数据展示面（Lookup/DescribeAll）的槽缓存复用：/system/tasks 5s 轮询
// 此前每次对全部 Scheduled 族各跑一次 NextSlotFn（生产=DB 直读），展示面
// 与调度面共用槽缓存后轮询读放大收敛到地板周期。

import (
	"sync/atomic"
	"testing"
	"time"
)

// Given Scheduled 任务（NextSlotFn 计数、远期槽）。
// When 同一地板周期内连续两次 DescribeAll + 一次 Lookup。
// Then NextSlotFn 只求值一次——展示面复用 tick/executeRun 维护的槽缓存；
// 地板到点后恢复求值（收敛用户重排/带外改库，展示新鲜度上界=地板周期，
// 与调度面同口径）。
func TestEngine_DescribeAllReusesSlotCacheWithinEvalFloor(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	e.SetRole(true)
	slot := time.Now().Add(time.Hour)
	var evals atomic.Int32
	if err := e.Register(Descriptor{
		ID: "t-slot-cache", Family: "t", Name: "槽缓存展示", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { evals.Add(1); return slot },
		Run:        func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-slot-cache")

	for range 2 {
		found := false
		for _, m := range e.DescribeAll() {
			if m.ID == "t-slot-cache" {
				found = true
				if m.NextSlot == "" {
					t.Fatal("槽缓存应展示非空 next_slot")
				}
			}
		}
		if !found {
			t.Fatal("任务未注册")
		}
	}
	if _, ok := e.Lookup("t-slot-cache"); !ok {
		t.Fatal("任务未注册")
	}
	if got := evals.Load(); got != 1 {
		t.Fatalf("地板周期内 NextSlotFn 求值 %d 次, want 1（两次 DescribeAll+一次 Lookup 复用槽缓存）", got)
	}

	// 地板到点后恢复求值——展示面不得把陈旧缓存固化成永久值。
	shrinkSlotEvalFloor(t, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, ok := e.Lookup("t-slot-cache"); !ok {
		t.Fatal("任务未注册")
	}
	if got := evals.Load(); got != 2 {
		t.Fatalf("地板到点后 NextSlotFn 累计求值 %d 次, want 2", got)
	}

	// 调度停止后槽不可达：缓存即使在地板周期内也不得直通（总闸/用户停止
	// 后 NextSlot 必须为空——NextSlotFn 双门失效钉测同契约），且停调期
	// 零求值零节拍推进。
	e.StopLoop("t-slot-cache")
	if m, ok := e.Lookup("t-slot-cache"); !ok || m.NextSlot != "" {
		t.Fatalf("停调后 NextSlot=%q, want 空（缓存不得在停调期直通）", m.NextSlot)
	}
	if got := evals.Load(); got != 2 {
		t.Fatalf("停调期 NextSlotFn 仍被求值 %d 次, want 2（停调零求值）", got)
	}
}
