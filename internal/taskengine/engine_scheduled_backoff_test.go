package taskengine

// Scheduled 失败退避兜底钉测：Run 早退不推进槽（失败且槽仍是过期旧值）时，
// tick 不得按秒级节拍无限重投（1 行/tick ≈ 8.6 万行/天）。退避 1s→5s→30s
// 封顶，槽推进/成功即清零；连续到 scheduledFailStreakStopLimit（4）轮自动轮
// 仍未推进则停调（终点形状见 engine_scheduling_stop_test.go，本文件只覆盖
// 前两轮的节流——用例在 runs>=2 即断言，不会走到停调终点）。

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Given Scheduled 任务的 Run 恒失败且不推进槽（NextSlotFn 恒返回过期旧槽）。
// When tick 循环运转。
// Then 退避兜底生效：350ms 窗口（≈35 ticks）内至多 2 次执行（无退避时
// 每 tick 重投 ≈30+ 次）；退避衰减（1s）后照常重投（终点是「连续 4 轮自动轮
// 未推进即停调」，本用例在首次 1s 退避后的第二轮结束，不触达终点）。
func TestEngine_ScheduledStaleSlotFailureBackoff(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-stale-slot", Family: "t", Name: "早退不推进槽", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return pastSlot }, // Run 早退不推进槽的形态
		Run: func(rc RunContext) error {
			runs.Add(1)
			return errors.New("boom")
		}})
	e.SetRole(true)
	e.StartLoop("t-stale-slot")

	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("350ms 窗口内执行 %d 次, want 1（首档退避必须精确生效）", got)
	}
	if got := countRuns(t, "t-stale-slot"); got != 1 {
		t.Fatalf("task_runs 落行 %d, want 1", got)
	}
	// 退避（首档 1s）衰减后重投——兜底是节流不是停摆。
	waitForEngine(t, "首档退避后的第二次执行", 2*time.Second, func() bool { return runs.Load() >= 2 })
	if got := runs.Load(); got < 2 {
		t.Fatalf("退避衰减后未恢复重投, runs=%d（兜底不得等同停调）", got)
	}
}

// 回归形状：失败但 Run 已推进槽（业务侧 advanceSlot 形态）——不触发退避，
// 排程按新槽执行（退避只兜「槽未推进」形态）。
func TestEngine_ScheduledAdvancedSlotFailureNoBackoff(t *testing.T) {
	e := newTestEngine(t)
	var slot atomic.Value
	slot.Store(time.Now().Add(-time.Second))
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-adv-slot", Family: "t", Name: "失败但推进槽", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return slot.Load().(time.Time) },
		Run: func(rc RunContext) error {
			runs.Add(1)
			slot.Store(time.Now().Add(10 * time.Second)) // 业务侧推进新槽
			return errors.New("boom")
		}})
	e.SetRole(true)
	e.StartLoop("t-adv-slot")

	waitForEngine(t, "推进槽后的首轮执行", 2*time.Second, func() bool { return runs.Load() == 1 })
	if runs.Load() != 1 {
		t.Fatalf("首轮执行次数=%d, want 1", runs.Load())
	}
	// 失败但槽已推进——不触发退避也不重投（等效既有「槽推进即不重投」语义）。
	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("失败但槽已推进不得触发退避/重投, got %d", got)
	}
}

// 回归形状：成功轮清零退避状态（failed 退避不被成功轮继承），且「成功 +
// 槽未推进」按「同一槽只执行一次」消费——不再每 tick 重投（旧语义「成功
// 不受退避约束、每 tick 到期」在 tick=1s 下最坏 8.6 万行 task_runs/天，
// 已裁定为槽消费语义）。
func TestEngine_ScheduledSuccessClearsBackoff(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-ok-slot", Family: "t", Name: "成功不推进槽", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return pastSlot },
		Run: func(rc RunContext) error {
			runs.Add(1)
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-ok-slot")

	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("成功轮消费本槽（同一槽只执行一次，不再每 tick 到期重投）, got %d, want 1", got)
	}
}
