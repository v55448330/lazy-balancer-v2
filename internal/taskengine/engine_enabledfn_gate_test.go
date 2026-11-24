package taskengine

// 历史 EnabledFn 调度门补全钉测试：tick 的 Scheduled/Periodic
// 分支此前只认 loopEnabled/running/角色门——EnabledFn 仅进元数据展示
// （Enabled 列），业务关时调度面照常投递（空转落行）。本文件钉三形状：
// ① EnabledFn=false 不调度（零 task_runs 零执行）；② 恢复 true 后下一 tick
// 到期即跑（节拍不被关闭期推进——与角色门 同款）；③ 在途 Run 不被
// EnabledFn 杀（门只作用于调度判定，当前轮跑完，下一轮才停）。

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Given Periodic 任务挂 EnabledFn（初值 false）+ 调度开关开。
// When 业务关期跑若干 tick，再翻 true。
// Then 关闭期零执行零落行；恢复后下一 tick 立即到期执行（节拍未被推进）。
func TestEngine_EnabledFnFalseSkipsPeriodicScheduling(t *testing.T) {
	e := newTestEngine(t)
	var enabled atomic.Bool
	ran := make(chan struct{}, 4)
	mustRegisterTaskForTest(t, e, Descriptor{ID: "t-enp", Family: "t", Name: "业务门周期", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		EnabledFn:  func() bool { return enabled.Load() },
		Run: func(rc RunContext) error {
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		}})
	e.StartLoop("t-enp")
	// 形状①：业务关——数百毫秒 tick 内零执行零 task_runs（曾空转落行）
	driveTicks(e, 30)
	if n := countRuns(t, "t-enp"); n != 0 {
		t.Fatalf("EnabledFn=false 期间不得调度落行，got %d 行", n)
	}
	select {
	case <-ran:
		t.Fatal("EnabledFn=false 期间 Run 体不得执行")
	default:
	}
	// 形状②：业务开——恢复后下一 tick 到期即跑（不推进节拍， 同款）
	enabled.Store(true)
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("EnabledFn 恢复 true 后下一 tick 应立即到期执行（节拍不得被关闭期推进）")
	}
}

// Given Scheduled 任务挂 EnabledFn（初值 false）+ 恒过期槽（仅 EnabledFn 门可拦）。
// When 业务关期跑若干 tick，再翻 true。
// Then 关闭期零执行零落行；恢复后下一 tick 投递过期槽。
func TestEngine_EnabledFnFalseSkipsScheduledScheduling(t *testing.T) {
	e := newTestEngine(t)
	var enabled atomic.Bool
	ran := make(chan struct{}, 4)
	mustRegisterTaskForTest(t, e, Descriptor{ID: "t-ens", Family: "t", Name: "业务门定时", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return time.Now().Add(-time.Hour) },
		EnabledFn:  func() bool { return enabled.Load() },
		Run: func(rc RunContext) error {
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		}})
	e.StartLoop("t-ens")
	driveTicks(e, 30)
	if n := countRuns(t, "t-ens"); n != 0 {
		t.Fatalf("EnabledFn=false 期间槽到期也不得调度落行，got %d 行", n)
	}
	select {
	case <-ran:
		t.Fatal("EnabledFn=false 期间 Run 体不得执行")
	default:
	}
	enabled.Store(true)
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("EnabledFn 恢复 true 后下一 tick 应立即投递过期槽")
	}
}

// Given Periodic 在途 Run（阻塞于释放通道）+ EnabledFn 中途翻 false。
// When 在途期间确定性地跑过若干 tick 后释放。
// Then 在途 Run 的上下文不被取消、跑完落 success（不被 EnabledFn 杀——门只
// 作用于调度判定），且此后不再调度新轮（下一轮才停）。
func TestEngine_EnabledFnFalseDoesNotKillInFlightRun(t *testing.T) {
	e := newTestEngine(t)
	var enabled atomic.Bool
	enabled.Store(true)
	started := make(chan struct{})
	release := make(chan struct{})
	firstCtx := make(chan context.Context, 1)
	// 误投递的新轮滞留在途（等到引擎 Stop 的 ctx 取消）：准入（running CAS）
	// 在 tick 内同步完成，故 driveTicks 返回后「有新轮在途」确定性可见——
	// 负断言不再依赖墙钟窗口内恰好发生 tick。
	var starts atomic.Int32
	if err := e.Register(Descriptor{ID: "t-enf", Family: "t", Name: "业务门在途", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		EnabledFn:  func() bool { return enabled.Load() },
		Run: func(rc RunContext) error {
			if starts.Add(1) > 1 {
				<-rc.Ctx.Done()
				return rc.Ctx.Err()
			}
			firstCtx <- rc.Ctx
			close(started)
			select {
			case <-rc.Ctx.Done():
				return rc.Ctx.Err()
			case <-release:
				return nil
			}
		}}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-enf")
	waitForEngineSignal(t, "业务门在途 Run 启动", started)
	inflight := <-firstCtx

	// 在途期间业务关：确定性驱动 tick——误杀形态（SetRole 同型取消）在 tick
	// 内同步取消本轮上下文，紧接着读 ctx.Err() 即终值。
	enabled.Store(false)
	driveTicks(e, 30)
	if err := inflight.Err(); err != nil {
		t.Fatalf("EnabledFn=false 不得杀在途 Run（本轮上下文已取消: %v）", err)
	}

	// 释放首轮：落 success（占位释放在终态行之后，settle 保证读到终值）
	close(release)
	settleTaskRuns(t, e, "t-enf")
	if lr := e.LatestRun("t-enf"); lr == nil || lr.Status != "success" {
		t.Fatalf("在途 Run 应跑完落 success（不被 EnabledFn 杀），got %+v", lr)
	}

	// 下一轮才停：关闭期再驱动若干 tick 不得准入新轮（误投递的新轮滞留在途）。
	// 先把节拍置零（=从未执行过）让周期到期判定确定成立——否则 20ms 间隔下
	// 紧跟驱动 tick 的「现在」可能尚未到期，负断言空转。
	reg := regOf(t, e, "t-enf")
	reg.mu.Lock()
	reg.lastCheck = time.Time{}
	reg.mu.Unlock()
	driveTicks(e, 30)
	if e.IsTaskInFlight("t-enf") {
		t.Fatal("EnabledFn=false 后不得再调度新轮（有新轮在途）")
	}
	if n := countRuns(t, "t-enf"); n != 1 {
		t.Fatalf("EnabledFn=false 后不得再调度新轮，got %d 行", n)
	}
}
