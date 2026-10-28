package taskengine

// 历史 EnabledFn 调度门补全钉测试：tick 的 Scheduled/Periodic
// 分支此前只认 loopEnabled/running/角色门——EnabledFn 仅进元数据展示
// （Enabled 列），业务关时调度面照常投递（空转落行）。本文件钉三形状：
// ① EnabledFn=false 不调度（零 task_runs 零执行）；② 恢复 true 后下一 tick
// 到期即跑（节拍不被关闭期推进——与角色门 同款）；③ 在途 Run 不被
// EnabledFn 杀（门只作用于调度判定，当前轮跑完，下一轮才停）。

import (
	"sync"
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
	e.Register(Descriptor{ID: "t-enp", Family: "t", Name: "业务门周期", Kind: KindPeriodic, RunsOn: RoleAny,
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
	time.Sleep(300 * time.Millisecond)
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
	e.Register(Descriptor{ID: "t-ens", Family: "t", Name: "业务门定时", Kind: KindScheduled, RunsOn: RoleAny,
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
	time.Sleep(300 * time.Millisecond)
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
// When 在途期间跑过若干 tick 后释放。
// Then 在途 Run 跑完落 success（不被 EnabledFn 杀——门只作用于调度判定），
// 且此后不再调度新轮（下一轮才停）。
func TestEngine_EnabledFnFalseDoesNotKillInFlightRun(t *testing.T) {
	e := newTestEngine(t)
	var enabled atomic.Bool
	enabled.Store(true)
	started := make(chan struct{})
	release := make(chan struct{})
	// 放弃形态（Run 未启动即失败）由 newTestEngine 的 Stop→ctx.Done 兜底，
	// 不另设 close cleanup（与测试体 close(release) 双重关闭会 panic）。
	// Run 体须重入安全：RED 阶段（门未实现）业务关不拦新轮，Run 会被
	// 连续再调度——close 用 sync.Once 幂等，避免 close of closed channel
	// panic 噪音淹没断言。
	var startOnce sync.Once
	if err := e.Register(Descriptor{ID: "t-enf", Family: "t", Name: "业务门在途", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		EnabledFn:  func() bool { return enabled.Load() },
		Run: func(rc RunContext) error {
			startOnce.Do(func() { close(started) })
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
	// 在途期间业务关：给足 tick 轮次——若实现误杀（SetRole 同型取消），终态已翻转
	enabled.Store(false)
	time.Sleep(100 * time.Millisecond)
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if lr := e.LatestRun("t-enf"); lr != nil && lr.Status == "success" {
			// 下一轮才停：关闭后不再有新轮落行
			time.Sleep(100 * time.Millisecond)
			if n := countRuns(t, "t-enf"); n != 1 {
				t.Fatalf("EnabledFn=false 后不得再调度新轮，got %d 行", n)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("在途 Run 应跑完落 success（不被 EnabledFn 杀），got %+v", e.LatestRun("t-enf"))
}
