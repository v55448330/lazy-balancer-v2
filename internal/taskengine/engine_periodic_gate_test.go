package taskengine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngine_PeriodicRechecksEnabledFnAfterIntervalDelay(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var enabled atomic.Bool
	enabled.Store(true)
	var enabledCalls, intervalCalls, runs atomic.Int32
	intervalEntered := make(chan struct{})
	releaseInterval := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseInterval) }) }
	t.Cleanup(release)
	ran := make(chan struct{}, 1)
	if err := e.Register(Descriptor{
		ID: "t-periodic-gate-race", Family: "t", Name: "周期业务门竞态", Kind: KindPeriodic, RunsOn: RoleAny,
		EnabledFn: func() bool {
			enabledCalls.Add(1)
			return enabled.Load()
		},
		IntervalFn: func() time.Duration {
			if intervalCalls.Add(1) == 1 {
				close(intervalEntered)
				<-releaseInterval
			}
			return time.Hour
		},
		Run: func(RunContext) error {
			runs.Add(1)
			ran <- struct{}{}
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-periodic-gate-race")

	tickDone := make(chan struct{})
	go func() {
		e.tick()
		close(tickDone)
	}()
	select {
	case <-intervalEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("IntervalFn 未进入")
	}
	enabled.Store(false)
	release()
	select {
	case <-tickDone:
	case <-time.After(2 * time.Second):
		t.Fatal("tick 未在 IntervalFn 放行后退出")
	}

	// 关闭期间不得按 IntervalFn 求值前的旧 true 投递。
	select {
	case <-ran:
		t.Fatal("EnabledFn 在 IntervalFn 等待期间翻 false，仍额外执行了一轮")
	case <-time.After(100 * time.Millisecond):
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("关闭后执行次数=%d, want 0", got)
	}
	if got := countRuns(t, "t-periodic-gate-race"); got != 0 {
		t.Fatalf("关闭后 task_runs=%d, want 0", got)
	}
	if got := enabledCalls.Load(); got < 2 {
		t.Fatalf("到期投递前 EnabledFn 调用次数=%d, want >=2（首次门+投递前复核）", got)
	}

	// false 复核必须置零节拍：重新开启后即使周期为一小时也应立即补跑。
	enabled.Store(true)
	e.tick()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("重新开启后未立即补跑，lastCheck 未按 false 复核置零")
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("重新开启后的累计执行次数=%d, want 1", got)
	}
}

func TestEngine_PeriodicEnabledFnSkipsSecondCheckWhenNotDueOrDisallowed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		due    bool
		master bool
		// wantEnabledCalls：非 due&&allows 路径的 EnabledFn 求值次数。
		// 「角色不符」经前置角色门整分支跳过（与 Scheduled 同型对称），
		// EnabledFn 零求值——从节点不再每 tick 白付闭包 DB 读。
		wantEnabledCalls int32
	}{
		{name: "not due", due: false, master: true, wantEnabledCalls: 1},
		{name: "due but role disallowed", due: true, master: false, wantEnabledCalls: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
			var enabledCalls, runs atomic.Int32
			if err := e.Register(Descriptor{
				ID: "t-periodic-gate-read-budget", Family: "t", Name: "周期业务门读取预算", Kind: KindPeriodic, RunsOn: RoleMasterOnly,
				EnabledFn:  func() bool { enabledCalls.Add(1); return true },
				IntervalFn: func() time.Duration { return time.Hour },
				Run:        func(RunContext) error { runs.Add(1); return nil },
			}); err != nil {
				t.Fatal(err)
			}
			e.SetRole(tc.master)
			e.StartLoop("t-periodic-gate-read-budget")
			if !tc.due {
				e.mu.RLock()
				r := e.regs["t-periodic-gate-read-budget"]
				e.mu.RUnlock()
				r.mu.Lock()
				r.lastCheck = time.Now()
				r.mu.Unlock()
			}

			e.tick()

			if got := enabledCalls.Load(); got != tc.wantEnabledCalls {
				t.Fatalf("非 due&&allows 路径 EnabledFn 调用=%d 次, want %d（不得增加每 tick DB 读）", got, tc.wantEnabledCalls)
			}
			if got := runs.Load(); got != 0 {
				t.Fatalf("非投递路径执行次数=%d, want 0", got)
			}
		})
	}
}

func TestEngine_PeriodicEnabledFnRecheckHonorsStopLoop(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var enabledCalls, runs atomic.Int32
	secondCheckEntered := make(chan struct{})
	releaseSecondCheck := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSecondCheck) }) }
	t.Cleanup(release)
	if err := e.Register(Descriptor{
		ID: "t-periodic-gate-stop-race", Family: "t", Name: "复核期间停止", Kind: KindPeriodic, RunsOn: RoleAny,
		EnabledFn: func() bool {
			if enabledCalls.Add(1) == 2 {
				close(secondCheckEntered)
				<-releaseSecondCheck
			}
			return true
		},
		IntervalFn: func() time.Duration { return time.Hour },
		Run: func(RunContext) error {
			runs.Add(1)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-periodic-gate-stop-race")
	tickDone := make(chan struct{})
	go func() {
		e.tick()
		close(tickDone)
	}()
	select {
	case <-secondCheckEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("第二次 EnabledFn 未进入")
	}
	e.StopLoop("t-periodic-gate-stop-race")
	// 持住 admission 所需的 e.mu：若删掉投递前 due/loopEnabled 复核，
	// tick 会卡在 reservePeriodicRun；正确复核则无需进入 admission 即返回。
	e.mu.Lock()
	release()
	select {
	case <-tickDone:
	case <-time.After(200 * time.Millisecond):
		e.mu.Unlock()
		t.Fatal("StopLoop 后仍进入 admission，投递前 due/loopEnabled 复核缺失")
	}
	e.mu.Unlock()

	if got := runs.Load(); got != 0 {
		t.Fatalf("StopLoop 后执行次数=%d, want 0", got)
	}
	if got := countRuns(t, "t-periodic-gate-stop-race"); got != 0 {
		t.Fatalf("StopLoop 后 task_runs=%d, want 0", got)
	}
	if got := enabledCalls.Load(); got < 2 {
		t.Fatalf("测试未触达第二次业务门，调用次数=%d", got)
	}
}

// Pause/SetRole 与投递竞态时，未通过 admission 的轮次不得
// 推进 lastCheck；恢复后必须立即补跑，而不是白等一个完整 interval。
func TestEngine_PeriodicAdmissionRaceDoesNotAdvanceBeat(t *testing.T) {
	tests := []struct {
		name    string
		runsOn  Role
		block   func(*Engine)
		recover func(*Engine)
	}{
		{
			name: "pause", runsOn: RoleAny,
			block:   func(e *Engine) { e.PauseScheduling() },
			recover: func(e *Engine) { e.ResumeScheduling() },
		},
		{
			name: "demote", runsOn: RoleMasterOnly,
			block:   func(e *Engine) { e.SetRole(false) },
			recover: func(e *Engine) { e.SetRole(true) },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
			var enabledCalls, runs atomic.Int32
			secondCheckEntered := make(chan struct{})
			releaseSecondCheck := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseSecondCheck) }) }
			t.Cleanup(release)
			ran := make(chan struct{}, 1)
			const id = "t-periodic-admission-race"
			if err := e.Register(Descriptor{
				ID: id, Family: "t", Name: "投递准入竞态", Kind: KindPeriodic, RunsOn: tc.runsOn,
				EnabledFn: func() bool {
					if enabledCalls.Add(1) == 2 {
						close(secondCheckEntered)
						<-releaseSecondCheck
					}
					return true
				},
				IntervalFn: func() time.Duration { return time.Hour },
				Run: func(RunContext) error {
					runs.Add(1)
					ran <- struct{}{}
					return nil
				},
			}); err != nil {
				t.Fatal(err)
			}
			e.StartLoop(id)
			tickDone := make(chan struct{})
			go func() {
				e.tick()
				close(tickDone)
			}()
			select {
			case <-secondCheckEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("第二次 EnabledFn 未进入")
			}
			tc.block(e)
			release()
			select {
			case <-tickDone:
			case <-time.After(2 * time.Second):
				t.Fatal("准入竞态 tick 未退出")
			}
			if got := runs.Load(); got != 0 {
				t.Fatalf("暂停/角色拒绝后执行次数=%d, want 0", got)
			}
			e.mu.RLock()
			r := e.regs[id]
			e.mu.RUnlock()
			r.mu.Lock()
			lastCheck := r.lastCheck
			r.mu.Unlock()
			if !lastCheck.IsZero() {
				t.Fatalf("未通过 admission 却推进 lastCheck=%s", lastCheck)
			}

			tc.recover(e)
			e.tick()
			select {
			case <-ran:
			case <-time.After(2 * time.Second):
				t.Fatal("恢复后未立即补跑")
			}
			if got := runs.Load(); got != 1 {
				t.Fatalf("恢复后的累计执行次数=%d, want 1", got)
			}
		})
	}
}

// 评审补强：直接钉 reservePeriodicRun 的 loop-disabled 分支及其计数回收，
// 覆盖 StopLoop 在最终 due 复核后、admission 前获胜时的兜底门。
func TestEngine_ReservePeriodicRunRejectsStoppedLoop(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	const id = "t-periodic-stopped-admission"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "停止后准入", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop(id)
	e.StopLoop(id)

	res, err := e.reservePeriodicRun(id, time.Now())
	if res != nil || err != errPeriodicLoopDisabled {
		t.Fatalf("res=%p err=%v, want nil/errPeriodicLoopDisabled", res, err)
	}
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	r.mu.Lock()
	lastCheck := r.lastCheck
	r.mu.Unlock()
	if !lastCheck.IsZero() {
		t.Fatalf("停止态 admission 推进 lastCheck=%s", lastCheck)
	}
	if got := e.inFlight.Load(); got != 0 {
		t.Fatalf("拒绝后 inFlight=%d, want 0", got)
	}
	waited := make(chan struct{})
	go func() {
		e.runWG.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("拒绝后 runWG 未归零")
	}
	if got := countRuns(t, id); got != 0 {
		t.Fatalf("停止态 admission 落 task_runs=%d, want 0", got)
	}
}
