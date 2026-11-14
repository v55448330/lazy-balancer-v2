package taskengine

// Register×Stop 竞态：stopped 检查必须在 e.mu 临界区内（与 reserveRunInternal
// 的 admission 同族）——锁外 check-then-lock 会让并发 Stop 穿过检查，产生
// 「已注册但永不被调度」的静默形态（StartLoop 对 stopped 恒 no-op）。

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// Given 引擎停止与注册并发（注册方已越过锁外 stopped 检查的窗口形态）。
// When Register 进入 admission。
// Then 临界区内复核 stopped：ErrEngineStopped 响亮拒绝，不得留下
// 「已注册永不调度」的静默项。
func TestEngine_RegisterConcurrentStopDoesNotLeaveSilentRegistration(t *testing.T) {
	e := newTestEngine(t)
	reached := make(chan struct{})
	release := make(chan struct{})
	oldHook := beforeRegisterAdmission
	beforeRegisterAdmission = func() {
		close(reached)
		<-release
	}
	t.Cleanup(func() { beforeRegisterAdmission = oldHook })

	var regErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		regErr = e.Register(Descriptor{ID: "t-reg-stop", Family: "t", Name: "停止竞态", Kind: KindOneshot,
			Run: func(RunContext) error { return nil }})
	}()
	waitForEngineSignal(t, "注册方进入 admission 窗口", reached)
	// Stop 先行提交（窗口内 stopped 已翻转）——放行后注册必须被临界区复核拒绝。
	e.Stop()
	close(release)
	wg.Wait()
	if !errors.Is(regErr, ErrEngineStopped) {
		t.Fatalf("停止后到达的注册 err=%v, want ErrEngineStopped（锁外 check-then-lock 会静默放行）", regErr)
	}
	e.mu.RLock()
	_, registered := e.regs["t-reg-stop"]
	e.mu.RUnlock()
	if registered {
		t.Fatal("已停止引擎不得留下注册项（StartLoop 恒 no-op，注册即永久静默态）")
	}
}

// Given 并发 Register×Stop 交错（无注入窗口，真实调度交错）。
// When 全部返回后。
// Then 不变量：注册成功 ⇒ 登记先于 Stop 的临界区提交（regs 可见）；
// 被停止拒绝 ⇒ ErrEngineStopped 且无注册项——不存在「拒绝却已登记」或
// 「成功却无登记」的半状态（stopped 检查与登记同临界区的可观测推论）。
func TestEngine_RegisterStopRaceInvariant(t *testing.T) {
	for round := range 50 {
		e := NewEngine(Options{TickInterval: time.Hour})
		var wg sync.WaitGroup
		errCh := make(chan error, 1)
		wg.Add(2)
		go func() {
			defer wg.Done()
			errCh <- e.Register(Descriptor{ID: "t-race", Family: "t", Name: "竞态", Kind: KindOneshot,
				Run: func(RunContext) error { return nil }})
		}()
		go func() { defer wg.Done(); e.Stop() }()
		wg.Wait()
		err := <-errCh
		e.mu.RLock()
		_, registered := e.regs["t-race"]
		e.mu.RUnlock()
		if err == nil && !registered {
			t.Fatalf("round %d: 注册成功却无登记项（检查与登记必须同临界区）", round)
		}
		if errors.Is(err, ErrEngineStopped) && registered {
			t.Fatalf("round %d: 停止拒绝却留下登记项——静默注册态", round)
		}
		if err != nil && !errors.Is(err, ErrEngineStopped) {
			t.Fatalf("round %d: 意外注册错误 %v", round, err)
		}
		e.Stop()
	}
}
