package main

import (
	"testing"
	"time"
)

// TestShutdownWithTimeout_syncSegmentIsCappedAndACMEKeepsBudget 钉住同步段上限：
// 同步停止阻塞时，ShutdownWithTimeout(10s) 必须只花一个同步段上限（3s）就继续
// ACME 收尾，而不是把传进来的 10s 吃满（那正是同步段侵占 ACME 收尾的回归形态）。
func TestShutdownWithTimeout_syncSegmentIsCappedAndACMEKeepsBudget(t *testing.T) {
	syncWorker := newLifecycleWorkerFake(fakeStartImmediate, fakeStopBlocksOnRelease)
	t.Cleanup(syncWorker.releaseNow)
	acmeWorker := newLifecycleWorkerFake(fakeStartPendsUntilStop, fakeStopUnblocksStart)
	lifecycle := newRuntimeLifecycle(syncWorker, func() lifecycleWorker { return acmeWorker })
	lifecycle.StartACME()

	started := time.Now()
	lifecycle.ShutdownWithTimeout(10 * time.Second)
	elapsed := time.Since(started)

	if elapsed < syncStopSegmentMax-200*time.Millisecond {
		t.Fatalf("同步段只等了 %s，want ≈%s（阻塞的同步停止必须被有界等待）", elapsed, syncStopSegmentMax)
	}
	if elapsed > syncStopSegmentMax+2*time.Second {
		t.Fatalf("关停耗时 %s：同步段吃掉了应当留给 ACME 收尾的预算（上限 %s + 收尾执行时间）", elapsed, syncStopSegmentMax)
	}
	select {
	case <-acmeWorker.exited:
	default:
		t.Fatal("ACME 收尾未获得执行机会（同步段把预算钳成 0）")
	}
}

// TestStopWithinIfBudgeted_skipsWhenBudgetExhausted 钉住「segment()=0 不传给
// Stop*Within」：被调方把 within<=0 当无界等待，直接传 0 会把预算门反转。
func TestStopWithinIfBudgeted_skipsWhenBudgetExhausted(t *testing.T) {
	calls := 0
	stop := func(time.Duration) bool { calls++; return true }

	if stopWithinIfBudgeted(0, stop) {
		t.Fatal("预算为 0 时不应执行停止")
	}
	if stopWithinIfBudgeted(-time.Second, stop) {
		t.Fatal("负预算时不应执行停止")
	}
	if calls != 0 {
		t.Fatalf("预算耗尽时仍调用了停止 %d 次", calls)
	}
	if !stopWithinIfBudgeted(500*time.Millisecond, stop) {
		t.Fatal("正预算时必须执行停止")
	}
	if calls != 1 {
		t.Fatalf("正预算时停止调用 %d 次, want 1", calls)
	}
}

// TestStartACME_waitsForInFlightStopBeforeNewGeneration 钉住跨代隔离：
// 关停等待超时（停止 goroutine 仍在跑）后，StartACME 必须先等它收尾再拉起新
// 一代——否则在途 queue.Stop 会关掉新一代队列（证书签发静默停摆）。
func TestStartACME_waitsForInFlightStopBeforeNewGeneration(t *testing.T) {
	// Given 第一代证书 worker 的 Stop 阻塞（模拟 CA 队列补偿在途）。
	blocked := newLifecycleWorkerFake(fakeStartImmediate, fakeStopBlocksOnRelease)
	second := newLifecycleWorkerFake(fakeStartImmediate, fakeStopImmediate)
	generation := 0
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker {
		generation++
		if generation == 1 {
			return blocked
		}
		return second
	})
	lifecycle.StartACME()
	waitForACMEService(t, lifecycle)

	// When 停止等待超时（互斥已释放，但停止仍在途），随后请求启动新一代。
	lifecycle.stopACMEWithin(20 * time.Millisecond)
	<-blocked.stopEntered
	// Then 新一代不得在上一代停止收尾前启动，收尾后必须启动。
	assertNewGenerationBlockedUntilStopSettles(t, lifecycle, second.started, blocked.releaseNow)
}

// waitForACMEService 等待 StartACME 完成装配（certService 非空）：StartACME
// 同步完成装配，因此这里只是防御性断言，避免测试在装配前进入停止。
func waitForACMEService(t *testing.T, lifecycle *runtimeLifecycle) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lifecycle.mu.Lock()
		assembled := lifecycle.certService != nil
		lifecycle.mu.Unlock()
		if assembled {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("StartACME 未在 2s 内装配证书服务")
}

// TestStartACME_refusesWhenStopStillInFlightAfterBudget 钉住超时分支：停止在
// 预算内未收尾时，StartACME 必须放弃启动并返回，而不是拉起一个必然被在途
// Stop 关掉的新队列。
func TestStartACME_refusesWhenStopStillInFlightAfterBudget(t *testing.T) {
	blocked := newLifecycleWorkerFake(fakeStartImmediate, fakeStopBlocksOnRelease)
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker { return blocked })
	lifecycle.StartACME()
	lifecycle.stopACMEWithin(20 * time.Millisecond)
	<-blocked.stopEntered
	t.Cleanup(blocked.releaseNow)

	started := time.Now()
	lifecycle.StartACME()
	elapsed := time.Since(started)
	if elapsed < acmeStopSegmentMax-200*time.Millisecond {
		t.Fatalf("StartACME 只等了 %s，want ≈%s（必须给出停止收尾的预算）", elapsed, acmeStopSegmentMax)
	}
	// 启动被拒绝：certService 仍为空（停止收尾后 `pendingStop` 才被清空）。
	lifecycle.mu.Lock()
	certService := lifecycle.certService
	lifecycle.mu.Unlock()
	if certService != nil {
		t.Fatal("停止仍在途时仍装配了新一代证书服务")
	}
	blocked.releaseNow()
}
