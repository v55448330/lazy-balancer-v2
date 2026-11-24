package services

import (
	"context"
	"testing"
	"time"
)

// TestCertificateService_scheduleDeploymentRetry_reentry_does_not_deadlock
// 部署回调内部署再失败会（异步）调用
// scheduleDeploymentRetry 重排同 jobID——重排的「等待在途回调退出」必须
// 等到回调自身返回（done 由其 defer 关闭）而非死锁。修复前
// certissuer.deploymentFailed 同步调用，重排在回调 goroutine 内等待自身
// done → 永久死锁。本测试断言两阶段（回调退出 + 重排完成）均有界完成。
func TestCertificateService_scheduleDeploymentRetry_reentry_does_not_deadlock(t *testing.T) {
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	releasedOnce := false
	// 成功/失败同一口径收口：close(release) 与 service.Stop 放 t.Cleanup——
	// 此前两者都写在 t.Fatal 之后，前置断言一旦失败，在途回调永久阻塞、
	// 包级单例的定时器族未收口，污染同包后续用例。
	releaseCallback := func() {
		if releasedOnce {
			return
		}
		releasedOnce = true
		close(release)
	}
	// 收口终态断言（LIFO：release → Stop → 本检查）：Stop 后不得残留 timer
	// 或在途回调登记——本用例的历史缺陷正是失败路径把两者留进同包后续用例。
	t.Cleanup(func() {
		service.timerMu.Lock()
		defer service.timerMu.Unlock()
		if len(service.deploymentTimers) != 0 || len(service.deploymentCallbacks) != 0 {
			t.Errorf("服务收口后仍残留部署定时器(%d)/在途回调(%d)", len(service.deploymentTimers), len(service.deploymentCallbacks))
		}
	})
	t.Cleanup(service.Stop)
	t.Cleanup(releaseCallback)
	service.retryDeployment = func(_ context.Context, _ int) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	service.scheduleDeploymentRetry(42, "lb_reentry", 0)
	<-entered
	rescheduled := make(chan struct{})
	go func() {
		service.scheduleDeploymentRetry(42, "lb_reentry", time.Hour)
		close(rescheduled)
	}()
	// 确定性证据=协程栈：重排必须阻塞在 waitDoneOrTimeout 的等待点（在途回调
	// done 未关闭），而不是「睡 50ms 还没返回」——后者在重排协程尚未被调度时
	// 同样成立（负载下假绿）。
	select {
	case <-rescheduled:
		t.Fatal("reschedule returned while callback in-flight (dedup broken)")
	default:
	}
	waitGoroutineBlockedOn(t, "TestCertificateService_scheduleDeploymentRetry_reentry_does_not_deadlock", "waitDoneOrTimeout")
	releaseCallback()
	select {
	case <-rescheduled:
	case <-time.After(5 * time.Second):
		t.Fatalf("reschedule deadlocked waiting for callback exit (历史修复)")
	}
}

// TestWaitDoneOrTimeout_returns_on_closed_channel
// done 关闭即快速返回；慢路径（默认 30s 超时放弃）不在测试内等待真实 30s。
func TestWaitDoneOrTimeout_returns_on_closed_channel(t *testing.T) {
	done := make(chan struct{})
	close(done)
	start := time.Now()
	// 统一传 s.cancelWaitTimeout，测试缝与 cancelDeploymentRetry/Stop 同模式）。
	waitDoneOrTimeout(done, 0, 1, "测试")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitDoneOrTimeout took %v on closed channel", elapsed)
	}
}

// 非零 timeout 被真实消费——未关闭的 done 在自定义短超时后放行，而非
// 固定 30s。
func TestWaitDoneOrTimeout_consumes_custom_timeout(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	start := time.Now()
	waitDoneOrTimeout(done, 30*time.Millisecond, 1, "测试")
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("waitDoneOrTimeout returned early (%v), want custom timeout consumed", elapsed)
	}
}
