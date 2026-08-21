package services

import (
	"context"
	"testing"
	"time"
)

// TestCertificateService_scheduleDeploymentRetry_reentry_does_not_deadlock
// （R57 A-#1 红→绿）：部署回调内部署再失败会（异步）调用
// scheduleDeploymentRetry 重排同 jobID——重排的「等待在途回调退出」必须
// 等到回调自身返回（done 由其 defer 关闭）而非死锁。修复前
// certissuer.deploymentFailed 同步调用，重排在回调 goroutine 内等待自身
// done → 永久死锁。本测试断言两阶段（回调退出 + 重排完成）均有界完成。
func TestCertificateService_scheduleDeploymentRetry_reentry_does_not_deadlock(t *testing.T) {
	service := NewCertificateService()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
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
	select {
	case <-rescheduled:
		t.Fatal("reschedule returned while callback in-flight (dedup broken)")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-rescheduled:
	case <-time.After(5 * time.Second):
		t.Fatalf("reschedule deadlocked waiting for callback exit (R57 A-#1)")
	}
	service.pauseDeploymentRetries()
}

// TestWaitDoneOrTimeout_returns_on_closed_channel（R57 A-#2 语义验证）：
// done 关闭即快速返回；慢路径（30s 超时放弃）不在测试内等待真实 30s。
func TestWaitDoneOrTimeout_returns_on_closed_channel(t *testing.T) {
	done := make(chan struct{})
	close(done)
	start := time.Now()
	waitDoneOrTimeout(done, 1, "测试")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitDoneOrTimeout took %v on closed channel", elapsed)
	}
}
