package services

// 部署重试的两个静默窗口钉测：
//  1. 规则屏障与 timer 登记必须原子——直接调用 scheduleDeploymentRetry 也
//     不得为屏障中的规则登记 timer（禁用动作的取消扫描已错过该 job）。
//  2. resumeDeploymentRetries 不得吞掉补扫错误（DB 故障静默 = 恢复后仍无重试）。

import (
	"database/sql"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestScheduleDeploymentRetry_refusesBlockedRuleAtomic(t *testing.T) {
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	oldManager := caQueueManager
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	caQueueManager = manager
	t.Cleanup(func() { caQueueManager = oldManager })
	blocked := manager.BlockJobsForRule("lb_blocked")

	if err := service.scheduleDeploymentRetry(42, "lb_blocked", time.Hour); !errors.Is(err, ErrCertificateDeploymentRetryBlocked) {
		t.Fatalf("scheduleDeploymentRetry error=%v, want ErrCertificateDeploymentRetryBlocked", err)
	}
	service.timerMu.Lock()
	_, hasTimer := service.deploymentTimers[42]
	service.timerMu.Unlock()
	if hasTimer {
		t.Fatal("屏障中的规则不得登记部署重试 timer")
	}
	manager.UnblockJobsForRule("lb_blocked", blocked)
}

func TestResumeDeploymentRetries_logsRescanFailure(t *testing.T) {
	oldDB := db.DB
	closed, err := sql.Open("sqlite", t.TempDir()+"/closed.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	db.DB = closed
	t.Cleanup(func() { db.DB = oldDB })

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.pauseDeploymentRetries()

	oldWriter := log.Writer()
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	service.resumeDeploymentRetries()

	if !strings.Contains(buf.String(), "恢复部署重试补扫失败") {
		t.Fatalf("补扫错误必须可见（旧实现静默丢弃），日志=%q", buf.String())
	}
}
