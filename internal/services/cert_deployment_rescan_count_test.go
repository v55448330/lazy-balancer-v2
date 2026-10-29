package services

import (
	"testing"
	"time"
)

// seedRescanJob 造一条「deployment_available_after 已过、材料齐全、规则启用
// ACME」的 downloaded 任务——补扫的合法候选形态。
func seedRescanJob(t *testing.T) (int, string) {
	t.Helper()
	_, database := newClusterTestService(t)
	const ruleID = "lb_rescan_count"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'rescan', 'example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'rescan CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,deployment_available_after)
		VALUES (?, 'example.com', 'downloaded', 7, 'cert', 'key', datetime('now','-1 hour'))`, ruleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return int(id), ruleID
}

// 补扫计数必须等于「本轮真正登记了 timer」的数量。暂停/停止与规则补偿屏障
// 期间没有任何调度，旧实现仍把每行计成「部署重建」——cert-waiting-ca 于是
// 在配置导入/规则删除补偿窗口每 30s 落一行「补扫完成：…部署重建 N」，
// 任务监控假绿而证书部署实际未重新登记。
func TestCertificateService_rescanDoesNotCountUnscheduledRetries(t *testing.T) {
	t.Run("paused service", func(t *testing.T) {
		jobID, _ := seedRescanJob(t)
		service := NewCertificateService()
		resetCertificateServiceForTest(t)
		scheduled := make(chan int, 1)
		service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
			scheduled <- id
			return nil
		}
		service.pauseDeploymentRetries()

		// When：暂停期补扫
		rescheduled, err := service.rescanDroppedDeploymentRetries()

		// Then：未调度、不计数
		if err != nil {
			t.Fatalf("rescan while paused: %v", err)
		}
		if rescheduled != 0 {
			t.Fatalf("rescheduled=%d, want 0（暂停期未登记任何 timer）", rescheduled)
		}
		// 同步可观测：返回计数=0 之外直查在册 timer 集（防「计数谎报 + 短延迟
		// timer 异步触发」形态），非阻塞核查回调通道；固定观测窗判「没发生」
		// 在负载下会假绿。
		service.timerMu.Lock()
		_, hasTimer := service.deploymentTimers[jobID]
		service.timerMu.Unlock()
		if hasTimer {
			t.Fatalf("paused rescan registered a deployment timer for job %d", jobID)
		}
		select {
		case id := <-scheduled:
			t.Fatalf("paused rescan scheduled job %d", id)
		default:
		}

		// 恢复后同一行必须真正重排——「不计数」不得退化为「永不调度」
		service.resumeDeploymentRetries()
		select {
		case id := <-scheduled:
			if id != jobID {
				t.Fatalf("resumed job=%d, want %d", id, jobID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("resume did not reschedule the dropped deployment retry")
		}
	})

	t.Run("rule barrier", func(t *testing.T) {
		jobID, ruleID := seedRescanJob(t)
		service := NewCertificateService()
		resetCertificateServiceForTest(t)
		oldManager := caQueueManager
		manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
		caQueueManager = manager
		t.Cleanup(func() { caQueueManager = oldManager })
		scheduled := make(chan int, 2)
		service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
			scheduled <- id
			return nil
		}
		blocked := manager.BlockJobsForRule(ruleID)

		// When：屏障期补扫
		rescheduled, err := service.rescanDroppedDeploymentRetries()

		// Then：屏障期未调度、不计数
		if err != nil {
			t.Fatalf("rescan while rule blocked: %v", err)
		}
		if rescheduled != 0 {
			t.Fatalf("rescheduled=%d, want 0（规则补偿屏障期）", rescheduled)
		}
		// 同步可观测：同暂停期子用例——直查在册 timer 集 + 非阻塞通道核查。
		service.timerMu.Lock()
		_, hasTimer := service.deploymentTimers[jobID]
		service.timerMu.Unlock()
		if hasTimer {
			t.Fatalf("barrier rescan registered a deployment timer for job %d", jobID)
		}
		select {
		case id := <-scheduled:
			t.Fatalf("barrier rescan scheduled job %d", id)
		default:
		}

		// 解锁后包级补扫（Unblock→rescanDroppedCertificateDeploymentRetries）
		// 必须真正重排
		manager.UnblockJobsForRule(ruleID, blocked)
		select {
		case id := <-scheduled:
			if id != jobID {
				t.Fatalf("unblocked job=%d, want %d", id, jobID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("unblock did not reschedule the dropped deployment retry")
		}
	})
}

// 规则屏障判定与暂停判定同源（deploymentRetrySchedulable）：包级调度入口
// 对屏障中的规则必须返回可识别的错误而非静默丢弃。
func TestScheduleCertificateDeploymentRetry_reportsBarrier(t *testing.T) {
	_, ruleID := seedRescanJob(t)
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.deploymentRetry = func(int, issuedCertificate, time.Duration) error { return nil }
	oldManager := caQueueManager
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	caQueueManager = manager
	t.Cleanup(func() { caQueueManager = oldManager })
	blocked := manager.BlockJobsForRule(ruleID)
	t.Cleanup(func() { manager.UnblockJobsForRule(ruleID, blocked) })

	err := scheduleCertificateDeploymentRetry(1, issuedCertificate{ruleID: ruleID}, 0)
	if err == nil || err != ErrCertificateDeploymentRetryBlocked {
		t.Fatalf("schedule error=%v, want ErrCertificateDeploymentRetryBlocked", err)
	}
}
