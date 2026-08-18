package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// R31 M4：Resume 直接调用时不得把正在执行的 'creating_%' 任务置回 'queued'——
// 否则执行结束后的状态转换失败会把合法签发误标 failed。
func TestCAQueueManager_Resume_skips_jobs_active_in_queue(t *testing.T) {
	// Given：任务正在队列中执行（q.active 含该任务，DB 状态 creating_order）
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_inflight','inflight','example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'inflight CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (42,'lb_inflight','example.com','creating_order',7)`); err != nil {
		t.Fatal(err)
	}
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_inflight", domains: "example.com"})
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	// When：队列活跃时直接 Resume
	manager.Resume()

	// Then：在途任务 DB 状态保持 creating_order，未被重入队置回 'queued'
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=42").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "creating_order" {
		t.Fatalf("inflight job status=%q, want creating_order (must not be requeued)", status)
	}
	queue.stop()
}

// R31 M5：规则阻塞期间被丢弃的 'downloaded' 部署重试（窗口已过），在解锁
// 最后一个阻塞令牌后必须补扫重新调度，否则滞停到下次 Resume/Start。
func TestCAQueueManager_UnblockJobsForRule_rescansDroppedDeploymentRetries(t *testing.T) {
	// Given：'downloaded' 任务部署窗口已过；规则被阻塞；证书服务已注册
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_unblock','unblock','example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'unblock CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id,cert_pem,key_pem,deployment_available_after) VALUES (42,'lb_unblock','example.com','downloaded',7,'cert','key',datetime('now','-1 hour'))`); err != nil {
		t.Fatal(err)
	}
	service := NewCertificateService()
	retried := make(chan int, 1)
	service.deploymentRetry = func(jobID int, _ issuedCertificate, _ time.Duration) {
		retried <- jobID
	}
	t.Cleanup(func() {
		certificateServiceMu.Lock()
		certificateService = nil
		certificateServiceMu.Unlock()
	})
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	blocked := manager.BlockJobsForRule("lb_unblock")

	// When：解锁最后一个阻塞令牌
	manager.UnblockJobsForRule("lb_unblock", blocked)

	// Then：补扫把滞停的部署重试重新调度
	select {
	case jobID := <-retried:
		if jobID != 42 {
			t.Fatalf("rescanned job=%d, want 42", jobID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deployment retry was not rescanned after rule unblock")
	}
}
