package services

// 部署补扫的 cleanup_* 分支必须与材料丢失重排同口径持在途守卫
//（requeueLostMaterialCertJob 的 qm.IsJobActive）：续签把行推进到
// downloaded/cleanup_*（新材料已落库）后，签发执行仍在途做 DNS 清理——补扫
// 抢先部署旧库材料会把行提交成 issued，worker 的部署确认对 issued 拒绝
//（from 集不含 issued），新材料静默丢弃。在途窗口内补扫必须整行跳过，
// 执行退出后下一轮照常接管。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func seedCleanupRescanJob(t *testing.T, status string) (int, string) {
	t.Helper()
	_, database := newClusterTestService(t)
	const ruleID = "lb_cleanup_rescan"
	const domain = "cleanup-rescan.example.test"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'cleanup-rescan', ?, 'http', 8443, 1, 1, 'acme_dns')`, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,expires_at)
		VALUES (?,?,?,0,'old-cert','old-key',datetime('now','+60 days'))`, ruleID, domain, status)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return int(id), domain
}

func newCleanupRescanQueueManager(t *testing.T) *CAQueueManager {
	t.Helper()
	oldManager := caQueueManager
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	caQueueManager = manager
	t.Cleanup(func() { caQueueManager = oldManager })
	return manager
}

// 目标形状：cleanup_*（材料在库）行的签发执行仍在途（队列 active 登记）——
// 补扫不得抢先部署旧材料；行状态与部署定时器都必须保持不动。
func TestRescanDroppedDeploymentRetries_skipsCleanupRowsWithActiveIssuance(t *testing.T) {
	for _, status := range []string{"cleanup_dns", "cleanup_warning"} {
		t.Run(status, func(t *testing.T) {
			jobID, domain := seedCleanupRescanJob(t, status)
			manager := newCleanupRescanQueueManager(t)
			queue := newCAQueue(models.CAProvider{ID: 1, Name: "cleanup-rescan CA", Provider: ProviderLetsEncrypt}, func() error { return nil }, t.TempDir())
			queue.enqueue(queueItem{jobID: jobID, ruleID: "lb_cleanup_rescan", domains: domain})
			manager.queues[1] = queue
			t.Cleanup(queue.stop)

			service := NewCertificateService()
			resetCertificateServiceForTest(t)
			scheduled := make(chan int, 1)
			service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
				scheduled <- id
				return nil
			}

			rescheduled, err := service.rescanDroppedDeploymentRetries()
			if err != nil {
				t.Fatalf("rescan: %v", err)
			}
			if rescheduled != 0 {
				t.Fatalf("rescheduled=%d, want 0（在途签发的 cleanup 行不得被补扫抢先部署）", rescheduled)
			}
			var got string
			if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&got); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if got != status {
				t.Fatalf("status=%q, want 保持 %q（在途执行不得被抢写）", got, status)
			}
			service.timerMu.Lock()
			_, hasTimer := service.deploymentTimers[jobID]
			service.timerMu.Unlock()
			if hasTimer {
				t.Fatal("在途 cleanup 行被登记了部署 timer")
			}
			select {
			case id := <-scheduled:
				t.Fatalf("在途 cleanup 行被调度部署: job=%d", id)
			default:
			}
		})
	}
}

// 回归形状（基线钉测）：同一 cleanup 行在签发执行退出后（队列无 active 登记）
// 必须被补扫照常接管——在途守卫不得把恢复通道整体关死。
func TestRescanDroppedDeploymentRetries_picksUpCleanupRowsAfterIssuanceExit(t *testing.T) {
	jobID, _ := seedCleanupRescanJob(t, "cleanup_dns")
	newCleanupRescanQueueManager(t)

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	scheduled := make(chan int, 1)
	service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}

	rescheduled, err := service.rescanDroppedDeploymentRetries()
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if rescheduled != 1 {
		t.Fatalf("rescheduled=%d, want 1（执行退出后补扫必须接管）", rescheduled)
	}
	if got := waitDeploymentRetry(t, scheduled); got != jobID {
		t.Fatalf("scheduled job=%d, want %d", got, jobID)
	}
}
