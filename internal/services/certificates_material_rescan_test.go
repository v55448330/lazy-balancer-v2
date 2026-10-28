package services

// 「部署生命周期 + 证书材料未落库」行的唯一回收通道（材料丢失行重排签发）
// 此前零直接测试：rescan 的第 4 类 SQL 分支与 requeueLostMaterialCertJob 任一
// 写错（CAS 状态集、在途守卫、审计）全量测试仍绿。本文件钉住端到端形态：
// 30s 补扫选中该行 → 转 queued 重新签发 → 一条「重新签发」审计（来源=证书
// 材料丢失）。

import (
	"context"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestRescanDroppedDeploymentRetries_requeuesLostMaterialJob(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedCAProviderBounds(t, 9, 1, 1000)

	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(ResetCAQueueManagerForTest)
	qm := GetCAQueueManager()
	qm.Start()

	// 预置该 provider 的队列并置空执行体：补扫只负责把行转 queued 并交给
	// 队列，断言不需要真实签发（且不得发起网络请求）。
	q := newCAQueue(models.CAProvider{ID: 9, Name: "provider-9", Provider: "letsencrypt"}, func() error { return nil }, t.TempDir())
	q.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	go q.loop()
	qm.mu.Lock()
	qm.queues[9] = q
	qm.mu.Unlock()

	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_lost','lost','http','lost.example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// downloaded + 空 PEM + 已过沉降阈值（10 分钟）→ 第 4 类分支。
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,updated_at)
		VALUES ('lb_lost','lost.example.com','downloaded',9,datetime('now','-11 minutes'))`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	if _, err := service.rescanDroppedDeploymentRetries(); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	var status, message string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &message); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "queued" || !strings.Contains(message, "证书材料未落库") {
		t.Fatalf("job=(%q,%q), want queued/证书材料未落库", status, message)
	}

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log
		WHERE action='重新签发' AND resource='证书任务' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read requeue audit: %v（材料丢失重排必须留审计行）", err)
	}
	if !strings.Contains(detail, "lb_lost") || !strings.Contains(detail, "来源：证书材料丢失") {
		t.Fatalf("audit detail=%q, want 规则归因 + 中文来源", detail)
	}
}

// Given 队列激活、任务处于 downloaded 且证书材料未落库。
// When 启动恢复 requeueNonTerminalCertJobs。
// Then 该行转 queued 重新签发（不得被当作「只差部署」跳过而滞留）。
func TestRequeueNonTerminalCertJobs_requeuesDownloadedJobWithoutMaterial(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedCAProviderBounds(t, 10, 1, 1000)

	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(ResetCAQueueManagerForTest)
	qm := GetCAQueueManager()
	qm.Start()

	q := newCAQueue(models.CAProvider{ID: 10, Name: "provider-10", Provider: "letsencrypt"}, func() error { return nil }, t.TempDir())
	q.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	go q.loop()
	qm.mu.Lock()
	qm.queues[10] = q
	qm.mu.Unlock()

	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_recover_lost','recover','http','recover.example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_recover_lost','recover.example.com','downloaded',10)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	if err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) error {
		t.Errorf("无材料任务不得进入部署重试，job=%d", gotJobID)
		return nil
	}); err != nil {
		t.Fatalf("recover: %v", err)
	}

	var status string
	if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（无材料行必须回签发）", status)
	}
}
