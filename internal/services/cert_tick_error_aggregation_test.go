package services

import (
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 30s 补扫（cert-waiting-ca）的逐条动作失败必须进入失败轮：真实 DB/入队故障下
// 只写应用日志会让本轮照常「补扫完成」，任务监控看不到仍有证书工作没有恢复
// （补建/滞留/续期三条路径已聚合错误，补扫两条逐条路径当时漏收口）。
func TestRescanDroppedDeploymentRetries_reportsDeploymentRetryFailure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_rescan_fail','rescan','http','rescan-fail.example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs
		(rule_id,domain,status,cert_pem,key_pem,deployment_available_after,updated_at)
		VALUES ('lb_rescan_fail','rescan-fail.example.com','downloaded','cert','key',datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed job: %v", err)
	}

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.deploymentRetry = func(int, issuedCertificate, time.Duration) error {
		return errors.New("database is locked")
	}

	if _, err := service.rescanDroppedDeploymentRetries(); err == nil {
		t.Fatalf("部署重试登记失败必须进入失败轮（否则监控假健康）")
	}
}

// 材料丢失行重排的入队失败同属逐条动作失败：CAS 已把行转 queued 但入队失败时，
// 该行不在任何队列里——只记 warn 会让本轮显示成功。
func TestRescanDroppedDeploymentRetries_reportsLostMaterialRequeueFailure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	// 队列激活但没有任何可用 CA provider：enqueueLocked 必然失败。
	if _, err := db.DB.Exec(`UPDATE ca_providers SET enabled=0`); err != nil {
		t.Fatalf("disable providers: %v", err)
	}
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(ResetCAQueueManagerForTest)
	GetCAQueueManager().Start()

	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_lost_fail','lost','http','lost-fail.example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
		VALUES ('lb_lost_fail','lost-fail.example.com','downloaded',datetime('now','-11 minutes'))`); err != nil {
		t.Fatalf("seed job: %v", err)
	}

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	if _, err := service.rescanDroppedDeploymentRetries(); err == nil {
		t.Fatalf("材料丢失行入队失败必须进入失败轮")
	}
}

// 回归形状：暂停/规则屏障期不登记不算失败（不得把有意暂停报成故障）。
func TestRescanDroppedDeploymentRetries_pausedIsNotFailure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.timerMu.Lock()
	service.timersPaused = true
	service.timerMu.Unlock()
	if _, err := service.rescanDroppedDeploymentRetries(); err != nil {
		t.Fatalf("暂停期补扫必须返回 nil: %v", err)
	}
}

// 证书文件对账的单行重建失败必须进入失败轮：容器重建/卷清理后文件缺失，写盘
// 失败（只读/磁盘满/坏 PEM）只记 error 日志时任务日志仍写「对账完成 0」，Caddy
// 下次重载仍缺文件。健康行照常重建，失败行聚合上抛。
func TestReconcileMissingCertFiles_reportsPerRowMaterializeFailure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	t.Cleanup(SetCertDirForTest(t.TempDir()))
	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_reconcile_ok','ok','http','ok.example.com',8443,1,1,'acme_dns'),
		       ('lb_reconcile_bad','bad','http','bad.example.com',8444,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	now := time.Now().UTC()
	okPEM, okKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(720*time.Hour), "ok.example.com")
	// 坏行：证书与私钥不成对——materializeCertPair 的配对校验必然失败（与磁盘
	// 只读/坏 PEM 同一失败面）。
	badPEM, _ := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(720*time.Hour), "bad.example.com")
	_, otherKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(720*time.Hour), "other.example.com")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at) VALUES
		('lb_reconcile_ok','ok.example.com','downloaded',?,?,datetime('now')),
		('lb_reconcile_bad','bad.example.com','downloaded',?,?,datetime('now'))`,
		okPEM, okKey, badPEM, otherKey); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}

	rebuilt, err := reconcileMissingCertFiles(t.Context(), db.DB)
	if err == nil {
		t.Fatalf("单行重建失败必须上抛（否则对账谎报完成）")
	}
	if rebuilt != 1 {
		t.Fatalf("健康行重建数=%d, want 1（失败行不得阻断其余行收敛）", rebuilt)
	}
}
