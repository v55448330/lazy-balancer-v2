package services

// 证书两处 P3 钉测：
//   - 手动证书巡检摘要不得在「已去重 + 有解析失败」轮写出与事实相反的
//     「无过期无临期」；
//   - 「部署生命周期 + 无材料」行必须由周期补扫回收（转 queued 重签），
//     否则该行没有任何通道，规则在重启前整条不发布。

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// Given 一张已过期的手动证书（当日已告警 → 去重门关闭）与一张 PEM 损坏的手动证书。
// When 手动证书巡检。
// Then 任务日志不得声称「无过期无临期」。
func TestRunManualCertExpiryCheck_doesNotClaimCleanWhenAbnormal(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	expiredPEM, _ := expiredShapeCertAndKey(t, "manual-expired.test", time.Now().Add(-24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_manual_expired','manual-expired','manual-expired.test','http',8081,1,1,'manual',?)`, expiredPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_manual_broken','manual-broken','manual-broken.test','http',8082,1,1,'manual','not-a-pem')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=30 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	gate := newManualCertExpiryAlertGate()
	// 预置「已过期档当日已告警」：下一轮 alerted=false 但统计仍 >0。
	if !gate.shouldAlert("lb_manual_expired", manualCertExpiryLevelExpired, time.Now()) {
		t.Fatalf("夹具前提不成立：首次告警门应放行")
	}

	if err := runManualCertExpiryCheck(context.Background(), gate); err != nil {
		t.Fatalf("manual check: %v", err)
	}

	// 该轮（异常但已去重、无新增告警）按去重门保持静默——日志文件可能不存在。
	logContent := readTaskLogIfExists(t, "cert-manual-poll")
	if strings.Contains(logContent, "无过期无临期") {
		t.Fatalf("异常轮写出与事实相反的摘要:\n%s", logContent)
	}
}

// readTaskLogIfExists 读任务日志，不存在按空串（去重静默轮无日志文件）。
func readTaskLogIfExists(t *testing.T, taskID string) string {
	t.Helper()
	data, err := os.ReadFile(taskengine.TaskLogPath(taskID))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read task log: %v", err)
	}
	return string(data)
}

// 反向：无异常 + 一行解析失败 → 仍应输出「无过期无临期」+ 跳过提示。
func TestRunManualCertExpiryCheck_cleanRoundStillReports(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_manual_broken2','manual-broken2','manual-broken2.test','http',8083,1,1,'manual','not-a-pem')`); err != nil {
		t.Fatal(err)
	}
	if err := runManualCertExpiryCheck(context.Background(), newManualCertExpiryAlertGate()); err != nil {
		t.Fatalf("manual check: %v", err)
	}
	logContent := readTaskLog(t, "cert-manual-poll")
	if !strings.Contains(logContent, "无过期无临期") || !strings.Contains(logContent, "解析失败") {
		t.Fatalf("纯解析失败轮必须留如实摘要:\n%s", logContent)
	}
}

// Given 一条「cleanup_dns + 无材料 + 已过沉降阈值」的任务（ACME 下载完成后
// 进程退出的形态）。
// When 周期补扫。
// Then 行转回 queued 并落业务摘要与审计（不再被无材料守卫静默跳过）。
func TestRescanRequeuesDeploymentLifecycleWithoutMaterial(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	const ruleID = "lb_lost_material"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'lost-material', 'lost.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'lost CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,updated_at)
		VALUES (?, 'lost.example.com', 'cleanup_dns', 7, '', '', datetime('now','-15 minutes'))`, ruleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	// 队列管理器就绪（生产由 InitCAQueueManager 注入）。预置队列但**不启动
	// loop**：本用例断言的是补扫的同步部分（行转 queued + 日志 + 审计）；若
	// 由 loop 异步派发，真实签发执行会在断言前改写状态（creating_account/
	// failed），断言退化为 goroutine 调度竞态（全量运行偶发 "want queued"）。
	oldManager := caQueueManager
	qm := &CAQueueManager{queues: make(map[int]*caQueue), active: true, blockedRules: map[string]map[RuleBlockToken]struct{}{}}
	qm.queues[7] = newCAQueue(models.CAProvider{ID: 7, Name: "lost CA", Provider: "letsencrypt"}, func() error { return nil }, t.TempDir())
	caQueueManager = qm
	t.Cleanup(func() {
		caQueueManager = oldManager
		qm.queues[7].stop()
	})

	service := NewCertificateService()
	resetCertificateServiceForTest(t)

	// When
	if _, err := service.rescanDroppedDeploymentRetries(); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	// Then：转 queued 重签
	var status string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("job status=%q，want queued（部署生命周期+无材料应重新排队签发）", status)
	}
	if logContent := readTaskLog(t, "cert-waiting-ca"); !strings.Contains(logContent, "缺证书材料") {
		t.Fatalf("补扫必须落业务摘要:\n%s", logContent)
	}
	if action, detail := lastAuditRow(t, "证书任务"); action != "重新签发" || !strings.Contains(detail, "证书材料丢失") {
		t.Fatalf("审计=%q/%q，want 重新签发/含证书材料丢失", action, detail)
	}
}

// 反向：沉降窗口内的无材料行不得被提前重排（避免与主部署路径抢同一任务）。
func TestRescanSkipsYoungLostMaterialJob(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	const ruleID = "lb_lost_fresh"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'lost-fresh', 'fresh.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'lost CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,updated_at)
		VALUES (?, 'fresh.example.com', 'downloaded', 7, '', '', datetime('now','-1 minute'))`, ruleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	oldManager := caQueueManager
	caQueueManager = &CAQueueManager{queues: make(map[int]*caQueue), active: true, blockedRules: map[string]map[RuleBlockToken]struct{}{}}
	t.Cleanup(func() { caQueueManager = oldManager })
	service := NewCertificateService()
	resetCertificateServiceForTest(t)

	if _, err := service.rescanDroppedDeploymentRetries(); err != nil {
		t.Fatalf("rescan: %v", err)
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("沉降窗口内 job status=%q，want 保持 downloaded", status)
	}
}
