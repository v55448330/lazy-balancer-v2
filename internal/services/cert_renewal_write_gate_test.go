package services

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 续期扫描的「写前门」必须早于**任何**写点：已达重试上限的 waiting_ca 任务在
// 旧实现里先走 waiting_ca → failed 终态迁移 + 审计行，逐任务角色复核只覆盖其后的
// 「入队」分支。降级（换主/导入排空/停机）落在最长 6h 的扫描窗口内时，新从节点
// 仍会写本地状态与审计行，破坏「从节点零写」不变式。
func TestCertRenewalScan_cappedJobRespectsDemoteBeforeWrite(t *testing.T) {
	// Given：一条已达上限的 waiting_ca 临期任务
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	ruleID := "lb_renewal_gate_capped"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id)
		VALUES (?,?, 'waiting_ca', datetime('now','+1 day'),?,1)`, ruleID, ruleID+".example.com", maxAttempts); err != nil {
		t.Fatalf("seed capped waiting_ca job: %v", err)
	}
	// 扫描开始前仍为主节点（入口角色检查通过），逐任务写前门处才降级。
	oldHook := certRenewalRoleRecheckHook
	certRenewalRoleRecheckHook = func() {
		if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
			t.Errorf("demote: %v", err)
		}
	}
	t.Cleanup(func() { certRenewalRoleRecheckHook = oldHook })

	// When
	resetCertificateServiceForTest(t)
	err := NewCertificateService().renewExpiringCertificates(context.Background())

	// Then：降级中止轮落 skipped 终态，且**零写**——状态不变、无审计行。
	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（降级中止轮不得落 success）", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "waiting_ca" {
		t.Fatalf("status=%q, want waiting_ca（写前门必须早于上限终态迁移）", status)
	}
	if got := countCertJobMaxAttemptsAuditRows(t); got != 0 {
		t.Fatalf("审计行=%d, want 0（从节点不得写审计）", got)
	}
}

// 回归形状：主节点健康轮里同一行仍照常收敛为 failed 并留一条审计行——
// 写前门只拦降级/取消，不得把正常终态迁移也挡掉。
func TestCertRenewalScan_cappedJobStillFailsOnHealthyMaster(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	ruleID := "lb_renewal_gate_healthy"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id)
		VALUES (?,?, 'waiting_ca', datetime('now','+1 day'),?,1)`, ruleID, ruleID+".example.com", maxAttempts); err != nil {
		t.Fatalf("seed capped waiting_ca job: %v", err)
	}

	resetCertificateServiceForTest(t)
	if err := NewCertificateService().renewExpiringCertificates(context.Background()); err != nil {
		t.Fatalf("健康主节点轮不得失败: %v", err)
	}

	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（上限终态迁移在健康主节点必须照常执行）", status)
	}
	if got := countCertJobMaxAttemptsAuditRows(t); got != 1 {
		t.Fatalf("审计行=%d, want 1（上限终态迁移必须留审计）", got)
	}
}

// 取消形状：ctx 已取消时写前门必须中止本轮（导入排空的 WaitInFlightRuns 依赖
// 续期扫描消费 ctx），且任务状态不被改写。
func TestCertRenewalScan_canceledContextStopsBeforeWrite(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	ruleID := "lb_renewal_gate_cancel"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id)
		VALUES (?,?, 'waiting_ca', datetime('now','+1 day'),?,1)`, ruleID, ruleID+".example.com", maxAttempts); err != nil {
		t.Fatalf("seed capped waiting_ca job: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resetCertificateServiceForTest(t)
	err := NewCertificateService().renewExpiringCertificates(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want 取消错误（写前门必须消费 ctx）", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "waiting_ca" {
		t.Fatalf("status=%q, want waiting_ca（取消轮不得写）", status)
	}
	if got := countCertJobMaxAttemptsAuditRows(t); got != 0 {
		t.Fatalf("审计行=%d, want 0（取消轮不得写审计）", got)
	}
}

// countCertJobMaxAttemptsAuditRows 统计续期上限终态迁移写入的操作审计行。
func countCertJobMaxAttemptsAuditRows(t *testing.T) int {
	t.Helper()
	if db.AuditDB == nil {
		return 0
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='签发失败'`).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}
