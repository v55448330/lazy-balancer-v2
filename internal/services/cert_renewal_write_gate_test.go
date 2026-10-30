package services

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 续期扫描的「写前门」必须早于**任何**写点。B2 失败语义统一后 waiting_ca→
// failed 上限终态迁移退役（失败统一落 failed），续期扫描对候选行的唯一写点=
// 入队迁移（failed→queued）+「续签排队」审计行。降级（换主/导入排空/停机）落在
// 最长 6h 的扫描窗口内时，新从节点仍会写本地状态与审计行，破坏「从节点零写」
// 不变式——写前门必须在**任何**写点前拦下。
func TestCertRenewalScan_enqueueRespectsDemoteBeforeWrite(t *testing.T) {
	// Given：一条退避窗口已到期的临期失败行（候选，写入点=入队迁移）
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
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_available_after,ca_provider_id)
		VALUES (?,?,'failed',datetime('now','+1 day'),0,datetime('now','-1 minute'),1)`, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed due failed job: %v", err)
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
	if status != "failed" {
		t.Fatalf("status=%q, want failed（写前门必须早于入队迁移）", status)
	}
	if got := countCertJobRenewalAuditRows(t); got != 0 {
		t.Fatalf("审计行=%d, want 0（从节点不得写审计）", got)
	}
}

// 回归形状：主节点健康轮里同一行仍照常入队并留一条「续签排队」审计行——
// 写前门只拦降级/取消，不得把正常入队写点也挡掉。
func TestCertRenewalScan_dueJobStillEnqueuesOnHealthyMaster(t *testing.T) {
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
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_available_after,ca_provider_id)
		VALUES (?,?,'failed',datetime('now','+1 day'),0,datetime('now','-1 minute'),1)`, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed due failed job: %v", err)
	}

	resetCertificateServiceForTest(t)
	if err := NewCertificateService().renewExpiringCertificates(context.Background()); err != nil {
		t.Fatalf("健康主节点轮不得失败: %v", err)
	}

	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（到期窗口行在健康主节点必须照常入队）", status)
	}
	if got := countCertJobRenewalAuditRows(t); got != 1 {
		t.Fatalf("审计行=%d, want 1（入队迁移必须留「续签排队」审计）", got)
	}
}

// 取消形状：ctx 已取消时写前门必须中止本轮（导入排空的 WaitInFlightRuns 依赖
// 续期扫描消费 ctx），且任务状态不被改写。
func TestCertRenewalScan_canceledContextStopsBeforeEnqueue(t *testing.T) {
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
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_available_after,ca_provider_id)
		VALUES (?,?,'failed',datetime('now','+1 day'),0,datetime('now','-1 minute'),1)`, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed due failed job: %v", err)
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
	if status != "failed" {
		t.Fatalf("status=%q, want failed（取消轮不得写）", status)
	}
	if got := countCertJobRenewalAuditRows(t); got != 0 {
		t.Fatalf("审计行=%d, want 0（取消轮不得写审计）", got)
	}
}

// countCertJobRenewalAuditRows 统计续期扫描入队迁移写入的「续签排队」审计行。
func countCertJobRenewalAuditRows(t *testing.T) int {
	t.Helper()
	if db.AuditDB == nil {
		return 0
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='续签排队'`).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// 候选装载阶段必须可取消：ctx 由引擎 RunContext 透传（配置导入/还原的
// PauseScheduling → CancelInFlightRuns → WaitInFlightRuns 只有在扫描的**每个**
// 阶段消费 ctx 时才不会被最长 6h 的候选装载推迟）。此前 ctx 只作用于写循环，
// 装载阶段对取消完全无感：导入排空要等整轮 SQL 扫描 + 逐规则证书选择跑完才
// 能返回。本用例在候选装载的中途取消，断言装载立即停止（第二行不再请求证书
// 选择）且一行都未入队。
func TestCertRenewalScan_canceledDuringCandidateLoadStopsScan(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	// 两条临期任务：第一条的证书选择回调里取消 ctx（导入排空/停机落在装载窗口）。
	for _, ruleID := range []string{"lb_cancel_load_a", "lb_cancel_load_b"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_provider_id)
			VALUES (?,?, 'issued', datetime('now','+1 day'),1)`, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed job %s: %v", ruleID, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	original := selectStoredRuleCertificate
	t.Cleanup(func() { selectStoredRuleCertificate = original })
	var selectionCalls int32
	selectStoredRuleCertificate = func(context.Context, string, string, time.Time) (CertificateSelection, bool, error) {
		atomic.AddInt32(&selectionCalls, 1)
		cancel() // 装载第一行时被取消
		return CertificateSelection{}, false, nil
	}

	// When
	resetCertificateServiceForTest(t)
	err := NewCertificateService().renewExpiringCertificates(ctx)

	// Then：取消错误上抛，装载在取消后立即停止（第二行不再选择），零入队。
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want 取消错误（候选装载阶段必须消费 ctx）", err)
	}
	if got := atomic.LoadInt32(&selectionCalls); got != 1 {
		t.Fatalf("证书选择调用 %d 次, want 1（取消后装载必须早退，不得扫完整个候选集）", got)
	}
	rows, err := database.Query("SELECT status FROM cert_jobs WHERE rule_id LIKE 'lb_cancel_load_%'")
	if err != nil {
		t.Fatalf("read job statuses: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			t.Fatalf("scan status: %v", err)
		}
		if status != "issued" {
			t.Fatalf("status=%q, want issued（取消轮不得入队/写库）", status)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate statuses: %v", err)
	}
}
