package services

// upsertQueuedCertJob 冲突白名单的部署生命周期段必须与 DeploymentLifecycleJobStatusSQL
// 单源同集（含 cleanup_*）：崩溃滞留在 DNS 清理窗口的行仍属「材料已落库」的部署
// 生命周期，规则写补偿必须能把它重排——漏收时 changed=false 且任务不在途，上游
// CreateOrRequeueCertJobVerified 归因成裸错，规则写折成 500 + 回滚。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedUpsertLifecycleJob(t *testing.T, status string) (int, string, string) {
	t.Helper()
	_, database := newClusterTestService(t)
	const ruleID = "lb_upsert_lifecycle"
	const domain = "lifecycle.example.test"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'upsert-lifecycle', 'http', ?, 8443, 1, 1, 'acme_dns')`, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem)
		VALUES (?,?,?,'cert','key')`, ruleID, domain, status)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return int(id), ruleID, domain
}

// 目标形状：部署生命周期全集（派生单源，含 cleanup_dns/cleanup_warning）逐状态
// 都必须可重排——白名单漏收任一状态即红。
func TestUpsertQueuedCertJob_requeuesDeploymentLifecycleRows(t *testing.T) {
	for _, status := range deploymentLifecycleJobStatuses {
		t.Run(status, func(t *testing.T) {
			id, ruleID, domain := seedUpsertLifecycleJob(t, status)

			gotID, changed, err := upsertQueuedCertJob(ruleID, []string{domain}, 0)
			if err != nil || !changed || gotID != id {
				t.Fatalf("id=%d changed=%v err=%v, want 重排既有行 %d（状态 %s 属部署生命周期）", gotID, changed, err, id, status)
			}
			var got string
			if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&got); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if got != "queued" {
				t.Fatalf("status=%q, want queued", got)
			}
		})
	}
}

// 回归形状（基线钉测）：排队中/执行态不在白名单——changed=false 让上游归因
// 在途/冷却，不得把正在执行的签发打回 queued。
func TestUpsertQueuedCertJob_keepsNonRequeueableRows(t *testing.T) {
	for _, status := range []string{"queued", "processing", "creating_order"} {
		t.Run(status, func(t *testing.T) {
			id, ruleID, domain := seedUpsertLifecycleJob(t, status)

			gotID, changed, err := upsertQueuedCertJob(ruleID, []string{domain}, 0)
			if err != nil || changed || gotID != id {
				t.Fatalf("id=%d changed=%v err=%v, want changed=false（%s 不可重排）", gotID, changed, err, status)
			}
			var got string
			if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&got); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if got != status {
				t.Fatalf("status=%q, want 保持 %q", got, status)
			}
		})
	}
}
