package services

import (
	"context"
	"testing"
)

// Given cert_jobs 的可空整型列（ca_provider_id / renewal_attempts /
// deployment_attempts）为 NULL 的带外行（绕过导入归一映射的旧快照）。
// When 补扫、启动恢复、续签扫描与补偿快照读取。
// Then 统一按 0 读取（COALESCE）：单行 NULL 只按「跟随默认 CA / 零重试」处理，
// 不会把整轮扫描升级为失败，也不会让该证书静默退出续签候选。
func TestCertJobNullableIntegerColumns_readAsZero(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)

	// 两条孤儿 failed+窗口到期行（无对应规则）→ 走禁用分支、不触碰 CA provider；
	// 首行三列全 NULL。整轮必须同时处置两行且不返回错误。
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id,renewal_attempts,deployment_attempts,ca_available_after,updated_at)
		VALUES (901,'lb_null_orphan','orphan-null.example','failed',NULL,NULL,NULL,datetime('now','-1 minute'),datetime('now')),
		       (902,'lb_null_orphan','orphan-sibling.example','failed',0,0,0,datetime('now','-1 minute'),datetime('now'))`); err != nil {
		t.Fatalf("seed orphan failed rows: %v", err)
	}
	// 启动恢复行：queued 孤儿，三列全 NULL。
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id,renewal_attempts,deployment_attempts,updated_at)
		VALUES (903,'lb_null_recover','recover-null.example','queued',NULL,NULL,NULL,datetime('now'))`); err != nil {
		t.Fatalf("seed recovery row: %v", err)
	}
	// 续签候选行：issued + 临期，三列全 NULL。
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,ca_provider_id,renewal_attempts,deployment_attempts,updated_at)
		VALUES (904,'lb_null_renew','renew-null.example','issued',datetime('now','+1 day'),NULL,NULL,NULL,datetime('now'))`); err != nil {
		t.Fatalf("seed renewal row: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_null_renew','null-renew','renew-null.example','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed renewal rule: %v", err)
	}

	service := NewCertificateService()
	resetCertificateServiceForTest(t)

	// When：30s 补扫（failed 行 CA 退避窗口到期）。
	if requeued, disabled, err := service.requeueWaitingCAJobs(); err != nil {
		t.Fatalf("CA 冷却补扫不得因单行 NULL 失败: %v", err)
	} else if requeued != 0 || disabled != 2 {
		t.Fatalf("requeued=%d disabled=%d, want 0/2（两行孤儿都应被处置）", requeued, disabled)
	}

	// When：启动恢复（非终态重排队）。
	if err := requeueNonTerminalCertJobs(context.Background(), nil); err != nil {
		t.Fatalf("启动恢复不得因单行 NULL 中止: %v", err)
	}

	// When：续签扫描。
	jobs, skipped, err := service.CheckExpiration(context.Background())
	if err != nil {
		t.Fatalf("续签扫描不得因单行 NULL 失败: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("scanSkipped=%d, want 0（可空列已 COALESCE，不得跳过行）", skipped)
	}
	var renewalCA, renewalAttempts int
	found := false
	for i := range jobs {
		if jobs[i].ID == 904 {
			renewalCA, renewalAttempts, found = jobs[i].CAProviderID, jobs[i].RenewalAttempts, true
		}
	}
	if !found {
		t.Fatalf("NULL 列的临期证书未进入续签候选（jobs=%d）", len(jobs))
	}
	if renewalCA != 0 || renewalAttempts != 0 {
		t.Fatalf("NULL 列应读作 0，实得 ca_provider_id=%d renewal_attempts=%d", renewalCA, renewalAttempts)
	}

	// Then：补扫与恢复确实处置了 NULL 行（status 落到 disabled），而不是整轮失败。
	for _, id := range []int{901, 902, 903} {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&status); err != nil {
			t.Fatalf("read job %d: %v", id, err)
		}
		if status != "disabled" {
			t.Fatalf("job %d status=%q, want disabled（孤儿任务应被处置）", id, status)
		}
	}

	// When：补偿快照读取（规则更新失败回滚用）。
	snapshot, err := SnapshotCertJobsForRule("lb_null_orphan")
	if err != nil {
		t.Fatalf("补偿快照不得因 NULL 列失败: %v", err)
	}
	if len(snapshot.jobs) != 2 {
		t.Fatalf("snapshot jobs=%d, want 2", len(snapshot.jobs))
	}
	for _, job := range snapshot.jobs {
		if job.caProviderID != 0 || job.renewalAttempts != 0 || job.deploymentAttempts != 0 {
			t.Fatalf("job %d 快照 NULL 列应读作 0，实得 %d/%d/%d",
				job.id, job.caProviderID, job.renewalAttempts, job.deploymentAttempts)
		}
	}
}
