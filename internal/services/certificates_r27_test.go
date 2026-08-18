package services

import (
	"context"
	"testing"
)

func TestSweepOrphanedCertJobs_disables_unreferenced_non_terminal_jobs(t *testing.T) {
	// Given：
	// - 规则 lb_sweep_ok 仍引用其 queued 任务（域名一致）→ 保留
	// - 规则 lb_sweep_migrated 已迁移域名，旧域名 queued 任务 → 禁用
	// - 任务所属规则 lb_sweep_gone 已删除 → 禁用
	// - 旧域名的 issued 任务为终态 → 不动（与启动恢复口径一致）
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_sweep_ok','sweep-ok','sweep.example.test','http',8443,1,1,'acme_dns'),
		('lb_sweep_migrated','sweep-migrated','new.example.test','http',8444,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES
		('lb_sweep_ok','sweep.example.test','queued',1),
		('lb_sweep_migrated','old.example.test','queued',1),
		('lb_sweep_gone','old.example.test','queued',1),
		('lb_sweep_migrated','old2.example.test','issued',1)
	`); err != nil {
		t.Fatalf("seed rules and jobs: %v", err)
	}

	// When
	sweepOrphanedCertJobs(context.Background())

	// Then
	var okCount, migratedCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_sweep_ok' AND status='queued'").Scan(&okCount); err != nil {
		t.Fatalf("count referenced jobs: %v", err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_sweep_migrated' AND domain='old.example.test' AND status='disabled'").Scan(&migratedCount); err != nil {
		t.Fatalf("count migrated disabled jobs: %v", err)
	}
	if okCount != 1 {
		t.Fatalf("referenced queued jobs=%d, want 1（引用中的任务不得被禁用）", okCount)
	}
	if migratedCount != 1 {
		t.Fatalf("migrated disabled jobs=%d, want 1（域名迁移后的遗留任务应被禁用）", migratedCount)
	}
	var goneStatus string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_sweep_gone'").Scan(&goneStatus); err != nil {
		t.Fatalf("read gone-rule job: %v", err)
	}
	if goneStatus != "disabled" {
		t.Fatalf("gone-rule job status=%q, want disabled", goneStatus)
	}
	var issuedStatus string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_sweep_migrated' AND domain='old2.example.test'").Scan(&issuedStatus); err != nil {
		t.Fatalf("read terminal orphan job: %v", err)
	}
	if issuedStatus != "issued" {
		t.Fatalf("terminal orphan status=%q, want issued（终态任务不动）", issuedStatus)
	}
}

func TestSweepOrphanedCertJobs_leaves_rule_disabled_jobs_alone(t *testing.T) {
	// Given：规则被停用（enabled=0），其非终态任务不再适用，应被巡检禁用
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_sweep_off','sweep-off','off.example.test','http',8445,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_sweep_off','off.example.test','queued',1)
	`); err != nil {
		t.Fatalf("seed disabled rule job: %v", err)
	}

	// When
	sweepOrphanedCertJobs(context.Background())

	// Then
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_sweep_off'").Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "disabled" {
		t.Fatalf("job status=%q, want disabled", status)
	}
}
