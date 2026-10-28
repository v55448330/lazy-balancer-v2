package services

//
// 交错可对旧域发起 CA 签发或留下孤儿任务行。upsertQueuedCertJob 必须经过
// lb_rules 当前态 EXISTS 守卫（对照 Retry 路径 handlers/certjobs.go 同口径）。
//
// 假成功摘要。查询失败必须写「扫描失败」行并终止本轮；逐行 Scan 失败计数
// 并入摘要（fail-visible）。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 目标形状①：规则已删除（无 lb_rules 行）——不得创建孤儿任务行。
func TestUpsertQueuedCertJob_guardRejectsWhenRuleMissing(t *testing.T) {
	_, database := newClusterTestService(t)

	_, _, err := upsertQueuedCertJob("lb_a86_gone", []string{"gone.example.test"}, 0)
	if !errors.Is(err, ErrCertRuleStateConflict) {
		t.Fatalf("err=%v, want ErrCertRuleStateConflict（409 冲突语义）", err)
	}
	var n int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_a86_gone'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("规则不存在仍创建了 %d 行孤儿任务", n)
	}
}

// 目标形状②：规则域名已变更（改域迁移后旧域冲突行仍在）——不得按旧域复活/重排。
func TestUpsertQueuedCertJob_guardRejectsStaleDomain(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_a86_moved','moved','http','new.example.test',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_a86_moved','old.example.test','failed')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, _, err := upsertQueuedCertJob("lb_a86_moved", []string{"old.example.test"}, 0); !errors.Is(err, ErrCertRuleStateConflict) {
		t.Fatalf("err=%v, want ErrCertRuleStateConflict（旧域重排必须按冲突拒绝）", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_a86_moved' AND domain='old.example.test'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("旧域任务行被改写为 %q——改域守卫缺失", status)
	}
}

// 目标形状③：规则已禁用——不得复活任务行。
func TestUpsertQueuedCertJob_guardRejectsDisabledRule(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_a86_off','off','http','off.example.test',8443,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_a86_off','off.example.test','failed')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, _, err := upsertQueuedCertJob("lb_a86_off", []string{"off.example.test"}, 0); !errors.Is(err, ErrCertRuleStateConflict) {
		t.Fatalf("err=%v, want ErrCertRuleStateConflict（禁用规则不得复活任务行）", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_a86_off'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("禁用规则任务行被改写为 %q", status)
	}
}

// 回归形状：启用 ACME 规则、域名匹配——upsert 照常建行（不受守卫误伤）。
func TestUpsertQueuedCertJob_guardAllowsCurrentACMERule(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_a86_ok','ok','http','ok.example.test',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	id, changed, err := upsertQueuedCertJob("lb_a86_ok", []string{"ok.example.test"}, 0)
	if err != nil || !changed || id <= 0 {
		t.Fatalf("id=%d changed=%v err=%v, want 正常建行", id, changed, err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued", status)
	}
}

// 目标形状（查询级）：cert_jobs 缺失时 CheckExpiration 与 checkFailedFirstIssuance
// 都必须返回非 nil error（不得 nil 伪装无候选）。
func TestRenewalScan_queriesReturnErrorOnBrokenSchema(t *testing.T) {
	newClusterTestService(t)
	if _, err := db.DB.Exec("DROP TABLE cert_jobs"); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	s := &CertificateService{}
	if _, _, err := s.CheckExpiration(); err == nil {
		t.Fatal("CheckExpiration 在 cert_jobs 缺失时返回 nil error（吞错）")
	}
	if _, _, err := s.checkFailedFirstIssuance(3); err == nil {
		t.Fatal("checkFailedFirstIssuance 在 cert_jobs 缺失时返回 nil error（吞错）")
	}
}

// 目标形状（行级）：不可转换的 renewal_attempts 畸形行计入 scanSkipped，
// 不产生候选、不产生 error（查询本身成功）。
func TestRenewalScan_rowScanFailuresReturnSkippedCount(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_a86_scan2','scan2','http','scan2.example.test',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts)
			VALUES ('lb_a86_scan2','scan2.example.test','issued',datetime('now','+1 day'),'abc')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := &CertificateService{}
	jobs, skipped, err := s.CheckExpiration()
	if err != nil {
		t.Fatalf("CheckExpiration err=%v（逐行畸形不应升级为查询错误）", err)
	}
	if len(jobs) != 0 || skipped != 1 {
		t.Fatalf("jobs=%d skipped=%d, want 0 候选 + 1 行扫描失败", len(jobs), skipped)
	}
}

// 查询级失败（cert_jobs 缺失的畸形库形态——备份损坏/带外干预的真实 SQLite
// 错误）→ 摘要行必须如实写「扫描失败」，不得伪装「无临期证书」假成功。
func TestRenewExpiringCertificates_queryFailureWritesFailureSummary(t *testing.T) {
	newTaskLogDir(t)
	newClusterTestService(t)
	if _, err := db.DB.Exec("DROP TABLE cert_jobs"); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	s := &CertificateService{}
	s.renewExpiringCertificates(context.Background())

	log := readTaskLog(t, "cert-renewal-scan")
	if strings.Contains(log, "无临期证书") {
		t.Fatalf("候选查询失败仍写「无临期证书」假成功摘要: %q", log)
	}
	if !strings.Contains(log, "扫描失败") {
		t.Fatalf("查询失败未写「扫描失败」摘要行: %q", log)
	}
}

// 逐行 Scan 失败（renewal_attempts 被带外直写为不可转换文本——非 STRICT 表
// 的真实畸形形态）→ 失败行跳过且计数并入摘要「N 行扫描失败已跳过」。
func TestRenewExpiringCertificates_rowScanFailuresCountedInSummary(t *testing.T) {
	newTaskLogDir(t)
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_a86_scan','scan','http','scan.example.test',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts)
			VALUES ('lb_a86_scan','scan.example.test','issued',datetime('now','+1 day'),'abc')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := &CertificateService{}
	s.renewExpiringCertificates(context.Background())

	log := readTaskLog(t, "cert-renewal-scan")
	if !strings.Contains(log, "1 行扫描失败已跳过") {
		t.Fatalf("逐行扫描失败未计数入摘要: %q", log)
	}
}
