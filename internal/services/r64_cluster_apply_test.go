package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// R64 A-N5：rules 开关关闭时证书轴联动跳过——本地 cert_jobs 保留、快照证书
// 不回插（证书行/文件是规则轴的派生数据；开关关闭时从节点本地 enabled=1 的
// acme_dns 规则保留，若仍清空证书轴，其 TLS 会静默永久丢失且无自愈路径）。
func TestReplaceSnapshotTx_RulesDisabledKeepsLocalCertJobs(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	// 本地：启用中的 acme_dns 规则 + 其证书行
	if _, err := database.ExecContext(ctx,
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		 VALUES ('lb_local_acme','local','http','local.test',443,1,1,'acme_dns');
		 INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_local_acme','local.test','issued','PEM-OLD','KEY-OLD')`,
	); err != nil {
		t.Fatalf("seed local rule+cert: %v", err)
	}

	// 主节点快照：无证书（对应"主节点已禁用/删除该规则"）
	snapshot := models.ClusterSnapshot{Version: 5}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	sk := &sectionSkips{disabled: map[string]bool{"rules": true}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM cert_jobs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rules disabled must keep local cert_jobs (got %d rows)——证书轴被清空会使本地 acme 规则 TLS 静默丢失", count)
	}
	var pem string
	if err := tx.QueryRowContext(ctx, "SELECT cert_pem FROM cert_jobs WHERE rule_id='lb_local_acme'").Scan(&pem); err != nil || pem != "PEM-OLD" {
		t.Fatalf("local cert row must be intact, got %q err=%v", pem, err)
	}
}

// R64 A-N5 反向锁定：rules 哈希一致（unchanged，非开关关闭）时证书轴仍全量
// 回放——clear+reinsert 是 (rule_id,domain) 唯一索引防撞设计（R50-era 注释），
// 不得被本修复误伤。
func TestReplaceSnapshotTx_RulesUnchangedStillReplaysCertJobs(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		 VALUES ('lb_acme','r','http','a.test',443,1,1,'acme_dns');
		 INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_acme','a.test','issued','PEM-OLD','KEY-OLD')`,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	snapshot := models.ClusterSnapshot{
		Version: 5,
		Rules:   []models.LbRule{{CaddyID: "lb_acme", Name: "r", Protocol: "http", Domain: "a.test", ListenPort: 443, Enabled: true, EnableTLS: true, TLSSource: "acme_dns"}},
		Certs:   []models.ClusterCertificate{{RuleID: "lb_acme", Domain: "a.test", CertPEM: "PEM-NEW", KeyPEM: "KEY-NEW"}},
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// rules unchanged（哈希跳过）——证书轴必须仍全量替换（防撞回放）
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{"rules": true}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var pem string
	if err := tx.QueryRowContext(ctx, "SELECT cert_pem FROM cert_jobs WHERE rule_id='lb_acme'").Scan(&pem); err != nil {
		t.Fatal(err)
	}
	if pem != "PEM-NEW" {
		t.Fatalf("hash-unchanged must still replay cert axis (collision-avoidance), got %q", pem)
	}
}
