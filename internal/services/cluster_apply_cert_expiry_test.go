package services

// 快照证书到期列（expires_at）的口径钉测：源值可解析则原样保留；源值缺失或
// 不可解析时从证书材料派生（平面 UTC，与 SQLite datetime() 消费口径同形）；
// 材料不可解析则落 NULL 且 apply 不失败。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 作用域=事务层（replaceSnapshotDB 是 replaceSnapshotTx 的裸包装，不含角色
// 复核/重载/提交后副作用），故按 cluster_test.go 的命名契约取
// TestReplaceSnapshotTx_*，不得冒充端到端 apply。
func TestReplaceSnapshotTx_certExpiresAtDerivation(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled) VALUES (9,'expiry CA','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','{}',1)`); err != nil {
		t.Fatalf("seed ca provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (12,'expiry DNS','dnspod','{}',1)`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	for _, ruleID := range []string{"lb_exp_empty", "lb_exp_keep", "lb_exp_bad"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
			VALUES (?,'expiry rule','http',? || '.example.com',443,1,'acme_dns',12,9,1)`, ruleID, ruleID); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	certPEM, keyPEM := matchingCertificatePair(t, "exp.example.com")
	notAfter, ok := CertNotAfterFromPEM(certPEM)
	if !ok {
		t.Fatalf("夹具前提不成立：生成的证书 PEM 无法解析")
	}
	wantDerived := notAfter.UTC().Format(crsTimeLayout)

	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	snapshot.Certs = []models.ClusterCertificate{
		// 源值缺失 → 从材料派生
		{RuleID: "lb_exp_empty", Domain: "lb_exp_empty.example.com", CertPEM: certPEM, KeyPEM: keyPEM, ExpiresAt: ""},
		// 源值可解析 → 原值优先（不被派生覆盖）
		{RuleID: "lb_exp_keep", Domain: "lb_exp_keep.example.com", CertPEM: certPEM, KeyPEM: keyPEM, ExpiresAt: "2099-01-02 03:04:05"},
		// 源值不可解析（带外/旧备份异常形态）+ 材料不可解析 → NULL
		{RuleID: "lb_exp_bad", Domain: "lb_exp_bad.example.com", CertPEM: "not-a-pem", KeyPEM: "not-a-key", ExpiresAt: "garbage"},
	}

	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	var derived string
	if err := database.QueryRow(`SELECT COALESCE(expires_at,'') FROM cert_jobs WHERE rule_id='lb_exp_empty'`).Scan(&derived); err != nil {
		t.Fatalf("read derived row: %v", err)
	}
	if derived != wantDerived {
		t.Fatalf("expires_at=%q，want %q（应从证书材料派生）", derived, wantDerived)
	}

	var kept string
	if err := database.QueryRow(`SELECT COALESCE(expires_at,'') FROM cert_jobs WHERE rule_id='lb_exp_keep'`).Scan(&kept); err != nil {
		t.Fatalf("read kept row: %v", err)
	}
	if kept != "2099-01-02 03:04:05" {
		t.Fatalf("expires_at=%q，want 源值原样保留", kept)
	}

	// 不可解析口径：聚合消费面以 datetime(expires_at) 为门，坏串与 NULL 等价
	// （都是「不可解析」）——派生失败时必须落 NULL 而不是落坏串。
	var badNull int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_exp_bad' AND expires_at IS NULL`).Scan(&badNull); err != nil {
		t.Fatalf("read bad row: %v", err)
	}
	if badNull != 1 {
		t.Fatalf("expires_at 未被归为 NULL（材料不可解析时应落 NULL）")
	}
}

func TestSnapshotExpiresAtUsable(t *testing.T) {
	// 消费侧口径（SQLite datetime() 可解析的落库形态）：
	for _, value := range []string{"2099-01-02 03:04:05", "2099-01-02T03:04:05Z", "2099-01-02T03:04:05+08:00"} {
		if !snapshotExpiresAtUsable(value) {
			t.Fatalf("snapshotExpiresAtUsable(%q)=false，want true", value)
		}
	}
	for _, value := range []string{"", "garbage", "not-a-date"} {
		if snapshotExpiresAtUsable(value) {
			t.Fatalf("snapshotExpiresAtUsable(%q)=true，want false", value)
		}
	}
}
