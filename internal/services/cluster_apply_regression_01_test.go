package services

import (
	"context"
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// rules 开关关闭时证书轴联动跳过——本地 cert_jobs 保留、快照证书
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

// 集群回写必须落规范域名：主节点行可能来自旧备份/带外改库（大写/空白/顺序
// 变体），从端原样回写后，按规范串精确匹配的消费面（任务 upsert 冲突键与回查、
// HasCertJob、签发冷却查询）在规则域变更后无法命中，同域集会并存两行。
func TestReplaceSnapshotTx_canonicalizesCertJobDomain(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	snapshot := models.ClusterSnapshot{
		Version: 5,
		Rules: []models.LbRule{{CaddyID: "lb_acme", Name: "r", Protocol: "http",
			Domain: "bak-acme.example.test,www.bak-acme.example.test", ListenPort: 443,
			Enabled: true, EnableTLS: true, TLSSource: "acme_dns"}},
		Certs: []models.ClusterCertificate{{RuleID: "lb_acme",
			Domain: " WWW.Bak-Acme.Example.Test , bak-acme.example.test ", CertPEM: "PEM-NEW", KeyPEM: "KEY-NEW"}},
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var domain string
	if err := tx.QueryRowContext(ctx, "SELECT domain FROM cert_jobs WHERE rule_id='lb_acme'").Scan(&domain); err != nil {
		t.Fatal(err)
	}
	if want := "bak-acme.example.test,www.bak-acme.example.test"; domain != want {
		t.Fatalf("cert_jobs.domain=%q, want %q（集群回写必须落规范串）", domain, want)
	}
}

// 反向锁定：rules 哈希一致（unchanged，非开关关闭）时证书轴仍全量
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

// 安全防护绑定与规则轴同门：rules 开关关闭时从节点保留本地规则（含本地绑定），
// 若安全节仍按主节点快照全量替换绑定表，本地规则的绑定会被清空并替换成指向
// 主端规则 id 的悬挂行——渲染侧 policiesForRule 无命中 = 全部 WAF 防护静默
// 消失（fail-open），而从节点只读无法重建绑定，除重新升主外无恢复路径。
func TestReplaceSnapshotTx_RulesDisabledKeepsLocalBindings(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	// 本地：规则 + 策略 + 绑定（关闭规则同步正是为了保住这套本地配置）
	if _, err := database.ExecContext(ctx,
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		 VALUES ('lb_local_waf','local','http','local.test',80,1);
		 INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'shared','blocking',1);
		 INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_local_waf',5)`,
	); err != nil {
		t.Fatalf("seed local rule+policy+binding: %v", err)
	}

	// 主节点快照：安全节启用，绑定指向只存在于主端的规则
	snapshot := models.ClusterSnapshot{
		Version:          5,
		SecurityPolicies: json.RawMessage(`[{"id":5,"name":"shared","mode":"blocking","enabled":1}]`),
		SecurityBindings: json.RawMessage(`[{"rule_caddy_id":"lb_master_only","policy_id":7}]`),
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	sk := &sectionSkips{disabled: map[string]bool{"rules": true}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var localBindings int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_local_waf' AND policy_id=5").Scan(&localBindings); err != nil {
		t.Fatal(err)
	}
	if localBindings != 1 {
		t.Fatalf("rules disabled must keep local security_policy_bindings (got %d rows)——绑定被清空会使本地规则静默失去全部 WAF 防护", localBindings)
	}
	var masterBindings int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_master_only'").Scan(&masterBindings); err != nil {
		t.Fatal(err)
	}
	if masterBindings != 0 {
		t.Fatalf("rules disabled must not insert master bindings for absent rules (got %d rows)——主端规则不在本机，插它只产生悬挂死行", masterBindings)
	}
}

// 对称面：security 开关关闭时绑定表整节本地保留（安全节整体不应用）。
func TestReplaceSnapshotTx_SecurityDisabledKeepsLocalBindings(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		 VALUES ('lb_local_waf','local','http','local.test',80,1);
		 INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'shared','blocking',1);
		 INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_local_waf',5)`,
	); err != nil {
		t.Fatalf("seed local rule+policy+binding: %v", err)
	}

	snapshot := models.ClusterSnapshot{
		Version:          5,
		SecurityBindings: json.RawMessage(`[{"rule_caddy_id":"lb_master_only","policy_id":7}]`),
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	sk := &sectionSkips{disabled: map[string]bool{"security": true}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var localBindings int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_local_waf' AND policy_id=5").Scan(&localBindings); err != nil {
		t.Fatal(err)
	}
	if localBindings != 1 {
		t.Fatalf("security disabled must keep local bindings (got %d rows)", localBindings)
	}
}
