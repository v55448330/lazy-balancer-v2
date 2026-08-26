package services

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// R65 A-N1 回归锁定：tx 渲染路径的 ACME 证书候选可见性。

// 谓词 miss 补查：事务引入/翻转的 acme 规则（已提交视图的 lb_rules 子查询将其
// 排除——UpdateRule manual→acme、EnableRule、v2 导入新 caddy_id 三形态同根）
// 在 tx 渲染时经 per-rule 补查获得证书，TLS 策略不再静默缺失。
func TestGenerateCaddyConfig_txFallbackFillsCandidatesForPredicateMiss(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "fallback.test")

	ctx := context.Background()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// committed 库中不存在该规则（子查询必 miss）；规则与证书行均只存在于 tx。
	if _, err := tx.ExecContext(ctx, `INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_r65_fallback','r65','http','fallback.test',443,1,1,'acme_dns');
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_r65_fallback','127.0.0.1',9443,1,1,'http');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_r65_fallback','fallback.test','issued',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed in tx: %v", err)
	}

	generated := generateCaddyConfigFromStore(tx) // certSource=db.DB → 子查询 miss → tx 补查
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	configJSON, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configJSON), `"any_tag":["lb_r65_fallback"]`) {
		t.Fatalf("tx 渲染缺少谓词 miss 规则的 TLS 策略（any_tag 缺失）: %s", configJSON)
	}
}

// 同 id 全量替换（v2 导入形态）：certSource=tx（ApplyConfigFromTxCertAwareForce）时
// 渲染并物化事务内的新 PEM——已提交视图的旧行不得覆写导入的新证书。
func TestGenerateCaddyConfig_txCertSourceUsesInTxPEM(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	oldPEM, oldKey := matchingCertificatePair(t, "import.test")
	newPEM, newKey := matchingCertificatePair(t, "import.test")

	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_r65_import','r65i','http','import.test',443,1,1,'acme_dns');
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_r65_import','127.0.0.1',9444,1,1,'http');
		INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES (501,'lb_r65_import','import.test','issued',?,?)`, oldPEM, oldKey); err != nil {
		t.Fatalf("seed committed: %v", err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// 导入形态：同 id 重插，PEM 更新（restoreTable 保留原 id）。
	if _, err := tx.ExecContext(ctx, `DELETE FROM cert_jobs;
		INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES (501,'lb_r65_import','import.test','issued',?,?)`, newPEM, newKey); err != nil {
		t.Fatalf("rewrite in tx: %v", err)
	}

	generated := generateCaddyConfigWithCertSource(tx, tx)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	certPath, _ := CertFilePaths("lb_r65_import")
	content, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read materialized cert: %v", err)
	}
	if strings.TrimSpace(string(content)) != strings.TrimSpace(newPEM) {
		t.Fatalf("物化证书与 tx 内新 PEM 不一致——已提交旧 PEM 覆写了导入证书")
	}
}
