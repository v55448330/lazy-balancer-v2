package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 回归锁定：tx 渲染路径的 ACME 证书候选可见性。

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
		VALUES ('lb_fallback_probe','fallback-probe','http','fallback.test',443,1,1,'acme_dns');
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_fallback_probe','127.0.0.1',9443,1,1,'http');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_fallback_probe','fallback.test','issued',?,?)`, certPEM, keyPEM); err != nil {
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
	if !strings.Contains(string(configJSON), `"any_tag":["lb_fallback_probe"]`) {
		t.Fatalf("tx 渲染缺少谓词 miss 规则的 TLS 策略（any_tag 缺失）: %s", configJSON)
	}
}

// 补查门控显式化：per-rule 补查只在「事务写过 lb_rules」（rulesWrittenInTx=true，
// store 的规则视图与已提交视图可能分叉）时执行。UpdateConfig 形态的事务（只写
// global_config）传 false——其 lb_rules 视图与 certSource 已提交视图恒一致，
// 主候选查询已完备，补查是纯冗余（N 条无候选 acme 规则 × 每轮渲染一次 SELECT）。
// false 时谓词 miss 规则按已提交视图渲染（无证书 → TLS 等待，any_tag 缺席）；
// true 时保持补查语义（any_tag 在场）。
func TestGenerateCaddyConfig_txFallbackGateHonorsRulesWrittenFlag(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "gated.test")

	ctx := context.Background()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_gated_probe','gated-probe','http','gated.test',443,1,1,'acme_dns');
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_gated_probe','127.0.0.1',9445,1,1,'http');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_gated_probe','gated.test','issued',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed in tx: %v", err)
	}

	// rulesWrittenInTx=false（UpdateConfig 形态）：不补查 → 证书不入场。
	gated := generateCaddyConfigWithCertSource(tx, database, false)
	if message, failed := gated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate gated config: %s", message)
	}
	gatedJSON, err := json.Marshal(gated)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gatedJSON), `"any_tag":["lb_gated_probe"]`) {
		t.Fatalf("rulesWrittenInTx=false 不应补查谓词 miss 规则（any_tag 应缺席）: %s", gatedJSON)
	}

	// rulesWrittenInTx=true（规则写事务形态）：补查 → 证书入场。
	ungated := generateCaddyConfigWithCertSource(tx, database, true)
	if message, failed := ungated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate ungated config: %s", message)
	}
	ungatedJSON, err := json.Marshal(ungated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ungatedJSON), `"any_tag":["lb_gated_probe"]`) {
		t.Fatalf("rulesWrittenInTx=true 必须补查谓词 miss 规则（any_tag 缺失）: %s", ungatedJSON)
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
		VALUES ('lb_import_probe','import-probe','http','import.test',443,1,1,'acme_dns');
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_import_probe','127.0.0.1',9444,1,1,'http');
		INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES (501,'lb_import_probe','import.test','issued',?,?)`, oldPEM, oldKey); err != nil {
		t.Fatalf("seed committed: %v", err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// 导入形态：同 id 重插，PEM 更新（restoreTable 保留原 id）。
	if _, err := tx.ExecContext(ctx, `DELETE FROM cert_jobs;
		INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES (501,'lb_import_probe','import.test','issued',?,?)`, newPEM, newKey); err != nil {
		t.Fatalf("rewrite in tx: %v", err)
	}

	generated := generateCaddyConfigWithCertSource(tx, tx, true)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	certPath, _ := CertFilePaths("lb_import_probe")
	content, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read materialized cert: %v", err)
	}
	if strings.TrimSpace(string(content)) != strings.TrimSpace(newPEM) {
		t.Fatalf("物化证书与 tx 内新 PEM 不一致——已提交旧 PEM 覆写了导入证书")
	}
}

// CRS 池指纹批次级缓存：同一轮全量渲染内指纹只求值一次（此前逐链求值——
// R 条有策略的 HTTP 规则 = R 次 SELECT+stat，单次保存最多 3 轮 → 3R）。
func TestGenerateCaddyConfig_crsPoolFingerprintEvaluatedOncePerBatch(t *testing.T) {
	seedInfraCRSFiles(t)
	xdb := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(xdb, []byte("fake-xdb-bytes"), 0o644); err != nil {
		t.Fatalf("seed ip2region: %v", err)
	}
	t.Cleanup(OverrideWafLivePathsForTest(crsLiveDir, xdb))
	_, database := newClusterTestService(t)
	for i, id := range []string{"lb_fp_a", "lb_fp_b", "lb_fp_c"} {
		seedHTTPRuleForGeneration(t, database, id, id+".example.test", 18080+i)
		seedBoundSecurityPolicy(t, database, id, "detection", true)
	}

	before := crsPoolFingerprintEvals.Load()
	// 计数器为包级共享：测后把本用例增量还回去（跨用例残留会让后续断言失真）。
	// 本包无 t.Parallel 用例，串行执行下「增量恰 1」是可判定的。
	t.Cleanup(func() {
		crsPoolFingerprintEvals.Add(-(crsPoolFingerprintEvals.Load() - before))
	})
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	if delta := crsPoolFingerprintEvals.Load() - before; delta != 1 {
		t.Fatalf("单轮渲染指纹求值 %d 次, want 1（批次级缓存必须收敛为一次）", delta)
	}

	// 第二轮独立渲染：批次缓存不得跨轮残留——新批次仍须各自求值一次。
	secondBase := crsPoolFingerprintEvals.Load()
	generated = generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("second generate config: %s", message)
	}
	if delta := crsPoolFingerprintEvals.Load() - secondBase; delta != 1 {
		t.Fatalf("第二轮渲染指纹求值 %d 次, want 1（批次缓存跨轮残留）", delta)
	}
}
