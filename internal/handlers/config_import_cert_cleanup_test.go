package handlers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 导入后「规则仍在但已无任何可用证书材料」的残留 ACME 证书/私钥文件必须
// 被清理（导入剪枝只动 DB 行；与 DeleteRule/orphanACME「失去材料即删私钥」
// 同约定）。手动证书材料在库、或存在域名适用的 issued/downloaded 任务材料的
// 规则不受影响。
func TestCleanupRulesWithoutUsableCertMaterial(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_mat_manual','manual','manual.example.test','http',8080,1,1,'manual','CERT','KEY'),
		('lb_mat_lost','lost','lost.example.test','http',8081,1,0,'', '', ''),
		('lb_mat_kept','kept','kept.example.test','http',8082,1,1,'acme_dns','',''),
		('lb_mat_olddom','olddom','new.example.test','http',8083,1,1,'acme_dns','','');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_mat_kept','kept.example.test','issued','CERT','KEY'),
		('lb_mat_olddom','old.example.test','issued','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules/jobs: %v", err)
	}
	for _, id := range []string{"lb_mat_manual", "lb_mat_lost", "lb_mat_kept", "lb_mat_olddom"} {
		if err := services.WriteCertFiles(id, "CERT", "KEY"); err != nil {
			t.Fatalf("write cert files for %s: %v", id, err)
		}
	}

	// When：先判定（不删文件），再按判定集删文件
	cleaned := cleanupCertFilesWithoutMaterial(context.Background(), t)

	// Then：失去材料的规则（关 TLS / 任务材料域名不适用）文件被清理；
	// manual 有证与材料适用的规则保留
	if cleaned != 2 {
		t.Fatalf("cleaned=%d, want 2（lb_mat_lost + lb_mat_olddom）", cleaned)
	}
	exists := func(id string) bool {
		_, certErr := os.Stat(filepath.Join(certDir, id+".crt"))
		_, keyErr := os.Stat(filepath.Join(certDir, id+".key"))
		return certErr == nil || keyErr == nil
	}
	for id, want := range map[string]bool{
		"lb_mat_manual": true,
		"lb_mat_kept":   true,
		"lb_mat_lost":   false,
		"lb_mat_olddom": false,
	} {
		if got := exists(id); got != want {
			t.Fatalf("rule %s files exist=%v, want %v", id, got, want)
		}
	}
}

// 「可用材料」谓词与渲染候选同源：渲染从任何非 disabled 行（含 failed/waiting_ca
// 保留的旧 PEM）取材料服务流量，导入清理因此不得把这类规则的证书文件删掉——
// 否则磁盘/DB 分叉，Caddy 重启后规则无证书可用。
func TestCleanupRulesWithoutUsableCertMaterial_keepsFailedRetainedPEM(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_mat_failed','failed','failed.example.test','http',8085,1,1,'acme_dns','',''),
		('lb_mat_waiting','waiting','waiting.example.test','http',8086,1,1,'acme_dns','','');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_mat_failed','failed.example.test','failed','CERT','KEY'),
		('lb_mat_waiting','waiting.example.test','waiting_ca','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules/jobs: %v", err)
	}
	for _, id := range []string{"lb_mat_failed", "lb_mat_waiting"} {
		if err := services.WriteCertFiles(id, "CERT", "KEY"); err != nil {
			t.Fatalf("write cert files for %s: %v", id, err)
		}
	}

	cleaned := cleanupCertFilesWithoutMaterial(context.Background(), t)

	if cleaned != 0 {
		t.Fatalf("cleaned=%d, want 0（failed/waiting_ca 保留的 PEM 仍是渲染材料）", cleaned)
	}
	for _, id := range []string{"lb_mat_failed", "lb_mat_waiting"} {
		if _, err := os.Stat(filepath.Join(certDir, id+".crt")); err != nil {
			t.Fatalf("规则 %s 的证书文件被误删（渲染仍会用到保留的 PEM）: %v", id, err)
		}
	}
}

// disabled 行是退役终态：其 PEM 不参与渲染，规则只剩它时文件必须清理（谓词的
// 另一半，防止把「渲染可消费面」放宽成「任何有 PEM 的行」）。
func TestCleanupRulesWithoutUsableCertMaterial_cleansDisabledOnlyMaterial(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_mat_disabled','disabled','disabled.example.test','http',8087,1,1,'acme_dns','','');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_mat_disabled','disabled.example.test','disabled','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules/jobs: %v", err)
	}
	if err := services.WriteCertFiles("lb_mat_disabled", "CERT", "KEY"); err != nil {
		t.Fatalf("write cert files: %v", err)
	}

	if cleaned := cleanupCertFilesWithoutMaterial(context.Background(), t); cleaned != 1 {
		t.Fatalf("cleaned=%d, want 1（disabled 行的 PEM 不参与渲染）", cleaned)
	}
	if _, err := os.Stat(filepath.Join(certDir, "lb_mat_disabled.crt")); err == nil {
		t.Fatal("disabled-only 规则的证书文件未被清理")
	}
}

// cleanupCertFilesWithoutMaterial 是测试侧的「判定 + 删文件」组合：与生产
// 锁外清理段同源（rulesWithoutUsableCertMaterial + removeCertFilesForRules）。
func cleanupCertFilesWithoutMaterial(ctx context.Context, t *testing.T) int {
	t.Helper()
	ids, err := rulesWithoutUsableCertMaterial(ctx, db.DB)
	if err != nil {
		t.Fatalf("判定无材料规则: %v", err)
	}
	cleaned, unprocessed := removeCertFilesForRules(ctx, ids)
	if unprocessed != 0 {
		t.Fatalf("unprocessed=%d, want 0（无预算压力场景）", unprocessed)
	}
	return cleaned
}

// 「无材料规则」通道必须逐项检查清理预算：此前只在进入通道前判一次，批量
// 通道（可含全部非 TLS 规则）会在预算耗尽后继续跑完，把导入会话锁与调度
// 暂停拖到无上界。这里以可注入的 stop 钩子钉「逐项生效 + 正确计数」。
func TestRemoveCertFilesForRules_honorsBudgetPerItem(t *testing.T) {
	withIsolatedGlobal(t)
	newBackupTestHandlers(t)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))

	original := importCleanupShouldStop
	t.Cleanup(func() { importCleanupShouldStop = original })
	calls := 0
	importCleanupShouldStop = func(context.Context) bool {
		calls++
		return calls > 2 // 第 3 次检查（index=2）起预算耗尽
	}

	cleaned, unprocessed := removeCertFilesForRules(context.Background(),
		[]string{"lb_budget_a", "lb_budget_b", "lb_budget_c", "lb_budget_d"})
	if cleaned != 2 || unprocessed != 2 {
		t.Fatalf("cleaned=%d unprocessed=%d, want 2/2（预算对无材料通道逐项生效）", cleaned, unprocessed)
	}
}
