package handlers

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	// 真实落盘：RemoveCertFiles 对缺失文件是幂等 no-op，只数计数器时
	// 「预算耗尽后仍继续删除」与「预算生效」不可区分（二者都返回同样的
	// 计数）。必须让四条规则都有文件，并用淘汰边界两侧的文件状态作判据。
	ruleIDs := []string{"lb_budget_a", "lb_budget_b", "lb_budget_c", "lb_budget_d"}
	for _, id := range ruleIDs {
		if err := services.WriteCertFiles(id, "CERT_"+id, "KEY_"+id); err != nil {
			t.Fatalf("seed cert files for %s: %v", id, err)
		}
	}

	original := importCleanupShouldStop
	t.Cleanup(func() { importCleanupShouldStop = original })
	calls := 0
	importCleanupShouldStop = func(context.Context) bool {
		calls++
		return calls > 2 // 第 3 次检查（index=2）起预算耗尽
	}

	cleaned, unprocessed := removeCertFilesForRules(context.Background(), ruleIDs)
	if cleaned != 2 || unprocessed != 2 {
		t.Fatalf("cleaned=%d unprocessed=%d, want 2/2（预算对无材料通道逐项生效）", cleaned, unprocessed)
	}

	// Then：预算内处理的 a/b 文件必须真的消失……
	for _, id := range []string{"lb_budget_a", "lb_budget_b"} {
		for _, suffix := range []string{".crt", ".key"} {
			if _, err := os.Stat(filepath.Join(certDir, id+suffix)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("预算内规则 %s 的 %s 未被删除（err=%v）", id, suffix, err)
			}
		}
	}
	// ……预算耗尽后不得再删除 c/d（此前预算只在进入通道前判一次，会把批量
	// 通道跑完并把导入会话锁/调度暂停拖到无上界）。
	for _, id := range []string{"lb_budget_c", "lb_budget_d"} {
		for _, suffix := range []string{".crt", ".key"} {
			if _, err := os.Stat(filepath.Join(certDir, id+suffix)); err != nil {
				t.Fatalf("预算耗尽后规则 %s 的 %s 仍被删除: %v", id, suffix, err)
			}
		}
	}
}

// certMaterialScanFailureQueryer 让第二条判定查询（材料行）返回只有一列的结果
// 集：调用方按两列 Scan → 逐行 Scan 失败。用于注入「材料行读取故障」。
type certMaterialScanFailureQueryer struct {
	db *sql.DB
}

func (q *certMaterialScanFailureQueryer) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if strings.Contains(query, "cert_jobs") {
		return q.db.QueryContext(ctx, "SELECT rule_id FROM cert_jobs")
	}
	return q.db.QueryContext(ctx, query, args...)
}

// 材料行读取失败时必须中止判定并返回错误：把「读取未知」降级成「确定无材料」
// 会让仍在服务（任务 PEM 可用）的规则的证书文件在导入清理中被删除，与本函数
// 自己的 fail-closed 契约相反。生产调用方在判定失败时跳过删除，因此故障下
// 证书文件必须零删除。
func TestRulesWithoutUsableCertMaterial_abortsOnMaterialRowScanFailure(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_scan_kept','kept','kept.example.test','http',8088,1,1,'acme_dns','',''),
		('lb_scan_lost','lost','lost.example.test','http',8089,1,0,'','','');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_scan_kept','kept.example.test','issued','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules/jobs: %v", err)
	}
	for _, id := range []string{"lb_scan_kept", "lb_scan_lost"} {
		if err := services.WriteCertFiles(id, "CERT", "KEY"); err != nil {
			t.Fatalf("write cert files for %s: %v", id, err)
		}
	}

	// When：材料行 Scan 失败
	ids, err := rulesWithoutUsableCertMaterial(context.Background(), &certMaterialScanFailureQueryer{db: db.DB})

	// Then：判定失败必须显式返回错误且不产出待删集
	if err == nil {
		t.Fatalf("材料行 Scan 失败必须返回错误，实际 ids=%v", ids)
	}
	if !strings.Contains(err.Error(), "任务材料") {
		t.Fatalf("error=%v, want 带「任务材料」上下文的错误", err)
	}
	if len(ids) != 0 {
		t.Fatalf("判定失败时 ids=%v, want 空（不得给出待删集）", ids)
	}
	// 生产调用方判定失败即跳过删除：两份证书文件都必须仍在
	for _, id := range []string{"lb_scan_kept", "lb_scan_lost"} {
		if _, statErr := os.Stat(filepath.Join(certDir, id+".crt")); statErr != nil {
			t.Fatalf("规则 %s 的证书文件在判定失败后被删除: %v", id, statErr)
		}
	}
}

// tls_source IS NULL 的存量行按渲染口径是 manual（读取口径全族单源
// COALESCE(tls_source,'manual')）：渲染按 manual 供证，导入清理判定不得把它当
// 「无材料」删掉仍在服务的证书文件。带外形态：写侧恒写 manual/acme_dns，
// NULL 只能来自旧版本遗留/带外直写。
func TestCleanupRulesWithoutUsableCertMaterial_nullTLSSourceKept(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_mat_nullsrc','nullsrc','null.example.test','http',8088,1,1,NULL,'CERT','KEY')`); err != nil {
		t.Fatalf("seed tls_source=NULL rule: %v", err)
	}
	if err := services.WriteCertFiles("lb_mat_nullsrc", "CERT", "KEY"); err != nil {
		t.Fatalf("write cert files: %v", err)
	}

	cleaned := cleanupCertFilesWithoutMaterial(context.Background(), t)
	if cleaned != 0 {
		t.Fatalf("cleaned=%d, want 0（tls_source=NULL 且 cert/key 非空按渲染口径=manual，不得进待删集）", cleaned)
	}
	if _, err := os.Stat(filepath.Join(certDir, "lb_mat_nullsrc.crt")); err != nil {
		t.Fatalf("仍在服务的证书文件被误删: %v", err)
	}
}
