package handlers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Commit 报错但实际已提交、且运行视图恢复无法物化证书时，不得先把新证书
// 回成旧字节；保留导入后文件并给出证书专用告警，等待人工/后续对账收敛。
func TestImportAbort_indeterminateCommitPreservesCertsWhenCommittedRecoveryFails(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	certPEM, keyPEM, err := generateTestCert("committed.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_commit_new','committed','http','committed.example.test',8871,1,1,'manual',?,?),
		('lb_render_broken','broken','http','broken.example.test',8872,1,1,'manual','BROKEN','BROKEN')`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := services.WriteCertFiles("lb_commit_new", "OLD_CERT", "OLD_KEY"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := services.SnapshotCertFiles([]string{"lb_commit_new"})
	if err != nil {
		t.Fatal(err)
	}
	if err := services.WriteCertFiles("lb_commit_new", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	session := &configImportSession{
		h: h, tx: tx, commitIndeterminate: true, runtimeApplyAttempted: true,
		runtime: &importRuntimeSnapshot{certFiles: snapshot},
	}

	abortErr := session.abort(errors.New("commit confirmation lost"))
	if abortErr == nil {
		t.Fatal("恢复渲染失败必须留在错误链中")
	}
	assertFileBytes(t, filepath.Join(certDir, "lb_commit_new.crt"), []byte(certPEM))
	assertFileBytes(t, filepath.Join(certDir, "lb_commit_new.key"), []byte(keyPEM))
	var certWarnings int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='配置备份' AND detail LIKE '%提交结果不确定%证书文件%'`).Scan(&certWarnings); err != nil {
		t.Fatal(err)
	}
	if certWarnings != 1 {
		t.Fatalf("证书专用不确定态告警=%d, want 1", certWarnings)
	}
}

// 已提交视图可正常恢复时，渲染本身即按新库物化证书；替换后的字节与
// 数据库一致，且恢复 /load 不进入失败分支。
func TestImportAbort_indeterminateCommittedViewMaterializesImportedCert(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	certPEM, keyPEM, err := generateTestCert("committed-ok.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_commit_ok','committed-ok','http','committed-ok.example.test',8873,1,1,'manual',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := services.WriteCertFiles("lb_commit_ok", "OLD_CERT", "OLD_KEY"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := services.SnapshotCertFiles([]string{"lb_commit_ok"})
	if err != nil {
		t.Fatal(err)
	}
	if err := services.WriteCertFiles("lb_commit_ok", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	session := &configImportSession{
		h: h, tx: tx, commitIndeterminate: true, runtimeApplyAttempted: true,
		runtime: &importRuntimeSnapshot{certFiles: snapshot},
	}

	abortErr := session.abort(errors.New("commit confirmation lost"))
	if strings.Contains(abortErr.Error(), "恢复已提交") {
		t.Fatalf("已提交视图恢复不应失败: %v", abortErr)
	}
	assertFileBytes(t, filepath.Join(certDir, "lb_commit_ok.crt"), []byte(certPEM))
	assertFileBytes(t, filepath.Join(certDir, "lb_commit_ok.key"), []byte(keyPEM))
}

// Commit 报错且实际回滚时，已提交视图没有新规则；快照中的“原本不存在”
// 必须用于删除未提交私钥，不能仅跳过回旧而留下孤儿材料。
func TestImportAbort_indeterminateRollbackRemovesUncommittedCertFiles(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	certPEM, keyPEM, err := generateTestCert("uncommitted.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := services.SnapshotCertFiles([]string{"lb_uncommitted_new"})
	if err != nil {
		t.Fatal(err)
	}
	if err := services.WriteCertFiles("lb_uncommitted_new", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	session := &configImportSession{
		h: h, tx: tx, commitIndeterminate: true, runtimeApplyAttempted: true,
		runtime: &importRuntimeSnapshot{certFiles: snapshot},
	}

	_ = session.abort(errors.New("commit confirmation lost"))

	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_uncommitted_new"+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("未提交规则证书%s 残留: %v", suffix, err)
		}
	}
}
