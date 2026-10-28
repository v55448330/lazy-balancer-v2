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

// 导入候选阶段落盘的证书字节（故意与库值、与导入前旧字节都不同）：
// 恢复/对账是否真的跑过，只能靠「磁盘字节最终等于库值」判定——若候选字节
// 与库值相同，则「完全跳过恢复」也满足「新证书仍在」，断言失去判别力。
const (
	importStagedCertBytes = "IMPORT_STAGED_CERT_BYTES"
	importStagedKeyBytes  = "IMPORT_STAGED_KEY_BYTES"
	importPriorCertBytes  = "OLD_CERT"
	importPriorKeyBytes   = "OLD_KEY"
)

// committedRecoveryFailureAudits 返回「恢复已提交视图运行配置失败」在系统审计
// 里的行数（recordCaddyApplyFailure → writeApplyFailureBanner 写点）。
func committedRecoveryFailureAudits(t *testing.T) int {
	t.Helper()
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
		WHERE resource='Caddy配置' AND detail LIKE '%恢复已提交运行配置失败%'`).Scan(&rows); err != nil {
		t.Fatalf("read committed-view recovery audit: %v", err)
	}
	return rows
}

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
	if err := services.WriteCertFiles("lb_commit_new", importPriorCertBytes, importPriorKeyBytes); err != nil {
		t.Fatal(err)
	}
	snapshot, err := services.SnapshotCertFiles([]string{"lb_commit_new"})
	if err != nil {
		t.Fatal(err)
	}
	// 导入候选字节：既不同于库值，也不同于导入前旧字节——恢复被完全跳过
	// 时磁盘会停在候选字节，回旧字节时停在旧字节，两种退化都能被下面的
	// 「磁盘==库值」断言抓住。
	if err := services.WriteCertFiles("lb_commit_new", importStagedCertBytes, importStagedKeyBytes); err != nil {
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

	importErr := errors.New("commit confirmation lost")
	abortErr := session.abort(importErr)
	if abortErr == nil {
		t.Fatal("恢复渲染失败必须留在错误链中")
	}
	// abort 返回的错误链必须包住原始导入错误（errors.Join 语义），而不是
	// 「返回了某个非 nil 错误」——入参本就非 nil，只判 nil 是恒真断言。
	if !errors.Is(abortErr, importErr) {
		t.Fatalf("abort 错误链未包住原始导入错误: %v", abortErr)
	}
	// 失败分支的追踪：错误链与系统审计都必须点名「恢复已提交视图运行配置失败」。
	// 与成功用例的「审计为 0」成对出现，才区分得开「恢复跑了但失败」与
	// 「恢复根本没跑」。
	if !strings.Contains(abortErr.Error(), "恢复已提交视图运行配置失败") {
		t.Fatalf("abort 错误链缺少恢复失败归因: %v", abortErr)
	}
	if rows := committedRecoveryFailureAudits(t); rows != 1 {
		t.Fatalf("「恢复已提交视图运行配置失败」审计行=%d, want 1（失败必须落系统审计）", rows)
	}
	// 证书文件的正面契约：确定性回滚禁止（否则制造确定分叉），已提交视图
	// 对账又在坏规则处失败——磁盘必须停在导入候选字节，既不回旧字节，也不被
	// 半途物化的其它规则覆写。候选字节与库值/旧字节都不同，任一种「静默回退」
	// 都会让这条断言变红；「恢复被完全跳过」则由上面的审计追踪断言排除。
	assertFileBytes(t, filepath.Join(certDir, "lb_commit_new.crt"), []byte(importStagedCertBytes))
	assertFileBytes(t, filepath.Join(certDir, "lb_commit_new.key"), []byte(importStagedKeyBytes))
	// 本分支无条件写出的不确定态披露行（恢复成功时同样存在，不承担判别职责，
	// 只钉「不确定态必须显性披露」）。
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
	if err := services.WriteCertFiles("lb_commit_ok", importPriorCertBytes, importPriorKeyBytes); err != nil {
		t.Fatal(err)
	}
	snapshot, err := services.SnapshotCertFiles([]string{"lb_commit_ok"})
	if err != nil {
		t.Fatal(err)
	}
	// 候选字节故意不同于库值：下面的「磁盘==库值」才能证明渲染按已提交视图
	// 重新物化了证书文件（恢复被跳过时磁盘停在候选字节）。
	if err := services.WriteCertFiles("lb_commit_ok", importStagedCertBytes, importStagedKeyBytes); err != nil {
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

	importErr := errors.New("commit confirmation lost")
	abortErr := session.abort(importErr)
	if abortErr == nil {
		t.Fatal("abort 必须返回原始导入错误（入参非 nil）")
	}
	if !errors.Is(abortErr, importErr) {
		t.Fatalf("abort 错误链未包住原始导入错误: %v", abortErr)
	}
	if strings.Contains(abortErr.Error(), "恢复已提交") {
		t.Fatalf("已提交视图恢复不应失败: %v", abortErr)
	}
	// 成功分支必须没有「恢复已提交视图运行配置失败」留痕——与失败用例的
	// 审计=1 成对，才钉得住「追踪只在真失败时出现」。
	if rows := committedRecoveryFailureAudits(t); rows != 0 {
		t.Fatalf("恢复成功却留下失败审计 %d 条（假告警）", rows)
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
