package services

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// failCRSVersionMarkerWrite 注入 VERSION 标记写失败（原子写路径与真实磁盘
// 写满/权限错误同一返回值）。
func failCRSVersionMarkerWrite(t *testing.T) {
	t.Helper()
	old := crsVersionMarkerWrite
	crsVersionMarkerWrite = func(string, []byte, os.FileMode) error {
		return errors.New("disk full")
	}
	t.Cleanup(func() { crsVersionMarkerWrite = old })
}

func readClusterVersion(t *testing.T) int64 {
	t.Helper()
	var v int64
	if err := db.DB.QueryRow(`SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read cluster_version: %v", err)
	}
	return v
}

// 快照恢复段的 VERSION 写失败必须上抛：rules/辅助文件已复制但版本标记缺失时，
// 调用方若照常 BumpClusterVersion 并记「恢复成功」审计，live 标记与规则树/DB
// 跨代——下一次启动会重复恢复或按旧标记把 DB 版本行校正到旧值。
func TestRestoreCRSFromSnapshot_versionMarkerFailurePropagates(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule reverted")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule updated")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.30.0\n")
	failCRSVersionMarkerWrite(t)

	if err := restoreCRSFromSnapshot(liveDir, snapshotDir, "v4.30.0"); err == nil {
		t.Fatalf("VERSION 标记写失败时恢复必须返回错误（不得静默按成功收尾）")
	}
}

// 端到端：恢复段 VERSION 写失败不得递增集群版本、不得记「恢复成功」审计。
func TestReconcileCRSState_versionMarkerFailureSkipsSuccessSideEffects(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule reverted")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.29.0\n")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule updated")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.30.0\n")
	baseline := readClusterVersion(t)
	failCRSVersionMarkerWrite(t)

	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.30.0")

	if got := readClusterVersion(t); got != baseline {
		t.Fatalf("cluster_version=%d, want %d（恢复失败不得递增集群版本）", got, baseline)
	}
	var auditRows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%从持久快照恢复%'`).Scan(&auditRows); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if auditRows != 0 {
		t.Fatalf("恢复失败仍写入 %d 条「恢复成功」审计（假成功）", auditRows)
	}
	if got := readCRSVersionMarker(liveDir); got != "v4.29.0" {
		t.Fatalf("live VERSION=%q, want v4.29.0（写失败的标记不得被当成已落盘）", got)
	}
}

// 播种路径同类：播种后 VERSION 写失败必须返回错误（标记缺失会让下次启动对账
// 按错误版本选方向），不得只记「已播种」成功日志。
func TestSeedCRSRules_versionMarkerFailureReported(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule bundled")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# bundled setup")
	failCRSVersionMarkerWrite(t)

	if err := seedCRSRulesFrom(liveDir, snapshotDir, distDir); err == nil {
		t.Fatalf("播种后 VERSION 写失败必须返回错误")
	}
}
