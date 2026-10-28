package services

// 导入崩溃残留对账：文件先落盘、事务随后才提交，进程在这之间被 SIGKILL/断电
// 时，磁盘上留有快照目录/新代 xdb 标记/威胁名单孤儿文件，而 DB 已回滚为旧代。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// withLeftoverProcessStart 让「早于本进程启动」的判据把所有既有夹具都算作
// 上一次运行的产物（夹具在本进程启动后创建，直接比较会一律判为本进程）。
func withLeftoverProcessStart(t *testing.T) {
	t.Helper()
	old := processStartedAt
	processStartedAt = time.Now().Add(time.Hour)
	t.Cleanup(func() { processStartedAt = old })
}

func TestPruneStaleWafSnapshotDirs_removesPreviousRunLeftovers(t *testing.T) {
	withLeftoverProcessStart(t)
	parent := t.TempDir()
	oldParent := wafSnapshotParentDir
	wafSnapshotParentDir = func() string { return parent }
	t.Cleanup(func() { wafSnapshotParentDir = oldParent })

	leftover := filepath.Join(parent, "lbbak-waf-snapshot-crash")
	if err := os.MkdirAll(filepath.Join(leftover, "crs", "rules"), 0o755); err != nil {
		t.Fatalf("seed snapshot dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(leftover, "crs", "rules", "x.conf"), []byte("SecRule"), 0o644); err != nil {
		t.Fatalf("seed snapshot file: %v", err)
	}
	unrelated := filepath.Join(parent, "other-temp-dir")
	if err := os.MkdirAll(unrelated, 0o755); err != nil {
		t.Fatalf("seed unrelated dir: %v", err)
	}

	pruneStaleWafSnapshotDirs()

	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("崩溃残留快照目录必须删除，err=%v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("非快照目录不得删除: %v", err)
	}
}

// 在途导入的快照目录晚于本进程启动，绝不能被同一次启动的对账删掉。
func TestPruneStaleWafSnapshotDirs_keepsCurrentProcessProduct(t *testing.T) {
	parent := t.TempDir()
	oldParent := wafSnapshotParentDir
	wafSnapshotParentDir = func() string { return parent }
	t.Cleanup(func() { wafSnapshotParentDir = oldParent })
	inFlight := filepath.Join(parent, "lbbak-waf-snapshot-live")
	if err := os.MkdirAll(inFlight, 0o755); err != nil {
		t.Fatalf("seed in-flight snapshot dir: %v", err)
	}

	pruneStaleWafSnapshotDirs()

	if _, err := os.Stat(inFlight); err != nil {
		t.Fatalf("本进程创建的导入快照目录不得删除: %v", err)
	}
}

func TestReconcileIP2RegionVersionFromDiskMarker_adoptsDiskGeneration(t *testing.T) {
	withLeftoverProcessStart(t)
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	xdbPath := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(xdbPath, []byte("xdb-bytes"), 0o644); err != nil {
		t.Fatalf("seed xdb: %v", err)
	}
	if err := os.WriteFile(xdbPath+".version", []byte("20260101"), 0o644); err != nil {
		t.Fatalf("seed xdb marker: %v", err)
	}
	oldPath := ip2regionLivePath
	ip2regionLivePath = xdbPath
	t.Cleanup(func() { ip2regionLivePath = oldPath })
	if _, err := db.DB.Exec(`DELETE FROM security_ip2region_version`); err != nil {
		t.Fatalf("clear version row: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_ip2region_version (id, version, updated_at) VALUES (1, '20251012', datetime('now'))`); err != nil {
		t.Fatalf("seed stale version row: %v", err)
	}

	reconcileIP2RegionVersionFromDiskMarker()

	current, err := GetIP2RegionVersion()
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if current != "20260101" {
		t.Fatalf("version=%q, want 20260101 按磁盘标记校正", current)
	}
}

func TestReconcileIP2RegionVersionFromDiskMarker_ignoresCurrentProcessInstall(t *testing.T) {
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	xdbPath := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(xdbPath, []byte("xdb-bytes"), 0o644); err != nil {
		t.Fatalf("seed xdb: %v", err)
	}
	if err := os.WriteFile(xdbPath+".version", []byte("20260101"), 0o644); err != nil {
		t.Fatalf("seed xdb marker: %v", err)
	}
	oldPath := ip2regionLivePath
	ip2regionLivePath = xdbPath
	t.Cleanup(func() { ip2regionLivePath = oldPath })
	if _, err := db.DB.Exec(`DELETE FROM security_ip2region_version`); err != nil {
		t.Fatalf("clear version row: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_ip2region_version (id, version, updated_at) VALUES (1, '20251012', datetime('now'))`); err != nil {
		t.Fatalf("seed version row: %v", err)
	}

	reconcileIP2RegionVersionFromDiskMarker()

	current, err := GetIP2RegionVersion()
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if current != "20251012" {
		t.Fatalf("version=%q, want 20251012（本进程写入的库不属崩溃残留，对账不得介入）", current)
	}
}

func TestPruneOrphanThreatFiles_removesDeletedSourceResidue(t *testing.T) {
	withLeftoverProcessStart(t)
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	dir := t.TempDir()
	restore := OverrideThreatWafDirForTest(dir)
	defer restore()
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources`); err != nil {
		t.Fatalf("clear threat sources: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (id,name,display_name) VALUES (1,'kept','kept')`); err != nil {
		t.Fatalf("seed threat source: %v", err)
	}
	for _, name := range []string{"threat-kept.iplist", "threat-removed.iplist", "threat-removed.iplist.fast"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("1.2.3.4\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	pruneOrphanThreatFiles()

	for _, name := range []string{"threat-removed.iplist", "threat-removed.iplist.fast"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s 必须被删除（源已不在表中），err=%v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "threat-kept.iplist")); err != nil {
		t.Fatalf("表内源的文件不得删除: %v", err)
	}
}

func TestPruneOrphanThreatFiles_keepsCurrentProcessWrites(t *testing.T) {
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	dir := t.TempDir()
	restore := OverrideThreatWafDirForTest(dir)
	defer restore()
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources`); err != nil {
		t.Fatalf("clear threat sources: %v", err)
	}
	inFlight := filepath.Join(dir, "threat-downloading.iplist")
	if err := os.WriteFile(inFlight, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatalf("seed in-flight file: %v", err)
	}

	pruneOrphanThreatFiles()

	if _, err := os.Stat(inFlight); err != nil {
		t.Fatalf("本进程写入的名单文件不得删除: %v", err)
	}
	if strings.Contains(dir, "lbbak-waf-snapshot") {
		t.Fatalf("夹具目录不符预期: %s", dir)
	}
}

// 启动入口接线：三项残留必须由 ReconcileWafFileCrashLeftovers 一次收敛
// （各函数自身的用例不覆盖「启动路径是否真的调用」）。
func TestReconcileWafFileCrashLeftovers_entryPrunesAllThreeResidues(t *testing.T) {
	withLeftoverProcessStart(t)
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	var isMaster bool
	if err := db.DB.QueryRow(`SELECT COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&isMaster); err != nil || !isMaster {
		t.Fatalf("夹具必须是主节点（否则版本行/威胁名单两项按写入门跳过）: is_master=%v err=%v", isMaster, err)
	}
	// ① 导入快照残留目录
	snapshotParent := t.TempDir()
	oldParent := wafSnapshotParentDir
	wafSnapshotParentDir = func() string { return snapshotParent }
	t.Cleanup(func() { wafSnapshotParentDir = oldParent })
	leftover := filepath.Join(snapshotParent, "lbbak-waf-snapshot-crash")
	if err := os.MkdirAll(leftover, 0o755); err != nil {
		t.Fatalf("seed snapshot dir: %v", err)
	}
	// ② xdb 版本标记与版本行分叉
	xdbPath := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(xdbPath, []byte("xdb-bytes"), 0o644); err != nil {
		t.Fatalf("seed xdb: %v", err)
	}
	if err := os.WriteFile(xdbPath+".version", []byte("20260101"), 0o644); err != nil {
		t.Fatalf("seed xdb marker: %v", err)
	}
	oldXdb := ip2regionLivePath
	ip2regionLivePath = xdbPath
	t.Cleanup(func() { ip2regionLivePath = oldXdb })
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET version='20251012' WHERE id=1`); err != nil {
		t.Fatalf("seed stale version row: %v", err)
	}
	// ③ 已删威胁源的残留名单
	dir := t.TempDir()
	restore := OverrideThreatWafDirForTest(dir)
	defer restore()
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources`); err != nil {
		t.Fatalf("clear threat sources: %v", err)
	}
	orphan := filepath.Join(dir, "threat-removed.iplist")
	if err := os.WriteFile(orphan, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatalf("seed orphan threat file: %v", err)
	}

	// When
	ReconcileWafFileCrashLeftovers()

	// Then
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("① 快照残留目录未清理，err=%v", err)
	}
	if current, err := GetIP2RegionVersion(); err != nil || current != "20260101" {
		t.Fatalf("② 版本行未按磁盘标记校正: version=%q err=%v", current, err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("③ 孤儿名单文件未清理，err=%v", err)
	}
}
