package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 回滚契约：restoreBackupInLock 的返回值必须覆盖**全部**本运行备份的恢复结果
// （rules 树 + setup/stock/overrides），而不只是规则树。只核对规则树时，
// setup/stock/overrides 任一恢复失败仍会回写 prevTag——留下
// 「旧 rules + 新 setup/stock/overrides + 旧版本号」混合代，后续更新会以错误
// stock 基线计算自定义 diff。
//
// 故障注入：把 setup 目标路径替换成非空目录——原子写（tmp+rename）必然失败，
// 与真实 I/O/权限失败同一返回路径。
func TestRestoreBackupInLock_auxiliaryRestoreFailureFailsAggregate(t *testing.T) {
	m := newTestCRSManager(t)
	// rules 备份完好（可成功还原）
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule new")
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), crsRulesProbeFile), "SecRule old")
	m.rulesBakCreated = true
	// setup 备份完好但目标被目录占据 → copyFile 失败
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.conf.bak"), "# old setup")
	m.setupBakCreated = true
	blockedSetup := filepath.Join(m.crsDir, "crs-setup.conf")
	if err := os.MkdirAll(blockedSetup, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedSetup, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if restored := m.restoreBackupInLock(); restored {
		t.Fatalf("setup 恢复失败时聚合结果必须为 false（否则版本号会被回写成旧版）")
	}
	// 部分成果保留：规则树已还原
	if data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule old" {
		t.Fatalf("rules 树应仍被还原: %q, %v", data, err)
	}
	// 失败项的备份不得被消费（唯一恢复副本）
	if _, err := os.Stat(crsTransientPath(m.crsDir, "crs-setup.conf.bak")); err != nil {
		t.Fatalf("setup 恢复失败时 .bak 必须保留以便重试: %v", err)
	}
}

// 全成功回归形状：四类备份都可还原时聚合结果必须为 true（不得因新增结果门
// 把正常回滚误判为失败）。
func TestRestoreBackupInLock_allBackupsRestoredReportsTrue(t *testing.T) {
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule new")
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), crsRulesProbeFile), "SecRule old")
	m.rulesBakCreated = true
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# new setup")
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.conf.bak"), "# old setup")
	m.setupBakCreated = true
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# new stock")
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.stock.conf.bak"), "# old stock")
	m.stockBakCreated = true
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# new overrides")
	writeTestFile(t, crsTransientPath(m.crsDir, "zz-user-overrides.conf.bak"), "# old overrides")
	m.overridesBakCreated = true

	if restored := m.restoreBackupInLock(); !restored {
		t.Fatalf("全部备份恢复成功时聚合结果必须为 true")
	}
	for path, want := range map[string]string{
		filepath.Join(m.crsDir, "crs-setup.conf"):           "# old setup",
		filepath.Join(m.crsDir, "crs-setup.stock.conf"):     "# old stock",
		filepath.Join(m.crsDir, "zz-user-overrides.conf"):   "# old overrides",
		filepath.Join(m.crsDir, "rules", crsRulesProbeFile): "SecRule old",
	} {
		if data, err := os.ReadFile(path); err != nil || string(data) != want {
			t.Fatalf("%s=%q, %v; want %q", path, data, err, want)
		}
	}
}

// 端到端：辅助文件恢复失败时不得回写旧版本号（VERSION 标记与 DB 版本行）。
func TestCRSRollbackAfterReloadFailure_partialAuxRestoreKeepsNewVersion(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.15.0", true) // DB 行已是新版本
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule new")
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), crsRulesProbeFile), "SecRule old")
	m.rulesBakCreated = true
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.15.0\n")
	// overrides 目标被目录占据 → 恢复失败（规则树恢复成功）
	writeTestFile(t, crsTransientPath(m.crsDir, "zz-user-overrides.conf.bak"), "# old overrides")
	m.overridesBakCreated = true
	blockedOverrides := filepath.Join(m.crsDir, "zz-user-overrides.conf")
	if err := os.MkdirAll(blockedOverrides, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedOverrides, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m.rollbackAfterReloadFailure("v4.14.0")

	if got := readCRSVersionMarker(m.crsDir); got != "v4.15.0" {
		t.Fatalf("VERSION 标记=%q, want v4.15.0（辅助文件恢复失败时不得回写旧版本）", got)
	}
	if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.15.0" {
		t.Fatalf("DB 版本行=%q, want v4.15.0（辅助文件恢复失败时不得回写旧版本）", version)
	}
}
