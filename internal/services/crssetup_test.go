package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSetupDiff(t *testing.T) {
	cases := []struct {
		name  string
		stock []string
		live  []string
		want  []string
	}{
		{"identical returns empty", []string{"a", "b"}, []string{"a", "b"}, nil},
		{"live additions are returned", []string{"a"}, []string{"a", "SecRule custom"}, []string{"SecRule custom"}},
		{"modified line is returned", []string{"SecRuleEngine On"}, []string{"SecRuleEngine DetectionOnly"}, []string{"SecRuleEngine DetectionOnly"}},
		{"comments are significant", []string{"SecRule id:1"}, []string{"# SecRule id:1"}, []string{"# SecRule id:1"}},
		{"order is preserved", []string{"a"}, []string{"z", "a", "y", "x"}, []string{"z", "y", "x"}},
		{"blank lines are skipped", []string{"a"}, []string{"a", "", "   ", "b"}, []string{"b"}},
		{"empty live returns empty", []string{"a"}, nil, nil},
		{"stock superset returns empty", []string{"a", "b", "c"}, []string{"a", "c"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSetupDiff(tc.stock, tc.live)
			if len(got) != len(tc.want) {
				t.Fatalf("extractSetupDiff()=%v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("extractSetupDiff()[%d]=%q, want %q (got %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestCRSUpdateRun_migratesSetupCustomizationsAndInstallsNewStock(t *testing.T) {
	// Given a live setup that diverges from the installed stock baseline
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "stock-a\nstock-b\nstock-c\n")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "stock-a\nstock-b-modified\nstock-c\nuser-custom\n")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "new-stock-1\nnew-stock-2\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When the update runs to completion
	m.run("manual")

	// Then the new stock setup is installed and recorded as the next baseline
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf"} {
		data, err := os.ReadFile(filepath.Join(m.crsDir, name))
		if err != nil || string(data) != "new-stock-1\nnew-stock-2\n" {
			t.Fatalf("%s=%q,%v, want new stock setup", name, data, err)
		}
	}

	// And the customizations were carried into the overrides file with a header
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil {
		t.Fatalf("zz-user-overrides.conf missing: %v", err)
	}
	content := string(overrides)
	if !strings.Contains(content, "# 由 CRS 更新自动迁移的用户自定义配置") {
		t.Fatalf("overrides missing migration header: %q", content)
	}
	for _, line := range []string{"stock-b-modified", "user-custom"} {
		if !strings.Contains(content, line) {
			t.Fatalf("overrides missing %q: %q", line, content)
		}
	}
	if strings.Contains(content, "stock-a") {
		t.Fatalf("overrides should not contain stock lines: %q", content)
	}

	// And the migration was logged with the extracted line count
	logData, err := os.ReadFile(CRSUpdateLogPath())
	if err != nil || !strings.Contains(string(logData), "已迁移 2 行用户自定义配置到 zz-user-overrides.conf") {
		t.Fatalf("crs-update.log=%q,%v, want migration entry with count", logData, err)
	}
}

func TestCRSUpdateRun_firstMigrationDiffsAgainstDistBaseline(t *testing.T) {
	// Given no stock baseline file (pre-migration install) but the image dist copy
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	distDir := t.TempDir()
	oldDistDir := crsDistDir
	crsDistDir = distDir
	t.Cleanup(func() { crsDistDir = oldDistDir })
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "SecRuleEngine On\nSecRequestBodyAccess On\n")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"),
		"SecRuleEngine On\nSecRequestBodyAccess On\nSecRule ARGS \"@rx attack\" \"id:1001,deny\"\n")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "SecRuleEngine On\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When the update runs
	m.run("manual")

	// Then only the user line was migrated, proving the dist baseline was used
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil {
		t.Fatalf("zz-user-overrides.conf missing: %v", err)
	}
	content := string(overrides)
	if !strings.Contains(content, `SecRule ARGS "@rx attack" "id:1001,deny"`) {
		t.Fatalf("overrides missing user rule: %q", content)
	}
	if strings.Contains(content, "SecRequestBodyAccess") {
		t.Fatalf("overrides should not contain dist baseline lines: %q", content)
	}
}

func TestCRSUpdateRun_rollbackRestoresPreviousLiveSetup(t *testing.T) {
	// Given a stock baseline path blocked by a stray directory, so the
	// baseline rewrite fails after the new setup was installed
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	if err := os.MkdirAll(filepath.Join(m.crsDir, "crs-setup.stock.conf"), 0755); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the update fails during the baseline write
	m.run("manual")

	// Then the previous live setup and rules are restored
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# tweaked" {
		t.Fatalf("crs-setup.conf=%q, want restored previous setup", setup)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("rules backup should have been restored")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); !os.IsNotExist(err) {
		t.Fatal("new rules should be rolled back")
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (reload after restore)", reloads)
	}

	// And the overrides freshly written during the failed attempt is removed:
	// restoring it would re-apply the same custom lines alongside the restored
	// setup（R37 S3）
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); !os.IsNotExist(err) {
		t.Fatal("zz-user-overrides.conf written during the failed attempt should be removed on rollback")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("zz-user-overrides.conf.bak should be consumed")
	}
}

// TestRestoreBackup_restoreFailureKeepsOverridesBak 验证 overrides 内容还原失败时
// 保留 .bak——唯一恢复副本不得在失败路径被销毁，否则「旧 setup + 新 overrides」
// 双重应用状态失去恢复副本、不可自愈（R38 三-1，对照 setup 段失败即保留的行为）。
func TestRestoreBackup_restoreFailureKeepsOverridesBak(t *testing.T) {
	// Given backups in place and a restore target occupied by a directory
	// (copyFile's WriteFile fails with EISDIR)
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules.bak", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf.bak"), "# previous")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# clobbered")
	if err := os.Mkdir(filepath.Join(m.crsDir, "zz-user-overrides.conf"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"), "# 更新前 overrides\nSecRuleARCustom 1")

	// When the backup is restored
	m.overridesBakCreated = true // 本运行已创建 bak（R39 1.1）：还原失败时保留 .bak
	m.restoreBackup()

	// Then the failed overrides restore keeps the only recovery copy
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak")); err != nil {
		t.Fatal("zz-user-overrides.conf.bak 不得在还原失败时被删除（R38 三-1）")
	}
	// And the independent setup/rules restore still completes
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# previous" {
		t.Fatalf("crs-setup.conf=%q, want restored backup", setup)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("rules backup should have been restored")
	}
}

// TestRestoreBackup_emptyMarkerRemoveFailureKeepsMarker 验证空 .bak 标记分支的
// os.Remove(overrides) 失败时同样保留标记，下次还原可重试（R38 三-1）。
func TestRestoreBackup_emptyMarkerRemoveFailureKeepsMarker(t *testing.T) {
	// Given backups in place and a freshly created overrides path that cannot
	// be removed (non-empty directory → ENOTEMPTY)
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules.bak", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf.bak"), "# previous")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# clobbered")
	if err := os.MkdirAll(filepath.Join(m.crsDir, "zz-user-overrides.conf", "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"), "")

	// When the backup is restored
	m.overridesBakCreated = true // 本运行已创建 bak（R39 1.1）：消费空标记时移除失败则保留
	m.restoreBackup()

	// Then the empty marker survives so a later restore can retry
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak")); err != nil {
		t.Fatal("空标记不得在移除失败时被消费（R38 三-1）")
	}
}

// TestCRSUpdateRun_staleOverridesBakNotConsumedOnEmptyDiffFailure 验证陈旧
// overrides.bak 不被空 diff 运行消费（R38 三-2 由 R39 1.1 闭合）：上次运行在
// reload 成功与清理之间崩溃留下的 N-1 版 .bak，在本运行 diff 为空（无迁移、无
// 新备份）且安装失败时，restoreBackup 不消费它——overrides 保持更新前内容、
// 不被两版本前的陈旧备份还原；.bak 原样保留（陈旧 bak 永不消费，保全副本语义
// 优先，R39 1.1 取代 R38 的运行开始即清理）。
func TestCRSUpdateRun_staleOverridesBakNotConsumedOnEmptyDiffFailure(t *testing.T) {
	// Given a live setup identical to the stock baseline (empty diff) plus a
	// stale overrides backup left by a crashed previous run
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "stock-a\nstock-b\n")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "stock-a\nstock-b\n")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# 当前 overrides\nSecRuleARCustom 2")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"), "# 两版本前的 overrides\nSecRuleARCustom 1")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "stock-a\nstock-b\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})
	m.reloader = func() error { return errors.New("注入的重载失败") }

	// When the update fails after installing the new rules (restoreBackup runs)
	m.run("manual")

	// Then the run failed
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	// And the overrides were not polluted by the two-versions-stale backup:
	// restoreBackup leaves overrides untouched（陈旧 bak 未被消费，R39 1.1）
	data, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil || string(data) != "# 当前 overrides\nSecRuleARCustom 2" {
		t.Fatalf("zz-user-overrides.conf=%q,%v, want untouched current content（陈旧 bak 不得还原两版本前内容）", data, err)
	}
	// 陈旧 .bak 原样保留：R39 1.1 改为永不消费跨运行 bak（保全语义优先），
	// 替代 R38 的「运行开始即清理」——该清理会毁掉三-1 保全的唯一恢复副本。
	bakData, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"))
	if err != nil || string(bakData) != "# 两版本前的 overrides\nSecRuleARCustom 1" {
		t.Fatalf("stale zz-user-overrides.conf.bak=%q,%v, want preserved（R39 1.1）", bakData, err)
	}
}

func TestCRSUpdateRun_installsStockSetupWhenNoneExists(t *testing.T) {
	// Given a live rules tree without any crs-setup.conf
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "stock-setup\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When the update runs
	m.run("manual")

	// Then the stock setup is installed and recorded as baseline, no overrides
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf"} {
		data, err := os.ReadFile(filepath.Join(m.crsDir, name))
		if err != nil || string(data) != "stock-setup\n" {
			t.Fatalf("%s=%q,%v, want stock setup", name, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); !os.IsNotExist(err) {
		t.Fatal("no overrides file should be written when there is nothing to migrate")
	}
}

// TestRestoreBackup_restoresSetupAndLeavesArtifactsWithoutBak 验证无 overrides
// 备份标记（本次运行未写 overrides）时，restoreBackup 不动 overrides 与 stock
// 基线（R37 S3：恢复只撤销本次迁移的写入）。
func TestRestoreBackup_restoresSetupAndLeavesArtifactsWithoutBak(t *testing.T) {
	// Given backups in place, clobbered live files, and migration artifacts
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules.bak", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf.bak"), "# previous")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-NEW.conf"), "SecRule new")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# clobbered")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# migrated")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# stock")

	// When the backup is restored
	m.restoreBackup()

	// Then rules and setup are back and the backups consumed
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("rules backup not restored")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-NEW.conf")); !os.IsNotExist(err) {
		t.Fatal("clobbered rules should be gone")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("rules.bak should be consumed")
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# previous" {
		t.Fatalf("crs-setup.conf=%q, want restored backup", setup)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "crs-setup.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("crs-setup.conf.bak should be consumed")
	}

	// And the migration artifacts without a backup marker are untouched
	for name, want := range map[string]string{
		"zz-user-overrides.conf": "# migrated",
		"crs-setup.stock.conf":   "# stock",
	} {
		data, err := os.ReadFile(filepath.Join(m.crsDir, name))
		if err != nil || string(data) != want {
			t.Fatalf("%s=%q,%v, want untouched %q", name, data, err, want)
		}
	}
}

// TestRestoreBackup_restoresPreexistingOverridesFromBak 验证 overrides 在更新前
// 已存在（.bak 有内容）时，restoreBackup 恢复更新前内容并消费 .bak（R37 S3）。
func TestRestoreBackup_restoresPreexistingOverridesFromBak(t *testing.T) {
	// Given backups in place, clobbered live files, and a content .bak
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules.bak", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf.bak"), "# previous")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# clobbered")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# 本次迁移覆写")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"), "# 更新前 overrides\nSecRuleARCustom 1")

	// When the backup is restored
	m.overridesBakCreated = true // 本运行已创建 bak（R39 1.1）：内容 .bak 可被消费
	m.restoreBackup()

	// Then the overrides file is back to its pre-update content and the .bak consumed
	data, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil || string(data) != "# 更新前 overrides\nSecRuleARCustom 1" {
		t.Fatalf("zz-user-overrides.conf=%q,%v, want restored pre-update content", data, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("zz-user-overrides.conf.bak should be consumed")
	}
}

// TestRestoreBackup_removesFreshlyCreatedOverrides 验证 overrides 由本次迁移新建
// （空 .bak 标记）时，restoreBackup 删除该文件——恢复后的配置与更新前一致（R37 S3）。
func TestRestoreBackup_removesFreshlyCreatedOverrides(t *testing.T) {
	// Given backups in place, clobbered live files, and an empty .bak marker
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules.bak", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf.bak"), "# previous")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# clobbered")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# 本次迁移新建")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"), "")

	// When the backup is restored
	m.overridesBakCreated = true // 本运行已创建 bak（R39 1.1）：空标记可被消费
	m.restoreBackup()

	// Then the freshly created overrides file is removed
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); !os.IsNotExist(err) {
		t.Fatal("freshly created zz-user-overrides.conf should be removed")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("zz-user-overrides.conf.bak should be consumed")
	}
}
