package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forceRenameFailure makes every rename fail, simulating Docker overlayfs
// EXDEV when the source lives in an image-baked lower layer.
func forceRenameFailure(t *testing.T) {
	t.Helper()
	old := osRename
	osRename = func(_, _ string) error { return errors.New("forced: invalid cross-device link") }
	t.Cleanup(func() { osRename = old })
}

func TestCopyFile_atomicWriteNoTmpResidue(t *testing.T) {
	// Given R45 F1-B：copyFile 先写 dst+".tmp" 再原子重命名
	root := t.TempDir()
	src := filepath.Join(root, "src.xdb")
	dst := filepath.Join(root, "sub", "live.xdb")
	writeTestFile(t, src, "full-new-content")

	// When 拷贝成功
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}

	// Then 目标内容完整且无临时文件残留
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "full-new-content" {
		t.Fatalf("dst content=%q,%v", data, err)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file should be renamed away after successful copy")
	}
}

func TestCopyFile_sourceErrorLeavesDstUntouched(t *testing.T) {
	// Given 一个已有内容的目标文件与一个不存在的源
	root := t.TempDir()
	src := filepath.Join(root, "missing.xdb")
	dst := filepath.Join(root, "live.xdb")
	writeTestFile(t, dst, "old-content")

	// When 拷贝失败
	if err := copyFile(src, dst); err == nil {
		t.Fatal("copyFile should fail for missing source")
	}

	// Then 目标文件原样保留（原子拷贝绝不截断旧文件）且无临时文件残留
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "old-content" {
		t.Fatalf("dst should be untouched on source error: %q,%v", data, err)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file should not exist after failed copy")
	}
}

func TestMoveTree_renameSucceeds(t *testing.T) {
	// Given a source tree with a nested file
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writeTestFile(t, filepath.Join(src, "sub", "a.conf"), "SecRule 1")

	// When moving the tree
	if err := moveTree(src, dst); err != nil {
		t.Fatal(err)
	}

	// Then the content lands at dst and src is gone
	data, err := os.ReadFile(filepath.Join(dst, "sub", "a.conf"))
	if err != nil || string(data) != "SecRule 1" {
		t.Fatalf("dst content=%q,%v", data, err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("src should be gone after moveTree")
	}
}

func TestMoveTree_fallsBackToCopyWhenRenameFails(t *testing.T) {
	// Given a source tree and a rename that always fails (overlayfs EXDEV)
	forceRenameFailure(t)
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writeTestFile(t, filepath.Join(src, "rules", "REQUEST-900.conf"), "SecRule 1")
	writeTestFile(t, filepath.Join(src, "rules", "REQUEST-901.conf"), "SecRule 2")

	// When moving the tree
	if err := moveTree(src, dst); err != nil {
		t.Fatal(err)
	}

	// Then every file was copied and the source was removed
	for _, rel := range []string{"rules/REQUEST-900.conf", "rules/REQUEST-901.conf"} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err != nil {
			t.Fatalf("expected %s copied: %v", rel, err)
		}
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("src should be removed after copy fallback")
	}
}

func TestCRSUpdateRun_successWhenRenameUnavailable(t *testing.T) {
	// Given an environment where rename always fails (Docker overlayfs)
	forceRenameFailure(t)
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})

	// When a manual update runs to completion
	m.run("manual")

	// Then the update succeeds despite rename being unavailable
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatal("new rules not in place")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); !os.IsNotExist(err) {
		t.Fatal("old rules should be replaced")
	}
}

// TestCRSUpdateRun_backupCopyFailureLeavesNoPartialRulesBak 验证 R49 B-N2(a)：
// rules→rules.bak 的备份拷贝中途失败（ENOSPC/EIO 类故障）时不得残留部分
// rules.bak——旧实现直接 copyDir 到 rules.bak，失败留下残树，restoreBackup
// 无完整性校验即消费它，会把残树搬入 live、WAF 静默削弱。事务化备份
// （tmp 兄弟目录 + 成功后 rename）使残树永远停留在 rules.bak.tmp 并被清理。
func TestCRSUpdateRun_backupCopyFailureLeavesNoPartialRulesBak(t *testing.T) {
	// Given 备份拷贝中途必然失败的 live 规则树：第一个文件可复制，第二个是
	// 悬空符号链接（ReadFile 必败，root 下同样确定性失败）
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-900.conf"), "SecRule a")
	if err := os.Symlink("missing-target", filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})
	m.reloader = func() error { return nil }

	// When 更新在 rules 备份步骤失败
	m.run("manual")

	// Then 不残留部分 rules.bak（或 tmp 暂存）供 restoreBackup 消费，live
	// 规则树完整原样保留（两个文件都在——残树搬入 live 会丢掉 901）
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if !strings.Contains(message, "备份现有 rules") {
		t.Fatalf("message=%q, want the backup failure cause", message)
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("partial rules.bak must not exist after a failed backup copy (R49 B-N2)")
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak.tmp")); !os.IsNotExist(err) {
		t.Fatal("rules.bak.tmp staging must be cleaned up after a failed backup copy")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-900.conf")); err != nil {
		t.Fatal("live rules tree must be untouched")
	}
	if _, err := os.Lstat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatal("live rules tree must stay complete: a partial bak must not replace it (R49 B-N2)")
	}
}

// TestCRSUpdateRun_installFailureRemovesFreshlyCreatedOverrides 验证审计场景：
// 手动改过 crs-setup.conf（迁移 diff 非空）且 overrides 由本次迁移新建，重载
// 失败后 overrides 被删除、旧 setup 恢复——恢复后的重载不再重复应用同一批
// 自定义行（R37 S3）。
func TestCRSUpdateRun_installFailureRemovesFreshlyCreatedOverrides(t *testing.T) {
	// Given a live setup with user customizations and no pre-existing overrides
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked\nSecRuleARCustom 1")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})
	reloads := 0
	// 首次重载（安装后）失败触发恢复；恢复后的重载成功（旧 setup + 无 overrides
	// 重复行，不再被 coraza 拒绝）
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When installation fails at the reload step
	m.run("manual")

	// Then the update is failed, the old setup is back, and the freshly created
	// overrides file is gone——restore 后 reload 成功（第二次重载返回 nil）
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if !strings.Contains(message, "reload boom") {
		t.Fatalf("message=%q, want the reload cause", message)
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# tweaked\nSecRuleARCustom 1" {
		t.Fatalf("crs-setup.conf=%q, want preserved pre-update setup", setup)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); !os.IsNotExist(err) {
		t.Fatal("freshly created zz-user-overrides.conf should be removed on restore")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, restore reload succeeds)", reloads)
	}
}

// TestCRSUpdateRun_installFailureRestoresPreexistingOverrides 验证 overrides 在
// 更新前已存在（前次迁移产物）时，安装失败后其内容被还原而非保留本次覆写（R37 S3）。
func TestCRSUpdateRun_installFailureRestoresPreexistingOverrides(t *testing.T) {
	// Given a live setup with user customizations and a pre-existing overrides file
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# stock baseline")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# 前次迁移产物\nSecRuleARPrev 1")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})
	m.reloader = func() error { return errors.New("reload boom") }

	// When installation fails at the reload step
	m.run("manual")

	// Then the overrides file is back to its pre-update content
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil || string(overrides) != "# 前次迁移产物\nSecRuleARPrev 1" {
		t.Fatalf("zz-user-overrides.conf=%q,%v, want restored pre-update content", overrides, err)
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "zz-user-overrides.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("zz-user-overrides.conf.bak should be consumed")
	}
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
}

// TestCRSUpdateRun_preservedOverridesBakSurvivesNextRunFailure 验证 R39 1.1：
// 运行 N 因还原失败保全的 zz-user-overrides.conf.bak（三-1 唯一恢复副本），在
// 运行 N+1 创建新备份前失败时不得被先行清除——旧实现 L91 无条件 os.Remove 会在
// 新备份尚未创建时毁掉该副本，恢复路径全失。
func TestCRSUpdateRun_preservedOverridesBakSurvivesNextRunFailure(t *testing.T) {
	// Given 运行 N 保全的 overrides 备份 + N+1 备份 crs-setup.conf 时失败
	//（目标位置被目录占用，copyFile 必然失败）
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	writeTestFile(t, crsTransientPath(m.crsDir, "zz-user-overrides.conf.bak"), "# 保全内容\nSecRulePreserved 1")
	if err := os.MkdirAll(crsTransientPath(m.crsDir, "crs-setup.conf.bak"), 0755); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})

	// When N+1 在创建新 bak 前失败
	m.run("manual")

	// Then 保全副本原样保留，overrides 未被本次迁移触碰
	data, err := os.ReadFile(crsTransientPath(m.crsDir, "zz-user-overrides.conf.bak"))
	if err != nil || string(data) != "# 保全内容\nSecRulePreserved 1" {
		t.Fatalf("preserved overrides .bak lost after failed run: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); !os.IsNotExist(err) {
		t.Fatal("zz-user-overrides.conf should not exist before migration")
	}
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
}
