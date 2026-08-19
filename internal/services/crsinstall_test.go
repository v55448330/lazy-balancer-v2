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
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
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

// TestCRSUpdateRun_installFailureRemovesFreshlyCreatedOverrides 验证审计场景：
// 手动改过 crs-setup.conf（迁移 diff 非空）且 overrides 由本次迁移新建，重载
// 失败后 overrides 被删除、旧 setup 恢复——恢复后的重载不再重复应用同一批
// 自定义行（R37 S3）。
func TestCRSUpdateRun_installFailureRemovesFreshlyCreatedOverrides(t *testing.T) {
	// Given a live setup with user customizations and no pre-existing overrides
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked\nSecRuleARCustom 1")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
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
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# stock baseline")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# 前次迁移产物\nSecRuleARPrev 1")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})
	m.reloader = func() error { return errors.New("reload boom") }

	// When installation fails at the reload step
	m.run("manual")

	// Then the overrides file is back to its pre-update content
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil || string(overrides) != "# 前次迁移产物\nSecRuleARPrev 1" {
		t.Fatalf("zz-user-overrides.conf=%q,%v, want restored pre-update content", overrides, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak")); !os.IsNotExist(err) {
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
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"), "# 保全内容\nSecRulePreserved 1")
	if err := os.MkdirAll(filepath.Join(m.crsDir, "crs-setup.conf.bak"), 0755); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When N+1 在创建新 bak 前失败
	m.run("manual")

	// Then 保全副本原样保留，overrides 未被本次迁移触碰
	data, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"))
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
