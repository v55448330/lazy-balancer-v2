package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// forceRenameFailure makes every rename fail, simulating Docker overlayfs
// EXDEV when the source lives in an image-baked lower layer.
func forceRenameFailure(t *testing.T) {
	t.Helper()
	old := osRename
	osRename = func(_, _ string) error { return errors.New("forced: invalid cross-device link") }
	t.Cleanup(func() { osRename = old })
}

// assertNoTempResidue 断言目录内无原子写临时文件残留。
// writeFileAtomicSynced / copyFile 的临时名为 .<base>-<rand>.tmp（CreateTemp
// 模板），固定名 <dst>.tmp 从不存在——按固定名断言恒真、对临时文件泄漏完全
// 无感，故按目录 glob 断言。
func assertNoTempResidue(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil {
		t.Fatalf("glob tmp residue: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("原子写临时文件残留: %v", matches)
	}
}

func TestCopyFile_atomicWriteNoTmpResidue(t *testing.T) {
	// Given：copyFile 原子落盘（自此为同目录唯一临时名
	// .<base>-<rand>.tmp + fsync；成功后只留目标文件）
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
	assertNoTempResidue(t, filepath.Dir(dst))
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
	assertNoTempResidue(t, filepath.Dir(dst))
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

// TOFU 完整性门：同一 tag 的发布包内容变化（上游同 tag 被替换/中间人）必须
// 阻断安装——live 规则树与 setup 保持上次成功产物，且不引入新文件。此前
// 更新族测试未隔离基线文件：/app/data 可写时首次用例写基线、第二次同 tag
// 不同字节即误红；不可写时该门恒不被断言（假绿）。
func TestCRSUpdateRun_sameTagContentChangeIsBlockedByTOFU(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	first := map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# setup-v1",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule first\n",
	}
	m.downloadTarball = fakeCRSDownload(t, first)
	if err := m.downloadAndInstall(context.Background(), "v4.15.0"); err != nil {
		t.Fatalf("首次安装应成功: %v", err)
	}
	liveSetup := filepath.Join(m.crsDir, "crs-setup.conf")
	before, err := os.ReadFile(liveSetup)
	if err != nil {
		t.Fatalf("读取首次安装产物: %v", err)
	}

	// 同 tag 内容变化
	second := map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# setup-v2",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule second\n",
		"coreruleset-4.15.0/rules/REQUEST-902.conf":     "SecRule injected\n",
	}
	m.downloadTarball = fakeCRSDownload(t, second)
	err = m.downloadAndInstall(context.Background(), "v4.15.0")
	if !errors.Is(err, errDownloadIntegrityMismatch) {
		t.Fatalf("同 tag 内容变化必须被 TOFU 门阻断，err=%v", err)
	}
	after, rerr := os.ReadFile(liveSetup)
	if rerr != nil {
		t.Fatalf("读取 live setup: %v", rerr)
	}
	if string(after) != string(before) {
		t.Fatalf("live crs-setup.conf 被替换（TOFU 门未在替换前阻断）: %q → %q", before, after)
	}
	if _, statErr := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-902.conf")); !os.IsNotExist(statErr) {
		t.Fatal("被阻断的发布包不得留下新规则文件")
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
	m.run("manual", nil)

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

// TestCRSUpdateRun_backupCopyFailureLeavesNoPartialRulesBak 验证
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
	m.run("manual", nil)

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
		t.Fatal("partial rules.bak must not exist after a failed backup copy")
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak.tmp")); !os.IsNotExist(err) {
		t.Fatal("rules.bak.tmp staging must be cleaned up after a failed backup copy")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-900.conf")); err != nil {
		t.Fatal("live rules tree must be untouched")
	}
	if _, err := os.Lstat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatal("live rules tree must stay complete: a partial bak must not replace it")
	}
}

// TestCRSUpdateRun_installFailureRemovesFreshlyCreatedOverrides 验证审计场景：
// 手动改过 crs-setup.conf（迁移 diff 非空）且 overrides 由本次迁移新建，重载
// 失败后 overrides 被删除、旧 setup 恢复——恢复后的重载不再重复应用同一批
// 自定义行。
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
	m.run("manual", nil)

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
	marker, err := os.ReadFile(filepath.Join(m.crsDir, "VERSION"))
	if err != nil || strings.TrimSpace(string(marker)) != "v4.14.0" {
		t.Fatalf("VERSION=%q,%v, want rolled back v4.14.0", strings.TrimSpace(string(marker)), err)
	}
}

// TestCRSUpdateRun_installFailureRestoresPreexistingOverrides 验证 overrides 在
// 更新前已存在（前次迁移产物）时，安装失败后其内容被还原而非保留本次覆写。
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
	m.run("manual", nil)

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

// TestCRSUpdateRun_preservedOverridesBakSurvivesNextRunFailure 验证 1.1
// 运行 N 因还原失败保全的 zz-user-overrides.conf.bak（三-1 唯一恢复副本），在
// 运行 N+1 创建新备份前失败时不得被先行清除——旧实现无条件 os.Remove 会在
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
	m.run("manual", nil)

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

// 裁定 2026-09-07（残余项处置）：CRS 更新触发的真实 Caddy 重载统一留痕。
func TestCRSUpdate_recordsReloadAudit(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return nil }
	m.run("manual", nil)

	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务' AND detail LIKE '%CRS 规则库更新%'").Scan(&n); err != nil {
		t.Fatalf("query reload audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("reload audit rows=%d, want 1（真实重载必须留痕）", n)
	}
}

func TestCRSUpdate_recordsReloadFailureAudit(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return errors.New("reload boom") }
	m.run("manual", nil)

	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy服务' AND detail LIKE '%CRS 规则库更新%'").Scan(&n); err != nil {
		t.Fatalf("query reload failure audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("reload failure audit rows=%d, want 1", n)
	}
}

// 重载失败回滚（树还原 + VERSION 标记 + DB 版本行）
// 必须在同一 wafFileMu 临界区内完成——旧实现 restoreBackup 取锁后立即释放，
// 标记/版本行锁外写（持锁读者可见「旧树+新标记」，并发导入可被覆盖标记）。
func TestCRSRollbackAfterReloadFailure_blocksWhileWafFileLockHeld(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.15.0", true) // DB 行已是新版本（待回滚）
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-901-INITIALIZATION.conf"), "SecRule live")
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), "REQUEST-901-INITIALIZATION.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.15.0\n")
	m.rulesBakCreated = true // 本运行已创建 rules.bak

	probeBlocksUnderWafFileLock(t, "CRS 重载失败回滚（树+VERSION+版本行）", func() error {
		m.rollbackAfterReloadFailure("v4.14.0")
		return nil
	})

	data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", "REQUEST-901-INITIALIZATION.conf"))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("rules 树未回滚: %q,%v", data, err)
	}
	if got := readCRSVersionMarker(m.crsDir); got != "v4.14.0" {
		t.Fatalf("VERSION 标记=%q, want v4.14.0（同代回滚）", got)
	}
	var version string
	if err := db.DB.QueryRow(`SELECT version FROM security_crs_version WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "v4.14.0" {
		t.Fatalf("DB 版本行=%q, want v4.14.0（恢复下轮重试能力）", version)
	}
}

// rules/setup/stock.bak 无「本运行创建」守卫——上一
// 运行在「备份已建→清理前」崩溃残留的完整备份，会在本运行到达备份点前失败
// （如下载失败走 fail(..., true)）时被 restoreBackup 无条件消费：live 树/setup
// 被回滚到崩溃前状态（若崩溃发生在 swap 后则与 DB 版本行分叉，同形态；
// 同版本也会回滚用户崩溃后的 setup 手改）。修复：镜像 overridesBakCreated
// 为三类备份补「本运行创建」标记，陈旧备份永不消费、原样保全
// （崩溃现场唯一恢复素材，与 overrides.bak 三-1 保全语义一致）。
func TestCRSUpdateRun_staleBaksNotConsumedOnEarlyFailure(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	// live 现状：上一运行崩溃后用户又手改了 setup
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule live-current")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# user tweaked after crash")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# current stock")
	// 上一运行崩溃残留的完整备份（「备份已建→清理前」窗口）
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), crsRulesProbeFile), "SecRule stale")
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.conf.bak"), "# ancient setup")
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.stock.conf.bak"), "# ancient stock")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("network down")
	}
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When 本运行下载失败（尚未到备份创建点）
	m.run("manual", nil)

	// Then 失败落库，live 树/setup/stock 原样保留（陈旧备份未被消费）
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile)); string(data) != "SecRule live-current" {
		t.Fatalf("live rules 被陈旧 rules.bak 覆盖: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf")); string(data) != "# user tweaked after crash" {
		t.Fatalf("live crs-setup.conf 被陈旧备份覆盖: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.stock.conf")); string(data) != "# current stock" {
		t.Fatalf("live crs-setup.stock.conf 被陈旧备份覆盖: %q", data)
	}
	// 陈旧备份原样保全（崩溃现场唯一恢复素材）
	for _, name := range []string{"rules.bak", "crs-setup.conf.bak", "crs-setup.stock.conf.bak"} {
		if _, err := os.Stat(crsTransientPath(m.crsDir, name)); err != nil {
			t.Fatalf("陈旧备份 %s 不得被消费/删除: %v", name, err)
		}
	}
}

// 回滚契约：restoreBackupInLock 返回 true 必须意味着「live 规则树已完整还原
// 到更新前状态」。两种「树未还原」形态不得按已还原上报——否则
// rollbackAfterReloadFailure 会把旧版本号（prevTag）写到仍是新树的
// VERSION 标记与 DB 版本行（版本行是 crsPoolFingerprint 池键输入，跨代态可
// 复用旧 coraza 池实例、新规则静默不生效）。
func TestCRSRollbackAfterReloadFailure_noBackupKeepsNewVersion(t *testing.T) {
	t.Run("无本运行备份", func(t *testing.T) {
		m := newTestCRSManager(t)
		seedCRSVersionRow(t, "v4.15.0", true) // DB 行已是新版本
		// live 是本运行安装的新树且完整（首装/带外清空旧树后直达交换的形态——
		// 备份点无旧树可备份，rulesBakCreated 保持 false）
		writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule new")
		writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.15.0\n")

		m.rollbackAfterReloadFailure("v4.14.0")

		// 树未还原 → 旧版本号不得回写（保留新版本，待下次成功更新/启动对账收敛）
		if got := readCRSVersionMarker(m.crsDir); got != "v4.15.0" {
			t.Fatalf("VERSION 标记=%q, want v4.15.0（无备份时不得回写旧版本到新树）", got)
		}
		if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.15.0" {
			t.Fatalf("DB 版本行=%q, want v4.15.0（无备份时不得回写旧版本到新树）", version)
		}
	})

	t.Run("本运行备份不可读", func(t *testing.T) {
		m := newTestCRSManager(t)
		seedCRSVersionRow(t, "v4.15.0", true)
		writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule new")
		writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.15.0\n")
		m.rulesBakCreated = true // 本运行已建备份，但备份目录被带外移走

		m.rollbackAfterReloadFailure("v4.14.0")

		if got := readCRSVersionMarker(m.crsDir); got != "v4.15.0" {
			t.Fatalf("VERSION 标记=%q, want v4.15.0（备份不可读时不得回写旧版本到新树）", got)
		}
		if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.15.0" {
			t.Fatalf("DB 版本行=%q, want v4.15.0（备份不可读时不得回写旧版本到新树）", version)
		}
	})
}

// 回归形状（正向）：陈旧备份在场时，本运行到达备份点会用新备份覆盖
// 之（复制覆写语义不变），失败路径消费的是本运行备份——live 回到「本次更新前」
// 状态而非崩溃前的陈旧状态。
func TestCRSUpdateRun_thisRunBaksConsumedOnSwapFailure(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule live-v414")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# user setup")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# stock")
	// 陈旧备份与 live 内容不同——若被消费会留下可观测的错误内容
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), crsRulesProbeFile), "SecRule stale")
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.conf.bak"), "# ancient setup")
	writeTestFile(t, crsTransientPath(m.crsDir, "crs-setup.stock.conf.bak"), "# ancient stock")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return errors.New("reload boom") }

	// When 本运行完成备份与树交换、重载失败回滚
	m.run("manual", nil)

	// Then 回滚消费的是本运行备份：live 恢复为「本次更新前」内容（非陈旧备份），
	// 备份全部消费清理，版本行回滚 v4.14.0 + failed
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile)); string(data) != "SecRule live-v414" {
		t.Fatalf("live rules 未由本运行备份还原: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf")); string(data) != "# user setup" {
		t.Fatalf("live crs-setup.conf 未由本运行备份还原: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.stock.conf")); string(data) != "# stock" {
		t.Fatalf("live crs-setup.stock.conf 未由本运行备份还原: %q", data)
	}
	for _, name := range []string{"rules.bak", "crs-setup.conf.bak", "crs-setup.stock.conf.bak"} {
		if _, err := os.Stat(crsTransientPath(m.crsDir, name)); !os.IsNotExist(err) {
			t.Fatalf("本运行备份 %s 应被消费清理", name)
		}
	}
	if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.14.0" {
		t.Fatalf("version=%q, want v4.14.0（重载失败同代回滚）", version)
	}
}

// 探针文件必须在拷贝序最后落地：完整性门只以「探针存在」为判据，而
// os.ReadDir 是升序——真实 CRS 树的探针（REQUEST-901-*）排在头部，排序拷贝
// 中断时它已落地，半棵树会被判完整（seed 不重播、备份被当权威旧树）。
func TestCopyDir_copiesProbeLastSoPartialTreeFailsGate(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "rules")
	dst := filepath.Join(root, "copy")
	writeTestFile(t, filepath.Join(src, crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(src, "REQUEST-900-EXCLUSION-RULES.conf"), "SecRule a")
	unreadable := filepath.Join(src, "zz-unreadable.conf")
	writeTestFile(t, unreadable, "SecRule boom")
	if os.Geteuid() == 0 {
		t.Skip("root 忽略文件权限位，无法构造拷贝读失败")
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	if err := copyDir(src, dst); err == nil {
		t.Fatal("读失败条目必须让拷贝报错")
	}
	if _, err := os.Stat(filepath.Join(dst, crsRulesProbeFile)); !os.IsNotExist(err) {
		t.Fatalf("中断的拷贝不得已含探针（否则完整性门误判完整）: %v", err)
	}
	if crsRulesTreeIntact(dst) {
		t.Fatal("半棵树不得过完整性门")
	}
}

// moveTree 的 copy 回退必须事务化：直写 dst 中断会在 dst 留半棵树，而
// 完整性门只看探针——探针一旦落地，半树被当作完整树。dst 必须保持「不存在
// 或上一代完整树」，残片只允许留在已清理的 .tmp。
func TestMoveTree_copyFallbackLeavesNoPartialTreeOnFailure(t *testing.T) {
	forceRenameFailure(t)
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writeTestFile(t, filepath.Join(src, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(src, "rules", "REQUEST-900.conf"), "SecRule a")
	unreadable := filepath.Join(src, "rules", "zz-unreadable.conf")
	writeTestFile(t, unreadable, "SecRule boom")
	if os.Geteuid() == 0 {
		t.Skip("root 忽略文件权限位，无法构造回退拷贝读失败")
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	if err := moveTree(src, dst); err == nil {
		t.Fatal("读失败必须让回退拷贝报错")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("失败的回退拷贝不得在 dst 留下半棵树: %v", err)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("暂存树必须清理: %v", err)
	}
}

// 空探针文件（0 字节）等同缺失：完整性门不得把 0 字节探针当完整契约。
func TestCRSRulesTreeIntact_rejectsEmptyProbe(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "REQUEST-900.conf"), "SecRule a")
	writeTestFile(t, filepath.Join(dir, crsRulesProbeFile), "")
	if crsRulesTreeIntact(dir) {
		t.Fatal("0 字节探针不得判完整")
	}
	writeTestFile(t, filepath.Join(dir, crsRulesProbeFile), "SecRule init")
	if !crsRulesTreeIntact(dir) {
		t.Fatal("非空探针 + .conf 必须判完整")
	}
}
