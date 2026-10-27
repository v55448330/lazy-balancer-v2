package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 备份目录的最终 rename 失败必须保住上一份可用备份，且不残留暂存树。
func TestCopyDirTransactional_renameFailureRestoresOldAndCleansTmp(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writeTestFile(t, filepath.Join(src, "a.conf"), "SecRule new")
	writeTestFile(t, filepath.Join(dst, "a.conf"), "SecRule old")

	oldRename := copyDirRename
	copyDirRename = func(src, target string) error {
		if src == dst+".tmp" && target == dst {
			return errors.New("rename blocked")
		}
		return oldRename(src, target)
	}
	t.Cleanup(func() { copyDirRename = oldRename })
	if err := copyDirTransactional(src, dst); err == nil {
		t.Fatal("copyDirTransactional should fail when the final rename is blocked")
	}
	data, err := os.ReadFile(filepath.Join(dst, "a.conf"))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("previous backup must be restored: data=%q err=%v", data, err)
	}
	for _, path := range []string{dst + ".tmp", dst + ".old"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("successful rollback must not leave %s: %v", path, err)
		}
	}
}

func TestCopyDirTransactional_renameFailureShapes(t *testing.T) {
	t.Run("first rename keeps destination untouched", func(t *testing.T) {
		root := t.TempDir()
		src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
		writeTestFile(t, filepath.Join(src, "a.conf"), "new")
		writeTestFile(t, filepath.Join(dst, "a.conf"), "old")
		oldRename := copyDirRename
		copyDirRename = func(src, target string) error {
			if src == dst && target == dst+".old" {
				return errors.New("first rename blocked")
			}
			return oldRename(src, target)
		}
		t.Cleanup(func() { copyDirRename = oldRename })
		if err := copyDirTransactional(src, dst); err == nil {
			t.Fatal("first rename failure must be returned")
		}
		data, err := os.ReadFile(filepath.Join(dst, "a.conf"))
		if err != nil || string(data) != "old" {
			t.Fatalf("destination changed after first rename failure: %q, %v", data, err)
		}
	})

	t.Run("rollback failure preserves old tree under old suffix", func(t *testing.T) {
		root := t.TempDir()
		src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
		writeTestFile(t, filepath.Join(src, "a.conf"), "new")
		writeTestFile(t, filepath.Join(dst, "a.conf"), "old")
		oldRename := copyDirRename
		copyDirRename = func(src, target string) error {
			if src == dst+".tmp" && target == dst || src == dst+".old" && target == dst {
				return errors.New("rename blocked")
			}
			return oldRename(src, target)
		}
		t.Cleanup(func() { copyDirRename = oldRename })
		if err := copyDirTransactional(src, dst); err == nil {
			t.Fatal("install and rollback failures must be returned")
		}
		data, err := os.ReadFile(filepath.Join(dst+".old", "a.conf"))
		if err != nil || string(data) != "old" {
			t.Fatalf("only previous backup was lost: %q, %v", data, err)
		}
	})

	t.Run("success replaces destination and removes old tree", func(t *testing.T) {
		root := t.TempDir()
		src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
		writeTestFile(t, filepath.Join(src, "a.conf"), "new")
		writeTestFile(t, filepath.Join(dst, "a.conf"), "old")
		if err := copyDirTransactional(src, dst); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dst, "a.conf"))
		if err != nil || string(data) != "new" {
			t.Fatalf("new backup not installed: %q, %v", data, err)
		}
		if _, err := os.Stat(dst + ".old"); !os.IsNotExist(err) {
			t.Fatalf("old backup residue remains: %v", err)
		}
	})
}

// TestRestoreBackup_partialRulesBakWithoutProbeSkipped 验证：rules.bak
// 含若干.conf 但缺探针文件（裸 copyDir 留下的部分残树）时
// restoreBackup 拒绝消费——「≥1 个 .conf」的旧门会放行它，用部分树替换完整
// live 树，WAF 规则数量静默减少。
func TestRestoreBackup_partialRulesBakWithoutProbeSkipped(t *testing.T) {
	// Given 缺探针文件的部分残树 rules.bak 与完好的 live 规则树
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), "REQUEST-900.conf"), "SecRule a")
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.bak"), "REQUEST-941.conf"), "SecRule b")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule live")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# live")

	// When 尝试还原备份
	m.rulesBakCreated = true // 本运行已创建 rules.bak（守卫——守卫之后仍由探针门拦截）
	m.restoreBackup()

	// Then live 规则树未被部分 bak 替换，bak 留在原地供排查（未消费）
	data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule live" {
		t.Fatalf("live rules must be untouched when rules.bak lacks the probe file: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatal("partial bak content must not land in live rules")
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak")); err != nil {
		t.Fatal("partial rules.bak should be left in place (not consumed)")
	}
}

// TestCRSUpdateRun_successCleansRulesOldResidue 验证：成功路径清理
// 上一次失败更新崩溃窗口留下的 rules.old 残留——否则它只能等下一次失败的
// 更新才被 restoreRulesBackup 开头清理，可长期占用一整棵规则树的磁盘。
func TestCRSUpdateRun_successCleansRulesOldResidue(t *testing.T) {
	// Given 完好的 live 树、rules.old 残留与一次可成功的更新
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	writeTestFile(t, filepath.Join(crsTransientPath(m.crsDir, "rules.old"), crsRulesProbeFile), "SecRule stale")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":                "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901-INITIALIZATION.conf": "SecRule a\n",
	})

	// When 更新成功
	m.run("manual", nil)

	// Then rules.old 残留被成功路径清理
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.old")); !os.IsNotExist(err) {
		t.Fatal("rules.old residue should be cleaned on the success path (历史修复)")
	}
}

// TestSeedCRSRules_partialLiveTreeIsReseeded 验证：崩溃窗口
// （moveTree copyDir 回退直写 live 中途崩溃）留下的部分规则树——目录存在、
// 有 .conf 但缺探针文件——不得让 SeedCRSRules 早退，应清除后重新播种。
func TestSeedCRSRules_partialLiveTreeIsReseeded(t *testing.T) {
	// Given 缺探针文件的部分 live 规则树与完好的 dist 副本
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-900.conf"), "SecRule partial")
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When 播种
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then 部分残树被清除并从 dist 重新播种，版本标记落到 bundled
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("partial live tree should be reseeded from dist: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatal("partial tree residue must be cleared before reseeding")
	}
	if got := readCRSVersionMarker(liveDir); got != CRSBundledVersion {
		t.Fatalf("live marker=%q, want bundled %q", got, CRSBundledVersion)
	}
}

// TestIP2RegionUpdateRun_failOpenMessageCarriesRollbackCause 验证
// 回滚升级链全部失败走 fail-open 时，DB message 必须携带回滚失败根因
// （「回滚旧库失败」）——仅进组件日志会让运维把磁盘/DB 状态误判为纯重载问题。
// 形态：reloader 持续失败 + 本运行备份被移走 + dist 源为目录（copy 级必败）
// → live 仍是本次已验证的新工件（fail-open 前提成立）但回滚报错。
func TestIP2RegionUpdateRun_failOpenMessageCarriesRollbackCause(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if err := os.WriteFile(ip2regionLivePath, []byte("old-live-content"), 0644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(ip2regionLivePath)
	// dist 用目录形态：rollback 的 dist 级 copyFile 必然失败，而 live 保持
	// 新工件（rename/copy 级因备份缺失同样失败）。
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(dist, 0755); err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, ip2regionLivePath, dist)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error {
		// 移走本运行备份：rename/copy 还原级必败，dist 级（目录）也必败 →
		// rollbackXDB 返回错误而 live 仍是已验证的新工件。
		if err := os.Remove(ip2regionLivePath + ".bak"); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove bak for rollback failure: %v", err)
		}
		return errors.New("reload boom")
	}

	// When 安装成功、reloader 持续失败、回滚链全败但 live 仍是新工件
	m.run("manual", nil)

	// Then fail-open 按成功落库，且 message 携带回滚失败根因。
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success (live 已是验证过的新工件)", status, message)
	}
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0", version)
	}
	if !strings.Contains(message, "回滚旧库失败") {
		t.Fatalf("fail-open message 必须携带回滚失败根因，got %q", message)
	}
	if !strings.Contains(message, "重载 Caddy 配置失败") {
		t.Fatalf("fail-open message 必须保留 reloader 失败原因，got %q", message)
	}
}
