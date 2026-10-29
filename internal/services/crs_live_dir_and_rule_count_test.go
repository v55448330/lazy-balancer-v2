package services

import (
	"path/filepath"
	"testing"
)

// liveDir 必须晚绑定全局 crsLiveDir：ConfigureWafDirs（自定义 data_dir）在
// 构造函数之后运行，构造期快照会让更新写相位落到旧路径而渲染读相位读新路径
// （「更新成功但规则不变 / 写只读路径失败」）。
func TestCRSUpdateManager_liveDirFollowsConfiguredWafDirs(t *testing.T) {
	redirectUpdateTestGlobals(t)
	m := newCRSUpdateManager(func() error { return nil })
	if m.crsDir != "" {
		t.Fatalf("生产构造不得快照 live 目录: %q", m.crsDir)
	}
	if got := m.liveDir(); got != crsLiveDir {
		t.Fatalf("liveDir()=%q, want 全局 crsLiveDir=%q", got, crsLiveDir)
	}
	late := filepath.Join(t.TempDir(), "late-waf", "crs")
	t.Cleanup(OverrideWafLivePathsForTest(late, ip2regionLivePath))
	if got := m.liveDir(); got != late {
		t.Fatalf("构造后改 ConfigureWafDirs 必须立即生效: liveDir()=%q want %q", got, late)
	}
	// 测试注入覆盖仍然优先（既有夹具依赖字段注入）。
	m.crsDir = filepath.Join(t.TempDir(), "injected")
	if got := m.liveDir(); got != m.crsDir {
		t.Fatalf("注入覆盖必须优先: %q != %q", got, m.crsDir)
	}
}

// 规则计数必须与完整性探针同口径（递归全树 .conf）：rules/ 出现子目录时
// 非递归计数会「库可用但 rule_count=0」，面板规则库卡片显示 0 条。
func TestCountSecRules_countsNestedRuleFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "REQUEST-901.conf"), "SecRule a\n")
	writeTestFile(t, filepath.Join(dir, "nested", "REQUEST-902.conf"), "SecRule b\nSecRule c\n")
	writeTestFile(t, filepath.Join(dir, "nested", "notes.txt"), "SecRule ignored\n")

	got, err := countSecRules(dir)
	if err != nil {
		t.Fatalf("countSecRules: %v", err)
	}
	if got != 3 {
		t.Fatalf("SecRule 计数=%d, want 3（递归 .conf，忽略非 .conf）", got)
	}
}
