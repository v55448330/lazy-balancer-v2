package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 集群同步与 lbbak 导入共用 ApplyWafFileBundle 落盘 live CRS 树，
// CRS 落盘成功后必须让 /security/crs 的规则数缓存失效（此前仅进程重启或
// 下一次成功更新才收敛）。
func TestApplyWafFileBundle_invalidatesCRSRuleCount(t *testing.T) {
	src := t.TempDir()
	srcRules := filepath.Join(src, "crs", "rules")
	if err := os.MkdirAll(srcRules, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRules, "REQUEST-900.conf"), []byte("SecRule a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "crs", "VERSION"), []byte("v4.14.0"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(src, "crs"), filepath.Join(src, "ip2region.xdb")))

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 {
		t.Fatalf("bundle 未携带 CRS 内容: %+v", bundle)
	}

	// 管理器指向独立的空 live 树，先预热缓存（0 条规则）。
	liveDir := filepath.Join(t.TempDir(), "crs")
	if err := os.MkdirAll(filepath.Join(liveDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = liveDir
	oldMgr := crsUpdateManager
	crsUpdateManager = m
	t.Cleanup(func() { crsUpdateManager = oldMgr })
	if got := m.RuleCount(); got != 0 {
		t.Fatalf("预热 RuleCount=%d, want 0", got)
	}

	t.Cleanup(OverrideWafLivePathsForTest(liveDir, ip2regionLivePath))
	changed, _, _, err := ApplyWafFileBundle(bundle)
	if err != nil || !changed {
		t.Fatalf("apply crsChanged=%v err=%v", changed, err)
	}
	if got := m.RuleCount(); got != 1 {
		t.Fatalf("带外替换后 RuleCount=%d, want 1（缓存未失效）", got)
	}
}

// 失败路径同样可能改写 live 树：入口 .sync-bak 自愈会回滚整棵树，替换段的
// 失败恢复会把旧树拷回。规则数缓存必须随树变更失效，否则面板 rule_count
// 与实际树分叉到进程重启（成功路径的失效钩子覆盖不到此处）。
func TestApplyWafFileBundle_failureInvalidatesCRSRuleCount(t *testing.T) {
	liveDir := filepath.Join(t.TempDir(), "crs")
	if err := os.MkdirAll(filepath.Join(liveDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"), []byte("SecRule old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(OverrideWafLivePathsForTest(liveDir, filepath.Join(t.TempDir(), "ip2region.xdb")))

	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = liveDir
	m.ruleCount = 3
	m.hasRuleCount = true
	oldMgr := crsUpdateManager
	crsUpdateManager = m
	t.Cleanup(func() { crsUpdateManager = oldMgr })

	payload := rawTarGz(t, []tarEntry{{name: "rules/REQUEST-901.conf", body: []byte("SecRule new\n")}})
	bundle := &WafFileBundle{CRSTarGz: payload, CRSSha256: strings.Repeat("0", 64)}
	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil {
		t.Fatal("声明哈希不符必须拒绝落盘")
	}
	m.mu.Lock()
	hasCount := m.hasRuleCount
	m.mu.Unlock()
	if hasCount {
		t.Fatal("失败路径（可能已回滚/恢复 live 树）必须失效规则数缓存")
	}
}
