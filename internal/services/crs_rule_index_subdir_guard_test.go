package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 同一棵 CRS 树的「规则全集」有三种口径：rule_count/完整性探针递归全树，
// 索引与缓存键只扫顶层。发行契约=扁平 rules/ 目录（当前等价）；子目录 .conf
// 出现即契约被打破——守卫必须能检出，索引仍只收顶层规则。
func TestCRSSubdirRuleGuard_detectsNestedConf(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "REQUEST-900.conf"), "SecRule ARGS \"@rx x\" \"id:910001,phase:2,pass\"\n")
	if warnCRSSubdirRuleFiles(filepath.Join(dir, "missing")) {
		t.Fatal("不存在的子目录不得报告命中")
	}

	sub := filepath.Join(dir, "nested")
	writeTestFile(t, filepath.Join(sub, "REQUEST-901.conf"), "SecRule ARGS \"@rx y\" \"id:910002,phase:2,pass\"\n")
	if !warnCRSSubdirRuleFiles(sub) {
		t.Fatal("子目录含 .conf 时守卫必须检出（契约被打破）")
	}

	oldDir := CRSRuleIndexDir
	CRSRuleIndexDir = dir
	t.Cleanup(func() { CRSRuleIndexDir = oldDir })
	index := buildCRSRuleIndex("v-test")
	if len(index.Rules) != 1 || index.Rules[0].File != "REQUEST-900.conf" {
		t.Fatalf("索引=%+v, want 仅顶层一条（CRS 发行契约=扁平目录）", index.Rules)
	}
	_ = os.RemoveAll(sub)
}

// 缓存键只聚合顶层 .conf 的 stat，子目录守卫是「契约被打破」的检测手段：
// 它必须在重建路径执行一次，不得在每次缓存键求值（=每次渲染取值）时递归
// 遍历整棵子目录树——稳态成本与「命中缓存即零工作」的文档口径不符。
func TestCRSSubdirRuleGuard_cacheHitDoesNotWalkSubdirs(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "REQUEST-900.conf"), "SecRule ARGS \"@rx x\" \"id:910001,phase:2,pass\"\n")
	sub := filepath.Join(dir, "nested")
	writeTestFile(t, filepath.Join(sub, "REQUEST-901.conf"), "SecRule ARGS \"@rx y\" \"id:910002,phase:2,pass\"\n")

	oldDir, oldCache, oldKey := CRSRuleIndexDir, crsRuleIndexCache, crsRuleIndexKey
	CRSRuleIndexDir = dir
	crsRuleIndexMu.Lock()
	crsRuleIndexCache, crsRuleIndexKey = nil, ""
	crsRuleIndexMu.Unlock()
	t.Cleanup(func() {
		CRSRuleIndexDir = oldDir
		crsRuleIndexMu.Lock()
		crsRuleIndexCache, crsRuleIndexKey = oldCache, oldKey
		crsRuleIndexMu.Unlock()
	})

	crsSubdirGuardWalks.Store(0)
	// 首次取值=重建：守卫必须执行（检出子目录 .conf）。
	_ = GetCRSRuleIndex()
	rebuildWalks := crsSubdirGuardWalks.Load()
	if rebuildWalks == 0 {
		t.Fatal("重建路径必须执行子目录守卫（子目录 .conf 是契约破裂，必须可检出）")
	}
	// 第二次取值=缓存命中：不得再递归遍历子目录。
	_ = GetCRSRuleIndex()
	if got := crsSubdirGuardWalks.Load(); got != rebuildWalks {
		t.Fatalf("缓存命中路径的子目录遍历次数=%d（重建时 %d）——命中必须零递归遍历", got, rebuildWalks)
	}
}
