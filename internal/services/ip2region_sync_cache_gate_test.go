package services

// 集群同步/lbbak 导入在从节点同样执行 xdb 后置重建——派生缓存（地域树/省份）
// 属「本节点只读不变量」的同一写入门，从节点不落盘；读侧缺缓存时按 xdb 在
// 内存重建（进程内记忆化），可用性不受影响。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// copyRepositoryXDB 直取仓库固定夹具（与 regionTree 扫描测试同一来源），
// 不用伪造 xdb——伪造文件的 header 段区指针为 0，解析不出地域树。
func copyRepositoryXDB(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "caddygeoip", "testdata", "ip2region_v4.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("repository xdb fixture unavailable: %v", err)
	}
	live := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(live, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return live
}

func TestRebuildRegionTreeCacheForSync_slaveWritesNoDerivedCaches(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	live := copyRepositoryXDB(t)
	withIP2RegionPaths(t, live, filepath.Join(filepath.Dir(live), "waf.dist", "ip2region.xdb"))

	RebuildRegionTreeCacheForSync()

	if _, err := os.Stat(live + ".regions.json"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写地域树派生缓存（stat err=%v）", err)
	}
	if _, err := os.Stat(live + ".provinces.json"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写省份派生缓存（stat err=%v）", err)
	}
	// 读侧仍可用：缺缓存按 xdb 内存重建。
	tree := GetIP2RegionRegionTree()
	if tree == nil || len(tree.Provinces) < 30 {
		t.Fatalf("从节点读侧未按 xdb 内存重建地域树: %+v", tree)
	}
}

func TestRebuildRegionTreeCacheForSync_masterWritesDerivedCache(t *testing.T) {
	setupSecurityEnumTestDB(t)
	// setupSecurityEnumTestDB 默认主节点。
	live := copyRepositoryXDB(t)
	withIP2RegionPaths(t, live, filepath.Join(filepath.Dir(live), "waf.dist", "ip2region.xdb"))

	RebuildRegionTreeCacheForSync()

	if _, err := os.Stat(live + ".regions.json"); err != nil {
		t.Fatalf("主节点应写地域树派生缓存: %v", err)
	}
}

// Given 只读降级形态：live 库缺失、在役 searcher 来自 waf.dist（从节点/写入
// 失败时的真实形态）
// When 连续两次取省份列表与地域树
// Then 省份 336 次采样只跑一次（记忆化键取在役来源，此前恒取 live 路径 →
// stat 失败 → 键恒空 → 每次调用重扫并全程持全局搜索锁）；地域树按在役来源
// 扫描（此前直接回退不存在的 regions.json → 恒 nil，UI 退化为采样省份）。
func TestReadOnlyDegraded_memoizesProvincesAndScansLoadedSource(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "missing-live.xdb")
	dist := copyRepositoryXDB(t)
	withIP2RegionPaths(t, live, dist)
	resetProvincesMemoForTest(t)
	resetRegionTreeMemoForTest(t)

	searcher, err := openIP2RegionSearcher(dist)
	if err != nil {
		t.Fatalf("open fixture searcher: %v", err)
	}
	ip2regionMu.Lock()
	ip2regionSearcher = searcher
	ip2regionSearcherSource = dist
	ip2regionMu.Unlock()

	base := ip2regionProvinceScans.Load()
	first := GetIP2RegionProvinces()
	second := GetIP2RegionProvinces()
	if scans := ip2regionProvinceScans.Load() - base; scans != 1 {
		t.Fatalf("降级形态两次调用采样 %d 次, want 1（记忆化键必须取在役来源）", scans)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("记忆化结果漂移: %v vs %v", first, second)
	}

	tree := GetIP2RegionRegionTree()
	if tree == nil || len(tree.Provinces) == 0 {
		t.Fatalf("降级形态必须按在役来源建树, got %+v", tree)
	}
	if again := GetIP2RegionRegionTree(); again != tree {
		t.Fatal("地域树稳态调用必须命中记忆化（同一指针）")
	}
}
