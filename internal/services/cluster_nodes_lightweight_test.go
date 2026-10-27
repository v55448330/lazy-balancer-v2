package services

import (
	"context"
	"testing"
	"time"
)

// 节点列表的 per-section 同步状态只消费 users/rules/security 三节
// 哈希，不得走全量快照构建（WAF 全树 tar.gz 哈希 + 全部证书 X.509 解析）。
// 该路径在任意 cluster_version 递增后由 UI 轮询触发，代价与阻塞面都必须与
// 「轻量三节哈希」一致。
func TestClusterService_NodesDoNotBuildFullSnapshotForSectionSync(t *testing.T) {
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-light")
	ctx := context.Background()
	hashes, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("lightweight hashes: %v", err)
	}
	if err := service.ReportNode(ctx, nodeID, withSectionHashes(reportForVersion(1), hashes), time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}

	// 让快照缓存失效：真实触发场景就是任意配置写递增 cluster_version 后的
	// 首次节点列表轮询。清空 WAF 引用缓存，确保「全量构建」可被计数观察到。
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	resetWafFileRefCacheForTest(t)

	nodes, err := service.Nodes(ctx, time.Now())
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 || len(nodes[0].SectionSync) != len(syncSections) {
		t.Fatalf("nodes=%#v, want section sync attached", nodes)
	}
	if got := wafFileRefFullBuilds.Load(); got != 0 {
		t.Fatalf("Nodes() triggered %d full WAF ref build(s), want 0 (lightweight section hashes only)", got)
	}
}

// resetWafFileRefCacheForTest 清空 WAF 引用缓存并复位全量构建计数，同时在
// t.Cleanup 里恢复调用前的状态。两者都是跨用例共享的包级状态：本用例清空缓存
// 后若不复位，后续依赖「已预热 ref」的用例会退化为全量重建（CRS 树 tar.gz +
// sha256），慢机/CI 上表现为随机超时而非确定性失败。
func resetWafFileRefCacheForTest(t *testing.T) {
	t.Helper()
	wafFileRefCache.mu.Lock()
	prevValid, prevSig, prevAt := wafFileRefCache.valid, wafFileRefCache.sig, wafFileRefCache.validatedAt
	prevRef := cloneWafFilesRef(wafFileRefCache.ref)
	wafFileRefCache.valid = false
	wafFileRefCache.sig = ""
	wafFileRefCache.ref = nil
	wafFileRefCache.mu.Unlock()
	prevBuilds := wafFileRefFullBuilds.Swap(0)
	t.Cleanup(func() {
		wafFileRefCache.mu.Lock()
		wafFileRefCache.valid, wafFileRefCache.sig, wafFileRefCache.validatedAt = prevValid, prevSig, prevAt
		wafFileRefCache.ref = prevRef
		wafFileRefCache.mu.Unlock()
		wafFileRefFullBuilds.Store(prevBuilds)
	})
}
