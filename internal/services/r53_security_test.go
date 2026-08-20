package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRefreshLatestAsync_backsOffAfterFailure 验证 R53 新-1：上游版本检查失败
// 时同样记录尝试时间，10 分钟守卫对失败路径生效——前端轮询 CRS 卡片不会每次
// 请求都重发一个 30s 超时的 GitHub fetch（持续失败会加速 403 限流）。
func TestRefreshLatestAsync_backsOffAfterFailure(t *testing.T) {
	// Given 上游 fetch 恒失败的管理器
	m := newTestCRSManager(t)
	calls := make(chan struct{}, 4)
	m.fetchLatestTag = func(context.Context) (string, error) {
		calls <- struct{}{}
		return "", errors.New("upstream 403")
	}
	refreshing := func() bool {
		m.latestMu.Lock()
		defer m.latestMu.Unlock()
		return m.latestRefreshing
	}

	// When 首次刷新失败完成后，10 分钟内再次调用
	m.RefreshLatestAsync()
	<-calls // 首次 fetch 已发出
	deadline := time.Now().Add(5 * time.Second)
	for refreshing() {
		if time.Now().After(deadline) {
			t.Fatal("first refresh did not settle")
		}
		time.Sleep(time.Millisecond)
	}
	m.RefreshLatestAsync()

	// Then 守卫拦截第二次触发（latestRefreshing 由调用方同步置位，此处立即判定）
	if refreshing() {
		t.Fatal("failed fetch must engage the 10min backoff: second call re-fired a fetch")
	}
	select {
	case <-calls:
		t.Fatal("second fetch fired within the failure backoff window")
	default:
	}
	// 失败不产生缓存版本
	if _, known := m.LatestVersionCached(); known {
		t.Fatal("failed fetch must not mark the latest version as known")
	}
}

// TestSeedCRSRules_versionOnlySnapshotTreatedAsDegenerate 验证 R53 新-4：
// 「VERSION 存在、rules 树缺失」的快照（persistCRSSnapshotFrom 的 RemoveAll
// 之后崩溃残留）必须进入退化判定——回退 dist 播种后用健康 live 树重建快照，
// 而不是留下一个永不自愈的 VERSION-only 残骸。
func TestSeedCRSRules_versionOnlySnapshotTreatedAsDegenerate(t *testing.T) {
	// Given VERSION-only 快照（无 rules 目录）与完好的 dist
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When 播种
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then live 来自 dist，且快照被重建为健康树（版本落 bundled）
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("live must be seeded from dist: %q,%v", data, err)
	}
	data, err = os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("VERSION-only snapshot must be healed from the reseeded live tree: %q,%v", data, err)
	}
	if got := readCRSVersionMarker(snapshotDir); got != CRSBundledVersion {
		t.Fatalf("snapshot marker=%q, want healed to bundled %q", got, CRSBundledVersion)
	}
}

// TestReconcileCRSState_versionOnlySnapshotHealed 验证 R53 新-4 的对账侧：
// VERSION-only 快照在 live 树健康且版本可确定时被重建，而非永久留残骸。
func TestReconcileCRSState_versionOnlySnapshotHealed(t *testing.T) {
	// Given 完好的 live 树（标记 v4.15.0）+ VERSION-only 快照，DB 记录与 live 一致
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule live")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")

	// When 启动对账
	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.15.0")

	// Then 快照被重建为 live 的健康树
	data, err := os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule live" {
		t.Fatalf("VERSION-only snapshot must be healed from the healthy live tree: %q,%v", data, err)
	}
	if got := readCRSVersionMarker(snapshotDir); got != "v4.15.0" {
		t.Fatalf("snapshot marker=%q, want healed to live version v4.15.0", got)
	}
	// live 不受影响
	data, err = os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule live" {
		t.Fatalf("live rules must be untouched: %q,%v", data, err)
	}
}
