package services

// 从节点 304 稳态同步轮每轮全量哈希 WAF
// 文件（整树 tar.gz + xdb 全读 + 逐威胁 .fast 哈希，全程持 wafFileMu）。
// 根因是「廉价签名缓存」的命中条件同时要求 `since(validatedAt) < TTL`，而
// TTL 30s 恒小于默认同步周期 60s（normalizeSyncInterval 默认 60、下限 10），
// 于是每个稳态 304 轮都必然过期重建——签名短路对生产节奏完全失效。
//
// 契约（本次修复）：
//   - 稳态（签名不变）的连续 304 轮只做 stat 签名（廉价、不读内容），全量
//     构建增量必须为 0；
//   - 内容复核周期（TTL）必须显著大于默认同步周期（至少覆盖数轮），否则
//     「每轮全量」必然复现；
//   - 「等长 + 同 mtime」的原地改写（rsync -t / install -p / 备份还原保留
//     时间戳）仍必须在有界窗口（≤ TTL）内被发现并自愈。

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// installWafRefCacheFixture 装配最小 WAF 活树（CRS rules 一份规则文件）并
// 复位引用缓存与其全量构建计数（测试收尾同样复位，避免包级状态污染后续用例）。
func installWafRefCacheFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dir, "crs"), filepath.Join(dir, "ip2region.xdb")))
	oldWaf := wafDir
	wafDir = filepath.Join(dir, "waf")
	t.Cleanup(func() { wafDir = oldWaf })
	rulesDir := filepath.Join(crsLiveDir, "rules")
	for _, d := range []string{rulesDir, wafDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	rulePath := filepath.Join(rulesDir, "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf")
	if err := os.WriteFile(rulePath, []byte("SecRule ARGS \"@rx foo\" \"id:1,deny\"\n"), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	resetWafRefCacheForTest()
	t.Cleanup(resetWafRefCacheForTest)
	return rulePath
}

// resetWafRefCacheForTest 复位引用缓存与全量构建计数（单源，用例前后各一次）。
func resetWafRefCacheForTest() {
	invalidateWafFileRefCache()
	wafFileRefFullBuilds.Store(0)
}

// backdateWafRefValidation 把「上次内容级全量构建」的时刻回拨 d（模拟时间
// 流逝——避免用例真 sleep 一个同步周期）。
func backdateWafRefValidation(d time.Duration) {
	wafFileRefCache.mu.Lock()
	wafFileRefCache.validatedAt = time.Now().Add(-d)
	wafFileRefCache.mu.Unlock()
}

// Given 签名缓存已建立（一次全量构建）。
// When 按默认同步周期（60s）连续 3 轮 304——文件无任何变化。
// Then 全量构建增量恒为 0 且引用哈希不变（旧实现 TTL 30s < 60s，每轮都重建）。
func TestBuildWafFileRef_steadyState304RoundsSkipFullRebuild(t *testing.T) {
	installWafRefCacheFixture(t)
	roundInterval := time.Duration(defaultSyncIntervalSeconds) * time.Second

	first := BuildWafFileRef()
	if first == nil || first.CRSSha256 == "" {
		t.Fatalf("首个引用=%+v, want CRS 哈希", first)
	}
	if got := wafFileRefFullBuilds.Load(); got != 1 {
		t.Fatalf("首次构建计数=%d, want 1", got)
	}

	for round := 1; round <= 3; round++ {
		// 第 round 轮 304 距上次全量构建 = round 个同步周期。
		backdateWafRefValidation(time.Duration(round) * roundInterval)
		ref := BuildWafFileRef()
		if got := wafFileRefFullBuilds.Load(); got != 1 {
			t.Fatalf("第 %d 轮 304 后全量构建增量=%d, want 0（签名未变必须短路：TTL 若小于同步周期则每轮整树 gzip+sha256 并阻塞 wafFileMu）", round, got-1)
		}
		if ref == nil || ref.CRSSha256 != first.CRSSha256 {
			t.Fatalf("第 %d 轮 304 引用=%+v, want 沿用缓存哈希 %q", round, ref, first.CRSSha256)
		}
	}
}

// Given 内容复核周期（TTL）与默认同步周期。
// When 校验二者关系。
// Then TTL 必须覆盖至少 3 个默认同步周期（否则稳态轮必然全量构建）。
func TestWafFileRefCacheTTL_coversSeveralDefaultSyncRounds(t *testing.T) {
	round := time.Duration(defaultSyncIntervalSeconds) * time.Second
	if wafFileRefCacheTTL < 3*round {
		t.Fatalf("引用缓存 TTL=%v, want ≥ %v（默认同步周期 %v 的 3 倍——否则每个稳态 304 轮都过期重建，本缺陷复现）",
			wafFileRefCacheTTL, 3*round, round)
	}
}

// Given 一次全量构建。
// When 等长 + 同 mtime 的原地改写（签名不变）后仍在 TTL 内查询，然后越过 TTL。
// Then TTL 内沿用缓存（稳态零全量）；TTL 到期必须全量重读并产出新哈希——陈旧
// 窗口有界（≤ TTL），不会永久发旧字节/旧哈希。
func TestBuildWafFileRef_sameSizeSameMtimeRewriteRecoveredWithinBoundedWindow(t *testing.T) {
	rulePath := installWafRefCacheFixture(t)
	before := []byte("SecRule ARGS \"@rx foo\" \"id:1,deny\"\n")
	after := []byte("SecRule ARGS \"@rx bar\" \"id:1,deny\"\n")
	if len(before) != len(after) {
		t.Fatal("夹具必须保持等长")
	}
	if err := os.WriteFile(rulePath, before, 0o644); err != nil {
		t.Fatalf("write before: %v", err)
	}
	info, err := os.Stat(rulePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	first := BuildWafFileRef()
	if first == nil || first.CRSSha256 == "" {
		t.Fatalf("首个引用=%+v, want CRS 哈希", first)
	}
	if err := os.WriteFile(rulePath, after, 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// 还原 mtime：廉价签名（size+mtime+mode）不变。
	if err := os.Chtimes(rulePath, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("restore mtime: %v", err)
	}

	// TTL 内：签名不变 → 沿用缓存（已知陈旧窗口）。
	backdateWafRefValidation(wafFileRefCacheTTL / 2)
	if cached := BuildWafFileRef(); cached == nil || cached.CRSSha256 != first.CRSSha256 {
		t.Fatalf("TTL 内引用=%+v, want 沿用缓存哈希 %q（稳态 304 轮不得全量构建）", cached, first.CRSSha256)
	}
	if got := wafFileRefFullBuilds.Load(); got != 1 {
		t.Fatalf("TTL 内全量构建计数=%d, want 1", got)
	}

	// 越过 TTL：必须全量重读并发现改写（陈旧窗口有界）。
	backdateWafRefValidation(wafFileRefCacheTTL + time.Second)
	refreshed := BuildWafFileRef()
	if got := wafFileRefFullBuilds.Load(); got != 2 {
		t.Fatalf("TTL 到期后全量构建计数=%d, want 2（内容复核必须重读）", got)
	}
	if refreshed == nil || refreshed.CRSSha256 == first.CRSSha256 {
		t.Fatalf("TTL 到期后引用=%+v, want 新哈希（等长同 mtime 改写必须在 ≤TTL 的窗口内被发现）", refreshed)
	}
}
