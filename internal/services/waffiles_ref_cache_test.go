package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 文件态引用构建在稳态下被从端每轮 304 同步与主端快照重建反复调用，
// 全量构建需要整树 tar.gz + xdb 全读 + 威胁文件哈希。廉价签名（路径+大小+
// mtime）未变时必须短路，签名变化时才重建。
func TestBuildWafFileRef_cheapSignatureShortCircuitsFullBuild(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dir, "crs"), filepath.Join(dir, "ip2region.xdb")))
	oldWaf := wafDir
	wafDir = filepath.Join(dir, "waf")
	t.Cleanup(func() { wafDir = oldWaf })
	rulesDir := filepath.Join(crsLiveDir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wafDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(rulesDir, "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf")
	if err := os.WriteFile(rulePath, []byte("SecRule ARGS \"@rx foo\" \"id:1,deny\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	invalidateWafFileRefCache()
	wafFileRefFullBuilds.Store(0)

	first := BuildWafFileRef()
	if first == nil || first.CRSSha256 == "" {
		t.Fatalf("first ref = %+v, want CRS hash", first)
	}
	if got := wafFileRefFullBuilds.Load(); got != 1 {
		t.Fatalf("full builds after first call = %d, want 1", got)
	}

	// 文件未变：只用 stat 签名，必须命中缓存。
	second := BuildWafFileRef()
	if got := wafFileRefFullBuilds.Load(); got != 1 {
		t.Fatalf("full builds after unchanged call = %d, want 1 (cache hit)", got)
	}
	if second == nil || second.CRSSha256 != first.CRSSha256 {
		t.Fatalf("cached ref = %+v, want same hash %q", second, first.CRSSha256)
	}

	// 内容与 mtime 变化：签名变化必须触发重建并产出新哈希。
	if err := os.WriteFile(rulePath, []byte("SecRule ARGS \"@rx bar\" \"id:1,deny\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changedAt := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(rulePath, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	third := BuildWafFileRef()
	if got := wafFileRefFullBuilds.Load(); got != 2 {
		t.Fatalf("full builds after change = %d, want 2", got)
	}
	if third == nil || third.CRSSha256 == first.CRSSha256 {
		t.Fatalf("ref after change = %+v, want different CRS hash", third)
	}
}

// 等长 + 同 mtime 的原地改写不改廉价签名（rsync -t / install -p / 备份还原
// 保留时间戳）：缓存必须有 TTL 兜底，否则旧 ref 与旧 bundle 永久命中
// （主端发旧字节给从端=静默分叉，或用旧哈希标注新字节=从端整包拒绝且无
// 自愈路径）。
func TestBuildWafFileRef_ttlRecoversFromSameSizeSameMtimeRewrite(t *testing.T) {
	oldTTL := wafFileRefCacheTTL
	wafFileRefCacheTTL = time.Minute
	t.Cleanup(func() { wafFileRefCacheTTL = oldTTL })

	dir := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(dir, "crs"), filepath.Join(dir, "ip2region.xdb")))
	oldWaf := wafDir
	wafDir = filepath.Join(dir, "waf")
	t.Cleanup(func() { wafDir = oldWaf })
	rulesDir := filepath.Join(crsLiveDir, "rules")
	for _, d := range []string{rulesDir, wafDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rulePath := filepath.Join(rulesDir, "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf")
	before := []byte("SecRule ARGS \"@rx foo\" \"id:1,deny\"\n")
	after := []byte("SecRule ARGS \"@rx bar\" \"id:1,deny\"\n")
	if len(before) != len(after) {
		t.Fatal("fixture must keep the same content length")
	}
	if err := os.WriteFile(rulePath, before, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	invalidateWafFileRefCache()

	first := BuildWafFileRef()
	if first == nil || first.CRSSha256 == "" {
		t.Fatalf("first ref = %+v, want CRS hash", first)
	}
	// 同尺寸改写后还原 mtime：签名不变，缓存期内仍返回旧 ref（已知窗口）
	if err := os.WriteFile(rulePath, after, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(rulePath, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if cached := BuildWafFileRef(); cached == nil || cached.CRSSha256 != first.CRSSha256 {
		t.Fatalf("cache-hit ref = %+v, want old hash %q within TTL", cached, first.CRSSha256)
	}
	// TTL 到期后必须全量重读，产出新哈希（自愈）
	wafFileRefCache.mu.Lock()
	wafFileRefCache.validatedAt = time.Now().Add(-2 * wafFileRefCacheTTL)
	wafFileRefCache.mu.Unlock()
	refreshed := BuildWafFileRef()
	if refreshed == nil || refreshed.CRSSha256 == first.CRSSha256 {
		t.Fatalf("ref after TTL expiry = %+v, want a different CRS hash", refreshed)
	}
}

func TestWafRefStatSignature_tracksCRSVersionWithoutRules(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(root, "crs"), filepath.Join(root, "missing.xdb")))
	oldWaf := wafDir
	wafDir = filepath.Join(root, "waf")
	t.Cleanup(func() { wafDir = oldWaf })
	if err := os.MkdirAll(crsLiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	versionPath := filepath.Join(crsLiveDir, "VERSION")
	fixed := time.Unix(1700000000, 0)
	writeVersion := func(value string) {
		t.Helper()
		if err := os.WriteFile(versionPath, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(versionPath, fixed, fixed); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("v1")
	first, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	// Same length and same mtime: the readable VERSION value itself must be signed.
	writeVersion("v2")
	second, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("VERSION content change must change the reference signature without a rules directory")
	}
	if err := os.Remove(versionPath); err != nil {
		t.Fatal(err)
	}
	missing, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if missing == second {
		t.Fatal("missing VERSION must have an explicit signature state distinct from a readable value")
	}
}

// .version（ip2region tag）与 CRS VERSION 同口径：内容入签名——tag 参与
// waf_files 节哈希与从端漂移判定，「等长改写且保留 mtime/mode」时命中旧
// 引用会让主从节哈希暂时不对齐（多一轮全量重拉才自愈）。
func TestWafRefStatSignature_tracksIP2RegionVersionContent(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(filepath.Join(root, "crs"), filepath.Join(root, "ip2region.xdb"))) // 不创建 rules：缺失形态下 tag 仍须入签名
	oldWaf := wafDir
	wafDir = filepath.Join(root, "waf")
	t.Cleanup(func() { wafDir = oldWaf })
	if err := os.WriteFile(ip2regionLivePath, []byte("xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	versionPath := ip2regionLivePath + ".version"
	fixed := time.Unix(1700000000, 0)
	writeTag := func(value string) {
		t.Helper()
		if err := os.WriteFile(versionPath, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(versionPath, fixed, fixed); err != nil {
			t.Fatal(err)
		}
	}
	writeTag("v1.0")
	first, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	// 等长 + 同 mtime/mode：内容变化必须改变签名。
	writeTag("v2.0")
	second, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal(".version 等长同 mtime 改写必须改变引用签名")
	}
	if err := os.Remove(versionPath); err != nil {
		t.Fatal(err)
	}
	missing, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if missing == second {
		t.Fatal(".version 缺失必须是独立签名状态")
	}
}

// OverrideWafLivePathsForTest 是测试侧切换活动路径的唯一入口：切换（含还原）
// 必须同时失效 wafFileRefCache。签名虽含两个绝对路径，但「同路径等长同 mtime
// 改写」与 mtime 精度退化（秒级 FS）形态下，下一夹具可能命中上一夹具的签名，
// 把旧 ref 带入新用例（假绿/假红）——与 wafFileBundleCache 的隔离口径对齐。
func TestOverrideWafLivePathsForTest_invalidatesRefCache(t *testing.T) {
	resetWafFileRefCacheForTest(t) // 复位并在用例结束后还原全局态
	prime := func() {
		wafFileRefCache.mu.Lock()
		wafFileRefCache.valid = true
		wafFileRefCache.sig = "stale-sig"
		wafFileRefCache.validatedAt = time.Now()
		wafFileRefCache.mu.Unlock()
	}
	cacheState := func() (bool, string) {
		wafFileRefCache.mu.Lock()
		defer wafFileRefCache.mu.Unlock()
		return wafFileRefCache.valid, wafFileRefCache.sig
	}

	prime()
	restore := OverrideWafLivePathsForTest(t.TempDir(), filepath.Join(t.TempDir(), "ip2region.xdb"))
	if valid, sig := cacheState(); valid || sig != "" {
		t.Fatalf("切换后缓存未失效 valid=%v sig=%q", valid, sig)
	}

	prime()
	restore()
	if valid, sig := cacheState(); valid || sig != "" {
		t.Fatalf("还原后缓存未失效 valid=%v sig=%q", valid, sig)
	}
}
