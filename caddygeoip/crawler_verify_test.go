package caddygeoip

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeResolver 可编程 DNS 替身：PTR 与正向结果按表返回。
type fakeResolver struct {
	mu      sync.Mutex
	ptr     map[string][]string // ip → PTR names（含尾点模拟 LookupAddr）
	host    map[string][]string // name → addrs
	ptrErr  map[string]error
	hostErr map[string]error
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.ptrErr[addr]; ok {
		return nil, err
	}
	return f.ptr[addr], nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.hostErr[host]; ok {
		return nil, err
	}
	return f.host[host], nil
}

// Given/When/Then：真爬虫（双跳通过）、机房伪装、伪造 PTR、超时、缓存命中。
func TestVerifyCrawler_passFailMatrix(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"34.100.1.1":  {"vm-34-100-1-1.bc.googleusercontent.com."},
			"1.2.3.4":     {"fake.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"fake.googlebot.com":              {"66.249.66.999"}, // 正向不含原 IP
		},
	})
	// 真 Googlebot：PTR 属域 + 正向回验含原 IP → 通过
	if !VerifyCrawler("66.249.66.1", "googlebot") {
		t.Error("真 Googlebot 应通过")
	}
	// GCP 机房伪装：PTR 后缀不属引擎域 → 拒
	if VerifyCrawler("34.100.1.1", "googlebot") {
		t.Error("GCP PTR 伪装应拒绝")
	}
	// 伪造 PTR 指向官方域：正向回验不含原 IP → 拒
	if VerifyCrawler("1.2.3.4", "googlebot") {
		t.Error("伪造 PTR（正向不含原 IP）应拒绝")
	}
	// 缓存：同 IP 二次询问不再触 DNS（通过结论已缓存）
	if !VerifyCrawler("66.249.66.1", "googlebot") {
		t.Error("缓存命中应直接通过")
	}
}

func TestVerifyCrawlerIPRangeFromList_jsonPerEngine(t *testing.T) {
	// Given：按引擎隔离的快照 JSON（与 root 服务 writeCrawlerIPListSnapshotAll 同形）
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["42.236.8.0/21"],"googlebot":["66.249.66.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ResetCrawlerVerifyCacheForTest(nil)

	// When / Then：360 命中只认 360 源，不得混用 Google 段
	if !verifyCrawlerIPRangeFromList("42.236.8.1", "so360spider") {
		t.Fatal("360 官方段应命中 iprange")
	}
	if verifyCrawlerIPRangeFromList("42.236.8.1", "googlebot") {
		t.Fatal("360 段不得串入 Googlebot 命中")
	}
}

func TestVerifyCrawler_dnsFailureFailClosed(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptrErr: map[string]error{"5.6.7.8": errors.New("resolver down")},
	})
	if VerifyCrawler("5.6.7.8", "googlebot") {
		t.Error("DNS 失败必须 fail-closed 拒绝")
	}
}

// ---- 第 78 轮 U14-06 / U14-09 ----

func resetCrawlerIPRangeCacheForTest() {
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap = nil
	crawlerFileCacheMu.Unlock()
}

func TestCrawlerIPRangeList_precompiledAndFailureThrottled(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	resetCrawlerIPRangeCacheForTest()

	// 缺失快照：fail-closed，且失败也写节流时间戳。
	if verifyCrawlerIPRangeFromList("66.249.66.1", "googlebot") {
		t.Fatal("missing snapshot must fail closed")
	}
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"googlebot":["66.249.66.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// 10 分钟内不重读：失败节流生效（旧实现在失败路径不写时间戳，会立即重读）。
	if verifyCrawlerIPRangeFromList("66.249.66.1", "googlebot") {
		t.Fatal("failure must be throttled for the reload interval")
	}
	// 过期后重读 → 命中；命中用预编译前缀（判定不再逐条 ParsePrefix）。
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap.loadedAt = time.Now().Add(-11 * time.Minute)
	crawlerFileCacheMu.Unlock()
	if !verifyCrawlerIPRangeFromList("66.249.66.1", "googlebot") {
		t.Fatal("snapshot reload must match the configured prefix")
	}
	crawlerFileCacheMu.Lock()
	snap := crawlerFileCacheSnap
	crawlerFileCacheMu.Unlock()
	if snap == nil || len(snap.prefixes["googlebot"]) != 1 {
		t.Fatalf("prefixes must be precompiled at load, got %#v", snap)
	}
	// 回归形状：段外地址不命中。
	if verifyCrawlerIPRangeFromList("66.249.67.1", "googlebot") {
		t.Fatal("address outside the prefix must not match")
	}
}

func TestVerifyCrawlerIPRange_invalidAddrNoPanic(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["140.0.0.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCrawlerIPRangeCacheForTest()
	for _, bad := range []string{"@", "not-an-addr", ""} {
		if verifyCrawlerIPRangeFromList(bad, "so360spider") {
			t.Fatalf("invalid address %q must not match", bad)
		}
	}
	if !verifyCrawlerIPRangeFromList("140.0.0.1", "so360spider") {
		t.Fatal("valid address regression: expected match")
	}
}
