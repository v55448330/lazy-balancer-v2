package caddygeoip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"lazy-balancer-v2/wafiplist"
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
	if VerifyCrawler("66.249.66.1", "googlebot") != CrawlerVerdictVerified {
		t.Error("真 Googlebot 应通过")
	}
	// GCP 机房伪装：PTR 后缀不属引擎域 → 拒
	if VerifyCrawler("34.100.1.1", "googlebot") != CrawlerVerdictSpoof {
		t.Error("GCP PTR 伪装应判确定否定")
	}
	// 伪造 PTR 指向官方域：正向回验不含原 IP → 拒
	if VerifyCrawler("1.2.3.4", "googlebot") != CrawlerVerdictSpoof {
		t.Error("伪造 PTR（正向不含原 IP）应判确定否定")
	}
	// 缓存：同 IP 二次询问不再触 DNS（通过结论已缓存）
	if VerifyCrawler("66.249.66.1", "googlebot") != CrawlerVerdictVerified {
		t.Error("缓存命中应直接通过")
	}
}

func TestVerifyCrawler_transientFailuresNotCached(t *testing.T) {
	t.Run("semaphore saturated", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(&fakeResolver{})
		for len(crawlerVerifySem) > 0 {
			<-crawlerVerifySem
		}
		for range cap(crawlerVerifySem) {
			crawlerVerifySem <- struct{}{}
		}
		t.Cleanup(func() {
			for len(crawlerVerifySem) > 0 {
				<-crawlerVerifySem
			}
		})

		if got := VerifyCrawler("9.8.7.6", "googlebot"); got != CrawlerVerdictTransient {
			t.Fatalf("saturated verifier must yield transient, got %v", got)
		}
		crawlerCacheMu.Lock()
		_, cached := crawlerCache["9.8.7.6|googlebot"]
		crawlerCacheMu.Unlock()
		if cached {
			t.Fatal("semaphore saturation is transient and must not create a 10-minute negative entry")
		}
	})

	for _, tc := range []struct {
		name string
		ip   string
		err  error
	}{
		{name: "resolver error", ip: "5.6.7.8", err: errors.New("resolver down")},
		{name: "context timeout", ip: "5.6.7.9", err: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetCrawlerVerifyCacheForTest(&fakeResolver{ptrErr: map[string]error{tc.ip: tc.err}})
			if got := VerifyCrawler(tc.ip, "googlebot"); got != CrawlerVerdictTransient {
				t.Fatalf("DNS failure must yield transient, got %v", got)
			}
			crawlerCacheMu.Lock()
			_, cached := crawlerCache[tc.ip+"|googlebot"]
			crawlerCacheMu.Unlock()
			if cached {
				t.Fatal("transient DNS failure must not be cached")
			}
		})
	}

	t.Run("forward resolver error", func(t *testing.T) {
		const (
			ip   = "66.249.66.9"
			host = "crawl-66-249-66-9.googlebot.com"
		)
		ResetCrawlerVerifyCacheForTest(&fakeResolver{
			ptr:     map[string][]string{ip: {host + "."}},
			hostErr: map[string]error{host: errors.New("forward resolver down")},
		})
		if got := VerifyCrawler(ip, "googlebot"); got != CrawlerVerdictTransient {
			t.Fatalf("failed forward verification is transient, got %v", got)
		}
		crawlerCacheMu.Lock()
		_, cached := crawlerCache[ip+"|googlebot"]
		crawlerCacheMu.Unlock()
		if cached {
			t.Fatal("forward resolver failure is transient and must not be cached")
		}
	})

	t.Run("deterministic negative stays cached", func(t *testing.T) {
		const ip = "34.100.1.1"
		ResetCrawlerVerifyCacheForTest(&fakeResolver{ptr: map[string][]string{
			ip: {"vm-34-100-1-1.bc.googleusercontent.com."},
		}})
		if got := VerifyCrawler(ip, "googlebot"); got != CrawlerVerdictSpoof {
			t.Fatalf("non-official PTR must be spoof, got %v", got)
		}
		crawlerCacheMu.Lock()
		entry, cached := crawlerCache[ip+"|googlebot"]
		crawlerCacheMu.Unlock()
		if !cached || entry.ok {
			t.Fatalf("deterministic negative must retain its negative cache entry: %+v cached=%v", entry, cached)
		}
	})
}

func TestVerifyCrawler_cacheCapacityPreservesLiveEntries(t *testing.T) {
	const newIP = "34.100.1.1"
	newResolver := func() *fakeResolver {
		return &fakeResolver{ptr: map[string][]string{
			newIP: {"vm-34-100-1-1.bc.googleusercontent.com."},
		}}
	}

	t.Run("prunes only expired entries", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(newResolver())
		oldMax := crawlerCacheMax
		crawlerCacheMax = 2
		t.Cleanup(func() { crawlerCacheMax = oldMax })
		now := time.Now()
		crawlerCacheMu.Lock()
		crawlerCache["keep|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCache["expired|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(-time.Minute)}
		crawlerCacheMu.Unlock()

		if got := VerifyCrawler(newIP, "googlebot"); got != CrawlerVerdictSpoof {
			t.Fatalf("test input must produce a deterministic negative, got %v", got)
		}
		crawlerCacheMu.Lock()
		keep, keepExists := crawlerCache["keep|googlebot"]
		_, expiredExists := crawlerCache["expired|googlebot"]
		_, newExists := crawlerCache[newIP+"|googlebot"]
		size := len(crawlerCache)
		crawlerCacheMu.Unlock()
		if !keepExists || !keep.ok {
			t.Fatal("capacity cleanup must not evict a live positive verification")
		}
		if expiredExists {
			t.Fatal("expired entry must be pruned at capacity")
		}
		if !newExists || size != 2 {
			t.Fatalf("after pruning size=%d newCached=%v, want size=2 and new result cached", size, newExists)
		}
	})

	t.Run("full live cache rejects new key without eviction", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(newResolver())
		oldMax := crawlerCacheMax
		crawlerCacheMax = 2
		t.Cleanup(func() { crawlerCacheMax = oldMax })
		now := time.Now()
		crawlerCacheMu.Lock()
		crawlerCache["keep-a|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCache["keep-b|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCacheMu.Unlock()

		if got := VerifyCrawler(newIP, "googlebot"); got != CrawlerVerdictSpoof {
			t.Fatalf("test input must produce a deterministic negative, got %v", got)
		}
		crawlerCacheMu.Lock()
		_, keepA := crawlerCache["keep-a|googlebot"]
		_, keepB := crawlerCache["keep-b|googlebot"]
		_, newExists := crawlerCache[newIP+"|googlebot"]
		size := len(crawlerCache)
		crawlerCacheMu.Unlock()
		if !keepA || !keepB || size != 2 {
			t.Fatalf("live entries must survive a full cache: keepA=%v keepB=%v size=%d", keepA, keepB, size)
		}
		if newExists {
			t.Fatal("a full live cache must skip the new key rather than evict verified crawlers")
		}
	})

	t.Run("full cache evicts a live negative to admit a new conclusion", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(newResolver())
		oldMax := crawlerCacheMax
		crawlerCacheMax = 2
		t.Cleanup(func() { crawlerCacheMax = oldMax })
		now := time.Now()
		crawlerCacheMu.Lock()
		// 一个正结论 + 一个负结论：负结论可被回收，正结论必须保留。
		crawlerCache["keep-pos|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCache["stale-neg|googlebot"] = crawlerVerifyCache{ok: false, expires: now.Add(5 * time.Minute)}
		crawlerCacheMu.Unlock()

		if got := VerifyCrawler(newIP, "googlebot"); got != CrawlerVerdictSpoof {
			t.Fatalf("test input must produce a deterministic negative, got %v", got)
		}
		crawlerCacheMu.Lock()
		keep, keepExists := crawlerCache["keep-pos|googlebot"]
		_, negExists := crawlerCache["stale-neg|googlebot"]
		_, newExists := crawlerCache[newIP+"|googlebot"]
		size := len(crawlerCache)
		crawlerCacheMu.Unlock()
		if !keepExists || !keep.ok {
			t.Fatal("positive conclusion must never be evicted at capacity")
		}
		if negExists {
			t.Fatal("a live negative conclusion may be evicted to admit a new conclusion")
		}
		if !newExists || size != 2 {
			t.Fatalf("after negative eviction size=%d newCached=%v, want size=2 and new result cached", size, newExists)
		}
	})
}

func TestVerifyCrawler_cacheCapacityPruneWorkBounded(t *testing.T) {
	const newIP = "34.100.1.1"
	ResetCrawlerVerifyCacheForTest(&fakeResolver{ptr: map[string][]string{
		newIP: {"vm-34-100-1-1.bc.googleusercontent.com."},
	}})
	oldMax := crawlerCacheMax
	crawlerCacheMax = 1000
	t.Cleanup(func() { crawlerCacheMax = oldMax })
	now := time.Now()
	crawlerCacheMu.Lock()
	for i := range crawlerCacheMax {
		crawlerCache[fmt.Sprintf("live-%d|googlebot", i)] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
	}
	crawlerCachePruneVisitsForTest = 0
	crawlerCacheMu.Unlock()

	if got := VerifyCrawler(newIP, "googlebot"); got != CrawlerVerdictSpoof {
		t.Fatalf("test input must produce a deterministic negative, got %v", got)
	}
	crawlerCacheMu.Lock()
	visits := crawlerCachePruneVisitsForTest
	size := len(crawlerCache)
	crawlerCacheMu.Unlock()
	if visits > crawlerCachePruneProbeLimit {
		t.Fatalf("capacity pruning visited %d entries, want bounded by %d (cache size=%d)", visits, crawlerCachePruneProbeLimit, size)
	}
	if size != crawlerCacheMax {
		t.Fatalf("live full cache size=%d, want %d", size, crawlerCacheMax)
	}
}

// ipRangeVerified 把生产入口的三态结论投影成布尔（测试侧 helper，不新增
// 生产包装函数）：仅 Verified 视为段命中。
func ipRangeVerified(ipStr, engineID string) bool {
	return verifyCrawlerIPRangeVerdict(ipStr, engineID) == CrawlerVerdictVerified
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
	if !ipRangeVerified("42.236.8.1", "so360spider") {
		t.Fatal("360 官方段应命中 iprange")
	}
	if ipRangeVerified("42.236.8.1", "googlebot") {
		t.Fatal("360 段不得串入 Googlebot 命中")
	}
}

func TestVerifyCrawler_dnsFailureFailClosed(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptrErr: map[string]error{"5.6.7.8": errors.New("resolver down")},
	})
	if got := VerifyCrawler("5.6.7.8", "googlebot"); got != CrawlerVerdictTransient {
		t.Fatalf("DNS 失败是瞬态（不得判伪装）, got %v", got)
	}
}

// ---- 回归钉 ----

func resetCrawlerIPRangeCacheForTest() {
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap = nil
	crawlerFileCacheMu.Unlock()
}

func TestCrawlerIPRangeList_precompiledAndFailureThrottled(t *testing.T) {
	oldFile := crawlerIPListFile
	oldRetry := crawlerIPListRetryInterval
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	crawlerIPListRetryInterval = time.Minute
	t.Cleanup(func() {
		crawlerIPListFile = oldFile
		crawlerIPListRetryInterval = oldRetry
	})
	resetCrawlerIPRangeCacheForTest()

	// 缺失快照：fail-closed，且失败也写节流时间戳。
	if ipRangeVerified("66.249.66.1", "googlebot") {
		t.Fatal("missing snapshot must fail closed")
	}
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"googlebot":["66.249.66.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// 失败节流期内不重读（旧实现在失败路径不写时间戳，会立即重读）。
	if ipRangeVerified("66.249.66.1", "googlebot") {
		t.Fatal("failure must be throttled for the retry interval")
	}
	// 失败只按短重试间隔节流（旧实现缓存满 10min，冷装窗口 360
	// 豁免 fail-closed 最长 10 分钟）；重试间隔过后重读 → 命中。
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap.loadedAt = time.Now().Add(-2 * time.Minute)
	crawlerFileCacheMu.Unlock()
	if !ipRangeVerified("66.249.66.1", "googlebot") {
		t.Fatal("snapshot reload must match the configured prefix")
	}
	crawlerFileCacheMu.Lock()
	snap := crawlerFileCacheSnap
	crawlerFileCacheMu.Unlock()
	if snap == nil || len(snap.prefixes["googlebot"]) != 1 || !snap.ok {
		t.Fatalf("prefixes must be precompiled at load, got %#v", snap)
	}
	// 成功快照按完整重载间隔缓存：超过重试间隔（1min）但未到 10min 不重读。
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap.loadedAt = time.Now().Add(-2 * time.Minute)
	crawlerFileCacheMu.Unlock()
	if !ipRangeVerified("66.249.66.1", "googlebot") {
		t.Fatal("successful snapshot must stay cached until the reload interval")
	}
	// 回归形状：段外地址不命中。
	if ipRangeVerified("66.249.67.1", "googlebot") {
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
		if ipRangeVerified(bad, "so360spider") {
			t.Fatalf("invalid address %q must not match", bad)
		}
	}
	if !ipRangeVerified("140.0.0.1", "so360spider") {
		t.Fatal("valid address regression: expected match")
	}
}

// 地址归一化（Unmap/zone），方向 fail-closed ----

// Given: 客户端 IP 为 4in6 映射形态，PTR 属引擎官方域，正向回验返回 v4 规范串
// When: 双跳验证
// Then: 同地址不同文本形态须判等通过（Unmap 归一）；正向不含原 IP 仍拒绝。
func TestVerifyCrawlerDNS_v4MappedFormsUnified(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr: map[string][]string{
			"::ffff:66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"::ffff:66.249.66.2": {"crawl-66-249-66-2.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}, // 正向返回 v4 规范串
			"crawl-66-249-66-2.googlebot.com": {"66.249.66.9"}, // 正向不含原 IP
		},
	})
	// 目标形状：4in6 客户端 + v4 规范正向应答 = 同地址，须通过
	// （旧字符串比较 "::ffff:66.249.66.1" == "66.249.66.1" 恒假 → 真爬虫误杀）。
	if VerifyCrawler("::ffff:66.249.66.1", "googlebot") != CrawlerVerdictVerified {
		t.Error("4in6 客户端与 v4 正向应答同地址应通过（Unmap 归一）")
	}
	// 回归形状：映射形态但正向回验不含原 IP → 仍 fail-closed。
	if VerifyCrawler("::ffff:66.249.66.2", "googlebot") != CrawlerVerdictSpoof {
		t.Error("4in6 客户端正向不含原 IP 仍须判确定否定")
	}
	// 畸形形状：带 zone 地址不得命中（fail-closed）。
	if VerifyCrawler("2001:db8::1%eth0", "googlebot") != CrawlerVerdictSpoof {
		t.Error("带 zone 地址是确定否定（不可解析）")
	}
}

// Given: 官方段名单含 v4 段与 v6 段
// When: 查询 4in6 映射形态/段外映射形态/原生 v6/带 zone 地址
// Then: 映射形态归一命中 v4 段；段外与 zone 形态 fail-closed；v6 不受影响。
func TestVerifyCrawlerIPRange_v4MappedAndZoneNormalized(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["42.236.8.0/21","2408:4000::/32"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCrawlerIPRangeCacheForTest()

	// 目标形状：4in6 映射形态命中 v4 段（Unmap 归一；旧实现 netip v4 前缀
	// 不含 4in6 地址，恒不命中 → 真爬虫被误判为伪装）。
	if !ipRangeVerified("::ffff:42.236.8.1", "so360spider") {
		t.Fatal("4in6 映射形态应命中 v4 官方段（Unmap 归一）")
	}
	// 回归形状 1：映射形态但段外 → fail-closed。
	if ipRangeVerified("::ffff:42.236.16.1", "so360spider") {
		t.Fatal("映射形态段外地址不得命中")
	}
	// 回归形状 2：原生 v6 命中 v6 段不受影响。
	if !ipRangeVerified("2408:4000::1", "so360spider") {
		t.Fatal("原生 v6 段内地址应命中")
	}
	// 畸形形状：带 zone 地址 fail-closed。
	if ipRangeVerified("2408:4000::1%eth0", "so360spider") {
		t.Fatal("带 zone 地址必须 fail-closed")
	}
}

// 快照体积门与坏条目可见性：超限文件按不可用 fail-closed（不得整体读入
// 内存）；坏 CIDR 逐条跳过但整体快照仍可用（不把单条损坏放大成整份豁免
// 失效），坏条目数经日志计数告警。
func TestCrawlerIPRangeSnapshot_sizeGateAndBadCIDRs(t *testing.T) {
	oldFile := crawlerIPListFile
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	t.Run("超限文件按不可用处理", func(t *testing.T) {
		crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
		resetCrawlerIPRangeCacheForTest()
		t.Cleanup(resetCrawlerIPRangeCacheForTest)
		// 合法 JSON 头部 + 填充到上限之上：若体积门缺失会被整体读入并解析，
		// 本断言改为 fail-closed 空快照。
		pad := strings.Repeat(" ", crawlerIPListMaxBytes)
		payload := `{"so360spider":["42.236.8.0/21"]}` + pad
		if err := os.WriteFile(crawlerIPListFile, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		snap := loadCrawlerIPRangeSnapshot()
		if snap.ok {
			t.Fatal("超限快照必须按不可用处理（fail-closed）")
		}
		if len(snap.prefixes) != 0 {
			t.Fatalf("超限文件不得产出豁免段: %v", snap.prefixes)
		}
		if ipRangeVerified("42.236.8.1", "so360spider") {
			t.Fatal("超限快照下必须 fail-closed（段内地址也不得豁免）")
		}
	})

	t.Run("坏CIDR跳过且快照仍可用", func(t *testing.T) {
		crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
		resetCrawlerIPRangeCacheForTest()
		t.Cleanup(resetCrawlerIPRangeCacheForTest)
		payload := `{"so360spider":["42.236.8.0/21","not-a-cidr","42.236.9.0/33"]}`
		if err := os.WriteFile(crawlerIPListFile, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		snap := loadCrawlerIPRangeSnapshot()
		if !snap.ok {
			t.Fatal("坏条目不得让整份快照降级为不可用")
		}
		if got := len(snap.prefixes["so360spider"]); got != 1 {
			t.Fatalf("有效段=%d, want 1（坏条目逐条跳过）", got)
		}
		if !ipRangeVerified("42.236.8.1", "so360spider") {
			t.Fatal("有效段必须仍可命中")
		}
	})

	t.Run("仅坏CIDR不豁免且告警方向正确", func(t *testing.T) {
		crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
		resetCrawlerIPRangeCacheForTest()
		t.Cleanup(resetCrawlerIPRangeCacheForTest)
		oldLogf := crawlerSnapshotLogf
		var warnings []string
		crawlerSnapshotLogf = func(format string, args ...any) {
			warnings = append(warnings, fmt.Sprintf(format, args...))
		}
		t.Cleanup(func() { crawlerSnapshotLogf = oldLogf })
		if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["not-a-cidr","42.236.9.0/33"]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if snap := loadCrawlerIPRangeSnapshot(); snap.ok {
			t.Fatal("仅含坏 CIDR 的快照必须按不可用处理")
		}
		if ipRangeVerified("42.236.8.1", "so360spider") {
			t.Fatal("坏 CIDR 不得授予爬虫豁免")
		}
		joined := strings.Join(warnings, "\n")
		if !strings.Contains(joined, "grant no crawler exemption") || strings.Contains(joined, "fail-open") {
			t.Fatalf("坏 CIDR 告警方向错误: %q", joined)
		}
	})
}

// 并发加载代际守卫——慢读者读到 rename 前的旧 inode，不得在新
// 快照落定后把旧内容写回（否则官方段更新后旧段最多沿用 10 分钟）。
func TestCrawlerIPRangeSnapshot_staleGenerationDoesNotOverwrite(t *testing.T) {
	resetCrawlerIPRangeCacheForTest()
	t.Cleanup(resetCrawlerIPRangeCacheForTest)
	freshMod := time.Now()
	fresh := &crawlerIPRangeSnapshot{
		prefixes: map[string][]netip.Prefix{"so360spider": {netip.MustParsePrefix("42.236.8.0/21")}},
		loadedAt: freshMod, ok: true, modTime: freshMod, size: 128,
	}
	if got := commitCrawlerIPRangeSnapshot(fresh); got != fresh {
		t.Fatal("first successful snapshot must be committed")
	}

	stale := &crawlerIPRangeSnapshot{
		prefixes: map[string][]netip.Prefix{"so360spider": {netip.MustParsePrefix("140.0.0.0/24")}},
		loadedAt: time.Now(), ok: true,
		modTime: freshMod.Add(-time.Hour), size: 96,
	}
	if got := commitCrawlerIPRangeSnapshot(stale); got != fresh {
		t.Fatal("旧代际（更早 mtime）读取结果不得覆盖新快照")
	}
	crawlerFileCacheMu.Lock()
	cached := crawlerFileCacheSnap
	crawlerFileCacheMu.Unlock()
	if cached != fresh || !cached.prefixes["so360spider"][0].Contains(netip.MustParseAddr("42.236.8.1")) {
		t.Fatalf("cache content was polluted by a stale reader: %#v", cached)
	}
}

// 反向形状：并发成功快照落定后，较早开始的失败读取不得把它降级成
// 空集（fail-closed 空窗）。TTL 到期后的失败读取（晚于成功落定）照常覆盖。
func TestCrawlerIPRangeSnapshot_freshSuccessNotDowngradedByOldFailure(t *testing.T) {
	resetCrawlerIPRangeCacheForTest()
	t.Cleanup(resetCrawlerIPRangeCacheForTest)
	fresh := &crawlerIPRangeSnapshot{
		prefixes: map[string][]netip.Prefix{"googlebot": {netip.MustParsePrefix("66.249.66.0/24")}},
		loadedAt: time.Now(), ok: true, modTime: time.Now(), size: 128,
	}
	commitCrawlerIPRangeSnapshot(fresh)

	readStartedBefore := &crawlerIPRangeSnapshot{
		prefixes: map[string][]netip.Prefix{},
		loadedAt: time.Now().Add(-time.Second), ok: false,
	}
	if got := commitCrawlerIPRangeSnapshot(readStartedBefore); got != fresh {
		t.Fatal("成功快照已刷新后，更早开始的失败读取不得降级快照")
	}

	// 对照：TTL 到期后发起的失败读取（晚于成功落定）仍须 fail-closed 覆盖。
	laterFailure := &crawlerIPRangeSnapshot{
		prefixes: map[string][]netip.Prefix{},
		loadedAt: time.Now().Add(time.Second), ok: false,
	}
	if got := commitCrawlerIPRangeSnapshot(laterFailure); got != laterFailure {
		t.Fatal("成功快照过期后的失败读取应覆盖为空快照（fail-closed）")
	}
}

func TestCrawlerIPRangeSnapshot_pathChangeRejectsInflightRead(t *testing.T) {
	oldPath := crawlerIPListFilePath()
	newPath := filepath.Join(t.TempDir(), "new-crawler.json")
	setCrawlerIPListFilePath(newPath)
	t.Cleanup(func() {
		setCrawlerIPListFilePath(oldPath)
		resetCrawlerIPRangeCacheForTest()
	})

	inflightOld := &crawlerIPRangeSnapshot{
		filePath: oldPath,
		prefixes: map[string][]netip.Prefix{"so360spider": {netip.MustParsePrefix("140.0.0.0/24")}},
		loadedAt: time.Now(), ok: true, modTime: time.Now(), size: 128,
	}
	if got := commitCrawlerIPRangeSnapshot(inflightOld); got.ok {
		t.Fatal("路径切换后的旧路径在途读必须 fail-closed，不得返回旧成功快照")
	}
	crawlerFileCacheMu.Lock()
	cached := crawlerFileCacheSnap
	crawlerFileCacheMu.Unlock()
	if cached != nil {
		t.Fatalf("旧路径在途读不得写入新路径缓存: %#v", cached)
	}

	fresh := &crawlerIPRangeSnapshot{
		filePath: newPath,
		prefixes: map[string][]netip.Prefix{"so360spider": {netip.MustParsePrefix("42.236.8.0/21")}},
		loadedAt: time.Now(), ok: true, modTime: time.Now(), size: 128,
	}
	commitCrawlerIPRangeSnapshot(fresh)
	if got := commitCrawlerIPRangeSnapshot(inflightOld); got != fresh {
		t.Fatal("新路径快照已落定后，旧路径在途读必须保留新快照")
	}
}

// 渲染侧经 crawler_ip_list_file 配置键下发根服务派生路径——
// 自定义 data_dir 部署下根服务把运行快照写到 <data_dir>/crawler-ip-lists.json，
// 插件若不消费配置键会恒读 /app/data/crawler-ip-lists.json（读侧分叉，360 类
// IP 段豁免静默失效）。Provision 必须应用配置路径；路径变化时重置快照缓存，
// 否则旧路径成功快照在其 TTL（≤10min）内继续服役，把上一部署形态的名单带进
// 新形态。fail-closed 语义与失败重试间隔不变。
func TestProvision_appliesCrawlerIPListFileAndResetsSnapshot(t *testing.T) {
	// Given：旧路径有一份成功快照已缓存（模拟上一部署形态）
	oldFile := crawlerIPListFile
	t.Cleanup(func() {
		setCrawlerIPListFilePath(oldFile)
		resetCrawlerIPRangeCacheForTest()
	})
	oldPath := filepath.Join(t.TempDir(), "old-crawler.json")
	if err := os.WriteFile(oldPath, []byte(`{"so360spider":["140.0.0.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	setCrawlerIPListFilePath(oldPath)
	resetCrawlerIPRangeCacheForTest()
	if !ipRangeVerified("140.0.0.1", "so360spider") {
		t.Fatal("旧路径快照应命中（前置条件）")
	}

	// When：Provision 携带渲染侧发射的派生路径（新部署形态，名单不同）
	newPath := filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	if err := os.WriteFile(newPath, []byte(`{"so360spider":["42.236.8.0/21"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &GeoIPHandler{CrawlerIPListFile: newPath}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Then：读取路径已切换到配置值，旧路径缓存快照不再服役（命中新名单而非旧名单）
	if got := crawlerIPListFilePath(); got != newPath {
		t.Fatalf("crawlerIPListFile=%q, want %q", got, newPath)
	}
	if !ipRangeVerified("42.236.8.1", "so360spider") {
		t.Fatal("Provision 后应按新路径快照判定（新名单命中）")
	}
	if ipRangeVerified("140.0.0.1", "so360spider") {
		t.Fatal("路径切换必须重置快照缓存——旧路径名单不得继续服役")
	}
}

// 兜底裁定：插件 Provision 默认不动——未配置时路径保持
// /app/data/crawler-ip-lists.json（容器默认形态渲染侧省略该键，见根服务
// TestBuildGeoipHandler_defaultPathsOmitted 的字节稳定裁定）。
func TestProvision_crawlerIPListFileDefaultsToAppData(t *testing.T) {
	oldFile := crawlerIPListFile
	t.Cleanup(func() {
		setCrawlerIPListFilePath(oldFile)
		resetCrawlerIPRangeCacheForTest()
	})
	setCrawlerIPListFilePath(filepath.Join(t.TempDir(), "other.json"))
	h := &GeoIPHandler{}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got := crawlerIPListFilePath(); got != "/app/data/crawler-ip-lists.json" {
		t.Fatalf("默认 crawlerIPListFile=%q, want /app/data/crawler-ip-lists.json", got)
	}
	if h.CrawlerIPListFile != "/app/data/crawler-ip-lists.json" {
		t.Fatalf("Provision 未回填默认: %q", h.CrawlerIPListFile)
	}
}

// 官方 IP 段快照不可用 = 无法判定（瞬态）：不得据此判伪装（会误封该引擎的
// 真爬虫并产生伪事件）；快照可用但段外才是确定否定。
func TestVerifyCrawlerIPRange_snapshotUnavailableIsTransient(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "missing-crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	resetCrawlerIPRangeCacheForTest()
	ResetCrawlerVerifyCacheForTest(nil)

	if got := VerifyCrawler("42.236.8.1", "so360spider"); got != CrawlerVerdictTransient {
		t.Fatalf("missing snapshot verdict=%v, want transient（快照不可用不得判伪装）", got)
	}

	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["42.236.8.0/21"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap.loadedAt = time.Now().Add(-2 * time.Minute) // 失败节流期已过
	crawlerFileCacheMu.Unlock()
	if got := VerifyCrawler("42.236.8.1", "so360spider"); got != CrawlerVerdictVerified {
		t.Fatalf("official range verdict=%v, want verified", got)
	}
	if got := VerifyCrawler("42.236.16.1", "so360spider"); got != CrawlerVerdictSpoof {
		t.Fatalf("outside official range verdict=%v, want spoof", got)
	}
}

// resetCrawlerSnapshotLogThrottleForTest 复位告警节流状态与发射计数。
func resetCrawlerSnapshotLogThrottleForTest() {
	crawlerSnapshotLogMu.Lock()
	crawlerSnapshotLogLast = map[string]time.Time{}
	crawlerSnapshotLogMu.Unlock()
	crawlerSnapshotLogCallsForTest.Store(0)
}

// 读侧有界代际读（与 wafiplist 名单加载器共用同一原语）：stat 与读之间的
// 原位改写（追加/截断/同尺寸改写）读到的是混合字节，不得当作一代快照落定。
func TestCrawlerIPRangeSnapshot_rewriteDuringReadFailsClosed(t *testing.T) {
	oldFile := crawlerIPListFile
	oldRead := crawlerReadBoundedFile
	oldInterval := crawlerSnapshotLogInterval
	t.Cleanup(func() {
		crawlerIPListFile = oldFile
		crawlerReadBoundedFile = oldRead
		crawlerSnapshotLogInterval = oldInterval
		resetCrawlerIPRangeCacheForTest()
		resetCrawlerSnapshotLogThrottleForTest()
	})
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	crawlerSnapshotLogInterval = 0
	resetCrawlerIPRangeCacheForTest()
	resetCrawlerSnapshotLogThrottleForTest()

	crawlerReadBoundedFile = func(string, int64) ([]byte, os.FileInfo, error) {
		return nil, nil, wafiplist.ErrFileRewriteDuringRead
	}
	snap := loadCrawlerIPRangeSnapshot()
	if snap.ok {
		t.Fatal("读期间被改写必须 fail-closed（混合字节不得当作一代内容）")
	}
	if len(snap.prefixes) != 0 {
		t.Fatalf("被拒绝的读取不得产出豁免段: %v", snap.prefixes)
	}
	if got := crawlerSnapshotLogCallsForTest.Load(); got != 1 {
		t.Fatalf("改写告警 %d 条, want 1（必须可见）", got)
	}
}

// 持久异常形态（超限文件等）按「路径+原因」节流；成功快照落定后清除记录，
// 再次故障立即可见——不能把日志洪峰当天，也不能把复发故障静默吞掉。
func TestCrawlerIPRangeSnapshot_anomalyLogThrottled(t *testing.T) {
	oldFile := crawlerIPListFile
	oldRetry := crawlerIPListRetryInterval
	oldInterval := crawlerSnapshotLogInterval
	t.Cleanup(func() {
		crawlerIPListFile = oldFile
		crawlerIPListRetryInterval = oldRetry
		crawlerSnapshotLogInterval = oldInterval
		resetCrawlerIPRangeCacheForTest()
		resetCrawlerSnapshotLogThrottleForTest()
	})
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	crawlerIPListRetryInterval = 0 // 失败快照每轮重读（模拟 10s 重试的放大形态）
	crawlerSnapshotLogInterval = time.Minute
	resetCrawlerIPRangeCacheForTest()
	resetCrawlerSnapshotLogThrottleForTest()

	oversized := `{"so360spider":["42.236.8.0/21"]}` + strings.Repeat(" ", crawlerIPListMaxBytes)
	writeSnapshot := func(payload string) {
		t.Helper()
		if err := os.WriteFile(crawlerIPListFile, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSnapshot(oversized)
	for i := 0; i < 3; i++ {
		if loadCrawlerIPRangeSnapshot().ok {
			t.Fatal("超限快照必须 fail-closed")
		}
		time.Sleep(time.Millisecond)
	}
	if got := crawlerSnapshotLogCallsForTest.Load(); got != 1 {
		t.Fatalf("超限告警 %d 条, want 1（同路径同原因按时间窗节流）", got)
	}

	// 恢复合法快照 → 清除节流记录
	writeSnapshot(`{"so360spider":["42.236.8.0/21"]}`)
	if !loadCrawlerIPRangeSnapshot().ok {
		t.Fatal("合法快照应可用（前置条件）")
	}
	// 再次超限（强制越过成功快照的完整重载间隔）
	writeSnapshot(oversized)
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap.loadedAt = time.Now().Add(-time.Hour)
	crawlerFileCacheMu.Unlock()
	if loadCrawlerIPRangeSnapshot().ok {
		t.Fatal("再次超限必须 fail-closed")
	}
	if got := crawlerSnapshotLogCallsForTest.Load(); got != 2 {
		t.Fatalf("恢复后再次故障必须立即重新告警, got %d want 2", got)
	}
}

// 加载期聚合为「升序不相交」前缀集：判定期二分查找（与 @ipListFast 同构）
// 的正确性依赖该不变量；未聚合的线性扫描在大段集下是每请求 O(n)。
func TestCrawlerIPRangeSnapshot_aggregatesSortedDisjoint(t *testing.T) {
	oldFile := crawlerIPListFile
	t.Cleanup(func() {
		crawlerIPListFile = oldFile
		resetCrawlerIPRangeCacheForTest()
	})
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	payload := `{"so360spider":["42.236.9.0/24","42.236.8.0/24","42.236.8.0/22","2408:4000:8000::/33","2408:4000::/33"]}`
	if err := os.WriteFile(crawlerIPListFile, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCrawlerIPRangeCacheForTest()

	snap := loadCrawlerIPRangeSnapshot()
	if !snap.ok {
		t.Fatal("合法快照应可用")
	}
	entries := snap.prefixes["so360spider"]
	// 兄弟段归并 + 被更宽段覆盖剔除：同一并集收敛为两条。
	want := []string{"42.236.8.0/22", "2408:4000::/32"}
	if len(entries) != len(want) {
		t.Fatalf("聚合结果=%v, want %v", entries, want)
	}
	for i := range want {
		if entries[i].String() != want[i] {
			t.Fatalf("聚合结果[%d]=%s, want %s（全量: %v）", i, entries[i], want[i], entries)
		}
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Addr().Compare(entries[i].Addr()) >= 0 {
			t.Fatalf("前缀集未升序: %v", entries)
		}
		if entries[i-1].Contains(entries[i].Addr()) || entries[i].Contains(entries[i-1].Addr()) {
			t.Fatalf("前缀集存在嵌套/重叠（二分失效）: %v", entries)
		}
	}
	// 二分命中面：并集语义不变（归并只合并兄弟段，不放大覆盖）
	for _, hit := range []string{"42.236.8.1", "42.236.9.77", "2408:4000:8000::1"} {
		if !ipRangeVerified(hit, "so360spider") {
			t.Fatalf("%s 应命中官方段", hit)
		}
	}
	for _, miss := range []string{"42.236.16.1", "2408:4001::1"} {
		if ipRangeVerified(miss, "so360spider") {
			t.Fatalf("%s 在段外不得命中", miss)
		}
	}
}

// 快照「不可用」必须可观测：缺失（冷启动正常形态）保持静默，但权限/目录等
// 读错误与内容不可解析（空文件/半截 JSON/非对象 JSON）都是 360 豁免静默失效
// 的真实形态，必须留痕（本模块自订「不可用必须可见」不变量）。
func TestCrawlerIPRangeSnapshot_unavailableReasonsAreLogged(t *testing.T) {
	oldFile := crawlerIPListFile
	oldRead := crawlerReadBoundedFile
	oldInterval := crawlerSnapshotLogInterval
	t.Cleanup(func() {
		crawlerIPListFile = oldFile
		crawlerReadBoundedFile = oldRead
		crawlerSnapshotLogInterval = oldInterval
		resetCrawlerIPRangeCacheForTest()
		resetCrawlerSnapshotLogThrottleForTest()
	})
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	// 非零节流间隔：记录「路径|原因」键，用例据此区分三类不可用原因。
	crawlerSnapshotLogInterval = time.Hour

	cases := []struct {
		name   string
		read   func(string, int64) ([]byte, os.FileInfo, error)
		reason string
	}{
		{
			name: "read-error",
			read: func(string, int64) ([]byte, os.FileInfo, error) {
				return nil, nil, os.ErrPermission
			},
			reason: "read",
		},
		{
			name: "empty",
			read: func(string, int64) ([]byte, os.FileInfo, error) {
				info, err := os.Stat(crawlerIPListFile)
				if err != nil {
					if werr := os.WriteFile(crawlerIPListFile, nil, 0o600); werr != nil {
						t.Fatal(werr)
					}
					info, err = os.Stat(crawlerIPListFile)
					if err != nil {
						t.Fatal(err)
					}
				}
				return []byte{}, info, nil
			},
			reason: "empty",
		},
		{
			name: "invalid-json",
			read: func(string, int64) ([]byte, os.FileInfo, error) {
				if err := os.WriteFile(crawlerIPListFile, []byte(`[]`), 0o600); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(crawlerIPListFile)
				if err != nil {
					t.Fatal(err)
				}
				return []byte(`[]`), info, nil
			},
			reason: "parse",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crawlerReadBoundedFile = tc.read
			resetCrawlerIPRangeCacheForTest()
			resetCrawlerSnapshotLogThrottleForTest()
			snap := loadCrawlerIPRangeSnapshot()
			if snap.ok {
				t.Fatalf("%s：不可用快照必须 fail-closed", tc.name)
			}
			if got := crawlerSnapshotLogCallsForTest.Load(); got != 1 {
				t.Fatalf("%s：不可用原因必须留痕，告警 %d 条, want 1", tc.name, got)
			}
			crawlerSnapshotLogMu.Lock()
			_, logged := crawlerSnapshotLogLast[crawlerIPListFile+"|"+tc.reason]
			crawlerSnapshotLogMu.Unlock()
			if !logged {
				t.Fatalf("%s：告警原因须为 %q，实际记录 %v", tc.name, tc.reason, crawlerSnapshotLogLast)
			}
		})
	}

	// 冷启动缺失形态保持静默：Caddy 可能先于根服务生成快照。
	crawlerReadBoundedFile = func(string, int64) ([]byte, os.FileInfo, error) {
		return nil, nil, os.ErrNotExist
	}
	resetCrawlerIPRangeCacheForTest()
	resetCrawlerSnapshotLogThrottleForTest()
	if snap := loadCrawlerIPRangeSnapshot(); snap.ok {
		t.Fatal("缺失快照必须 fail-closed")
	}
	if got := crawlerSnapshotLogCallsForTest.Load(); got != 0 {
		t.Fatalf("冷启动缺失形态不得告警，实际 %d 条", got)
	}
}

// 快照内容不可用（null/{}/全坏条目）不得把 ok 置真：判定侧对空集返回瞬态，
// 若 ok=true 则 10 分钟缓存期内所有引擎验证恒瞬态，且诊断被成功路径的
// clearCrawlerSnapshotLogs 抹掉（豁免整体静默失效）。
func TestParsePayload_emptySnapshotIsUnavailable(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"null", "null", false},
		{"empty object", "{}", false},
		{"engine with empty list", `{"360":[]}`, false},
		{"all cidrs unparsable", `{"360":["not-a-cidr","1.2.3.4/99"]}`, false},
		{"one usable prefix", `{"360":["203.0.113.0/24"]}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &crawlerIPRangeSnapshot{filePath: "snapshot.json", prefixes: map[string][]netip.Prefix{}}
			if got := s.parsePayload([]byte(c.raw)); got != c.want {
				t.Fatalf("parsePayload(%s)=%v, want %v", c.raw, got, c.want)
			}
		})
	}
}
