package dnspod

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// emptyDomainListTransport 统计 Domain.List 次数并恒返回空域列表
// （domain_total=0 → 首次扫描即终态 not found）。
type emptyDomainListTransport struct {
	mu        sync.Mutex
	listCalls int
}

func (transport *emptyDomainListTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_, _ = io.ReadAll(request.Body)
	_ = request.Body.Close()
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		transport.mu.Lock()
		transport.listCalls++
		transport.mu.Unlock()
	}
	body := `{"status":{"code":"1","message":"Action successful"},"domains":[],"info":{"domain_total":0}}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}, nil
}

func (transport *emptyDomainListTransport) calls() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.listCalls
}

// 负缓存钉：全量扫描确认「域名不在账户」后，同一 zone 的再次解析不得再发
// Domain.List——否则误填/已移出账户的 zone 每次挑战都全量分页扫，叠加重试
// 会把配置错误放大成厂商限流。解析失败不落负缓存的旧实现第二次调用照样
// 全量扫（本用例对旧实现必红）。
func TestProvider_getDomainID_negativeCacheSkipsRelist(t *testing.T) {
	resetDomainIDCacheForTest(t)
	provider := New("id,token")
	transport := &emptyDomainListTransport{}
	provider.client.Transport = transport

	if _, err := provider.getDomainID(context.Background(), "missing.com"); err == nil {
		t.Fatal("不存在的域名必须报错")
	}
	first := transport.calls()
	if first == 0 {
		t.Fatal("首次解析必须发起 Domain.List")
	}
	if _, err := provider.getDomainID(context.Background(), "missing.com"); err == nil {
		t.Fatal("负缓存命中同样必须报 not found")
	}
	if got := transport.calls(); got != first {
		t.Fatalf("负缓存生效后第二次解析又发了 %d 次 Domain.List（共 %d）——不得重复全量扫描", got-first, got)
	}

	// 负缓存必须可作废：配置变更（换账户/zone 后补进账户）走
	// invalidateDomainIDCache 后，下一次解析必须重新发起 Domain.List。
	provider.invalidateDomainIDCache("missing.com")
	if _, err := provider.getDomainID(context.Background(), "missing.com"); err == nil {
		t.Fatal("作废后仍必须报 not found")
	}
	if got := transport.calls(); got != first+1 {
		t.Fatalf("invalidateDomainIDCache 后未重新扫描：calls=%d want=%d", got, first+1)
	}
}

// 负缓存短 TTL：过期后必须重新扫描（zone 后补进账户的收敛延迟上限即 TTL）。
func TestProvider_getDomainID_negativeCacheExpires(t *testing.T) {
	resetDomainIDCacheForTest(t)
	provider := New("id,token")
	transport := &emptyDomainListTransport{}
	provider.client.Transport = transport
	oldTTL := domainIDNegativeTTL
	domainIDNegativeTTL = 20 * time.Millisecond
	t.Cleanup(func() { domainIDNegativeTTL = oldTTL })

	if _, err := provider.getDomainID(context.Background(), "missing.com"); err == nil {
		t.Fatal("不存在的域名必须报错")
	}
	first := transport.calls()
	time.Sleep(40 * time.Millisecond) // 越过 TTL
	if _, err := provider.getDomainID(context.Background(), "missing.com"); err == nil {
		t.Fatal("过期后仍必须报 not found")
	}
	if got := transport.calls(); got != first+1 {
		t.Fatalf("负缓存过期后未重新扫描：calls=%d want=%d", got, first+1)
	}
}

// 正缓存 LRU 上限：容量满后插入新键必须淘汰旧键（防进程级无上限增长）。
func TestProvider_domainIDCache_capacityEviction(t *testing.T) {
	resetDomainIDCacheForTest(t)
	oldTTL := domainIDNegativeTTL
	domainIDNegativeTTL = time.Minute
	t.Cleanup(func() { domainIDNegativeTTL = oldTTL })

	domainIDCacheMu.Lock()
	originalPos := domainIDCache
	originalNeg := domainIDNegativeCache
	originalOrder := domainIDCacheOrder
	domainIDCache = map[string]string{}
	domainIDNegativeCache = map[string]time.Time{}
	domainIDCacheOrder = nil
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = originalPos
		domainIDNegativeCache = originalNeg
		domainIDCacheOrder = originalOrder
		domainIDCacheMu.Unlock()
	})

	provider := New("id,token")
	// 插入 capacity+50 个正缓存键。
	for i := range domainIDCacheCapacity + 50 {
		provider.putDomainIDCache("zone-"+strconv.Itoa(i), "1")
	}
	domainIDCacheMu.Lock()
	size := len(domainIDCache)
	domainIDCacheMu.Unlock()
	if size > domainIDCacheCapacity {
		t.Fatalf("正缓存无上限增长：size=%d cap=%d", size, domainIDCacheCapacity)
	}
	// 命中会触碰 LRU：反复命中的键不得被纯插入淘汰。
	hotKey := provider.domainIDCacheKey("hot-zone")
	provider.putDomainIDCache(hotKey, "7")
	for i := range 100 {
		provider.putDomainIDCache("fill-"+strconv.Itoa(i), "1")
		if _, ok := provider.getDomainIDCache(hotKey); !ok {
			t.Fatalf("命中键在 %d 次插入后被淘汰——LRU 触碰语义失效", i+1)
		}
	}
}

// resetDomainIDCacheForTest 清空包级正/负缓存与 LRU 序——同包用例共享进程，
// 任一用例留下的条目会让「首次解析必须发起 Domain.List」这类断言随机假红。
func resetDomainIDCacheForTest(t *testing.T) {
	t.Helper()
	clear := func() {
		domainIDCacheMu.Lock()
		domainIDCache = map[string]string{}
		domainIDNegativeCache = map[string]time.Time{}
		domainIDCacheOrder = nil
		domainIDCacheMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}
