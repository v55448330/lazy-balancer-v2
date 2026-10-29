package dnspod

import (
	"testing"
	"time"
)

func seedDomainIDCache(t *testing.T, loginToken string, entries map[string]string) {
	t.Helper()
	provider := New(loginToken)
	scoped := make(map[string]string, len(entries))
	for zone, id := range entries {
		scoped[provider.domainIDCacheKey(zone)] = id
	}
	domainIDCacheMu.Lock()
	var previous map[string]string
	var previousNeg map[string]time.Time
	var previousOrder []string
	if domainIDCache != nil {
		previous = make(map[string]string, len(domainIDCache))
		for key, id := range domainIDCache {
			previous[key] = id
		}
	}
	if domainIDNegativeCache != nil {
		previousNeg = make(map[string]time.Time, len(domainIDNegativeCache))
		for key, at := range domainIDNegativeCache {
			previousNeg[key] = at
		}
	}
	previousOrder = append([]string(nil), domainIDCacheOrder...)
	domainIDCache = scoped
	domainIDNegativeCache = map[string]time.Time{}
	// 重建 LRU 使用序（种子条目按 map 遍历序入队——夹具内顺序无语义）。
	domainIDCacheOrder = domainIDCacheOrder[:0]
	for key := range scoped {
		domainIDCacheOrder = append(domainIDCacheOrder, key)
	}
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = previous
		domainIDNegativeCache = previousNeg
		domainIDCacheOrder = previousOrder
		domainIDCacheMu.Unlock()
	})
}

func TestSeedDomainIDCache_restoresPreviousEntries(t *testing.T) {
	domainIDCacheMu.Lock()
	original := domainIDCache
	originalNeg := domainIDNegativeCache
	originalOrder := domainIDCacheOrder
	domainIDCache = map[string]string{"existing-zone": "existing-id"}
	domainIDNegativeCache = map[string]time.Time{}
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = original
		domainIDNegativeCache = originalNeg
		domainIDCacheOrder = originalOrder
		domainIDCacheMu.Unlock()
	})

	t.Run("isolated fixture", func(t *testing.T) {
		seedDomainIDCache(t, "id,token", map[string]string{"example.com": "25"})
		domainIDCacheMu.Lock()
		_, existingSurvived := domainIDCache["existing-zone"]
		domainIDCacheMu.Unlock()
		if existingSurvived {
			t.Fatal("fixture must start from its explicitly seeded cache")
		}
	})

	domainIDCacheMu.Lock()
	defer domainIDCacheMu.Unlock()
	if len(domainIDCache) != 1 || domainIDCache["existing-zone"] != "existing-id" {
		t.Fatalf("cache after fixture=%v, want previous entries restored", domainIDCache)
	}
}
