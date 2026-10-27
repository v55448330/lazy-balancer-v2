package dnspod

import "testing"

func seedDomainIDCache(t *testing.T, loginToken string, entries map[string]string) {
	t.Helper()
	provider := New(loginToken)
	scoped := make(map[string]string, len(entries))
	for zone, id := range entries {
		scoped[provider.domainIDCacheKey(zone)] = id
	}
	domainIDCacheMu.Lock()
	var previous map[string]string
	if domainIDCache != nil {
		previous = make(map[string]string, len(domainIDCache))
		for key, id := range domainIDCache {
			previous[key] = id
		}
	}
	domainIDCache = scoped
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = previous
		domainIDCacheMu.Unlock()
	})
}

func TestSeedDomainIDCache_restoresPreviousEntries(t *testing.T) {
	domainIDCacheMu.Lock()
	original := domainIDCache
	domainIDCache = map[string]string{"existing-zone": "existing-id"}
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = original
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
