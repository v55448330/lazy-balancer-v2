package dnspod

// Domain.List 无进展守卫与「收手未扫尽不落负缓存」回归（与 Record.List /
// aliyun/tencent/cloudflare 的枚举翻页守卫同族）：
//   - 异常服务端忽略 offset 重复下发同页（domain_total 失真偏大）时，
//     整页无新域名 ID 即收手——不得空转 domainListMaxPages（1000 页）；
//   - 无进展/页数上限收手时扫描**未取尽**，「域名不在账户」结论不成立，
//     不得落 60s 负缓存把一次异常放大成 TTL 内持续失败；
//   - 畸形空 ID 条目不参与 seen 去重（整页空 ID 不得折叠成无进展）。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// domainListShapeTransport 按模式下发 Domain.List：
//   - "repeat"：忽略 offset，每页重复同 2 个域名，domain_total=1000（失真）；
//   - "emptyIDs"：第 1 页整页空 ID 畸形条目，第 2 页含目标域名（total=4，
//     第 3 页 offset≥total 空页真终态）；
//   - "mixedRepeat"：每页 1 个真实域名 + 1 个空 ID 条目（真实 ID 跨页重复）。
type domainListShapeTransport struct {
	mu    sync.Mutex
	mode  string
	calls int
}

func (transport *domainListShapeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, err := io.ReadAll(request.Body); err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if !strings.HasSuffix(request.URL.Path, "Domain.List") {
		return progressTestJSONResponse(request, `{"status":{"code":"1","message":"ok"}}`), nil
	}
	transport.calls++
	type listedDomain struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	domains := []listedDomain{}
	total := 1000
	switch transport.mode {
	case "repeat":
		domains = append(domains,
			listedDomain{ID: "1", Name: "a.com"},
			listedDomain{ID: "2", Name: "b.com"})
	case "emptyIDs":
		if transport.calls == 1 {
			for i := range 3 {
				domains = append(domains, listedDomain{ID: "", Name: "noise" + strconv.Itoa(i) + ".com"})
			}
		} else if transport.calls == 2 {
			domains = append(domains, listedDomain{ID: "9", Name: "target.com"})
			total = 4
		} else {
			total = 4
		}
	case "mixedRepeat":
		domains = append(domains,
			listedDomain{ID: "1", Name: "a.com"},
			listedDomain{ID: "", Name: "noise.com"})
	}
	payload, err := json.Marshal(map[string]any{
		"status":  map[string]string{"code": "1", "message": "ok"},
		"domains": domains,
		"info":    map[string]any{"domain_total": total},
	})
	if err != nil {
		return nil, err
	}
	return progressTestJSONResponse(request, string(payload)), nil
}

func progressTestJSONResponse(request *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func negativeCacheHas(provider *Provider, zone string) bool {
	domainIDCacheMu.Lock()
	defer domainIDCacheMu.Unlock()
	_, ok := domainIDNegativeCache[provider.domainIDCacheKey(zone)]
	return ok
}

// 异常服务端重复下发同页：第 2 页整页无新域名 ID 即收手（2 次调用），
// 不空转 1000 页；未扫尽不得落负缓存（下次解析重新发起扫描）。
func TestGetDomainID_repeatedPagesStopWithoutNegativeCache(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &domainListShapeTransport{mode: "repeat"}
	provider := New("id,token")
	provider.client.Transport = transport

	_, err := provider.getDomainID(context.Background(), "target.com")
	if err == nil {
		t.Fatal("want not-found error（目标域名不在重复页内）")
	}
	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	if calls != 2 {
		t.Fatalf("calls=%d, want 2（整页重复无进展即收手，不空转页数上限）", calls)
	}
	if negativeCacheHas(provider, "target.com") {
		t.Fatal("无进展收手未扫尽，不得落负缓存（异常服务端不得放大成 TTL 内持续失败）")
	}
}

// 整页空 ID 畸形条目不得折叠成无进展：第 2 页的目标域名必须扫到。
func TestGetDomainID_emptyIDPageDoesNotFoldProgress(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &domainListShapeTransport{mode: "emptyIDs"}
	provider := New("id,token")
	provider.client.Transport = transport

	id, err := provider.getDomainID(context.Background(), "target.com")
	if err != nil {
		t.Fatalf("getDomainID: %v（整页空 ID 不得误判无进展提前收手）", err)
	}
	if id != "9" {
		t.Fatalf("id=%q, want 9", id)
	}
	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	if calls < 2 {
		t.Fatalf("calls=%d, want ≥2（必须翻到第 2 页取目标域名）", calls)
	}
}

// 真实 ID 跨页重复 + 每页夹带空 ID 条目：空 ID 不豁免重复守卫，第 2 页
// 真实 ID 已见即收手；未扫尽不落负缓存。
func TestGetDomainID_emptyIDsDoNotDisableRepeatGuard(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &domainListShapeTransport{mode: "mixedRepeat"}
	provider := New("id,token")
	provider.client.Transport = transport

	_, err := provider.getDomainID(context.Background(), "target.com")
	if err == nil {
		t.Fatal("want not-found error")
	}
	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	if calls != 2 {
		t.Fatalf("calls=%d, want 2（真实 ID 重复页仍须收手）", calls)
	}
	if negativeCacheHas(provider, "target.com") {
		t.Fatal("未扫尽不得落负缓存")
	}
}

// 回归形状：完整扫描（空页真终态）确认域名不在账户时，负缓存照常落
// （60s TTL 语义不变），命中即短路不再发请求。
func TestGetDomainID_exhaustiveScanStillCachesNotFound(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &domainListShapeTransport{mode: "emptyIDs"}
	provider := New("id,token")
	provider.client.Transport = transport

	// other.com 不在任何页：第 1 页空 ID（跳过）、第 2 页 target.com、
	// 第 3 页空页真终态——完整扫尽，负缓存必须落。
	_, err := provider.getDomainID(context.Background(), "other.com")
	if err == nil {
		t.Fatal("want not-found error")
	}
	if !negativeCacheHas(provider, "other.com") {
		t.Fatal("完整扫尽的 not-found 必须落负缓存（既有 TTL 语义）")
	}
	transport.mu.Lock()
	before := transport.calls
	transport.mu.Unlock()
	if _, err := provider.getDomainID(context.Background(), "other.com"); err == nil {
		t.Fatal("want cached not-found error")
	}
	transport.mu.Lock()
	after := transport.calls
	transport.mu.Unlock()
	if after != before {
		t.Fatalf("calls %d→%d, 负缓存命中不得再发请求", before, after)
	}
}

// Record.List 侧同族：整页空 ID 不得折叠无进展（第 2 页目标记录必须扫到），
// 空 ID 条目不得进 collected。
func TestListChallengeRecords_emptyIDPageDoesNotFoldProgress(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "1"})
	var calls int
	var mu sync.Mutex
	provider := New("id,token")
	provider.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if _, err := io.ReadAll(request.Body); err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(request.URL.Path, "Domain.List") {
			return progressTestJSONResponse(request, `{"status":{"code":"1","message":"ok"},"domains":[{"id":"1","name":"example.com"}],"info":{"domain_total":1}}`), nil
		}
		calls++
		type listed struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		records := []listed{}
		if calls == 1 {
			for range challengeListPageSize {
				records = append(records, listed{ID: "", Name: "_acme-challenge", Type: "TXT", Value: "v"})
			}
		} else {
			records = append(records, listed{ID: "77", Name: "_acme-challenge", Type: "TXT", Value: "target"})
		}
		payload, _ := json.Marshal(map[string]any{
			"status":  map[string]string{"code": "1", "message": "ok"},
			"records": records,
			"info":    map[string]any{"record_total": 1000},
		})
		return progressTestJSONResponse(request, string(payload)), nil
	})

	records, err := provider.listChallengeRecords(context.Background(), "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("listChallengeRecords: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 {
		t.Fatalf("calls=%d, want ≥2（整页空 ID 不得误判无进展提前收手）", calls)
	}
	if len(records) != 1 || records[0].recordID != "77" {
		t.Fatalf("records=%+v, want 仅第 2 页目标记录（空 ID 不进 collected）", records)
	}
}
