package dnspod

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// staleDomainIDTransport 模拟「域名被移出账户后重建」：Domain.List 只认
// currentID，Record.Create 对其他 domain_id 报「域名ID错误」（code 6）。
type staleDomainIDTransport struct {
	mu        sync.Mutex
	currentID string
	creates   []string
	listCalls int
}

func (transport *staleDomainIDTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	transport.mu.Lock()
	switch {
	case strings.HasSuffix(request.URL.Path, "Domain.List"):
		transport.listCalls++
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"domains":[{"id":%q,"name":"example.com"}]}`, transport.currentID)
	case strings.HasSuffix(request.URL.Path, "Record.Create"):
		domainID := params.Get("domain_id")
		transport.creates = append(transport.creates, domainID)
		if domainID != transport.currentID {
			responseBody = `{"status":{"code":"6","message":"域名ID错误"}}`
		} else {
			responseBody = `{"status":{"code":"1","message":"ok"},"record":{"id":"900"}}`
		}
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func seedDomainIDCache(t *testing.T, entries map[string]string) {
	t.Helper()
	domainIDCacheMu.Lock()
	domainIDCache = entries
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = map[string]string{}
		domainIDCacheMu.Unlock()
	})
}

// CERT42-7（第 42 轮审计）：Record.Create 返回「域名不存在」类错误时，zone→
// domain_id 缓存可能是陈旧值（域名移出账户/删除后重建，新 ID 与缓存不符）——
// 须作废该 zone 缓存并重解析一次再重试一次，而非直接把错误抛给签发链。
func TestProvider_Present_retriesWithFreshDomainIDOnStaleCache(t *testing.T) {
	// Given a stale cached zone→domain_id while the API moved the domain to id 42
	seedDomainIDCache(t, map[string]string{"example.com": "stale-1"})
	transport := &staleDomainIDTransport{currentID: "42"}
	provider := New("id,token")
	provider.client.Transport = transport

	// When presenting a challenge
	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then the stale cache was invalidated, re-resolved once and retried once
	if err != nil {
		t.Fatalf("Present()=%v, want nil（缓存作废后重试成功）", err)
	}
	transport.mu.Lock()
	creates := append([]string(nil), transport.creates...)
	listCalls := transport.listCalls
	transport.mu.Unlock()
	if !reflect.DeepEqual(creates, []string{"stale-1", "42"}) {
		t.Fatalf("Record.Create domain_ids=%v, want [stale-1 42]（陈旧一次+重解析一次）", creates)
	}
	if listCalls != 1 {
		t.Fatalf("Domain.List calls=%d, want 1（重解析一次）", listCalls)
	}
	domainIDCacheMu.Lock()
	cached := domainIDCache["example.com"]
	domainIDCacheMu.Unlock()
	if cached != "42" {
		t.Fatalf("cached domain id=%q, want 42（重解析后回写）", cached)
	}
}

// CERT42-7 回归形状一：域名真正移出账户（Domain.List 查无）时，作废缓存后
// 重解析失败直接返回错误——不得循环重试。
func TestProvider_Present_staleCacheRetryStopsWhenDomainGone(t *testing.T) {
	// Given a stale cache and an account that no longer holds the zone
	seedDomainIDCache(t, map[string]string{"example.com": "stale-1"})
	transport := &staleDomainIDTransport{currentID: "42"}
	provider := New("id,token")
	// Domain.List 不返回 example.com（域名已不在账户内）
	provider.client.Transport = &domainGoneTransport{inner: transport}

	// When presenting a challenge
	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then exactly one create attempt happened and the error surfaces
	if err == nil {
		t.Fatal("want error（域名已移出账户）, got nil")
	}
	transport.mu.Lock()
	creates := append([]string(nil), transport.creates...)
	transport.mu.Unlock()
	if !reflect.DeepEqual(creates, []string{"stale-1"}) {
		t.Fatalf("Record.Create domain_ids=%v, want [stale-1]（重解析失败不再重试）", creates)
	}
}

// domainGoneTransport 包装 staleDomainIDTransport，让 Domain.List 返回空列表
// （域名已不在账户内）。
type domainGoneTransport struct {
	inner *staleDomainIDTransport
}

func (transport *domainGoneTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1","message":"ok"},"domains":[]}`)),
			Request:    request,
		}, nil
	}
	return transport.inner.RoundTrip(request)
}

// CERT42-7 回归形状二：非「域名不存在」类错误（如权限/限流）不作废缓存、不重试。
func TestProvider_Present_doesNotRetryOnUnrelatedCreateError(t *testing.T) {
	// Given a cached id and an API that fails Record.Create with a non-domain error
	seedDomainIDCache(t, map[string]string{"example.com": "cached-7"})
	transport := &createFailingTransport{code: "-1", message: "登录失败"}
	provider := New("id,token")
	provider.client.Transport = transport

	// When presenting a challenge
	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then a single create attempt was made and the cache is untouched
	if err == nil {
		t.Fatal("want error, got nil")
	}
	transport.mu.Lock()
	creates := append([]string(nil), transport.creates...)
	transport.mu.Unlock()
	if !reflect.DeepEqual(creates, []string{"cached-7"}) {
		t.Fatalf("Record.Create domain_ids=%v, want [cached-7]（非域名错误不重试）", creates)
	}
	domainIDCacheMu.Lock()
	cached := domainIDCache["example.com"]
	domainIDCacheMu.Unlock()
	if cached != "cached-7" {
		t.Fatalf("cached domain id=%q, want cached-7（缓存不得作废）", cached)
	}
}

type createFailingTransport struct {
	mu      sync.Mutex
	code    string
	message string
	creates []string
}

func (transport *createFailingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	transport.mu.Lock()
	if strings.HasSuffix(request.URL.Path, "Record.Create") {
		transport.creates = append(transport.creates, params.Get("domain_id"))
		responseBody = fmt.Sprintf(`{"status":{"code":%q,"message":%q}}`, transport.code, transport.message)
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}
