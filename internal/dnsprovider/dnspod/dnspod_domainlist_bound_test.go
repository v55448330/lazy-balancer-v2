package dnspod

// Domain.List 扫描上限的假阴性钉测。
//
// 历史 domainListMaxPages=100 × pageSize=3000 = 30 万域名封顶——超量账户中
// 排在 30 万位之后的域名（真实存在于账户）被误判 not found 并落负缓存
// （60s 内持续失败）。上限只防「忽略 offset 的异常服务端」死循环，翻页
// 终止本就由 total/空页真判定承载——上限提高到 1000 页（300 万域名），
// 假阴性面消除，防御语义不变。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// bigAccountTransport 服务一个 domains 条账户的 Domain.List（pageSize 3000
// 分页），目标域名排在最后一位（旧行为的第 101 页）。
type bigAccountTransport struct {
	mu      sync.Mutex
	domains []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	total int
}

func newBigAccountTransport(t *testing.T, count int) *bigAccountTransport {
	t.Helper()
	transport := &bigAccountTransport{total: count}
	transport.domains = make([]struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}, count)
	for i := range count {
		name := fmt.Sprintf("domain%d.example.com", i)
		if i == count-1 {
			name = "target.com"
		}
		transport.domains[i] = struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{ID: strconv.Itoa(i + 1), Name: name}
	}
	return transport
}

func (transport *bigAccountTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(request.URL.Path, "Domain.List") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"1","message":"ok"}}`)),
			Request:    request,
		}, nil
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	offset, _ := strconv.Atoi(params.Get("offset"))
	transport.mu.Lock()
	defer transport.mu.Unlock()
	start, end := offset, min(offset+domainListPageSize, transport.total)
	if start > transport.total {
		start = transport.total
	}
	payload, err := json.Marshal(map[string]any{
		"status":  map[string]string{"code": "1", "message": "ok"},
		"domains": transport.domains[start:end],
		"info":    map[string]string{"domain_total": strconv.Itoa(transport.total)},
	})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(payload))),
		Request:    request,
	}, nil
}

// 30 万零一个域名的账户，目标排在最后（第 101 页）：必须扫到，不得被
// 旧 100 页上限截断成假阴性 not found。
func TestGetDomainID_scansBeyondLegacyPageBound(t *testing.T) {
	seedDomainIDCache(t, "id,token", map[string]string{})
	provider := New("id,token")
	provider.client.Transport = newBigAccountTransport(t, 300001)

	id, err := provider.getDomainID(t.Context(), "target.com")
	if err != nil {
		t.Fatalf("getDomainID: %v（30 万位之后的真实域名不得误判 not found）", err)
	}
	if id != "300001" {
		t.Fatalf("id=%q, want 300001", id)
	}
}
