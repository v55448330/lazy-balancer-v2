package dnspod

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// perAccountDomainTransport 按 login_token 返回各自账户的 Domain.List
// （同一 zone 在两个账户下 domain_id 不同）。
type perAccountDomainTransport struct {
	mu  sync.Mutex
	ids map[string]string // login_token -> domain_id
}

func (transport *perAccountDomainTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	if strings.HasSuffix(request.URL.Path, "Domain.List") {
		transport.mu.Lock()
		id := transport.ids[params.Get("login_token")]
		transport.mu.Unlock()
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"domains":[{"id":%q,"name":"example.com"}]}`, id)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

// F49-7（第 49 轮审计）：domainIDCache 以裸 zone 为键，同进程多 DNSPod 账户
// （多条 DNS 凭证）交替签发同一 zone 时，账户 B 首调即命中账户 A 缓存的
// domain_id——Record.Create 用错账户的 ID（靠「域名ID错误」自愈纯属侥幸）。
// 缓存键必须按账户（login_token 摘要）隔离。
func TestProvider_getDomainID_cacheIsScopedPerAccount(t *testing.T) {
	// Given: 同一 zone 在两个账户下的 domain_id 不同
	seedDomainIDCache(t, "111,keyA", map[string]string{})
	transport := &perAccountDomainTransport{ids: map[string]string{
		"111,keyA": "1001",
		"222,keyB": "2002",
	}}
	providerA := New("111,keyA")
	providerA.client.Transport = transport
	providerB := New("222,keyB")
	providerB.client.Transport = transport

	// When: 账户 A 先解析（写入缓存），账户 B 再解析同一 zone
	idA, err := providerA.getDomainID(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("account A getDomainID: %v", err)
	}
	idB, err := providerB.getDomainID(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("account B getDomainID: %v", err)
	}

	// Then: 各自命中各自账户的 ID——B 首调即正确，不得复用 A 的缓存
	if idA != "1001" {
		t.Fatalf("account A domain id=%q, want 1001", idA)
	}
	if idB != "2002" {
		t.Fatalf("account B domain id=%q, want 2002（跨账户串缓存）", idB)
	}
}
