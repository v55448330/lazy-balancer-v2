package tencent

import (
	"net/http"
	"sync"
	"testing"
)

func TestSetUserAgent_versionized(t *testing.T) {
	prev := userAgent
	t.Cleanup(func() { userAgent = prev })
	SetUserAgent("v2.4.2")
	if userAgent != "lazy-balancer/v2.4.2" {
		t.Fatalf("userAgent=%q, want lazy-balancer/v2.4.2", userAgent)
	}
	SetUserAgent("")
	if userAgent != "lazy-balancer/v2.4.2" {
		t.Fatalf("空串不得清空已有 UA: %q", userAgent)
	}
}

// 出网 UA 钉测：SDK common v1.3.159 构造请求不写 User-Agent（Go 默认 UA 出网），
// 生产接缝在 New() 装配的 Transport wrapper 上追加版本化 UA——钉测从生产链路
// 最底层（http.DefaultTransport 底座）捕获实际出网请求头，装配缺失或版本
// 段丢失即红。
func TestProvider_outboundUserAgent_versionized(t *testing.T) {
	prev := userAgent
	t.Cleanup(func() { userAgent = prev })
	SetUserAgent("v2.4.2")

	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	capture := &uaCaptureTransport{recordTransport: &recordTransport{records: map[uint64]string{}}}
	prevBase := http.DefaultTransport
	http.DefaultTransport = capture
	t.Cleanup(func() { http.DefaultTransport = prevBase })

	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "ua-probe", 600); err != nil {
		t.Fatalf("present: %v", err)
	}
	capture.mu.Lock()
	ua := capture.userAgent
	capture.mu.Unlock()
	if ua != "lazy-balancer/v2.4.2" {
		t.Fatalf("outbound UA=%q, want lazy-balancer/v2.4.2", ua)
	}
}

// uaCaptureTransport 是生产链路底座的捕获桩：记录到达 RoundTrip 的 User-Agent，
// 响应构造复用既有 recordTransport 桩。
type uaCaptureTransport struct {
	*recordTransport
	mu        sync.Mutex
	userAgent string
}

func (t *uaCaptureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.userAgent = r.Header.Get("User-Agent")
	t.mu.Unlock()
	return t.recordTransport.RoundTrip(r)
}
