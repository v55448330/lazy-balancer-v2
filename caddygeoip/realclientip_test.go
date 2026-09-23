package caddygeoip

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// realClientIP（v2.3.x 真实 IP 支持）：优先取 Caddy client_ip 变量——
// trusted_proxies 启用时它是经网段+头校验的真实 IP；伪造 XFF 不得改变判定。
// 变量缺席时回退 socket RemoteAddr（直连部署行为不变）。
func TestRealClientIP_prefersClientIPVar(t *testing.T) {
	// Given：socket 为 CDN IP，client_ip 变量为真实 IP，XFF 伪造
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "198.51.100.77",
	})
	req = req.WithContext(ctx)

	// When/Then
	if got := realClientIP(req); got != "198.51.100.77" {
		t.Fatalf("realClientIP=%q, want client_ip var 198.51.100.77", got)
	}
}

func TestRealClientIP_clientIPVarIgnoresForgedHeaders(t *testing.T) {
	// Given：client_ip 变量=socket（直连，Caddy 未采信任何头）+ 伪造权威头
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	req.Header.Set("CF-Connecting-IP", "9.9.9.9")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "203.0.113.1",
	})
	req = req.WithContext(ctx)

	// When/Then：伪造头不改变判定
	if got := realClientIP(req); got != "203.0.113.1" {
		t.Fatalf("realClientIP=%q, want 203.0.113.1 (forged headers ignored)", got)
	}
}

func TestRealClientIP_fallsBackToRemoteAddr(t *testing.T) {
	for _, tc := range []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"host:port", "203.0.113.5:1234", "203.0.113.5"},
		{"bare IP", "2001:db8::1", "2001:db8::1"},
		{"unparseable", "not-an-ip", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if got := realClientIP(req); got != tc.want {
				t.Fatalf("realClientIP(%q)=%q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}
