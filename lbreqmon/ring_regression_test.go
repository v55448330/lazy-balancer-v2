package lbreqmon

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// hijackableWriter 底层实现 Hijacker 的响应包装基座。
type hijackableWriter struct {
	http.ResponseWriter
}

func (h *hijackableWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

// statusWriter 不得断开 ResponseController 的 Unwrap 链：
// 底层支持 Hijack 时，包装后的 Hijack 必须可用（全站 WS 依赖）。
func TestStatusWriter_unwrapPreservesHijack(t *testing.T) {
	base := &hijackableWriter{ResponseWriter: httptest.NewRecorder()}
	w := &statusWriter{ResponseWriter: base}
	_, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Fatalf("ResponseController.Hijack through statusWriter: %v (Unwrap chain broken)", err)
	}
	if w.status != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d, want 101（升级响应直写连接，不经过 WriteHeader）", w.status)
	}
}

// WriteHeader 已显式给出状态时，Hijack 不得把它改写为 101。
func TestStatusWriter_hijackKeepsExplicitStatus(t *testing.T) {
	base := &hijackableWriter{ResponseWriter: httptest.NewRecorder()}
	w := &statusWriter{ResponseWriter: base}
	w.WriteHeader(http.StatusUnauthorized)
	_, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if w.status != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", w.status)
	}
}

// 受信代理判定缺席时伪造 XFF 不得改变观测到的客户端 IP；var 在场时用 var 值。
func TestClientIP_ignoresForgedXFF(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		varIP      string
		want       string
	}{
		{"forged xff falls back to remote", "198.51.100.7:4321", "9.9.9.9", "", "198.51.100.7"},
		{"forged xff chain falls back to remote", "198.51.100.7:4321", "9.9.9.9, 10.0.0.1", "", "198.51.100.7"},
		{"trusted var wins over forged xff", "198.51.100.7:4321", "9.9.9.9", "1.2.3.4", "1.2.3.4"},
		{"ipv6 remote host", "[2001:db8::1]:4321", "", "", "2001:db8::1"},
		{"bare remote addr", "203.0.113.5", "", "", "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.varIP != "" {
				ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
				caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, tc.varIP)
				r = r.WithContext(ctx)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP=%q, want %q (xff=%q var=%q)", got, tc.want, tc.xff, tc.varIP)
			}
		})
	}
}
