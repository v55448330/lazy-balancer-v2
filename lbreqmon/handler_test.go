package lbreqmon

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// serveOnce 驱动一次 ServeHTTP 并取回最新记录（测试隔离：先清空环形缓冲）。
func serveOnce(t *testing.T, r *http.Request, next caddyhttp.Handler) (RequestRecord, error) {
	t.Helper()
	resetRingForTest()
	rec := httptest.NewRecorder()
	err := ReqMonHandler{}.ServeHTTP(rec, r, next)
	snap := Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot entries=%d, want 1 (ServeHTTP must record exactly once)", len(snap))
	}
	return snap[0], err
}

// 错误路由终结的请求必须观测到真实状态码：下游返回 HandlerError 时响应由
// Caddy server 层在包装器之外写出（statusWriter 看不到 WriteHeader），
// 观测状态不得恒 0（连接监控把 0 显示为绿色 2xx，WAF 拦截/上游故障全失真）。
func TestServeHTTP_handlerErrorStatusObserved(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"bare handler error", caddyhttp.HandlerError{StatusCode: http.StatusForbidden}, http.StatusForbidden},
		{"wrapped handler error", fmt.Errorf("waf: %w", caddyhttp.HandlerError{StatusCode: http.StatusBadGateway}), http.StatusBadGateway},
		{"plain error maps to server default", errors.New("dial upstream failed"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return tc.err // 不写响应——错误路由在链外终结
			})
			req := httptest.NewRequest(http.MethodGet, "http://example.test/blocked", nil)
			got, err := serveOnce(t, req, next)
			if !errors.Is(err, tc.err) && err != tc.err {
				t.Fatalf("ServeHTTP must pass the error through, got %v", err)
			}
			if got.Status != tc.want {
				t.Fatalf("observed status=%d, want %d (error-terminated request must not observe 0)", got.Status, tc.want)
			}
		})
	}
}

// 回归形状：下游已写出的状态码优先于错误映射（响应头已提交，线上状态即已写值）。
func TestServeHTTP_writtenStatusWinsOverError(t *testing.T) {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNotFound)
		return caddyhttp.HandlerError{StatusCode: http.StatusInternalServerError}
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/x", nil)
	got, _ := serveOnce(t, req, next)
	if got.Status != http.StatusNotFound {
		t.Fatalf("observed status=%d, want 404 (already-written status is the wire truth)", got.Status)
	}
}

// 基础捕获面：状态/字节/方法/协议/scheme/RuleID 头/UA/Host/URI/请求体长。
func TestServeHTTP_capturesRequestMetadata(t *testing.T) {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://example.test/path?q=1", strings.NewReader("body"))
	req.Header.Set("X-LB-Rule-ID", "lb-rule-7")
	req.Header.Set("User-Agent", "capture-agent/1.0")
	req.RemoteAddr = "198.51.100.23:5555"
	got, err := serveOnce(t, req, next)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if got.Status != http.StatusCreated || got.Size != 5 {
		t.Fatalf("status/size=%d/%d, want 201/5", got.Status, got.Size)
	}
	if got.Method != http.MethodPost || got.Host != "example.test" || got.URI != "/path?q=1" {
		t.Fatalf("method/host/uri=%q/%q/%q", got.Method, got.Host, got.URI)
	}
	if got.RuleID != "lb-rule-7" || got.UA != "capture-agent/1.0" {
		t.Fatalf("rule_id/ua=%q/%q", got.RuleID, got.UA)
	}
	if got.ClientIP != "198.51.100.23" {
		t.Fatalf("client_ip=%q, want RemoteAddr host", got.ClientIP)
	}
	if got.Scheme != "http" {
		t.Fatalf("scheme=%q, want http (r.TLS=nil)", got.Scheme)
	}
	if got.ReqSize != 4 {
		t.Fatalf("req_size=%d, want ContentLength 4", got.ReqSize)
	}
	if got.Ts <= 0 || got.DurationMs < 0 {
		t.Fatalf("ts/duration=%d/%v must be sane", got.Ts, got.DurationMs)
	}
	if got.Proto == "" {
		t.Fatal("proto must be captured")
	}
}

// TLS 请求 scheme=https；隐式 200（下游只 Write 不 WriteHeader）。
func TestServeHTTP_tlsSchemeAndImplicitOK(t *testing.T) {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, _ = w.Write([]byte("ok"))
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.TLS = &tls.ConnectionState{}
	got, _ := serveOnce(t, req, next)
	if got.Scheme != "https" {
		t.Fatalf("scheme=%q, want https", got.Scheme)
	}
	if got.Status != http.StatusOK {
		t.Fatalf("implicit status=%d, want 200", got.Status)
	}
}

// hijack（WebSocket 升级）后的连接字节必须计入 Size：升级响应之后的流量
// 绕过 statusWriter.Write，不追踪则 WS 连接的观测体量恒为升级响应几十字节。
func TestServeHTTP_hijackedBytesCounted(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	base := &pipeHijackWriter{ResponseWriter: httptest.NewRecorder(), conn: server}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return err
		}
		// 升级后的双向流量：写 7 字节（经 brw 与直接写两路），读 3 字节。
		if _, err := brw.WriteString("1234567"); err != nil {
			return err
		}
		if err := brw.Flush(); err != nil {
			return err
		}
		buf := make([]byte, 3)
		if _, err := conn.Read(buf); err != nil {
			return err
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/ws", nil)
	resetRingForTest()
	done := make(chan error, 1)
	go func() {
		// 对端：读走 7 字节、写入 3 字节（不计入响应 Size）。
		buf := make([]byte, 7)
		if _, err := client.Read(buf); err != nil {
			done <- err
			return
		}
		_, err := client.Write([]byte("abc"))
		done <- err
	}()
	if err := (ReqMonHandler{}).ServeHTTP(base, req, next); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("peer: %v", err)
	}
	snap := Snapshot()
	if len(snap) != 1 {
		t.Fatalf("entries=%d, want 1", len(snap))
	}
	if snap[0].Size != 7 {
		t.Fatalf("hijacked size=%d, want 7 (post-upgrade writes must be counted)", snap[0].Size)
	}
}

// pipeHijackWriter 以 net.Pipe 服务端为 Hijack 目标的响应包装基座。
type pipeHijackWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (p *pipeHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return p.conn, bufio.NewReadWriter(bufio.NewReader(p.conn), bufio.NewWriter(p.conn)), nil
}
