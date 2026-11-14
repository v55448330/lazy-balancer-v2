package handlers

// admin API 访问的共享 HTTP 客户端：Transport 连接池跨请求复用（每请求新建
// client 的旧形态会让每个调用点各自维护连接），同时保留每请求超时语义
// （context 承载，覆盖到 body 读取）。

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type caddyAdminRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn caddyAdminRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type caddyAdminTrackedBody struct {
	io.Reader
	closeCalls int
}

func (body *caddyAdminTrackedBody) Close() error {
	body.closeCalls++
	return nil
}

func TestCaddyAdminGet_redirectErrorClosesBodyAndCancelsRequest(t *testing.T) {
	withIsolatedGlobal(t)
	oldClient := caddyAdminHTTPClient
	body := &caddyAdminTrackedBody{Reader: strings.NewReader("redirect")}
	var requestCtx context.Context
	caddyAdminHTTPClient = &http.Client{
		Transport: caddyAdminRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requestCtx = request.Context()
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"http://redirect.invalid/next"}},
				Body:       body,
				Request:    request,
			}, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect rejected")
		},
	}
	t.Cleanup(func() { caddyAdminHTTPClient = oldClient })

	response, err := caddyAdminGet(context.Background(), "http://admin.invalid", "/config/", time.Hour)
	if err == nil || response == nil {
		t.Fatalf("redirect result response=%v err=%v, want non-nil response and error", response, err)
	}
	if body.closeCalls == 0 {
		t.Fatal("redirect error response body was not closed")
	}
	if requestCtx == nil {
		t.Fatal("round trip did not capture request context")
	}
	select {
	case <-requestCtx.Done():
	default:
		t.Fatal("redirect error left the per-request timeout context active")
	}
}

func TestCaddyAdminGet_sharesTransportAcrossCalls(t *testing.T) {
	var mu sync.Mutex
	newConns := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			newConns++
			mu.Unlock()
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	// When 用三个不同超时（原三个调用点的 250ms/2s/5s）依次访问同一 admin 端点。
	for _, timeout := range []time.Duration{250 * time.Millisecond, 2 * time.Second, 5 * time.Second} {
		resp, err := caddyAdminGet(context.Background(), server.URL, "/config/", timeout)
		if err != nil {
			t.Fatalf("get with timeout %s: %v", timeout, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
	}

	// Then 三次请求共用连接池：只建立 1 条 TCP 连接。
	mu.Lock()
	got := newConns
	mu.Unlock()
	if got != 1 {
		t.Fatalf("TCP 连接数=%d, want 1（Transport 必须跨调用复用）", got)
	}
	if caddyAdminHTTPClient.Transport != caddyAdminTransport {
		t.Fatal("共享客户端必须使用包级 Transport（每请求新建 Transport 会丢连接池）")
	}
}

func TestCaddyAdminGet_preservesPerRequestTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 固定 500ms 响应：短超时必须先失败；超时语义丢失则约 500ms 后成功
		// （断言失败而非挂起）。
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(slow.Close)

	// When 超时短于服务端响应时间。
	start := time.Now()
	_, err := caddyAdminGet(context.Background(), slow.URL, "/config/", 50*time.Millisecond)

	// Then 必须按单请求超时失败（不得无限等待、也不得因共享客户端取消超时）。
	if err == nil {
		t.Fatal("超时未生效：共享客户端丢失了每请求 timeout 语义")
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("超时耗时=%v, want ≤50ms 量级（超时未被 context 承载）", elapsed)
	}
}

// 超时成功后连接池仍可用（cancel 随 Body.Close 回收，不污染后续请求）：
// 必须是真实超时（短超时打慢端点），而不是直接用快端点发首请求——否则
// 测不到「超时请求遗留在途状态」这一目标形态。
func TestCaddyAdminGet_succeedsAfterTimeout(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			// 500ms 响应：50ms 超时必然先触发真实超时。
			time.Sleep(500 * time.Millisecond)
			_, _ = io.WriteString(w, `{"slow":true}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(fast.Close)

	// 第一次：真实超时（同一共享客户端的连接/context 进入取消态）。
	if _, err := caddyAdminGet(context.Background(), fast.URL, "/slow", 50*time.Millisecond); err == nil {
		t.Fatal("首请求未超时：慢端点应触发每请求 timeout")
	}

	// 第二次：同一客户端、同一主机，超时后必须仍可成功。
	resp, err := caddyAdminGet(context.Background(), fast.URL, "/config/", time.Second)
	if err != nil {
		t.Fatalf("超时后的第二次请求失败: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body=%s, want %s", body, `{"ok":true}`)
	}
}
