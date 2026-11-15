package handlers

// 威胁大屏三个 admin 代理端点（collector/events/traffic）共享同一
// threatAdminClient（与 humanAdminClient 同模式）：单源统一 2s 超时/客户端
// 形态，避免每请求新建 client。本钉测以「多次轮询复用同一 TCP 连接」为
// 可观察契约（连接复用由 http.DefaultTransport 连接池承载——Transport=nil
// 的 client 共享该池；基线钉防未来给 client 设独立 Transport/
// DisableKeepAlives 破坏复用）。collector/events 保留 NewRequestWithContext
// 可取消语义（请求 ctx 传入）。

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func TestThreatScreenAdminProxy_reusesConnectionAcrossPolls(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	var conns atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/lb/traffic-collector":
			_, _ = w.Write([]byte(`{"enabled":true}`))
		case "/lb/traffic-events":
			_, _ = w.Write([]byte(`{"enabled":false,"events":[],"next_seq":0,"sample_n":0}`))
		case "/lb/traffic-stats":
			_, _ = w.Write([]byte(`{"countries":{},"sample_n":0,"collecting":false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	admin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	defer admin.Close()

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	router := gin.New()
	router.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	router.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)
	router.GET("/security/overview/threat-screen/traffic", h.GetThreatScreenTraffic)

	for i := range 3 {
		// collector：带 lease_id 的 POST（本地登记走 services 内存面）。
		rec := postJSON(t, router, "/security/overview/threat-screen/collector", map[string]any{
			"lease_id": "tab-reuse", "ttl_ms": 30000, "sample_n": 1,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("collector poll %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
		rec = getRequest(t, router, "/security/overview/threat-screen/events")
		if rec.Code != http.StatusOK {
			t.Fatalf("events poll %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
		rec = getRequest(t, router, "/security/overview/threat-screen/traffic")
		if rec.Code != http.StatusOK {
			t.Fatalf("traffic poll %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("3 轮×3 端点新建 TCP 连接=%d, want 1（共享客户端连接池复用）", got)
	}
}

// collector/events 保留 NewRequestWithContext 可取消语义：请求 ctx 取消
// 必须传导到上游 admin 调用（共享客户端不得退化为不可取消的形态）。
func TestThreatScreenAdminProxy_requestContextPropagated(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	entered := make(chan struct{}, 1)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		// 挂住直到请求 ctx 被取消（客户端断开传导）或测试兜底超时。
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer admin.Close()

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	router := gin.New()
	router.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector", nil).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		done <- rec.Code
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("上游 admin 未收到请求")
	}
	cancel()
	select {
	case code := <-done:
		if code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d, want 503（请求 ctx 取消必须中止上游调用）", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("请求 ctx 取消后 handler 仍阻塞——NewRequestWithContext 可取消语义丢失")
	}
}
