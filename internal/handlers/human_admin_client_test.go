package handlers

// 人机验证运行态/统计代理共享同一 Caddy admin HTTP 客户端（humanAdminClient，
// 与 reqMonClient 同模式）：单源统一超时/客户端形态，避免各端点各自维护。
// 本钉测以「多次轮询复用同一 TCP 连接」为可观察契约。注：连接复用本身由
// http.DefaultTransport 连接池承载（Transport=nil 的 client 共享该池），
// 故本测试是基线钉（防未来给 client 设独立 Transport/DisableKeepAlives 而
// 破坏复用），非「修复前必然红」的回归——共享客户端收敛的是客户端单源形态。

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func TestHumanAdminProxy_reusesConnectionAcrossPolls(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	var conns atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"challenges":1,"passes":1,"fails":0}`))
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
	router.GET("/security/human/stats", h.GetHumanVerifyStats)
	for range 3 {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/human/stats", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("3 次轮询新建 TCP 连接=%d, want 1（共享客户端连接池复用）", got)
	}
}
