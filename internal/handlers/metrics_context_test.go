package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// 指标读库必须消费请求 context：客户端已经断开时，规则、上游与历史
// 查询不得继续跑完并占用 SQLite 连接。
func TestMetricsHandlers_canceledRequestContextAbortsDatabaseReads(t *testing.T) {
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES
		('lb_ctx_http','ctx http','http','ctx-http.example.test',18081,1),
		('lb_ctx_tcp','ctx tcp','tcp','',18082,1)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, enabled) VALUES ('lb_ctx_tcp','127.0.0.1',9000,1)`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("caddy_http_requests_total 1\n"))
	}))
	t.Cleanup(metricsServer.Close)
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: metricsServer.URL}}

	cases := []struct {
		name    string
		path    string
		route   string
		handler gin.HandlerFunc
	}{
		{name: "global history", path: "/metrics/history", route: "/metrics/history", handler: h.GetMetricsHistory},
		{name: "rule history", path: "/rules/lb_ctx_http/metrics-history", route: "/rules/:caddy_id/metrics-history", handler: h.GetRuleMetricsHistory},
		{name: "rule and upstream reads", path: "/metrics/rule/lb_ctx_tcp", route: "/metrics/rule/:caddy_id", handler: h.GetRuleMetrics},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.GET(tc.route, tc.handler)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			request := httptest.NewRequest(http.MethodGet, tc.path, nil).WithContext(ctx)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("canceled status=%d body=%s, want 500", response.Code, response.Body.String())
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loadRuleUpstreams(canceled, "lb_ctx_tcp"); !errors.Is(err, context.Canceled) {
		t.Fatalf("upstream read err=%v, want context.Canceled", err)
	}
}
