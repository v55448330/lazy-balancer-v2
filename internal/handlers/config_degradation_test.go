package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 未注入 cfg 的嵌入/装配形态必须与既有空指标契约一致：返回可解码的
// 零值数据，不得在 handler 内裸解引用配置并 panic。
func TestHandlers_nilConfigReturnsZeroValueResponses(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg = nil
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_nil_cfg','nil cfg','http','nil-cfg.example.test',18080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)

	cases := []struct {
		name    string
		method  string
		path    string
		route   string
		handler gin.HandlerFunc
	}{
		{name: "dashboard", method: http.MethodGet, path: "/metrics/dashboard", handler: h.GetMetricsDashboard},
		{name: "caddy metrics", method: http.MethodGet, path: "/caddy/metrics", handler: h.GetCaddyMetrics},
		{name: "host metrics", method: http.MethodGet, path: "/caddy/host-metrics", handler: h.GetHostMetrics},
		{name: "rule metrics", method: http.MethodGet, path: "/metrics/rule/lb_nil_cfg", route: "/metrics/rule/:caddy_id", handler: h.GetRuleMetrics},
		{name: "system info", method: http.MethodGet, path: "/system/info", handler: h.GetSystemInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			route := tc.route
			if route == "" {
				route = tc.path
			}
			router.GET(route, tc.handler)
			recorder := httptest.NewRecorder()
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("nil cfg panic: %v", recovered)
					}
				}()
				router.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
			}()
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200 zero-value response", recorder.Code, recorder.Body.String())
			}
		})
	}
}
