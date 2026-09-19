package services

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PERF42-1（第 42 轮审计）：/metrics 响应必须经 16MB LimitReader+1 探测
// （与 handlers/metrics.go fetchCaddyMetrics 同型）——超限按读取失败处理返回空
// 健康表，防指标基数膨胀时裸 io.ReadAll 无界分配内存。
func TestCaddyService_getUpstreamHealthFromMetrics_rejectsOversizedBody(t *testing.T) {
	// Given a /metrics endpoint returning >16MB with a valid health line at the tail
	const metricLine = `caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.1:80"} 1` + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("# padding\n", (16<<20)/10))
		_, _ = io.WriteString(w, metricLine)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	// When the oversized metrics body is fetched
	health := service.getUpstreamHealthFromMetrics()

	// Then it is rejected wholesale rather than parsed into memory
	if len(health) != 0 {
		t.Fatalf("health=%v, want empty（超限响应应整体拒收）", health)
	}
}

// PERF42-1 回归形状：16MB 以内的正常响应照常解析。
func TestCaddyService_getUpstreamHealthFromMetrics_parsesSmallBody(t *testing.T) {
	// Given a small /metrics body with healthy and unhealthy upstreams
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "# HELP caddy_reverse_proxy_upstreams_healthy\n"+
			`caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.1:80"} 1`+"\n"+
			`caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.2:80"} 0`+"\n"+
			`caddy_layer4_proxy_upstream_healthy{upstream="10.0.0.3:443"} 1`+"\n")
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	// When the metrics body is fetched
	health := service.getUpstreamHealthFromMetrics()

	// Then all three upstreams are parsed
	if len(health) != 3 || !health["10.0.0.1:80"] || health["10.0.0.2:80"] || !health["10.0.0.3:443"] {
		t.Fatalf("health=%v, want 3 parsed upstreams", health)
	}
}
