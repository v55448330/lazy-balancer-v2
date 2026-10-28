package services

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	health := service.getUpstreamHealthFromMetrics(context.Background())

	// Then it is rejected wholesale rather than parsed into memory
	if len(health) != 0 {
		t.Fatalf("health=%v, want empty（超限响应应整体拒收）", health)
	}
}

func TestCaddyService_GetUpstreamHealthDetailed_usesDedicatedMetricsURL(t *testing.T) {
	// Given：Admin 只提供配置/被动指标，独立 metrics 端点提供主动健康状态。
	adminMetricsHits, metricsHits := 0, 0
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			adminMetricsHits++
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/reverse_proxy/upstreams":
			_, _ = io.WriteString(w, `[{"address":"10.0.0.1:80","num_requests":3,"fails":0}]`)
		case "/config/":
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.1:80"}]}]}]}}}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(admin.Close)
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metricsHits++
		_, _ = io.WriteString(w, `caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.1:80"} 1`+"\n")
	}))
	t.Cleanup(metrics.Close)
	service := NewCaddyServiceWithMetricsURL(admin.URL, metrics.URL+"/metrics")

	// When
	health, err := service.GetUpstreamHealthDetailed()

	// Then：主动健康来自独立端点，admin /metrics 零请求，Admin 其他数据不丢。
	if err != nil {
		t.Fatalf("get upstream health: %v", err)
	}
	if adminMetricsHits != 0 || metricsHits != 1 {
		t.Fatalf("metrics hits admin=%d dedicated=%d, want 0/1", adminMetricsHits, metricsHits)
	}
	detail := health["srv0"]["10.0.0.1:80"]
	if detail == nil || !detail.Healthy || detail.Unknown || detail.NumRequests != 3 {
		t.Fatalf("health detail=%+v, want healthy with 3 requests from admin", detail)
	}
}

// 回归形状：16MB 以内的正常响应照常解析。
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
	health := service.getUpstreamHealthFromMetrics(context.Background())

	// Then all three upstreams are parsed
	if len(health) != 3 || !health["10.0.0.1:80"] || health["10.0.0.2:80"] || !health["10.0.0.3:443"] {
		t.Fatalf("health=%v, want 3 parsed upstreams", health)
	}
}

type upstreamHealthHits struct {
	metrics        atomic.Int32
	upstreams      atomic.Int32
	config         atomic.Int32
	configFailures atomic.Int32
	load           atomic.Int32
}

func newUpstreamHealthCacheAdmin(t *testing.T, hits *upstreamHealthHits, metricsGate <-chan struct{}) *httptest.Server {
	t.Helper()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			hits.metrics.Add(1)
			if metricsGate != nil {
				<-metricsGate
			}
			_, _ = io.WriteString(w, `caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.1:80"} 1`+"\n")
		case "/reverse_proxy/upstreams":
			hits.upstreams.Add(1)
			_, _ = io.WriteString(w, `[{"address":"10.0.0.1:80","num_requests":3,"fails":0}]`)
		case "/config/":
			hits.config.Add(1)
			if hits.configFailures.Load() > 0 {
				hits.configFailures.Add(-1)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"10.0.0.1:80"}]}]}]}}}}}`)
		case "/load":
			hits.load.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(admin.Close)
	return admin
}

func TestCaddyService_GetUpstreamHealthDetailed_cachesAndCopiesResults(t *testing.T) {
	var hits upstreamHealthHits
	admin := newUpstreamHealthCacheAdmin(t, &hits, nil)
	service := NewCaddyService(admin.URL)

	first, err := service.GetUpstreamHealthDetailed()
	if err != nil {
		t.Fatal(err)
	}
	first["srv0"]["10.0.0.1:80"].Healthy = false
	first["srv0"]["10.0.0.1:80"].NumRequests = 999
	second, err := service.GetUpstreamHealthDetailed()
	if err != nil {
		t.Fatal(err)
	}

	if got := hits.metrics.Load(); got != 1 {
		t.Fatalf("metrics hits=%d, want 1 within TTL", got)
	}
	if got := hits.upstreams.Load(); got != 1 {
		t.Fatalf("upstreams hits=%d, want 1 within TTL", got)
	}
	if got := hits.config.Load(); got != 1 {
		t.Fatalf("config hits=%d, want 1 within TTL", got)
	}
	detail := second["srv0"]["10.0.0.1:80"]
	if detail == nil || !detail.Healthy || detail.NumRequests != 3 {
		t.Fatalf("cached detail=%+v, caller mutation polluted shared result", detail)
	}
}

func TestCaddyService_GetUpstreamHealthDetailed_singleFlightsConcurrentRequests(t *testing.T) {
	var hits upstreamHealthHits
	gate := make(chan struct{})
	admin := newUpstreamHealthCacheAdmin(t, &hits, gate)
	service := NewCaddyService(admin.URL)
	const callers = 8
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(callers)
	done.Add(callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			ready.Done()
			defer done.Done()
			_, err := service.GetUpstreamHealthDetailed()
			errs <- err
		}()
	}
	ready.Wait()
	close(gate)
	done.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := hits.metrics.Load(); got != 1 {
		t.Fatalf("concurrent metrics hits=%d, want single-flight 1", got)
	}
	if got := hits.upstreams.Load(); got != 1 {
		t.Fatalf("concurrent upstream hits=%d, want single-flight 1", got)
	}
	if got := hits.config.Load(); got != 1 {
		t.Fatalf("concurrent config hits=%d, want single-flight 1", got)
	}
}

func TestCaddyService_ApplyConfig_invalidatesUpstreamHealthCache(t *testing.T) {
	var hits upstreamHealthHits
	admin := newUpstreamHealthCacheAdmin(t, &hits, nil)
	service := NewCaddyService(admin.URL)
	if _, err := service.GetUpstreamHealthDetailed(); err != nil {
		t.Fatalf("prime health cache: %v", err)
	}
	if err := service.ApplyConfig(map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"routes": []interface{}{map[string]interface{}{
							"handle": []interface{}{map[string]interface{}{
								"handler":   "reverse_proxy",
								"upstreams": []interface{}{map[string]interface{}{"dial": "10.0.0.2:80"}},
							}},
						}},
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if got := hits.load.Load(); got != 1 {
		t.Fatalf("/load hits=%d, want 1", got)
	}
	if _, err := service.GetUpstreamHealthDetailed(); err != nil {
		t.Fatalf("get health after apply: %v", err)
	}
	if got := hits.metrics.Load(); got != 2 {
		t.Fatalf("metrics hits=%d, want 2（成功 /load 后必须失效健康缓存）", got)
	}
	if got := hits.upstreams.Load(); got != 2 {
		t.Fatalf("upstreams hits=%d, want 2（成功 /load 后必须失效健康缓存）", got)
	}
}

func TestCaddyService_GetUpstreamHealthDetailed_cacheExpires(t *testing.T) {
	oldTTL := upstreamHealthCacheTTL
	upstreamHealthCacheTTL = 20 * time.Millisecond
	t.Cleanup(func() { upstreamHealthCacheTTL = oldTTL })
	var hits upstreamHealthHits
	admin := newUpstreamHealthCacheAdmin(t, &hits, nil)
	service := NewCaddyService(admin.URL)
	if _, err := service.GetUpstreamHealthDetailed(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := service.GetUpstreamHealthDetailed(); err != nil {
		t.Fatal(err)
	}
	if got := hits.config.Load(); got != 2 {
		t.Fatalf("config hits=%d, want refresh after TTL", got)
	}
}

func TestCaddyService_GetUpstreamHealthDetailed_doesNotCacheErrors(t *testing.T) {
	var hits upstreamHealthHits
	hits.configFailures.Store(1)
	admin := newUpstreamHealthCacheAdmin(t, &hits, nil)
	service := NewCaddyService(admin.URL)
	if _, err := service.GetUpstreamHealthDetailed(); err == nil {
		t.Fatal("first config failure must propagate")
	}
	if _, err := service.GetUpstreamHealthDetailed(); err != nil {
		t.Fatalf("second request must retry after failure: %v", err)
	}
	if _, err := service.GetUpstreamHealthDetailed(); err != nil {
		t.Fatal(err)
	}
	if got := hits.config.Load(); got != 2 {
		t.Fatalf("config hits=%d, want failure retry then success cache", got)
	}
}
