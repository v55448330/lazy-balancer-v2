package handlers

// 监控面板聚合的并发门：TTL 命中零抓取；并发 miss 只跑一趟聚合（single-flight，
// 旧实现用全局锁串行整段聚合）；失败写短负缓存——同窗内多页签不重复击穿
// Caddy，到期即重试（自愈快）。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func overrideDashboardFetch(t *testing.T, fn func(context.Context, string) ([]byte, error)) {
	t.Helper()
	old := metricsDashboardFetch
	metricsDashboardFetch = fn
	t.Cleanup(func() { metricsDashboardFetch = old })
}

func requestDashboard(t *testing.T, h *Handlers) int {
	t.Helper()
	rec := httptest.NewRecorder()
	ginCtx, engine := gin.CreateTestContext(rec)
	_ = engine
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/metrics/dashboard", nil)
	h.GetMetricsDashboard(ginCtx)
	return rec.Code
}

func TestGetMetricsDashboard_singleFlightForConcurrentMisses(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.metricsService = services.NewMetricsService("http://127.0.0.1:1/metrics", 30)
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)

	var fetchCalls atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		fetchCalls.Add(1)
		time.Sleep(80 * time.Millisecond) // 模拟慢抓取：并发窗口内其余请求必须等待同一趟
		return []byte("caddy_http_requests_total 100\n"), nil
	})

	const concurrency = 8
	var wg sync.WaitGroup
	codes := make([]int, concurrency)
	wg.Add(concurrency)
	for i := range concurrency {
		go func() {
			defer wg.Done()
			codes[i] = requestDashboard(t, h)
		}()
	}
	wg.Wait()

	for _, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("并发请求状态码=%d, want 200", code)
		}
	}
	if got := fetchCalls.Load(); got != 1 {
		t.Fatalf("并发 8 请求抓取 %d 次, want 1（single-flight 未生效，仍串行重试）", got)
	}

	// TTL 内再次请求：零抓取。
	if code := requestDashboard(t, h); code != http.StatusOK {
		t.Fatalf("TTL 内请求状态码=%d, want 200", code)
	}
	if got := fetchCalls.Load(); got != 1 {
		t.Fatalf("TTL 内请求触发抓取, 累计=%d, want 1", got)
	}
}

func TestGetMetricsDashboard_failureNegativeCacheShortRetry(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	h.metricsService = services.NewMetricsService("http://127.0.0.1:1/metrics", 30)
	resetMetricsDashboardCacheForTest()
	oldNeg := metricsDashboardNegativeTTL
	metricsDashboardNegativeTTL = 50 * time.Millisecond
	t.Cleanup(func() {
		metricsDashboardNegativeTTL = oldNeg
		resetMetricsDashboardCacheForTest()
	})

	var fetchCalls atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		fetchCalls.Add(1)
		return nil, errors.New("upstream metrics down")
	})

	// Given 抓取失败。
	if code := requestDashboard(t, h); code != http.StatusBadGateway {
		t.Fatalf("失败请求状态码=%d, want 502", code)
	}
	// When 负缓存窗口内立即重试。
	if code := requestDashboard(t, h); code != http.StatusBadGateway {
		t.Fatalf("负缓存请求状态码=%d, want 502", code)
	}
	// Then 不重复抓取（窗口内收敛）。
	if got := fetchCalls.Load(); got != 1 {
		t.Fatalf("负缓存窗口内抓取 %d 次, want 1", got)
	}

	// When 负缓存过期（短窗口）→ 立即重试，允许快速自愈。
	time.Sleep(80 * time.Millisecond)
	if code := requestDashboard(t, h); code != http.StatusBadGateway {
		t.Fatalf("过期后请求状态码=%d, want 502", code)
	}
	if got := fetchCalls.Load(); got != 2 {
		t.Fatalf("负缓存过期后抓取累计=%d, want 2（失败可快速重试）", got)
	}
}
