package handlers

// 行为钉：规则指标历史端点属 business 组（任意登录用户可读），5xx
// 只回固定文案——底层错误（SQL 文本/表列名/数据目录路径）只进运行日志。

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestGetRuleMetricsHistory_5xxHidesInternalError(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_metrics_5xx','metrics-5xx','http','metrics5xx.example.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// MetricsDB 指向已关闭的库：查询必然失败且错误文本含驱动内部结构。
	closed, err := sql.Open("sqlite", t.TempDir()+"/metrics.db")
	if err != nil {
		t.Fatalf("open metrics db: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close metrics db: %v", err)
	}
	previous := db.MetricsDB
	db.MetricsDB = closed
	t.Cleanup(func() { db.MetricsDB = previous })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics-history", (&Handlers{}).GetRuleMetricsHistory)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_metrics_5xx/metrics-history", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "读取历史指标失败") {
		t.Fatalf("body=%s, want 固定文案「读取历史指标失败」", body)
	}
	for _, leak := range []string{"database is closed", "sql:", ".db", "/var/", "/tmp/"} {
		if strings.Contains(body, leak) {
			t.Fatalf("body=%s, want 不含内部错误细节 %q", body, leak)
		}
	}
}

// 单规则 TCP 指标读取上游失败：固定文案 + 运行日志留痕（不回显表名/SQL）。
func TestGetRuleMetrics_tcpUpstreamReadFailureHidesInternalError(t *testing.T) {
	withIsolatedGlobal(t)
	database := initializeRuleFeatureTestDB(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_tcp_metrics_5xx','tcp-metrics-5xx','tcp','',9000,1)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	// 上游表缺失：读路径必然失败，错误文本含表名与 SQLite 驱动文案。
	if _, err := database.Exec(`DROP TABLE upstreams`); err != nil {
		t.Fatalf("drop upstreams: %v", err)
	}
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	oldFetch := metricsDashboardFetch
	metricsDashboardFetch = func(context.Context, string) ([]byte, error) {
		return []byte("caddy_http_requests_total 1\n"), nil
	}
	t.Cleanup(func() { metricsDashboardFetch = oldFetch })
	logs := captureLog(t)

	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://metrics.invalid/metrics"}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics", h.GetRuleMetrics)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_tcp_metrics_5xx/metrics", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "读取规则上游失败") {
		t.Fatalf("body=%s, want 固定文案「读取规则上游失败」", body)
	}
	for _, leak := range []string{"no such table", "upstreams", "sql:", ".db"} {
		if strings.Contains(body, leak) {
			t.Fatalf("body=%s, want 不含内部错误细节 %q", body, leak)
		}
	}
	if logText := logs.String(); !strings.Contains(logText, "读取规则上游失败") || !strings.Contains(logText, "no such table") {
		t.Fatalf("日志=%q, want 固定文案与底层错误（表名只进日志）", logText)
	}
}

// 全局指标历史的查询失败：与同端点其余三个失败分支同口径（固定文案 + 日志），
// 不得成为「静默 500」。
func TestGetMetricsHistory_queryFailureLogsAndHidesInternalError(t *testing.T) {
	closed, err := sql.Open("sqlite", t.TempDir()+"/metrics.db")
	if err != nil {
		t.Fatalf("open metrics db: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close metrics db: %v", err)
	}
	previous := db.MetricsDB
	db.MetricsDB = closed
	t.Cleanup(func() { db.MetricsDB = previous })
	logs := captureLog(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics/history", (&Handlers{}).GetMetricsHistory)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics/history?interval=1h", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "读取指标历史失败") {
		t.Fatalf("body=%s, want 固定文案「读取指标历史失败」（与 Scan/rows.Err 分支同源）", body)
	}
	for _, leak := range []string{"database is closed", "sql:", ".db", "/tmp/"} {
		if strings.Contains(body, leak) {
			t.Fatalf("body=%s, want 不含内部错误细节 %q", body, leak)
		}
	}
	if logText := logs.String(); !strings.Contains(logText, "读取指标历史失败") || !strings.Contains(logText, "database is closed") {
		t.Fatalf("日志=%q, want 固定文案与底层错误", logText)
	}
}

// 采集失败（502）不得把指标源地址/内网 IP:端口/传输错误回给任意登录用户。
func TestGetCaddyMetrics_502HidesUpstreamDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	metricsURL := server.URL + "/metrics"
	server.Close() // 连接被拒：错误文本含 URL、host:port 与 dial 细节。
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	logs := captureLog(t)

	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: metricsURL}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "采集 Caddy 指标失败") {
		t.Fatalf("body=%s, want 固定文案「采集 Caddy 指标失败」", body)
	}
	for _, leak := range []string{"http://", "https://", "dial tcp", "127.0.0.1"} {
		if strings.Contains(body, leak) {
			t.Fatalf("body=%s, want 不含指标源地址/传输细节 %q", body, leak)
		}
	}
	if logText := logs.String(); !strings.Contains(logText, "采集 Caddy 指标失败") || !strings.Contains(logText, "dial tcp") {
		t.Fatalf("日志=%q, want 固定文案与传输细节（仅日志可见）", logText)
	}
}

// 面板负缓存保存的失败文案同样不得携带指标源地址（命中时原样重复）。
func TestGetMetricsDashboard_failureMessageHidesUpstreamDetails(t *testing.T) {
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		return nil, errors.New(`Get "http://10.20.30.40:2019/metrics": dial tcp 10.20.30.40:2019: connect: connection refused`)
	})
	logs := captureLog(t)

	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://10.20.30.40:2019/metrics"}}
	gin.SetMode(gin.TestMode)
	// 两次请求：第二次命中的是负缓存条目，文案来源必须与首次一致（无地址）。
	for attempt := range 2 {
		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = httptest.NewRequest(http.MethodGet, "/metrics/dashboard", nil)
		h.GetMetricsDashboard(ginCtx)
		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("attempt=%d status=%d body=%s, want 502", attempt, recorder.Code, recorder.Body.String())
		}
		body := recorder.Body.String()
		if !strings.Contains(body, "采集 Caddy 指标失败") {
			t.Fatalf("attempt=%d body=%s, want 固定文案", attempt, body)
		}
		for _, leak := range []string{"10.20.30.40", "http://", "dial tcp"} {
			if strings.Contains(body, leak) {
				t.Fatalf("attempt=%d body=%s, want 不含指标源地址/传输细节 %q", attempt, body, leak)
			}
		}
	}
	if logText := logs.String(); !strings.Contains(logText, "10.20.30.40") {
		t.Fatalf("日志=%q, want 失败详情（地址）只进运行日志", logText)
	}
}

// 抓取截止时间单源：HTTP 客户端不设独立超时——否则它恒先于自身上限触发，
// 「自身超时/取消不写负缓存」的分支在真实 HTTP 路径永不可达。
func TestLoadCaddyMetricsSnapshot_selfTimeoutSkippedFromNegativeCache(t *testing.T) {
	withIsolatedGlobal(t)
	if caddyMetricsHTTPClient.Timeout != 0 {
		t.Fatalf("caddyMetricsHTTPClient.Timeout=%v, want 0（截止时间只由 caddyMetricsFetchTimeout 表达）", caddyMetricsHTTPClient.Timeout)
	}
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	oldTimeout := caddyMetricsFetchTimeout
	caddyMetricsFetchTimeout = 60 * time.Millisecond
	t.Cleanup(func() { caddyMetricsFetchTimeout = oldTimeout })
	oldFetch := metricsDashboardFetch
	metricsDashboardFetch = fetchCaddyMetrics // 走真实 HTTP 客户端，不经注入缝。
	t.Cleanup(func() { metricsDashboardFetch = oldFetch })

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
		_, _ = w.Write([]byte("caddy_http_requests_total 1\n"))
	}))
	defer server.Close()
	url := server.URL + "/metrics"

	// When：第一次抓取被自身上限截断。
	start := time.Now()
	if _, err := loadCaddyMetricsSnapshot(context.Background(), url, true); err == nil {
		t.Fatal("自身上限到期必须返回 error")
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("抓取耗时=%v, want 被自身上限（60ms）截断", elapsed)
	}
	// Then：超时不写负缓存——第二次请求立刻重新抓取（计数=2）。
	if _, err := loadCaddyMetricsSnapshot(context.Background(), url, true); err == nil {
		t.Fatal("第二次抓取同样必须返回 error")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("上游命中次数=%d, want 2（自身超时不得写入负缓存）", got)
	}
}
