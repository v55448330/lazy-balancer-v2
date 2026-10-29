package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

type metricsCursorErrorDriver struct{}

var metricsCursorErrorDriverOnce sync.Once

func (metricsCursorErrorDriver) Open(string) (driver.Conn, error) {
	return metricsCursorErrorConn{}, nil
}

type metricsCursorErrorConn struct{}

func (metricsCursorErrorConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not supported")
}
func (metricsCursorErrorConn) Close() error              { return nil }
func (metricsCursorErrorConn) Begin() (driver.Tx, error) { return nil, errors.New("not supported") }
func (metricsCursorErrorConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &metricsCursorErrorRows{}, nil
}

type metricsCursorErrorRows struct {
	read bool
}

// 列必须与 GetRuleMetricsHistory 的 SELECT 完全一致（9 列，含
// requests_blocked）——原 8 列让首次 Scan 就失败，游标中断分支从未执行。
func (*metricsCursorErrorRows) Columns() []string {
	return []string{"timestamp", "requests_total", "requests_2xx", "requests_3xx", "requests_4xx", "requests_5xx", "requests_blocked", "bytes_in", "bytes_out"}
}
func (*metricsCursorErrorRows) Close() error { return nil }
func (r *metricsCursorErrorRows) Next(dest []driver.Value) error {
	if r.read {
		return errors.New("cursor interrupted")
	}
	r.read = true
	// 时间戳必须是处理器可解析的布局（time.Time 经驱动转换后无法按
	// "2006-01-02 15:04:05" 解析，会在时间解析分支提前 500）。
	dest[0] = "2026-10-18 00:00:00"
	for i := 1; i < len(dest); i++ {
		dest[i] = int64(i)
	}
	return nil
}

func newMetricsTestDatabase(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 直换包级句柄必须同步复位 currentDB（契约，
		// 与 newBackupTestHandlers 同型），防跨用例留下 nil/已关闭句柄。
		db.SetDB(oldDB)
	})
}

func TestMetricsHandlers_useDedicatedCaddyMetricsURL(t *testing.T) {
	// Given：admin 与 Prometheus 指标端点分离；admin 端点故意返回 503。
	tests := []struct {
		name  string
		mount func(*gin.Engine, *Handlers)
		path  string
	}{
		{name: "caddy metrics", mount: func(r *gin.Engine, h *Handlers) { r.GET("/metrics", h.GetCaddyMetrics) }, path: "/metrics"},
		{name: "host metrics", mount: func(r *gin.Engine, h *Handlers) { r.GET("/metrics", h.GetHostMetrics) }, path: "/metrics"},
		{name: "rule metrics", mount: func(r *gin.Engine, h *Handlers) { r.GET("/rules/:caddy_id/metrics", h.GetRuleMetrics) }, path: "/rules/lb_metrics_url/metrics"},
		{name: "dashboard", mount: func(r *gin.Engine, h *Handlers) { r.GET("/dashboard", h.GetMetricsDashboard) }, path: "/dashboard"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newMetricsTestDatabase(t)
			if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_metrics_url','metrics','http','metrics.example.test',80,1)`); err != nil {
				t.Fatal(err)
			}
			resetMetricsDashboardCacheForTest()
			t.Cleanup(resetMetricsDashboardCacheForTest)
			adminHits, metricsHits := 0, 0
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				adminHits++
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer admin.Close()
			metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				metricsHits++
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("caddy_http_requests_total 100\n"))
			}))
			defer metrics.Close()
			cfg := &config.Config{CaddyAdminURL: admin.URL, CaddyMetricsURL: metrics.URL + "/metrics"}
			h := &Handlers{cfg: cfg, metricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 30)}
			router := gin.New()
			test.mount(router, h)

			// When
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))

			// Then：四个消费面都直读 CaddyMetricsURL，绝不回退/拼接 admin URL。
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want dedicated metrics endpoint 200", response.Code, response.Body.String())
			}
			if adminHits != 0 || metricsHits != 1 {
				t.Fatalf("hits admin=%d metrics=%d, want 0/1", adminHits, metricsHits)
			}
		})
	}
}

func TestGetCaddyMetrics_clientCancellationDoesNotAbortSharedScrape(t *testing.T) {
	// 共享抓取脱离首个请求的取消信号：single-flight 的结果同时交给所有等待
	// 者，leader 客户端断开不得中止抓取（否则同批健康连接收到伪造的上游失败）。
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	requestStarted := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-release
		_, _ = w.Write([]byte("caddy_http_requests_total 1\n"))
	}))
	defer server.Close()
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: server.URL, CaddyMetricsURL: server.URL + "/metrics"}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx)
	done := make(chan int, 1)

	// When
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		done <- rec.Code
	}()
	<-requestStarted
	cancel()

	// Then：取消后抓取仍在跑（本 handler 不得随客户端断开收工）。
	select {
	case code := <-done:
		close(release)
		t.Fatalf("status=%d, want 挂起（客户端取消不得中止共享抓取）", code)
	case <-time.After(200 * time.Millisecond):
	}
	// 上游完成后 handler 正常收尾（响应丢弃即可）。
	close(release)
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("status=%d, want 200（抓取完成后的正常结果）", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("抓取完成后请求未返回")
	}
}

func TestGetCaddyMetrics_returns_bad_gateway_on_caddy_error_status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer server.Close()
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: server.URL, CaddyMetricsURL: server.URL + "/metrics"}}
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "采集 Caddy 指标失败") {
		t.Fatalf("status=%d body=%s, want 502 with collection error", response.Code, response.Body.String())
	}
}

func TestGetRuleMetricsHistory_returns_error_when_cursor_fails(t *testing.T) {
	// Given
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_history', 'history', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	const driverName = "metrics-cursor-error"
	metricsCursorErrorDriverOnce.Do(func() { sql.Register(driverName, metricsCursorErrorDriver{}) })
	metricsDB, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatalf("open cursor error database: %v", err)
	}
	oldMetricsDB := db.MetricsDB
	db.MetricsDB = metricsDB
	t.Cleanup(func() {
		_ = metricsDB.Close()
		db.MetricsDB = oldMetricsDB
	})
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics-history", h.GetRuleMetricsHistory)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_history/metrics-history", nil))

	// Then：必须真正到达 rows.Err() 分支（原假驱动列数 8 vs Scan 9
	// 让首次 Scan 即以列数不匹配 500，游标中断分支从未被覆盖）。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取历史指标失败") {
		t.Fatalf("body=%s, want 固定文案「读取历史指标失败」（详情只进日志）", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "cursor interrupted") {
		t.Fatalf("body=%s, want 不得回显驱动内部错误（business 组 5xx 政策）", response.Body.String())
	}
}

func TestLoadRuleUpstreams_returns_scan_error(t *testing.T) {
	// Given
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_scan', 'scan', 'tcp', 9001, 1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, enabled) VALUES ('lb_scan', '127.0.0.1', 'bad-port', 1)`); err != nil {
		t.Fatalf("seed malformed upstream: %v", err)
	}

	// When
	_, err := loadRuleUpstreams(context.Background(), "lb_scan")

	// Then
	if err == nil {
		t.Fatal("loadRuleUpstreams returned nil error for malformed row")
	}
}

func TestLoadRuleUpstreams_coalesces_nullable_columns(t *testing.T) {
	// Given
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_nullable', 'nullable', 'tcp', 9002, 1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, enabled, weight, dynamic_dns, protocol, max_connections) VALUES ('lb_nullable', '127.0.0.1', 9000, 1, NULL, NULL, NULL, NULL)`); err != nil {
		t.Fatalf("seed nullable upstream: %v", err)
	}

	// When
	upstreams, err := loadRuleUpstreams(context.Background(), "lb_nullable")

	// Then
	if err != nil {
		t.Fatalf("loadRuleUpstreams: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].Host != "127.0.0.1" || upstreams[0].Port != 9000 {
		t.Fatalf("upstreams=%#v", upstreams)
	}
}

var _ driver.QueryerContext = metricsCursorErrorConn{}

// 监控面板聚合端点 5s TTL 缓存(与 helpers.go
// systemSampleTTL 同模式)——TTL 内重复调用不得重复抓取 Caddy /metrics。
func TestGetMetricsDashboard_cachesCaddyFetchWithinTTL(t *testing.T) {
	// Given:假 Caddy 计数 /metrics 命中
	newMetricsTestDatabase(t)
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("caddy_http_requests_total 100\n"))
	}))
	defer server.Close()
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: server.URL, CaddyMetricsURL: server.URL + "/metrics"}, metricsService: services.NewMetricsService(server.URL, 30)}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics/dashboard", h.GetMetricsDashboard)

	// When:5s TTL 内连续两次调用
	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/metrics/dashboard", nil))
	second := httptest.NewRecorder()
	router.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/metrics/dashboard", nil))

	// Then:两次 200,假端点仅命中 1 次
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("status first=%d second=%d, want 双 200", first.Code, second.Code)
	}
	if hits != 1 {
		t.Fatalf("caddy /metrics hits=%d, want 1(5s TTL 缓存命中)", hits)
	}
}

// MetricsDB 未装配时两个历史端点必须返回空数据
// 200，不得 nil-deref panic。
func TestMetricsHistory_nilMetricsDBReturnsEmpty(t *testing.T) {
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_nil_metrics', 'nil', 'http', 8081, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	oldMetricsDB := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetricsDB })

	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics-history", h.GetRuleMetricsHistory)
	router.GET("/metrics/history", h.GetMetricsHistory)

	for _, test := range []struct {
		path string
		want string
	}{
		{path: "/rules/lb_nil_metrics/metrics-history", want: `"rows":[]`},
		{path: "/metrics/history?interval=1h", want: `"data":[]`},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200", test.path, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), test.want) {
			t.Fatalf("%s body=%s, want %s", test.path, response.Body.String(), test.want)
		}
	}
}

// metricsService 未装配（&Handlers{} / NewHandlers(Dependencies{}) 形态的测试、
// 嵌入或未来新进程入口）时 GET /metrics/overview 必须与同文件对
// db.MetricsDB==nil 的口径一致——返回零值 200，而不是对 nil 指针接收者调用
// GetOverview 触发 panic（gin Recovery 500，同族端点「未装配返回空」分裂）。
func TestGetMetricsOverview_unassembledServiceReturnsZeroValue(t *testing.T) {
	handler := &Handlers{cfg: &config.Config{}}
	gin.SetMode(gin.TestMode)
	router := gin.New() // 不挂 Recovery：panic 直接冒泡到测试即红
	router.GET("/metrics/overview", handler.GetMetricsOverview)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics/overview", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（未装配 metricsService 返回零值）", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, `"code":0`) || !strings.Contains(body, `"total_rules":0`) {
		t.Fatalf("body=%s, want code=0 且零值 overview", body)
	}
}
