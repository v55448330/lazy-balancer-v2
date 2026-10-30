package services

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// isolateMetricsState 隔离包级状态转换 map（含 FIFO 键序），测试间互不串扰。
func isolateMetricsState(t *testing.T) {
	t.Helper()
	metricsStateMu.Lock()
	saved := metricsStateFailed
	savedOrder := metricsStateOrder
	metricsStateFailed = map[string]bool{}
	metricsStateOrder = nil
	metricsStateMu.Unlock()
	t.Cleanup(func() {
		metricsStateMu.Lock()
		metricsStateFailed = saved
		metricsStateOrder = savedOrder
		metricsStateMu.Unlock()
	})
}

func TestLogStateTransition_fail_ok_fail_emits_warn_info_warn(t *testing.T) {
	// Given
	isolateMetricsState(t)

	// When/Then：fail→ok→fail 恰好 warn、info、warn 各一次；
	// 持续同一状态（仍失败/仍正常）静默；初始状态视为 ok（首次成功静默）。
	if lvl := logStateTransition("collect", true); lvl != "warn" {
		t.Fatalf("first failure level=%q, want warn", lvl)
	}
	if lvl := logStateTransition("collect", true); lvl != "" {
		t.Fatalf("persistent failure level=%q, want silent", lvl)
	}
	if lvl := logStateTransition("collect", false); lvl != "info" {
		t.Fatalf("recovery level=%q, want info", lvl)
	}
	if lvl := logStateTransition("collect", false); lvl != "" {
		t.Fatalf("persistent ok level=%q, want silent", lvl)
	}
	if lvl := logStateTransition("collect", true); lvl != "warn" {
		t.Fatalf("second failure level=%q, want warn", lvl)
	}
	if lvl := logStateTransition("endpoint", false); lvl != "" {
		t.Fatalf("first success of unseen key level=%q, want silent", lvl)
	}
	// 类别间状态独立
	if lvl := logStateTransition("parse", true); lvl != "warn" {
		t.Fatalf("independent key failure level=%q, want warn", lvl)
	}
	if lvl := logStateTransition("collect", false); lvl != "info" {
		t.Fatalf("collect recovery after independent key failure level=%q, want info", lvl)
	}
}

func TestMetricsService_collect_logs_failures_once_per_state_transition(t *testing.T) {
	// 30s 周期持久失败不得逐 tick 刷日志——fail→ok→fail 应恰好
	// 2 条 warn + 1 条 info（状态转换口径）。
	// Given
	// 复用单源隔离夹具（主库 + 指标库，四句柄成对还原）。
	setupIsolatedDBWithMetrics(t)
	isolateMetricsState(t)

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 5`))
	}))
	t.Cleanup(live.Close)

	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	service := NewMetricsService(deadURL, 30)

	// When：失败 ×2（仅首次 warn）、成功（恢复 info）、失败 ×2（仅首次 warn）
	service.collect()
	service.collect()
	service.metricsURL = live.URL
	service.collect()
	service.metricsURL = deadURL
	service.collect()
	service.collect()

	// Then
	if count := strings.Count(logs.String(), "Failed to collect metrics:"); count != 2 {
		t.Fatalf("failure warn count=%d, want 2 (state-transition dedup): %s", count, logs.String())
	}
	if count := strings.Count(logs.String(), "metrics collection recovered"); count != 1 {
		t.Fatalf("recovery info count=%d, want 1: %s", count, logs.String())
	}
}

// readFailBody 读取时恒定报错，模拟 body 中段断连。
type readFailBody struct{ err error }

func (b readFailBody) Read([]byte) (int, error) { return 0, b.err }
func (readFailBody) Close() error               { return nil }

// fixedResponseTransport 每次请求返回预置响应（Get 成功、status 200，
// body 可切换为中段读取失败的读端），用于驱动 collect 的 body 读取路径。
type fixedResponseTransport struct {
	mu   sync.Mutex
	resp *http.Response
}

func (f *fixedResponseTransport) set(body io.ReadCloser) {
	f.mu.Lock()
	f.resp = &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: body}
	f.mu.Unlock()
}

func (f *fixedResponseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resp, nil
}

func TestMetricsService_collect_logs_read_failures_once_per_state_transition(t *testing.T) {
	// body 中段读取错误此前裸 return（52fdb0f7 失败族枚举中唯一
	// 零信号成员）。现经状态转换日志（read 类别）：ok→fail 一次 warn、
	// fail→ok 一次 info、持续同一状态静默。
	// Given
	// 复用单源隔离夹具（主库 + 指标库，四句柄成对还原）。
	setupIsolatedDBWithMetrics(t)
	isolateMetricsState(t)

	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	tr := &fixedResponseTransport{}
	readErr := errors.New("connection reset mid-body")
	tr.set(readFailBody{err: readErr})
	service := NewMetricsService("http://metrics.invalid", 30)
	service.client = &http.Client{Timeout: 10 * time.Second, Transport: tr}

	// When：失败 ×2（仅首次 warn）、成功（恢复 info）、失败 ×2（仅首次 warn）
	service.collect()
	service.collect()
	tr.set(io.NopCloser(strings.NewReader(`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 1`)))
	service.collect()
	tr.set(readFailBody{err: readErr})
	service.collect()
	service.collect()

	// Then
	out := logs.String()
	if count := strings.Count(out, "Failed to read metrics body:"); count != 2 {
		t.Fatalf("read failure warn count=%d, want 2 (state-transition dedup): %s", count, out)
	}
	if count := strings.Count(out, "metrics body read recovered"); count != 1 {
		t.Fatalf("read recovery info count=%d, want 1: %s", count, out)
	}
}

func TestClassifyStatusCodes_uses_complete_numeric_ranges(t *testing.T) {
	// Given
	codes := map[int]int64{
		199: 1,
		200: 2,
		299: 3,
		300: 4,
		399: 5,
		400: 6,
		499: 7,
		500: 8,
		599: 9,
		600: 10,
	}

	// When
	counts := classifyStatusCodes(codes)

	// Then：四类只收区间内码；1xx/600+ 不进入任何分类（四类之和 < 总请求）。
	if counts.status2xx != 5 || counts.status3xx != 9 || counts.status4xx != 13 || counts.status5xx != 17 {
		t.Fatalf("classified counts=%+v", counts)
	}
	if sum := counts.status2xx + counts.status3xx + counts.status4xx + counts.status5xx; sum != 44 {
		t.Fatalf("四类之和=%d, want 44（总投入 55，区间外的 11 不得落入任何分类）", sum)
	}
}

func TestMetricsService_parsePrometheusMetrics_accepts_decimal_and_scientific_samples(t *testing.T) {
	// Given
	service := &MetricsService{}
	text := strings.Join([]string{
		`caddy_http_requests_total{handler="reverse_proxy",host="example.com",server="http_443"} 2e1`,
		`caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",host="example.com",method="GET",server="http_443"} 2e1`,
		`caddy_http_response_size_bytes_sum{host="example.com"} 12.75`,
		`caddy_http_request_size_bytes_sum{host="example.com"} 1.5e2`,
	}, "\n")

	// When
	metrics, err := service.parsePrometheusMetrics(text)

	// Then
	if err != nil {
		t.Fatalf("parse metrics: %v", err)
	}
	if metrics.requestsTotal != 20 || metrics.requests2xx != 20 || metrics.bytesOut != 12 || metrics.bytesIn != 150 {
		t.Fatalf("parsed metrics=%+v", metrics)
	}
}

func TestMetricsService_parsePrometheusMetrics_rejects_invalid_sample(t *testing.T) {
	// Given
	service := &MetricsService{}

	// When
	_, err := service.parsePrometheusMetrics(`caddy_http_response_size_bytes_sum{host="example.com"} invalid`)

	// Then
	if err == nil {
		t.Fatal("invalid Prometheus sample was silently accepted")
	}
}

func TestMetricsService_parsePrometheusMetrics_does_not_count_duration_count_as_request_total(t *testing.T) {
	// Given
	service := &MetricsService{}
	text := strings.Join([]string{
		`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 12`,
		`caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",host="example.com"} 12`,
	}, "\n")

	// When
	metrics, err := service.parsePrometheusMetrics(text)

	// Then
	if err != nil {
		t.Fatalf("parse metrics: %v", err)
	}
	if metrics.requestsTotal != 12 || metrics.requests2xx != 12 {
		t.Fatalf("requestsTotal=%d requests2xx=%d, want 12/12", metrics.requestsTotal, metrics.requests2xx)
	}
}

func TestMetricsService_parsePrometheusMetrics_parses_and_validates_bucket_counts(t *testing.T) {
	tests := []struct {
		name    string
		count   string
		wantP50 int
		wantErr bool
	}{
		// 插值语义（2026-10-09 裁定）：单桶 le=0.1 计 20 → P50 rank=10 →
		// fraction=0.5 → 50ms（旧桶边语义为 100ms——本用例真契约=科学计数法可解析）
		{name: "scientific notation", count: "2e1", wantP50: 50},
		{name: "invalid value", count: "invalid", wantErr: true},
		{name: "negative count", count: "-1", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			service := &MetricsService{}
			text := `caddy_http_request_duration_seconds_bucket{handler="reverse_proxy",host="example.com",le="0.1"}   ` + test.count

			// When
			metrics, err := service.parsePrometheusMetrics(text)

			// Then
			if test.wantErr {
				if err == nil {
					t.Fatalf("bucket count %q was accepted", test.count)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse metrics: %v", err)
			}
			if metrics.latencyP50 != test.wantP50 {
				t.Fatalf("latencyP50=%d, want %d", metrics.latencyP50, test.wantP50)
			}
		})
	}
}

func TestMetricsService_parsePrometheusMetrics_aggregates_histograms_across_hosts_and_handlers(t *testing.T) {
	// Given
	service := &MetricsService{}
	var lines []string
	for _, series := range []struct {
		host    string
		handler string
		counts  []string
	}{
		{host: "a.example.com", handler: "reverse_proxy", counts: []string{"4", "8", "9", "10"}},
		{host: "b.example.com", handler: "subroute", counts: []string{"6", "12", "20", "20"}},
	} {
		for index, upperBound := range []string{"0.1", "0.5", "1", "+Inf"} {
			lines = append(lines, `caddy_http_request_duration_seconds_bucket{handler="`+series.handler+`",host="`+series.host+`",le="`+upperBound+`"} `+series.counts[index])
		}
	}

	// When
	metrics, err := service.parsePrometheusMetrics(strings.Join(lines, "\n"))

	// Then
	if err != nil {
		t.Fatalf("parse metrics: %v", err)
	}
	// 插值语义（2026-10-09 裁定）：聚合 0.1→10/0.5→20/1→29/+Inf→30，total=30。
	// P50 rank=15 → (0.1,0.5] fraction=0.5 → 300ms；P95 rank=28.5 → (0.5,1]
	// fraction≈0.944 → 972ms；P99 rank=29.7 → fraction>1 收敛上界 → 1000ms。
	if metrics.latencyP50 != 300 || metrics.latencyP95 != 972 || metrics.latencyP99 != 1000 {
		t.Fatalf("latencies=%d/%d/%d, want 300/972/1000", metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)
	}
}

func TestMetricsService_storeRuleMetricsText_ruleLabelAggregation(t *testing.T) {
	// 2026-09-15:rule label(lazybalancer_*)聚合——请求/状态码/字节/blocked
	// 按 rule 正确归集,写同一 metrics_history 行。
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES ('lb_rl1','rl1','a.example.com','http',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	service := &MetricsService{}
	// fixture 必须是真实 exposition 形态(class/direction 在前,
	// rule 在后——client_golang 字典序);原 fixture rule 在前=假绿。
	text := `lazybalancer_requests_total{rule="lb_rl1"} 100
lazybalancer_request_status_total{class="2xx",rule="lb_rl1"} 80
lazybalancer_request_status_total{class="4xx",rule="lb_rl1"} 20
lazybalancer_bytes_total{direction="in",rule="lb_rl1"} 1024
lazybalancer_bytes_total{direction="out",rule="lb_rl1"} 2048
lazybalancer_security_blocked_total{rule="lb_rl1"} 5`

	// When
	err := service.storeRuleMetricsText(text)

	// Then
	if err != nil {
		t.Fatalf("store rule-label metrics: %v", err)
	}
	var requests, s2xx, s4xx, blocked, bytesIn, bytesOut int64
	if err := db.MetricsDB.QueryRow(`SELECT requests_total, requests_2xx, requests_4xx, requests_blocked, bytes_in, bytes_out FROM metrics_history WHERE rule_id='lb_rl1'`).Scan(&requests, &s2xx, &s4xx, &blocked, &bytesIn, &bytesOut); err != nil {
		t.Fatalf("query stored metric: %v", err)
	}
	if requests != 100 || s2xx != 80 || s4xx != 20 || blocked != 5 || bytesIn != 1024 || bytesOut != 2048 {
		t.Fatalf("stored=(%d,%d,%d,%d,%d,%d), want (100,80,20,5,1024,2048)", requests, s2xx, s4xx, blocked, bytesIn, bytesOut)
	}
}

func TestMetricsService_storeRuleMetricsText_multipleRulesIndependent(t *testing.T) {
	// 多规则独立归集(不串)
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES
		('lb_rl2','rl2','a.example.com','http',8080,1),
		('lb_rl3','rl3','b.example.com','http',8080,1)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	service := &MetricsService{}
	text := `lazybalancer_requests_total{rule="lb_rl2"} 50
lazybalancer_requests_total{rule="lb_rl3"} 200`

	// When
	err := service.storeRuleMetricsText(text)

	// Then
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var c2, c3 int64
	if err := db.MetricsDB.QueryRow(`SELECT requests_total FROM metrics_history WHERE rule_id='lb_rl2'`).Scan(&c2); err != nil {
		t.Fatal(err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT requests_total FROM metrics_history WHERE rule_id='lb_rl3'`).Scan(&c3); err != nil {
		t.Fatal(err)
	}
	if c2 != 50 || c3 != 200 {
		t.Fatalf("rl2=%d rl3=%d, want 50/200", c2, c3)
	}
}

func TestMetricsService_storeRuleMetricsText_emptyTextNoRows(t *testing.T) {
	// 空 text 无行
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES ('lb_rl4','rl4','a.example.com','http',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	service := &MetricsService{}
	if err := service.storeRuleMetricsText(""); err != nil {
		t.Fatalf("empty text must not error: %v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_history`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rows=%d, want 0", count)
	}
}

func TestMetricsService_updateOverview_keepsPreviousCountsOnQueryFailure(t *testing.T) {
	// Given：先用健康 DB 建立前值 overview（3 条规则、2 条启用）
	// 复用单源隔离夹具（四句柄成对还原）。
	setupIsolatedDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (name, protocol, listen_port, enabled) VALUES
		('r1','http',8080,1), ('r2','http',8081,1), ('r3','tcp',9000,0)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	service := &MetricsService{}
	service.updateOverview(parsedMetrics{})
	if got := service.GetOverview(); got.ActiveRules != 2 || got.TotalRules != 3 {
		t.Fatalf("baseline overview=%+v, want ActiveRules=2 TotalRules=3", got)
	}

	// Stub COUNT 失败：关闭规则库（与 storeRuleMetricsText 错误测试同模式）
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close rule database: %v", err)
	}

	// When：COUNT 查询失败的 tick
	service.updateOverview(parsedMetrics{})

	// Then：overview 必须保留前值计数而非静默归零（日志声称 keeping previous value
	// 时行为必须与日志一致）
	got := service.GetOverview()
	if got.ActiveRules != 2 {
		t.Fatalf("active rules=%d, want 2 (previous value kept on COUNT failure)", got.ActiveRules)
	}
	if got.TotalRules != 3 {
		t.Fatalf("total rules=%d, want 3 (previous value kept on COUNT failure)", got.TotalRules)
	}
}

func TestMetricsService_updateOverview_nilDBPreservesCountsAndSamples(t *testing.T) {
	oldDB, oldCurrent := db.DB, db.GetDB()
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldCurrent)
	})
	service := &MetricsService{overview: models.MetricsOverview{ActiveRules: 7, TotalRules: 9, OnlineNodes: 2}}

	// When/Then：启动/拆除窗口 DB 未初始化不得 panic；计数保留而流量样本照常推进。
	service.updateOverview(parsedMetrics{requestsTotal: 123, requests2xx: 120})
	got := service.GetOverview()
	if got.ActiveRules != 7 || got.TotalRules != 9 || got.OnlineNodes != 2 {
		t.Fatalf("nil DB reset counts: %+v", got)
	}
	if got.TotalRequests != 123 || got.Status2xx != 120 {
		t.Fatalf("nil DB dropped metrics sample: %+v", got)
	}
}

func TestMetricsService_updateOverview_counts_online_nodes_dynamically(t *testing.T) {
	// Given：4 个节点——新鲜在线、陈旧在线(status 仍为 online)、待审批、last_seen 为空
	// 复用单源隔离夹具（四句柄成对还原）。
	setupIsolatedDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET sync_interval=60 WHERE id=1`); err != nil {
		t.Fatalf("seed sync_interval: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,is_approved,status,last_seen) VALUES
		(1,'online','slave','10.0.0.1',1,'online',datetime('now')),
		(2,'stale','slave','10.0.0.2',1,'online',datetime('now','-3 minutes')),
		(3,'pending','slave','10.0.0.3',0,'pending',NULL),
		(4,'no-seen','slave','10.0.0.4',1,'online',NULL)`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}
	service := &MetricsService{}

	// When
	service.updateOverview(parsedMetrics{})

	// Then：仅已批准且 last_seen 未超过 2×sync_interval 的节点计为在线
	if got := service.GetOverview().OnlineNodes; got != 1 {
		t.Fatalf("online nodes=%d, want 1 (stale/pending/NULL last_seen excluded)", got)
	}
}

func TestMetricsServiceCleanupHistory_stillCleansWhenGlobalConfigDropped(t *testing.T) {
	// retention 配置读取失败时清理不得静默跳过——2026-09-15 用户裁定
	// 后配置读取路径已移除(固定 7 天窗口),本测试保留极端形态回归:配置表
	// 不存在时清理仍按 7 天窗口执行。
	// Given：过期（100 天）与近期（当前）各 1 条历史；DROP global_config
	// 模拟配置表极端损坏
	// 复用单源隔离夹具（主库 + 指标库，四句柄成对还原）。
	setupIsolatedDBWithMetrics(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp) VALUES
		('lb_old', datetime('now','-100 days')),
		('lb_fresh', datetime('now'))`); err != nil {
		t.Fatalf("seed metrics history: %v", err)
	}
	if _, err := db.DB.Exec(`DROP TABLE global_config`); err != nil {
		t.Fatalf("break retention read: %v", err)
	}

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then：清理仍执行（固定 7 天窗口,配置读取路径已移除,读失败不影响）——
	// 过期行被删、近期行保留
	var oldRows, freshRows int
	if err := db.MetricsDB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN timestamp < datetime('now','-7 days') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN timestamp >= datetime('now','-7 days') THEN 1 ELSE 0 END), 0)
		FROM metrics_history`).Scan(&oldRows, &freshRows); err != nil {
		t.Fatalf("count metrics history: %v", err)
	}
	if oldRows != 0 {
		t.Fatalf("old rows after cleanup = %d, want 0 (cleanup must still run with fixed 7-day window)", oldRows)
	}
	if freshRows != 1 {
		t.Fatalf("fresh rows after cleanup = %d, want 1", freshRows)
	}
}

// 正则标签顺序与真实 exposition 一致——
// client_golang 字典序(class/direction 在前,rule 在后)。fixture 必须
// 真实形态。
func TestMetricsService_storeRuleMetricsText_realExpositionOrder(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES ('lb_rl5','rl5','a.example.com','http',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	service := &MetricsService{}
	// 真实 exposition 形态(容器实证):class/direction 在前,rule 在后
	text := `lazybalancer_requests_total{rule="lb_rl5"} 100
lazybalancer_request_status_total{class="2xx",rule="lb_rl5"} 80
lazybalancer_request_status_total{class="4xx",rule="lb_rl5"} 20
lazybalancer_bytes_total{direction="in",rule="lb_rl5"} 1024
lazybalancer_bytes_total{direction="out",rule="lb_rl5"} 2048`

	if err := service.storeRuleMetricsText(text); err != nil {
		t.Fatalf("store: %v", err)
	}
	var requests, s2xx, s4xx, bytesIn, bytesOut int64
	if err := db.MetricsDB.QueryRow(`SELECT requests_total, requests_2xx, requests_4xx, bytes_in, bytes_out FROM metrics_history WHERE rule_id='lb_rl5'`).Scan(&requests, &s2xx, &s4xx, &bytesIn, &bytesOut); err != nil {
		t.Fatalf("query: %v", err)
	}
	if requests != 100 || s2xx != 80 || s4xx != 20 || bytesIn != 1024 || bytesOut != 2048 {
		t.Fatalf("stored=(%d,%d,%d,%d,%d), want (100,80,20,1024,2048)", requests, s2xx, s4xx, bytesIn, bytesOut)
	}
}

// geoip 透传序列剔除的行为钉——携带
// handler="http.handlers.geoip2region" 的序列整条剔除（同请求经透传路由+
// 主路由双计，剔除后恢复真实计数）。钉与实现形态无关（Split+Join → Builder
// 单副本重构的行为锚）。
func TestMetricsService_collect_filtersGeoipPassHandlerSeries(t *testing.T) {
	// Given 双序列暴露文本（reverse_proxy + geoip 透传各 20）
	setupMetricsRetentionTest(t)
	isolateMetricsState(t)
	text := strings.Join([]string{
		`caddy_http_requests_total{handler="reverse_proxy",host="example.com",server="http_443"} 20`,
		`caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com",server="http_443"} 20`,
		`caddy_http_request_duration_seconds_bucket{code="200",handler="reverse_proxy",host="example.com",method="GET",server="http_443",le="0.5"} 20`,
	}, "\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(text))
	}))
	t.Cleanup(server.Close)
	service := NewMetricsService(server.URL, 30)

	// When
	service.collect()

	// Then geoip 透传序列剔除——总数只计 reverse_proxy 的 20（双计=40 为缺陷）
	if got := service.GetOverview().TotalRequests; got != 20 {
		t.Fatalf("TotalRequests=%d, want 20（geoip 透传序列未剔除）", got)
	}
}

// 「启动首轮立即采集」不变量已随 metrics-collector daemon 归口：
// RunTicker bootstrap（立即首跑）语义由 taskengine_wire_runtime_test.go 的
// TestRuntimeLifecycleMetricsCollector 钉住（daemon 启动即采集，不等首个节拍）。

// 采样采集必须单趟解析：旧实现每周期 10 趟全文正则（全局 6 + 规则 4），
// 16MB body 时 ≈144MB 正则输入。此钉用扫描钩子把「每周期 1 趟」变成机器
// 可判定断言（生产钩子恒 nil）。
func TestMetricsService_collect_singleExpositionScanPerCycle(t *testing.T) {
	setupMetricsRetentionTest(t)
	isolateMetricsState(t)
	text := strings.Join([]string{
		`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 20`,
		`caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",host="example.com"} 20`,
		`caddy_http_response_size_bytes_sum{handler="reverse_proxy",host="example.com"} 4096`,
		`caddy_http_request_size_bytes_sum{handler="reverse_proxy",host="example.com"} 1024`,
		`caddy_http_request_duration_seconds_bucket{le="0.5",host="example.com"} 20`,
		`lazybalancer_requests_total{rule="lb_scan"} 20`,
		`lazybalancer_request_status_total{class="2xx",rule="lb_scan"} 20`,
		`lazybalancer_bytes_total{direction="in",rule="lb_scan"} 1024`,
	}, "\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(text))
	}))
	t.Cleanup(server.Close)
	scans := 0
	prometheusScanHook = func(string) { scans++ }
	t.Cleanup(func() { prometheusScanHook = nil })
	service := NewMetricsService(server.URL, 30)

	// When
	service.collect()

	// Then：恰好 1 趟全文扫描，且全局与规则级样本都被正确落库
	if scans != 1 {
		t.Fatalf("全文扫描次数=%d, want 1（单趟聚合）", scans)
	}
	if got := service.GetOverview().TotalRequests; got != 20 {
		t.Fatalf("TotalRequests=%d, want 20（全局样本）", got)
	}
	var ruleRows int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_history WHERE rule_id='lb_scan'`).Scan(&ruleRows); err != nil {
		t.Fatal(err)
	}
	if ruleRows != 1 {
		t.Fatalf("规则级行数=%d, want 1（同一趟扫描的规则级样本）", ruleRows)
	}
}

// 规则级历史行必须单事务批量写：任一行失败整批回滚（旧实现每规则一条独立
// Exec，部分成功即留下半批行、且每规则一次写事务）。
func TestMetricsService_storePerRuleMetrics_isAtomicBatch(t *testing.T) {
	newClusterTestService(t)
	if _, err := db.MetricsDB.Exec(`CREATE TRIGGER abort_bad_rule BEFORE INSERT ON metrics_history WHEN NEW.rule_id='lb_bad' BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;`); err != nil {
		t.Fatal(err)
	}
	service := &MetricsService{}
	byRule := map[string]*ruleLabelAggregate{
		"lb_good": {requests: 1},
		"lb_bad":  {requests: 2},
	}

	// When
	err := service.storePerRuleMetrics(byRule)

	// Then：错误上抛且整批回滚（0 行）
	if err == nil {
		t.Fatal("单行写入失败必须上抛")
	}
	var rows int
	if qerr := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_history`).Scan(&rows); qerr != nil {
		t.Fatal(qerr)
	}
	if rows != 0 {
		t.Fatalf("metrics_history 行数=%d, want 0（整批回滚，不留半批）", rows)
	}
}

// 指标库未初始化时清理/写入必须显式返回而不 nil deref（生产启动链不可达，
// 与 refreshDBOverviewMetrics 的 nil 守卫同口径）。
func TestMetricsService_nilMetricsDBGuards(t *testing.T) {
	oldMetricsDB := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetricsDB })
	service := &MetricsService{}

	if err := service.storeMetrics(parsedMetrics{}); err == nil {
		t.Fatal("storeMetrics 在 nil 指标库时必须返回错误")
	}
	if err := service.storePerRuleMetrics(map[string]*ruleLabelAggregate{"lb_x": {}}); err == nil {
		t.Fatal("storePerRuleMetrics 在 nil 指标库时必须返回错误")
	}
	if err := service.cleanupHistory(); err == nil {
		t.Fatal("cleanupHistory 在 nil 指标库时必须返回错误（清理没跑成不得伪装 success）")
	}
}

// 「历史清理与采集不串行 + 单飞」不变量已随归口重构消失：采集
// （metrics-collector daemon）与清理（metrics-history-cleanup Periodic）是
// 两个独立任务，在途重叠由引擎 admission（in-flight 跳过）结构性保证——
// 原 goroutine 单飞/Stop 等待/竞态负向钉测随自建循环一并退役。

// 概览 DB 派生指标每采集周期只刷新一次：旧形态 collect 与 updateOverview 各
// 刷一次（6 条 COUNT/周期）。钩子把「每周期 1 次」变成机器可判定断言。
func TestMetricsService_collect_refreshesOverviewCountsOncePerCycle(t *testing.T) {
	setupMetricsRetentionTest(t)
	isolateMetricsState(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 5` + "\n"))
	}))
	t.Cleanup(server.Close)
	refreshes := 0
	overviewRefreshHook = func() { refreshes++ }
	t.Cleanup(func() { overviewRefreshHook = nil })
	service := NewMetricsService(server.URL, 30)

	service.collect()

	if refreshes != 1 {
		t.Fatalf("DB 派生指标刷新次数=%d, want 1（每周期一次，旧形态两次）", refreshes)
	}
	if got := service.GetOverview().TotalRequests; got != 5 {
		t.Fatalf("TotalRequests=%d, want 5", got)
	}
}

// 概览 COUNT 失败必须按状态转换去重（30s 周期持久故障时此前 2~3 行/天→每轮
// 各一条 error；5s 间隔时 ×6）。
func TestMetricsService_refreshDBOverviewMetrics_dedupesFailureLogs(t *testing.T) {
	setupMetricsRetentionTest(t)
	isolateMetricsState(t)
	// Given：先以健康库建立非零基线（2/3）——零值基线下「保留前值」与「静默
	// 归零」不可区分，断言零鉴别力。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (name, protocol, listen_port, enabled) VALUES
		('r1','http',8080,1), ('r2','http',8081,1), ('r3','tcp',9000,0)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	service := NewMetricsService("", 30)
	service.refreshDBOverviewMetrics()
	if got := service.GetOverview(); got.ActiveRules != 2 || got.TotalRules != 3 {
		t.Fatalf("baseline overview=%+v, want ActiveRules=2 TotalRules=3", got)
	}
	originalWriter := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })
	swapBrokenDB(t)

	// When：连续两个周期都查失败
	service.refreshDBOverviewMetrics()
	service.refreshDBOverviewMetrics()

	// Then：每个类别只首报一次
	for _, key := range []string{"query active rules failed", "query total rules failed", "query online nodes failed"} {
		if count := strings.Count(logs.String(), key); count != 1 {
			t.Fatalf("%q 日志次数=%d, want 1（状态转换去重）: %s", key, count, logs.String())
		}
	}
	// 计数必须保留非零前值（失败分支被绕过即归零/漂移 → 本断言红）
	got := service.GetOverview()
	if got.ActiveRules != 2 || got.TotalRules != 3 {
		t.Fatalf("overview=%+v, want ActiveRules=2 TotalRules=3（失败保留前值）", got)
	}
	if !strings.Contains(logs.String(), "keeping previous value=2") {
		t.Fatalf("首报行必须带保留前值=2: %s", logs.String())
	}
}

// 后台采集刷新必须读 db.GetDB()（atomic 句柄）而非同步侧 db.DB：两个来源
// 分裂时后台循环会静默空转或读到另一个库，指标永久不生效且零日志。
func TestRefreshDBOverviewMetrics_usesAtomicHandle(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES
		('lb_h1','h1','a.example.com','http',8080,1),
		('lb_h2','h2','b.example.com','http',8081,1)`); err != nil {
		t.Fatal(err)
	}
	service := &MetricsService{}
	service.refreshDBOverviewMetrics()
	if got := service.GetOverview(); got.ActiveRules != 2 || got.TotalRules != 2 {
		t.Fatalf("overview=%+v, want 2/2", got)
	}

	// Given：后台句柄被摘除（db.DB 仍有效并新增一条规则）
	db.SetDB(nil)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled)
		VALUES ('lb_h3','h3','c.example.com','http',8082,1)`); err != nil {
		t.Fatal(err)
	}

	// When
	service.refreshDBOverviewMetrics()

	// Then：保持前值（句柄不可用即不刷新）——读到 3 说明走了同步侧 db.DB
	if got := service.GetOverview(); got.ActiveRules != 2 || got.TotalRules != 2 {
		t.Fatalf("overview=%+v，刷新读了未注册的 db.DB（必须走 db.GetDB）", got)
	}
}

// Given 静态族（metrics 采集 collect）已记为失败，随后动态族
// （rulelog-tail-cap-<规则 id>）新增超过上限的键。
// When 越过 metricsStateEvictCap。
// Then 只淘汰动态族自身的旧键——静态族的状态记忆必须保留（整表重置会让
// 持久故障族重新各打一条 warn），且 map 始终有界。
func TestLogStateTransition_familyScopedEviction(t *testing.T) {
	isolateMetricsState(t)
	if got := logStateTransition("collect", true); got != "warn" {
		t.Fatalf("首报=%q, want warn", got)
	}
	for i := range metricsStateEvictCap + 8 {
		logStateTransition(fmt.Sprintf("rulelog-tail-cap-%d", i), true)
	}
	if got := logStateTransition("collect", true); got != "" {
		t.Fatalf("跨族状态被清空：collect 重新记 %q（上限淘汰必须按族进行）", got)
	}
	if got := logStateTransition("rulelog-tail-cap-0", true); got != "warn" {
		t.Fatalf("同族最旧键未淘汰：重新失败=%q, want warn", got)
	}
	metricsStateMu.Lock()
	size := len(metricsStateFailed)
	metricsStateMu.Unlock()
	if size > metricsStateEvictCap {
		t.Fatalf("状态 map 键数=%d，超出上限 %d", size, metricsStateEvictCap)
	}
}

// 标签定位必须名精确 + 值内 `}` 安全：子串宽容会在标签后缀/值形态变化时
// 静默取错分值。
func TestPrometheusLabelParsing_nameBoundaryAndQuotedBrace(t *testing.T) {
	line := `caddy_http_request_duration_seconds_count{role="admin",le="0.1",status_code="500",msg="a}b"} 42`

	if got, ok := prometheusLabelValue(line, "le"); !ok || got != "0.1" {
		t.Fatalf(`le=%q ok=%v, want "0.1"（不得命中 role="...le="）`, got, ok)
	}
	if got, ok := prometheusLabelValue(line, "code"); ok {
		t.Fatalf(`code=%q ok=%v, want 不命中（只有 status_code）`, got, ok)
	}
	if got, ok := prometheusLabelValue(line, "status_code"); !ok || got != "500" {
		t.Fatalf(`status_code=%q ok=%v, want "500"`, got, ok)
	}
	if _, got, ok := PrometheusSampleLine(line); !ok || got != "42" {
		t.Fatalf(`sample=%q ok=%v, want "42"（值内 } 不得截断标签块）`, got, ok)
	}
}

// 同一次抓取的两步结论不得相反：仪表盘实时指标解析器跳过 NaN/±Inf（转 int64
// 对非有限值是实现相关的），规则指标采集此前对同形态报错。统一为跳过，且
// 「不可解析」仍是错误（跳过只针对非有限值）。
func TestAggregatePrometheusText_skipsNonFiniteSamples(t *testing.T) {
	global := aggregatePrometheusText(strings.Join([]string{
		`caddy_http_requests_total{host="a"} 5`,
		`caddy_http_requests_total{host="b"} NaN`,
		`caddy_http_response_size_bytes_sum{host="c"} +Inf`,
		`caddy_http_request_size_bytes_sum{host="d"} -Inf`,
	}, "\n"), prometheusScanGlobal)
	if global.globalErr != nil {
		t.Fatalf("globalErr=%v, want 非有限样本跳过而非报错", global.globalErr)
	}
	if global.global.requestsTotal != 5 || global.global.bytesOut != 0 || global.global.bytesIn != 0 {
		t.Fatalf("global=%+v, want 仅有限样本参与聚合", global.global)
	}

	rules := aggregatePrometheusText(`lazybalancer_requests_total{rule="r"} NaN`, prometheusScanRules)
	if rules.rulesErr != nil {
		t.Fatalf("rulesErr=%v, want 非有限样本跳过而非报错", rules.rulesErr)
	}
	if agg := rules.rules["r"]; agg != nil && agg.requests != 0 {
		t.Fatalf("rule agg=%+v, want 0 请求", agg)
	}

	if bad := aggregatePrometheusText(`caddy_http_requests_total{host="a"} not-a-number`, prometheusScanGlobal); bad.globalErr == nil {
		t.Fatal("不可解析的样本值仍必须报错（跳过仅针对 NaN/±Inf）")
	}
}

// 标签值含空格（合法 exposition）时行取值必须引号感知：仪表盘与规则指标采集
// 共用同一实现，避免一侧切错值、另一侧正常。
func TestAggregatePrometheusText_toleratesSpaceInLabelValue(t *testing.T) {
	res := aggregatePrometheusText(strings.Join([]string{
		`caddy_http_requests_total{host="a b"} 5`,
		`lazybalancer_requests_total{rule="lb x"} 3`,
	}, "\n"), prometheusScanGlobal|prometheusScanRules)
	if res.globalErr != nil {
		t.Fatalf("globalErr=%v, want 引号感知取值", res.globalErr)
	}
	if res.global.requestsTotal != 5 {
		t.Fatalf("requestsTotal=%d, want 5", res.global.requestsTotal)
	}
	if res.rulesErr != nil {
		t.Fatalf("rulesErr=%v, want 引号感知取值", res.rulesErr)
	}
	if agg := res.rules["lb x"]; agg == nil || agg.requests != 3 {
		t.Fatalf("rule agg=%+v, want rule=\"lb x\" 计数 3", agg)
	}
}

// 「Start/Stop 一次性生命周期」钉测随 Start/Stop 归口退役：metrics-collector
// daemon 的启停/重启语义由引擎 lifecycle（StartLoop/StopLoop/角色门）唯一
// 承担，结构体不再持有自建循环生命周期。
