package services

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// isolateMetricsState 隔离包级状态转换 map（N+9 C3-S2），测试间互不串扰。
func isolateMetricsState(t *testing.T) {
	t.Helper()
	metricsStateMu.Lock()
	saved := metricsStateFailed
	metricsStateFailed = map[string]bool{}
	metricsStateMu.Unlock()
	t.Cleanup(func() {
		metricsStateMu.Lock()
		metricsStateFailed = saved
		metricsStateMu.Unlock()
	})
}

func TestLogMetricsStateTransition_fail_ok_fail_emits_warn_info_warn(t *testing.T) {
	// Given
	isolateMetricsState(t)

	// When/Then：fail→ok→fail 恰好 warn、info、warn 各一次；
	// 持续同一状态（仍失败/仍正常）静默；初始状态视为 ok（首次成功静默）。
	if lvl := logMetricsStateTransition("collect", true); lvl != "warn" {
		t.Fatalf("first failure level=%q, want warn", lvl)
	}
	if lvl := logMetricsStateTransition("collect", true); lvl != "" {
		t.Fatalf("persistent failure level=%q, want silent", lvl)
	}
	if lvl := logMetricsStateTransition("collect", false); lvl != "info" {
		t.Fatalf("recovery level=%q, want info", lvl)
	}
	if lvl := logMetricsStateTransition("collect", false); lvl != "" {
		t.Fatalf("persistent ok level=%q, want silent", lvl)
	}
	if lvl := logMetricsStateTransition("collect", true); lvl != "warn" {
		t.Fatalf("second failure level=%q, want warn", lvl)
	}
	if lvl := logMetricsStateTransition("endpoint", false); lvl != "" {
		t.Fatalf("first success of unseen key level=%q, want silent", lvl)
	}
	// 类别间状态独立
	if lvl := logMetricsStateTransition("parse", true); lvl != "warn" {
		t.Fatalf("independent key failure level=%q, want warn", lvl)
	}
	if lvl := logMetricsStateTransition("collect", false); lvl != "info" {
		t.Fatalf("collect recovery after independent key failure level=%q, want info", lvl)
	}
}

func TestMetricsService_collect_logs_failures_once_per_state_transition(t *testing.T) {
	// N+9 C3-S2：30s 周期持久失败不得逐 tick 刷日志——fail→ok→fail 应恰好
	// 2 条 warn + 1 条 info（状态转换口径）。
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
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
	// N+11 D3-F4：body 中段读取错误此前裸 return（52fdb0f7 失败族枚举中唯一
	// 零信号成员）。现经状态转换日志（read 类别）：ok→fail 一次 warn、
	// fail→ok 一次 info、持续同一状态静默。
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
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

	// Then
	if counts.status2xx != 5 || counts.status3xx != 9 || counts.status4xx != 13 || counts.status5xx != 17 || counts.other != 11 {
		t.Fatalf("classified counts=%+v", counts)
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
		{name: "scientific notation", count: "2e1", wantP50: 100},
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
	if metrics.latencyP50 != 500 || metrics.latencyP95 != 1000 || metrics.latencyP99 != 1000 {
		t.Fatalf("latencies=%d/%d/%d, want 500/1000/1000", metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)
	}
}

func TestMetricsService_storePerHostMetrics_normalizes_bracketed_IPv6_host(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES ('lb_ipv6','ipv6','::1','http',8080,1)`); err != nil {
		t.Fatalf("seed IPv6 rule: %v", err)
	}
	service := &MetricsService{}
	text := `caddy_http_request_duration_seconds_count{code="200",host="[::1]:8080"} 7`

	// When
	err := service.storePerHostMetrics(text)

	// Then
	if err != nil {
		t.Fatalf("store per-host metrics: %v", err)
	}
	var ruleID string
	if err := db.MetricsDB.QueryRow(`SELECT rule_id FROM metrics_history`).Scan(&ruleID); err != nil {
		t.Fatalf("query stored metric: %v", err)
	}
	if ruleID != "lb_ipv6" {
		t.Fatalf("ruleID=%q, want lb_ipv6", ruleID)
	}
}

func TestMetricsService_storePerHostMetrics_aggregates_multi_domain_rule_into_single_row(t *testing.T) {
	// M19：同一规则配多域名时，两条 host 序列必须合并为单行历史记录，
	// 否则同一时间戳出现多行、按规则聚合时重复计数。
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES ('lb_multi','multi','a.example.com,b.example.com','http',8080,1)`); err != nil {
		t.Fatalf("seed multi-domain rule: %v", err)
	}
	service := &MetricsService{}
	text := strings.Join([]string{
		`caddy_http_request_duration_seconds_count{code="200",host="a.example.com"} 3`,
		`caddy_http_request_duration_seconds_count{code="404",host="a.example.com"} 1`,
		`caddy_http_request_duration_seconds_count{code="200",host="b.example.com"} 5`,
	}, "\n")

	// When
	if err := service.storePerHostMetrics(text); err != nil {
		t.Fatalf("store per-host metrics: %v", err)
	}

	// Then：单行且计数为两域之和（requests 4+5=9，2xx 3+5=8，4xx 1）。
	var rows, requests, status2xx, status4xx int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(requests_total),0), COALESCE(SUM(requests_2xx),0), COALESCE(SUM(requests_4xx),0) FROM metrics_history WHERE rule_id='lb_multi'`).Scan(&rows, &requests, &status2xx, &status4xx); err != nil {
		t.Fatalf("query stored metrics: %v", err)
	}
	if rows != 1 || requests != 9 || status2xx != 8 || status4xx != 1 {
		t.Fatalf("rows=%d requests=%d 2xx=%d 4xx=%d, want 1/9/8/1", rows, requests, status2xx, status4xx)
	}
}

func TestMetricsService_storePerHostMetrics_logs_unchanged_domain_conflict_once(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	for _, ruleID := range []string{"lb_z", "lb_a"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES (?,?, 'shared.example.com','http',8080,1)`, ruleID, ruleID); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })
	service := &MetricsService{}
	text := `caddy_http_request_duration_seconds_count{code="200",host="shared.example.com"} 3`

	// When
	err := service.storePerHostMetrics(text)
	if err == nil {
		err = service.storePerHostMetrics(text)
	}

	// Then
	if err != nil {
		t.Fatalf("store per-host metrics: %v", err)
	}
	var ruleID string
	if err := db.MetricsDB.QueryRow(`SELECT rule_id FROM metrics_history`).Scan(&ruleID); err != nil {
		t.Fatalf("query stored metric: %v", err)
	}
	if ruleID != "lb_a" {
		t.Fatalf("ruleID=%q, want lexicographically smallest lb_a", ruleID)
	}
	if count := strings.Count(logs.String(), "Metrics domain conflict:"); count != 1 {
		t.Fatalf("conflict log count=%d logs=%q, want 1", count, logs.String())
	}
	if !strings.Contains(logs.String(), "shared.example.com") {
		t.Fatalf("conflict log %q does not identify shared.example.com", logs.String())
	}
}

func TestMetricsService_storePerHostMetrics_returns_rule_query_error(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if err := database.Close(); err != nil {
		t.Fatalf("close rule database: %v", err)
	}
	service := &MetricsService{}
	text := `caddy_http_request_duration_seconds_count{code="200",host="example.com"} 1`

	// When
	err := service.storePerHostMetrics(text)

	// Then
	if err == nil {
		t.Fatal("closed rule database query error was swallowed")
	}
}

func TestMetricsService_updateOverview_keepsPreviousCountsOnQueryFailure(t *testing.T) {
	// Given：先用健康 DB 建立前值 overview（3 条规则、2 条启用）
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (name, protocol, listen_port, enabled) VALUES
		('r1','http',8080,1), ('r2','http',8081,1), ('r3','tcp',9000,0)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	service := &MetricsService{}
	service.updateOverview(parsedMetrics{})
	if got := service.GetOverview(); got.ActiveRules != 2 || got.TotalRules != 3 {
		t.Fatalf("baseline overview=%+v, want ActiveRules=2 TotalRules=3", got)
	}

	// Stub COUNT 失败：关闭规则库（与 storePerHostMetrics 错误测试同模式）
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

func TestMetricsService_updateOverview_counts_online_nodes_dynamically(t *testing.T) {
	// Given：4 个节点——新鲜在线、陈旧在线(status 仍为 online)、待审批、last_seen 为空
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
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

func TestMetricsServiceCleanupHistory_fallsBackToDefaultDaysWhenRetentionReadFails(t *testing.T) {
	// N-5：retention 配置读取失败时清理不得静默跳过——记录日志并按默认
	// 7 天继续（此前静默 return，指标历史无界增长且零日志信号）。
	// Given：过期（10 天）与近期（当前）各 1 条历史；DROP global_config
	// 令配置读取失败
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp) VALUES
		('lb_old', datetime('now','-10 days')),
		('lb_fresh', datetime('now'))`); err != nil {
		t.Fatalf("seed metrics history: %v", err)
	}
	if _, err := db.DB.Exec(`DROP TABLE global_config`); err != nil {
		t.Fatalf("break retention read: %v", err)
	}

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then：清理仍以默认 7 天执行——过期行被删、近期行保留
	var oldRows, freshRows int
	if err := db.MetricsDB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN timestamp < datetime('now','-7 days') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN timestamp >= datetime('now','-7 days') THEN 1 ELSE 0 END), 0)
		FROM metrics_history`).Scan(&oldRows, &freshRows); err != nil {
		t.Fatalf("count metrics history: %v", err)
	}
	if oldRows != 0 {
		t.Fatalf("old rows after cleanup = %d, want 0 (cleanup must run with default 7d)", oldRows)
	}
	if freshRows != 1 {
		t.Fatalf("fresh rows after cleanup = %d, want 1", freshRows)
	}
}
