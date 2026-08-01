package services

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

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
