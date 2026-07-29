package services

import (
	"strings"
	"testing"
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
		`caddy_http_requests_total{code="200"} 2e1`,
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
