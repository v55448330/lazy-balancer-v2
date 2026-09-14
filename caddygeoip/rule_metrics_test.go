package caddygeoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newTestRuleMetricsHandler(t *testing.T, rule string) *RuleMetricsHandler {
	t.Helper()
	h := &RuleMetricsHandler{Rule: rule}
	ctx, cancel := caddy.NewContextWithCause(caddy.Context{Context: context.Background()})
	t.Cleanup(func() { cancel(nil) })
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return h
}

func TestRuleMetricsHandler_ServeHTTP(t *testing.T) {
	rule := "lb_metrics_test"
	h := newTestRuleMetricsHandler(t, rule)

	// ① 200 响应:计数+2xx+字节
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
		return nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(h.requestsTotal.WithLabelValues(rule)); got != 1 {
		t.Fatalf("requests_total=%v, want 1", got)
	}
	if got := testutil.ToFloat64(h.statusTotal.WithLabelValues(rule, "2xx")); got != 1 {
		t.Fatalf("status 2xx=%v, want 1", got)
	}
	if got := testutil.ToFloat64(h.bytesTotal.WithLabelValues(rule, "out")); got <= 0 {
		t.Fatalf("bytes out=%v, want >0", got)
	}

	// ② coraza 中断(403):HandlerError 携 statusCode
	blockedNext := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return caddyhttp.HandlerError{StatusCode: 403, ID: "abcdefghijklmnop"}
	})
	if err := h.ServeHTTP(rec, req, blockedNext); err == nil {
		t.Fatal("want passthrough error")
	}
	if got := testutil.ToFloat64(h.statusTotal.WithLabelValues(rule, "4xx")); got != 1 {
		t.Fatalf("status 4xx=%v, want 1 (coraza interruption counted as 4xx)", got)
	}

	// ③ 在途 gauge 归零(defer Dec)
	if got := testutil.ToFloat64(h.requestsInFlight.WithLabelValues(rule)); got != 0 {
		t.Fatalf("in_flight=%v, want 0 after defer Dec", got)
	}
}

// metrics nil 降级(未 Provision/注册失败——计数 no-op 不 panic)
func TestRuleMetricsHandler_nilMetricsDegrades(t *testing.T) {
	h := &RuleMetricsHandler{Rule: "lb_nil"} // 不 Provision——metrics 全 nil
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	// 不 panic
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), next); err != nil {
		t.Fatal(err)
	}
}
