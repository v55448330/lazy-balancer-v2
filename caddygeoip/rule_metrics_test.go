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

// Provision 预解析标签句柄钉：Rule 是渲染期静态值，句柄在 Provision 期
// 一次解析，热路径只做 Inc/Add；退回每请求 WithLabelValues（vec map 读锁
// 查找）时本钉的句柄字段将不复存在（编译期失败）。
func TestRuleMetricsHandler_provisionResolvesHandles(t *testing.T) {
	h := newTestRuleMetricsHandler(t, "lb_handles_pin")
	if h.reqCounter == nil || h.inFlight == nil || h.bytesIn == nil || h.bytesOut == nil {
		t.Fatal("Provision must pre-resolve counter/gauge label handles")
	}
	for _, class := range statusClasses {
		if h.statusByClass[class] == nil {
			t.Fatalf("statusByClass[%s] unresolved at Provision", class)
		}
	}
	if got := testutil.ToFloat64(h.reqCounter); got != 0 {
		t.Fatalf("reqCounter=%v, want 0 (fresh series)", got)
	}
}

// Given: RuleMetricsHandler Provision（/load 渲染）
// Then: 无标签 gauge lazybalancer_rule_metrics_epoch_seconds 注册且值=Provision
// Unix 秒（>0）——仪表盘规则页「统计自 HH:MM（上次配置重载）」的锚点；同一
// registry 重复 Provision（reload 注册复用路径）后仍为单序列（Set 覆盖不累加）。
func TestRuleMetricsHandler_epochGaugeSetAtProvision(t *testing.T) {
	h := &RuleMetricsHandler{Rule: "lb_epoch_pin"}
	ctx, cancel := caddy.NewContextWithCause(caddy.Context{Context: context.Background()})
	t.Cleanup(func() { cancel(nil) })
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	reg := ctx.GetMetricsRegistry()
	if reg == nil {
		t.Fatal("test context lacks metrics registry")
	}
	if h.epochSeconds == nil {
		t.Fatal("epochSeconds gauge unresolved at Provision")
	}
	if got := testutil.ToFloat64(h.epochSeconds); got <= 0 {
		t.Fatalf("epoch_seconds=%v, want >0（Provision Unix 秒）", got)
	}
	// reload 幂等：同一 registry 重复 Provision → 仍单序列且值刷新（Set 覆盖）。
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("re-Provision: %v", err)
	}
	if got := testutil.ToFloat64(h.epochSeconds); got <= 0 {
		t.Fatalf("epoch_seconds after re-Provision=%v, want >0", got)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	series := 0
	for _, mf := range families {
		if mf.GetName() == "lazybalancer_rule_metrics_epoch_seconds" {
			series += len(mf.GetMetric())
		}
	}
	if series != 1 {
		t.Fatalf("epoch gauge series=%d, want 1（reload 注册复用不重复注册）", series)
	}
}
