package caddygeoip

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
)

// RuleMetricsHandler 是规则级全量流量指标中间件(caddy_id 直接作 label,
// 2026-09-15 用户裁定:替代域名/host 匹配——通配符/大小写/IDNA/多域名/空域名
// 全部天然正确,历史采集与 dashboard 实时同源)。
// 包装链全流量(ResponseRecorder 读 status/size,与 Caddy 自身 metrics
// instrumentation 同模式 caddyhttp/metrics.go:346),计数:
//
//	lazybalancer_requests_total{rule}         — 请求总数
//	lazybalancer_request_status_total{rule,class} — 2xx/3xx/4xx/5xx 分类
//	lazybalancer_bytes_total{rule,direction}  — 入站(in)/出站(out)字节
//	lazybalancer_requests_in_flight{rule}     — 在途连接(gauge)
//
// 稳定设计:仅 Caddy 稳定公开 API(ResponseRecorder/HandlerError——v2 长期
// 稳定);Provision 幂等注册(caddy-l4 registerOrExisting 同模式);零失败模式。
type RuleMetricsHandler struct {
	// Rule 是所属负载均衡规则的 caddy_id(渲染期静态注入)。
	Rule string `json:"rule,omitempty"`

	requestsTotal    *prometheus.CounterVec
	statusTotal      *prometheus.CounterVec
	bytesTotal       *prometheus.CounterVec
	requestsInFlight *prometheus.GaugeVec
}

func init() {
	caddy.RegisterModule(RuleMetricsHandler{})
}

// CaddyModule returns the Caddy module information.
func (RuleMetricsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_rule_metrics",
		New: func() caddy.Module { return new(RuleMetricsHandler) },
	}
}

// Provision 注册指标到 Caddy 的 metrics registry(与 blocked counter 同模式)。
func (h *RuleMetricsHandler) Provision(ctx caddy.Context) error {
	reg := ctx.GetMetricsRegistry()
	if reg == nil {
		return nil
	}
	h.requestsTotal = registerOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lazybalancer", Name: "requests_total",
		Help: "Total requests per load balancer rule.",
	}, []string{"rule"}))
	h.statusTotal = registerOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lazybalancer", Name: "request_status_total",
		Help: "Requests per load balancer rule by status class (2xx/3xx/4xx/5xx).",
	}, []string{"rule", "class"}))
	h.bytesTotal = registerOrExisting(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "lazybalancer", Name: "bytes_total",
		Help: "Bytes per load balancer rule by direction (in/out).",
	}, []string{"rule", "direction"}))
	h.requestsInFlight = registerOrExisting(reg, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "lazybalancer", Name: "requests_in_flight",
		Help: "In-flight requests per load balancer rule.",
	}, []string{"rule"}))
	return nil
}

// isHandlerError 判定错误是否为 caddyhttp.HandlerError(携 statusCode 的
// 处理器错误——coraza 中断/限流等;非 HandlerError 的连接级错误无状态码,
// 不计状态类,与 Caddy 自身 instrumentation 同口径)。
func isHandlerError(err error) bool {
	var herr caddyhttp.HandlerError
	return errors.As(err, &herr)
}

// statusClass 归类状态码到 2xx/3xx/4xx/5xx(其他归 "other")。
func statusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "other"
	}
}

// ServeHTTP 包装链全流量:在途 gauge Inc/Dec 包住整个下游;ResponseRecorder
// 读最终 status(含 coraza 中断的 HandlerError.StatusCode)与响应大小;
// 请求大小用 Caddy 同款的近似估算(头+体)。nil metrics 守卫(注册失败降级)。
func (h *RuleMetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.requestsInFlight != nil {
		h.requestsInFlight.WithLabelValues(h.Rule).Inc()
		defer h.requestsInFlight.WithLabelValues(h.Rule).Dec()
	}

	statusCode := 200
	writeHeaderRecorder := caddyhttp.ShouldBufferFunc(func(status int, header http.Header) bool {
		statusCode = status
		return false
	})
	wrec := caddyhttp.NewResponseRecorder(w, nil, writeHeaderRecorder)
	err := next.ServeHTTP(wrec, r)
	if err != nil {
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			statusCode = handlerErr.StatusCode
		}
	}

	if h.requestsTotal != nil {
		h.requestsTotal.WithLabelValues(h.Rule).Inc()
	}
	// SECLB29-F5(第 29 轮审计):非 HandlerError 错误不计状态类(与 Caddy 自身
	// instrumentation 同口径 metrics.go:368-373——错误只计 requestErrors,不计
	// 2xx 状态类);HandlerError 携 statusCode 照常归类。
	if h.statusTotal != nil && (err == nil || isHandlerError(err)) {
		h.statusTotal.WithLabelValues(h.Rule, statusClass(statusCode)).Inc()
	}
	// SECLB30-3(第 30 轮审计):非 HandlerError 错误不计字节(与 Caddy 自身
	// instrumentation 同口径——错误路径不观测 size);HandlerError 携 statusCode
	// 照常计(F5 只对齐了状态类,字节漏对齐)。
	if h.bytesTotal != nil && (err == nil || isHandlerError(err)) {
		h.bytesTotal.WithLabelValues(h.Rule, "in").Add(float64(computeApproximateRequestSize(r)))
		h.bytesTotal.WithLabelValues(h.Rule, "out").Add(float64(wrec.Size()))
	}
	return err
}

// computeApproximateRequestSize 与 Caddy 自身 metrics 完全一致的请求大小估算
// (头+体:url+method+proto+headers+host+content_length,无分隔符)——
// SR30-4(第 30 轮审计):原版无 +4/header,此前实现是 promhttp 变体致
// bytes_in 与全局口径恒定 +4/header 偏差。逐行对齐 caddyhttp/metrics.go:388。
func computeApproximateRequestSize(r *http.Request) int64 {
	size := 0
	if r.URL != nil {
		size += len(r.URL.String())
	}
	size += len(r.Method) + len(r.Proto)
	for name, values := range r.Header {
		size += len(name)
		for _, value := range values {
			size += len(value)
		}
	}
	size += len(r.Host)
	if r.ContentLength != -1 {
		size += int(r.ContentLength)
	}
	return int64(size)
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddy.Provisioner           = (*RuleMetricsHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*RuleMetricsHandler)(nil)
)
