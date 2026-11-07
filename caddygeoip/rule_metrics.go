package caddygeoip

import (
	"errors"
	"net/http"
	"time"

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
//	lazybalancer_rule_metrics_epoch_seconds   — 统计起点(上次 /load Unix 秒,无标签)
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
	// epochSeconds 统计起点锚点：每次 Provision（=每次 /load 渲染本实例）
	// 置当前 Unix 秒。计数器随 /load 归零，本 gauge 告知消费方「这些数字从
	// 何时起算」——仪表盘规则页显示「统计自 HH:MM（上次配置重载）」。
	epochSeconds prometheus.Gauge

	// 预解析标签句柄（Provision 期一次性 WithLabelValues）：Rule 是渲染期
	// 静态值，每请求 6 次 vec map 查找（读锁+哈希）是纯浪费——热路径只对
	// 句柄 Inc/Add。nil 表示指标未注册（降级 no-op，与 nil vec 守卫同语义）。
	reqCounter    prometheus.Counter
	inFlight      prometheus.Gauge
	bytesIn       prometheus.Counter
	bytesOut      prometheus.Counter
	statusByClass map[string]prometheus.Counter
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
	// 已知有界残留（不就地修）：label 子序列随规则删除/改名永久驻留
	// （全仓无 DeleteLabelValues）——逐实例删除不可行：Cleanup 在 reload 时
	// 对存活实例同样被调用，删除会把存活规则计数清零。根治需根服务按
	// 「新配置规则集 − 旧集合」reconcile（跨 module，暂不立项）。残留规模有界
	// （每规则 4+1+5 条序列），进程重启归零，按文档化残留接受。
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
	// 统计起点 gauge（无标签，全实例共享单序列；reload 经 registerOrExisting
	// 复用同一 collector，Set 覆盖不累加）。
	h.epochSeconds = registerOrExisting(reg, prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "lazybalancer", Name: "rule_metrics_epoch_seconds",
		Help: "Rule metrics collection epoch (Unix seconds when the current config was loaded).",
	}))
	h.epochSeconds.Set(float64(time.Now().Unix()))
	// 预解析本实例的全部标签句柄——同一 vec 重复 Provision（注册复用路径）
	// 重建句柄指向同一下层序列，安全。
	h.reqCounter = h.requestsTotal.WithLabelValues(h.Rule)
	h.inFlight = h.requestsInFlight.WithLabelValues(h.Rule)
	h.bytesIn = h.bytesTotal.WithLabelValues(h.Rule, "in")
	h.bytesOut = h.bytesTotal.WithLabelValues(h.Rule, "out")
	h.statusByClass = make(map[string]prometheus.Counter, len(statusClasses))
	for _, class := range statusClasses {
		h.statusByClass[class] = h.statusTotal.WithLabelValues(h.Rule, class)
	}
	return nil
}

// isHandlerError 判定错误是否为 caddyhttp.HandlerError(携 statusCode 的
// 处理器错误——coraza 中断/限流等;非 HandlerError 的连接级错误无状态码,
// 不计状态类,与 Caddy 自身 instrumentation 同口径)。
func isHandlerError(err error) bool {
	var herr caddyhttp.HandlerError
	return errors.As(err, &herr)
}

// statusClasses 状态类全集——statusClass 的每个返回值都必须在此列出
// （Provision 按本表预解析句柄，ServeHTTP 查表命中）。
var statusClasses = []string{"2xx", "3xx", "4xx", "5xx", "other"}

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
	if h.inFlight != nil {
		h.inFlight.Inc()
		defer h.inFlight.Dec()
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

	if h.reqCounter != nil {
		h.reqCounter.Inc()
	}
	// 非 HandlerError 错误不计状态类(与 Caddy 自身
	// instrumentation 同口径 metrics.go:368-373——错误只计 requestErrors,不计
	// 2xx 状态类);HandlerError 携 statusCode 照常归类。
	if h.statusByClass != nil && (err == nil || isHandlerError(err)) {
		h.statusByClass[statusClass(statusCode)].Inc()
	}
	// 非 HandlerError 错误不计字节(与 Caddy 自身
	// instrumentation 同口径——错误路径不观测 size);HandlerError 携 statusCode
	// 照常计（状态类与字节口径对齐）。
	if h.bytesIn != nil && (err == nil || isHandlerError(err)) {
		h.bytesIn.Add(float64(computeApproximateRequestSize(r)))
		h.bytesOut.Add(float64(wrec.Size()))
	}
	return err
}

// computeApproximateRequestSize 与 Caddy 自身 metrics 完全一致的请求大小估算
// (头+体:url+method+proto+headers+host+content_length,无分隔符)——
// 原版无 +4/header,此前实现是 promhttp 变体致
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
