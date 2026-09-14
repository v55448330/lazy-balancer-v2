package caddygeoip

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
)

// securityBlockedTotal 是安全拦截(WAF/GeoIP/IP ACL coraza 中断)的 Prometheus
// 计数器——包级单次构造,Provision 时注册到 Caddy 的 metrics registry
// (ctx.GetMetricsRegistry——非默认 registry,默认 registry 不会暴露在
// Caddy /metrics 端点);registerOrExisting 复用已注册实例(reload 幂等,
// 与 caddy-l4 l4proxy metrics 同模式)。
var securityBlockedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "lazybalancer",
		Name:      "security_blocked_total",
		Help:      "Requests interrupted by the security engine (WAF/GeoIP/IP ACL) with a 4xx status.",
	},
	[]string{"rule"},
)

// registerOrExisting 注册到 reg,已注册时复用既有实例——Caddy reload 会重
// Provision,重复注册 MustRegister 会 panic(崩溃风险,用户裁定零容忍);
// 与 caddy-l4 的 registerOrExisting(l4proxy/metrics.go:34)同模式。
func registerOrExisting[C prometheus.Collector](reg *prometheus.Registry, c C) C {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing
			}
		}
		// 其他注册错误=指标不可用——回落未注册实例(计数 no-op 而非崩溃)。
	}
	return c
}

func init() {
	caddy.RegisterModule(SecurityBlockedCounter{})
}

// SecurityBlockedCounter 是安全拦截计数中间件:包装 WAF handler,检测 coraza
// 中断(caddyhttp.HandlerError 携非空 ID 且 4xx status)并按规则计数。
// 稳定优先设计(2026-09-15 用户裁定,负载均衡/WAF 稳定最重要):
//   - Provision 无操作——无 I/O/无外部依赖/无失败模式,配置加载零风险;
//   - ServeHTTP 只读检测——不修改请求/响应/错误,链语义与无插件时逐字节一致;
//   - 无锁/无共享态——prometheus counter 线程安全,reload 幂等;
//   - 仅用 Caddy 稳定公开 API(caddy.Module/caddyhttp.HandlerError)——
//     后续 Caddy 升级兼容面最小(该类型自 v2.0 起稳定)。
type SecurityBlockedCounter struct {
	// Rule 是所属负载均衡规则的 caddy_id(渲染期静态注入)。
	Rule string `json:"rule,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (SecurityBlockedCounter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_blocked_counter",
		New: func() caddy.Module { return new(SecurityBlockedCounter) },
	}
}

// Provision 注册计数器到 Caddy 的 metrics registry(非默认 registry——
// 默认 registry 的指标不暴露在 Caddy /metrics 端点);registerOrExisting
// 保证 reload 幂等(重复注册复用实例,不 panic)。
func (h *SecurityBlockedCounter) Provision(ctx caddy.Context) error {
	if reg := ctx.GetMetricsRegistry(); reg != nil {
		registerOrExisting(reg, securityBlockedTotal)
	}
	return nil
}

// ServeHTTP 调用链下游处理器,只读检查返回错误:coraza 中断(HandlerError 携
// 非空 ID=transaction id,且 4xx status=拦截而非引擎内部错误)时按规则计数;
// 上游 4xx 不产 HandlerError(反向代理直写响应)不误计;返回值原样透传。
func (h *SecurityBlockedCounter) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := next.ServeHTTP(w, r)
	var herr caddyhttp.HandlerError
	if err != nil && errors.As(err, &herr) && herr.ID != "" && herr.StatusCode >= 400 && herr.StatusCode < 500 {
		securityBlockedTotal.WithLabelValues(h.Rule).Inc()
	}
	return err
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddy.Provisioner           = (*SecurityBlockedCounter)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecurityBlockedCounter)(nil)
)
