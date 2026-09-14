package caddygeoip

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// securityBlockedTotal 是安全拦截(WAF/GeoIP/IP ACL coraza 中断)的 Prometheus
// 计数器——包级单次注册(init),进程生命周期累计,与 Caddy 其余 metrics 同
// 源同生命周期;/metrics 端点随 Caddy 内置注册表自动暴露(与 caddy-l4 的
// l4proxy metrics 同机制)。
var securityBlockedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "lazybalancer",
		Name:      "security_blocked_total",
		Help:      "Requests interrupted by the security engine (WAF/GeoIP/IP ACL) with a 4xx status.",
	},
	[]string{"rule"},
)

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

// Provision 无操作——无任何可失败路径(幂等,reload 安全)。
func (h *SecurityBlockedCounter) Provision(caddy.Context) error { return nil }

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
