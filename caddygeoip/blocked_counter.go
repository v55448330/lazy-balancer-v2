package caddygeoip

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
)

// securityBlockedMetricName 是安全拦截计数器指标名。
const securityBlockedMetricName = "security_blocked_total"

// newSecurityBlockedCounterVec 每次 Provision 新建 CounterVec 并注册——
// caddy-l4 newProxyMetrics 同模式(l4proxy/metrics.go:54):同 registry 时
// registerOrExisting 复用已注册实例(不丢数据),跨 reload 新 registry 时
// 全新注册(归零,与 caddy_http_* 同纪元)——P3-1(第 28.5 轮审计):包级
// singleton 跨 reload 不归零,与 caddy_http_* 纪元错位,扣除常态钳 4xx 到 0。
func newSecurityBlockedCounterVec(reg *prometheus.Registry) *prometheus.CounterVec {
	return registerOrExisting(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "lazybalancer",
			Name:      securityBlockedMetricName,
			Help:      "Requests interrupted by the security engine (WAF/GeoIP/IP ACL) with a 4xx status.",
		},
		[]string{"rule"},
	))
}

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

// SecurityBlockedCounter 是安全拦截计数中间件:包装 WAF handler,检测安全层
// 中断(caddyhttp.HandlerError 携非空 ID 且 4xx status)并按规则计数。
// 覆盖:coraza 中断(WAF/GeoIP/IP ACL,ID=tx.ID())+限流 429(ID=caddyhttp.Error
// 生成的 randString);上游 4xx 不产 HandlerError 不误计。
// 稳定优先设计(2026-09-15 用户裁定,负载均衡/WAF 稳定最重要):
//   - Provision 无操作——无 I/O/无外部依赖/无失败模式,配置加载零风险;
//   - ServeHTTP 只读检测——不修改请求/响应/错误,链语义与无插件时逐字节一致;
//   - 无锁/无共享态——prometheus counter 线程安全,reload 幂等;
//   - API 兼容面:caddy.Module/caddyhttp.HandlerError 稳定(v2.0 起);
//     ctx.GetMetricsRegistry() 是 EXPERIMENTAL(Caddy 标注 subject to change)
//     ——已 nil 守卫(移除则降级为不计数而非崩溃),P5-3(第 28.5 轮审计)。
type SecurityBlockedCounter struct {
	// Rule 是所属负载均衡规则的 caddy_id(渲染期静态注入)。
	Rule string `json:"rule,omitempty"`

	metrics *prometheus.CounterVec
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
		h.metrics = newSecurityBlockedCounterVec(reg)
	}
	return nil
}

// ServeHTTP 调用链下游处理器,只读检查返回错误:安全层中断(HandlerError 携
// 非空 ID——coraza tx.ID() 或限流 caddyhttp.Error 生成的 randString,且 4xx
// status=拦截而非引擎内部错误)时按规则计数;
// 上游 4xx 不产 HandlerError(反向代理直写响应)不误计;返回值原样透传。
func (h *SecurityBlockedCounter) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := next.ServeHTTP(w, r)
	var herr caddyhttp.HandlerError
	// P3-2(第 28.5 轮审计):「ID 非空+4xx」误纳非安全 4xx——caddyhttp.Error
	// 恒生成 ID(randString 9 字符),proxy 499/request_body 413 也被计入。
	// 精确判定:len(ID)==16(coraza tx.ID,randomString(16))或 status==429
	// (限流,caddyhttp.Error 生成 9 字符 ID)——覆盖安全拦截全部,排除
	// proxy 499/request_body 413/其他 caddyhttp.Error 4xx(全 9 字符)。
	// 脆弱点:coraza 若改 tx.ID 长度→断;但 v2.x 一直 16 且 coraza 由
	// Dockerfile pin+构建断言控制——可控。
	if err != nil && errors.As(err, &herr) && (len(herr.ID) == 16 || herr.StatusCode == http.StatusTooManyRequests) {
		h.metrics.WithLabelValues(h.Rule).Inc()
	}
	return err
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddy.Provisioner           = (*SecurityBlockedCounter)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecurityBlockedCounter)(nil)
)
