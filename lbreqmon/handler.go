package lbreqmon

import (
	"errors"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ReqMonHandler HTTP 反代请求观测处理器（http.handlers.lb_reqmon）。
// 无实例状态：捕获统一写包级环形缓冲（reload 重建实例零影响）。
// Provisioner/接口面刻意最小化——渲染侧以 {"handler":"lb_reqmon"} 注入
// 路由链首，无任何可配字段（容量为编译期常量，用户裁定）。
type ReqMonHandler struct{}

// CaddyModule returns the Caddy module information.
func (ReqMonHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_reqmon",
		New: func() caddy.Module { return new(ReqMonHandler) },
	}
}

// Provision implements caddy.Provisioner.
func (ReqMonHandler) Provision(caddy.Context) error { return nil }

// Validate implements caddy.Validator.
func (ReqMonHandler) Validate() error { return nil }

// ServeHTTP 捕获请求与响应元数据后放行下游链。
// 错误终结的请求：响应由 Caddy server 层在包装器之外写出（错误路由/默认
// 错误应答绕过 statusWriter），观测状态从返回错误映射——HandlerError 取其
// StatusCode，其余错误按 server 层默认 500（caddyhttp errLogValues 同口径，
// 与 caddygeoip rule_metrics 的 errors.As 范式同形；独立模块不 import，
// 两侧口径改动必须成对）。已写出的状态码优先（响应头已提交=线上事实）。
func (ReqMonHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	sw := &statusWriter{ResponseWriter: w}
	start := time.Now()
	err := next.ServeHTTP(sw, r)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	status := sw.status
	if status == 0 && err != nil {
		status = http.StatusInternalServerError
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) && handlerErr.StatusCode != 0 {
			status = handlerErr.StatusCode
		}
	}
	reqSize := r.ContentLength // -1=流式/未知（chunked）
	Record(RequestRecord{
		Ts:         time.Now().UnixMilli(),
		ClientIP:   clientIP(r),
		Method:     r.Method,
		Proto:      r.Proto,
		Scheme:     scheme,
		RuleID:     r.Header.Get("X-LB-Rule-ID"), // headers 链首已 set，reqmon 在其后可读
		UA:         r.Header.Get("User-Agent"),
		Host:       r.Host,
		URI:        r.URL.RequestURI(),
		Status:     status,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000,
		Size:       sw.bytes,
		ReqSize:    reqSize,
	})
	return err
}

// 配置面：本模块只消费 JSON 渲染形态（渲染侧 {"handler":"lb_reqmon"} 注入），
// 不实现 UnmarshalCaddyFile——Caddyfile 直配不支持（产品内不可达）。

// Interface guards（编译期契约）。
var (
	_ caddy.Module                = (*ReqMonHandler)(nil)
	_ caddy.Provisioner           = (*ReqMonHandler)(nil)
	_ caddy.Validator             = (*ReqMonHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ReqMonHandler)(nil)
)
