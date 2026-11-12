package lbreqmon

import (
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
func (ReqMonHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	sw := &statusWriter{ResponseWriter: w}
	start := time.Now()
	err := next.ServeHTTP(sw, r)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
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
		Status:     sw.status,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000,
		Size:       sw.bytes,
		ReqSize:    reqSize,
	})
	return err
}

// UnmarshalCaddyFile 支持 Caddyfile 形态（lb_reqmon 无参数）。

// Interface guards（编译期契约）。
var (
	_ caddy.Module                = (*ReqMonHandler)(nil)
	_ caddy.Provisioner           = (*ReqMonHandler)(nil)
	_ caddy.Validator             = (*ReqMonHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ReqMonHandler)(nil)
)
