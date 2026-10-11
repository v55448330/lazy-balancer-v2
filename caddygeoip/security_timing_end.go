package caddygeoip

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(SecurityTimingEnd{})
}

// SecurityTimingEnd 是安全链末尾的耗时收点(2026-09-27 双点计时修复):
// blocked_counter 计「拦截事件」的耗时(HandlerError 返回时链未到
// reverse_proxy,耗时=纯安全评估,已准确);放行事件的耗时若也在
// blocked_counter 的 next 返回后计,会混入上游代理往返(实测 329ms 中主要
// 是上游响应时间而非 WAF 评估)——本处理器置于安全链末尾、reverse_proxy
// 之前,读 blocked_counter 注入的起始纳秒头计算纯评估耗时写入侧车文件。
//
// 覆盖:放行+检测记录(logged)事件在 coraza ProcessLogging 之前已完成
// 全部策略评估,此处读值即纯安全链耗时;信任直通(passthrough)时安全链
// 整体跳过,本处理器在 subroute 内不执行,无计时(无事件,无关联缺口)。
//
// 稳定设计:零 Provision/零失败模式;读请求头+写侧车文件,任何失败静默
// 降级(该事件耗时报「—」);next 原样透传,链语义与无插件时一致。
type SecurityTimingEnd struct{}

// CaddyModule returns the caddy module information.
func (SecurityTimingEnd) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_timing_end",
		New: func() caddy.Module { return &SecurityTimingEnd{} },
	}
}

// ServeHTTP 计算全链纯评估耗时（键 <timing_id>:end）写入侧车文件，原样透传
// 下游（reverse_proxy）。计时读头逻辑收敛于 recordSecurityTiming（PLUG-R1，
// security_timing.go）。
func (h *SecurityTimingEnd) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	recordSecurityTiming(r, ":end")
	return next.ServeHTTP(w, r)
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddyhttp.MiddlewareHandler = (*SecurityTimingEnd)(nil)
)
