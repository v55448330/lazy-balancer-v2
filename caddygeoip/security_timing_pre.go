package caddygeoip

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(SecurityTimingPre{})
}

// SecurityTimingPre 是预检段耗时收点(2026-09-27 分段计时):
// 置于 IP 预检 handler 之后、请求体限额/限流/WAF 之前——记录「链首→预检完成」
// 的耗时,写侧车文件键 <timing_id>:pre。摄取管道按规则归属选值:预检段规则
// (IP ACL/GeoIP/信任/威胁,id 1-14 与 800xxx)取 :pre;WAF 段规则(CRS 9xxxxx/
// 自定义)取 :end-:pre(隔离 WAF 评估成本,不含预检开销)。
//
// 拦截语义:预检拦了(id:2 deny 等)链在此中断——:pre 行已写入(本 handler 在
// 预检之后,预检拦时本 handler 不执行!)。修正:预检拦截时链未到达本 handler,
// :pre 行不存在——blocked_counter 写 :end(=预检耗时,链首→拦截返回);
// 摄取对预检段事件查 :pre 优先、miss 回退 :end,两种形态都覆盖。
type SecurityTimingPre struct{}

// CaddyModule returns the caddy module information.
func (SecurityTimingPre) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_timing_pre",
		New: func() caddy.Module { return &SecurityTimingPre{} },
	}
}

// ServeHTTP 记录预检段耗时（键 <timing_id>:pre），原样透传下游。
// 计时读头逻辑收敛于 recordSecurityTiming（PLUG-R1，security_timing.go）。
func (h *SecurityTimingPre) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	recordSecurityTiming(r, ":pre")
	return next.ServeHTTP(w, r)
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddyhttp.MiddlewareHandler = (*SecurityTimingPre)(nil)
)
