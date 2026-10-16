package caddygeoip

import "github.com/caddyserver/caddy/v2"

// init 注册流量统计 admin 模块——Caddy 对 admin.api 命名空间全量自动挂载
// （admin.go newAdminHandler 遍历 GetModules("admin.api") 逐个实例化并挂路由），
// 注册即生效，无需配置启用（v7 首版漏此 init 致端点 404，主审实测捕获）。
func init() {
	caddy.RegisterModule(TrafficStatsAdmin{})
}
