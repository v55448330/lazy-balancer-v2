package handlers

func init() {
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/tools",
		Tag:         "MCP",
		Summary:     "MCP 工具注册表",
		Response:    `{"code":0,"message":"查询成功","data":[{"name":"list_rules","description":"列出全部负载均衡规则","method":"GET","path":"/api/v1/rules","read_only":true}]}`,
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 工具名称、描述、映射的 REST 请求与读写分类，不含内部路由参数注记（path_args/query_args），包含各工具 input_schema。read_only 表示该工具对只读 API Key 可用：GET 且非 export_config，或 4 个读探测 POST 工具（test_ca_provider/parse_certificate/validate_import/preview_config）。它与 HTTP 方法是否为 GET 不等价——export_config 虽为 GET 但对只读 Key 不可见（read_only=false）；其余写工具（含 test_certificate_config 证书配置测试）对只读 Key 不可用。",
	})
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/ops-playbook",
		Tag:         "MCP",
		Summary:     "下载 MCP 操作手册",
		Response:    "\"# Lazy Balancer V2 MCP 操作手册\\n\\n（正文以 text/markdown 附件下载，与 MCP 资源 lazy-balancer://docs/ops-playbook 同源。）\"",
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 操作手册 markdown 正文，与 MCP 资源 lazy-balancer://docs/ops-playbook 同一来源。",
	})
}
