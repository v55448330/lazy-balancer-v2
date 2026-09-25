package handlers

func init() {
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/tools",
		Tag:         "MCP",
		Summary:     "MCP 工具注册表",
		Response:    `{"code":0,"message":"查询成功","data":[{"name":"list_rules","description":"列出全部负载均衡规则","method":"GET","path":"/api/v1/rules","read_only":true}]}`,
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 工具名称、描述、映射的 REST 请求与读写分类，不含内部路由参数注记（path_args/query_args），包含各工具 input_schema。read_only 字段为 HTTP 语义只读（method==GET），不代表只读 API Key 可见性——可见性由服务端按 Key 权限过滤（只读 Key 隐藏 export_config，但可见 test_ca_provider/test_certificate_config/parse_certificate/validate_import/preview_config 5 个读探测 POST 工具）。",
	})
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/ops-playbook",
		Tag:         "MCP",
		Summary:     "下载 MCP 操作手册",
		Response:    `{"markdown":"（手册全文以 text/markdown 文件流返回，attachment 下载）"}`,
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 操作手册 markdown 正文，与 MCP 资源 lazy-balancer://docs/ops-playbook 同一来源。",
	})
}
