package handlers

func init() {
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/tools",
		Tag:         "MCP",
		Summary:     "MCP 工具注册表",
		Response:    `{"code":0,"message":"查询成功","data":[{"name":"list_rules","description":"列出全部负载均衡规则","method":"GET","path":"/api/v1/rules","read_only":true}]}`,
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 工具名称、描述、映射的 REST 请求与读写分类，不包含内部参数 schema。",
	})
}
