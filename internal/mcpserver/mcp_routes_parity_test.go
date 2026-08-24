package mcpserver_test

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
)

// TestMCPToolSpecs_cover_registeredGinRoutes MCP 工具↔路由对照绊线（R68 B-F7）：
// 每个工具的 (method, path) 必须命中 SetupRouter 注册的真实路由——工具指向已
// 改名/删除的路由只会在 Agent 调用时 404，编译期与既有测试均不可见（OpenAPI
// 侧有同款绊线，MCP 侧此前为空白）。{param} 形态经 ginPathToOpenAPI 反向
// 归一为 Gin 的 :param 后比对。
func TestMCPToolSpecs_cover_registeredGinRoutes(t *testing.T) {
	router := newAPIDocTestRouter(t)
	registered := make(map[string]struct{}, len(router.Routes()))
	for _, route := range router.Routes() {
		registered[route.Method+" "+route.Path] = struct{}{}
	}
	missing := 0
	specs := mcpserver.ListToolSpecs()
	for _, spec := range specs {
		ginPath := openAPIToGinPath(spec.Path)
		if _, ok := registered[spec.Method+" "+ginPath]; !ok {
			t.Errorf("工具 %s 指向未注册路由 %s %s——REST 路由已改名/删除而工具规格未同步", spec.Name, spec.Method, spec.Path)
			missing++
		}
	}
	if missing == 0 && len(specs) == 0 {
		t.Fatal("工具清单为空——ListToolSpecs 可能已重构，请同步更新本绊线")
	}
}

// openAPIToGinPath 将 {param} 形态还原为 Gin 的 :param（ginPathToOpenAPI 反函数）。
func openAPIToGinPath(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '{':
			b.WriteByte(':')
		case '}':
		default:
			b.WriteByte(path[i])
		}
	}
	return b.String()
}
