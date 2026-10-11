package mcpserver

// U9-P3-1 修复钉：MCP 只读探测集（ReadOnlyProbeTools）↔ REST 只读白名单
// （auditpolicy.readOnlyWriteRoutes）机械互检。此前钉测试仅单向防过曝
// （非 GET 工具可见 ⇒ 必在探测集），缺两个反向：
// ① 探测集每项须真实对应 REST 只读路由（陈旧/错拼项 → 工具可见但恒 403）；
// ② 对应白名单路由的 MCP 工具须在探测集（欠曝）。
import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// ginPath 将 {param} 形态还原为 Gin 的 :param（mcp_routes_parity_test.go
// openAPIToGinPath 同义——外部测试包不可共享，此处内联）。
// APIMCP-R1（第 69 轮）：与 openAPIToGinPath 对齐为全替换循环——旧实现只转
// 首个 {param}，多参路径（如 /security/policies/{id}/bind/{caddy_id}）会得
// 半转换形态让互检静默失真。
func ginPath(path string) string {
	for {
		i := strings.IndexByte(path, '{')
		if i < 0 {
			return path
		}
		j := strings.IndexByte(path[i:], '}')
		if j < 0 {
			return path
		}
		path = path[:i] + ":" + path[i+1:i+j] + path[i+j+1:]
	}
}

// Given 全部注册工具规格与 REST 只读白名单。
// When 逐工具比对「非 GET ⇔ 探测集 ⇔ IsReadOnlyWriteRoute」三向一致性。
// Then 三个方向全部闭合（探测集=白名单的 MCP 投影，无陈旧项无欠曝项）。
func TestReadOnlyProbeTools_matchRestWhitelist(t *testing.T) {
	probeHit := 0
	for _, spec := range tools {
		inProbe := false
		if _, ok := ReadOnlyProbeTools[spec.name]; ok {
			inProbe = true
			probeHit++
		}
		restReadOnly := services.IsReadOnlyWriteRoute(spec.method, ginPath("/api/v1"+spec.path))
		if spec.method == "GET" {
			if inProbe {
				t.Errorf("GET 工具 %s 不应出现在只读探测集", spec.name)
			}
			continue
		}
		// 方向①：探测集项必须真实对应只读路由（陈旧/错拼 → 恒 403）
		if inProbe && !restReadOnly {
			t.Errorf("探测集工具 %s（%s %s）不在 REST 只读白名单——只读 Key 可见但调用恒 403", spec.name, spec.method, spec.path)
		}
		// 方向②：非 GET 工具命中白名单却不在探测集（欠曝）
		if !inProbe && restReadOnly {
			t.Errorf("非 GET 工具 %s（%s %s）命中 REST 只读白名单但不在 ReadOnlyProbeTools——只读 Key 看不到可用工具", spec.name, spec.method, spec.path)
		}
	}
	if probeHit == 0 {
		t.Fatal("探测集命中数为 0——比对形态失效（工具规格或路径口径漂移）")
	}
}
