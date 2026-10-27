package handlers

import (
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
)

// MCP 工具 schema 属性 ↔ 传输面反向门：forward 只按 pathArgs/queryArgs 取值，
// 其余参数整体序列化进请求体。因此某个属性若在 REST 契约里是 query 参数
// （apiDocContracts[method+" "+ginPath].queryParameters），它必须登记为
// toolSpec.queryArgs——否则 Agent 按 schema 传值时参数会静默落进 body，
// REST 把 body 当业务数据解析，语义从「过滤/选项」变成「数据被改写」。
//
// 现行实例：import_config 的 sections 是 REST ?sections= 的分类子集，落进 body
// 后会改写备份正文的分类记录 → v3 校验和不匹配 → 健康备份被判「已篡改」硬拒。
// 既有对账门只覆盖 GET 反向等集（tools_test.go），写方法没有反向门，同类漂移
// 因此可以全绿上线。
//
// 无法归类的属性（REST 侧无同名 query 参数）合法留在 body；本门只钉「同名于
// REST query 参数 ⇒ 必须走 query」这一条不变式。
func TestMCPToolSchemas_routeRESTQueryParamsToQueryArgs(t *testing.T) {
	checkedTools := 0
	checkedProperties := 0
	for _, spec := range mcpserver.ToolTransportsForTest() {
		contract, ok := apiDocContracts[spec.Method+" "+spec.GinPath]
		if !ok || len(contract.queryParameters) == 0 {
			continue
		}
		var shape struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if spec.Schema == "" {
			continue
		}
		if err := json.Unmarshal([]byte(spec.Schema), &shape); err != nil {
			t.Errorf("%s schema 解析失败: %v", spec.Name, err)
			continue
		}
		declaredQuery := make(map[string]bool, len(spec.QueryArgs))
		for _, name := range spec.QueryArgs {
			declaredQuery[name] = true
		}
		checkedTools++
		for _, param := range contract.queryParameters {
			if _, declared := shape.Properties[param.name]; !declared {
				// schema 不暴露该 REST query 参数：Agent 无法传，不构成错面。
				continue
			}
			checkedProperties++
			if !declaredQuery[param.name] {
				t.Errorf("%s (%s %s) 的 input_schema 声明了 %q，其同名参数在 REST 契约中是 query 参数，但它未登记为 queryArgs——转发时会落进请求体改写业务数据而非过滤；请把 %q 加入该工具注册的 queryArgs",
					spec.Name, spec.Method, spec.GinPath, param.name, param.name)
			}
		}
	}
	if checkedProperties == 0 {
		t.Fatal("没有任何「schema 属性同名于 REST query 参数」的样本——反向门空转（契约键或 schema 解析形态可能失效）")
	}
}
