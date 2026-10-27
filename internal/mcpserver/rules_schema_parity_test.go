package mcpserver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// decodeRuleSchema 解析一份规则工具的 input_schema。
func decodeRuleSchema(t *testing.T, name, schema string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(schema), &decoded); err != nil {
		t.Fatalf("解析 %s schema: %v", name, err)
	}
	properties, ok := decoded["properties"].(map[string]any)
	if !ok || len(properties) == 0 {
		t.Fatalf("%s schema 无 properties", name)
	}
	return properties
}

// stripSchemaDescriptions 删掉所有 description 键：create 与 update 的字段说明
// 可因语境不同（创建默认值 vs 更新「省略=保留原值」），但类型/枚举/上下界等
// 约束必须一致。
func stripSchemaDescriptions(node any) any {
	switch value := node.(type) {
	case map[string]any:
		stripped := make(map[string]any, len(value))
		for key, item := range value {
			if key == "description" {
				continue
			}
			stripped[key] = stripSchemaDescriptions(item)
		}
		return stripped
	case []any:
		stripped := make([]any, len(value))
		for index, item := range value {
			stripped[index] = stripSchemaDescriptions(item)
		}
		return stripped
	default:
		return value
	}
}

// TestRuleToolSchemasShareIdenticalConstraints 钉住 create_rule / update_rule
// 的同一字段必须共用同一份约束（类型/枚举/上下界/嵌套结构）：两份巨型字面量
// 此前只在 create 侧写了部分写侧约束，Agent 按 update schema 构参会先吃 400。
// 描述文本允许因语境不同，故比较前统一剥掉 description。
// updateOnlyRuleSchemaFields 登记「只在 update_rule 出现」的字段及理由：对称性
// 是本门的目标，但版本前置条件在语义上只存在于更新（创建没有基线版本可比），
// 故显式豁免而不是把字段硬塞进 create。豁免表本身也被反向校验：字段一旦回到
// create_rule 或从 update_rule 消失，本门立即变红（防陈旧豁免长期掩盖漂移）。
var updateOnlyRuleSchemaFields = map[string]string{
	"expected_updated_at": "乐观并发前置条件：以既有 updated_at 为基线，创建时无基线",
}

func TestRuleToolSchemasShareIdenticalConstraints(t *testing.T) {
	createProperties := decodeRuleSchema(t, "create_rule", createRuleSchema)
	updateProperties := decodeRuleSchema(t, "update_rule", updateRuleSchema)

	for name := range createProperties {
		if _, exists := updateProperties[name]; !exists {
			t.Errorf("字段 %q 只在 create_rule schema 中——update 无法提交该字段", name)
		}
	}
	for name := range updateProperties {
		if name == "caddy_id" {
			continue
		}
		if _, exempt := updateOnlyRuleSchemaFields[name]; exempt {
			continue
		}
		if _, exists := createProperties[name]; !exists {
			t.Errorf("字段 %q 只在 update_rule schema 中——create 无法提交该字段", name)
		}
	}
	for name, reason := range updateOnlyRuleSchemaFields {
		if _, exists := createProperties[name]; exists {
			t.Errorf("字段 %q 已在 create_rule schema 中，update-only 豁免必须删除（理由：%s）", name, reason)
		}
		if _, exists := updateProperties[name]; !exists {
			t.Errorf("update-only 豁免登记的字段 %q 不在 update_rule schema 中", name)
		}
	}
	for name, createConstraint := range createProperties {
		updateConstraint, exists := updateProperties[name]
		if !exists {
			continue
		}
		if got, want := stripSchemaDescriptions(updateConstraint), stripSchemaDescriptions(createConstraint); !reflect.DeepEqual(got, want) {
			t.Errorf("字段 %q 的约束在 create/update 间分叉：create=%v update=%v", name, want, got)
		}
	}
}

// TestRuleToolSchemasDocumentWriteSideConstraints 钉住 schema 已声明的写侧约束
// （后端会拒绝，schema 必须先行告知，否则 Agent 只能靠 400 试错）：
// NTLM 四列接管、重试窗口值域、健康检查超时小于间隔、回源域名的协议限制。
func TestRuleToolSchemasDocumentWriteSideConstraints(t *testing.T) {
	creates := decodeRuleSchema(t, "create_rule", createRuleSchema)
	updates := decodeRuleSchema(t, "update_rule", updateRuleSchema)

	description := func(properties map[string]any, field string) string {
		t.Helper()
		property, ok := properties[field].(map[string]any)
		if !ok {
			t.Fatalf("schema 缺少字段 %q", field)
		}
		text, _ := property["description"].(string)
		return text
	}
	number := func(properties map[string]any, field, key string) float64 {
		t.Helper()
		property, ok := properties[field].(map[string]any)
		if !ok {
			t.Fatalf("schema 缺少字段 %q", field)
		}
		value, ok := property[key].(float64)
		if !ok {
			t.Fatalf("字段 %q 缺少 %s", field, key)
		}
		return value
	}

	for name, properties := range map[string]map[string]any{"create_rule": creates, "update_rule": updates} {
		ntlm := description(properties, "ntlm_compatible")
		for _, required := range []string{"tcp_try_duration=-1", "upstream_force_http1=1", "proxy_flush_interval=-1", "upstream_keepalive_timeout=300"} {
			if !strings.Contains(ntlm, required) {
				t.Errorf("%s: ntlm_compatible 描述缺少接管四列条件 %q", name, required)
			}
		}
		if got := number(properties, "tcp_try_duration", "minimum"); got != -1 {
			t.Errorf("%s: tcp_try_duration minimum=%v, want -1（-1=禁用重试）", name, got)
		}
		if got := number(properties, "tcp_try_duration", "maximum"); got != 60000 {
			t.Errorf("%s: tcp_try_duration maximum=%v, want 60000", name, got)
		}
		if got := number(properties, "tcp_try_interval", "minimum"); got != 0 {
			t.Errorf("%s: tcp_try_interval minimum=%v, want 0", name, got)
		}
		if got := number(properties, "tcp_try_interval", "maximum"); got != 60000 {
			t.Errorf("%s: tcp_try_interval maximum=%v, want 60000", name, got)
		}
		if timeout := description(properties, "health_check_timeout"); !strings.Contains(timeout, "health_check_interval") {
			t.Errorf("%s: health_check_timeout 描述未说明「须小于 health_check_interval」", name)
		}
		upstreams, ok := properties["upstreams"].(map[string]any)
		if !ok {
			t.Fatalf("%s schema 缺少 upstreams", name)
		}
		items, _ := upstreams["items"].(map[string]any)
		itemProperties, _ := items["properties"].(map[string]any)
		origin, _ := itemProperties["origin_domain"].(map[string]any)
		originDescription, _ := origin["description"].(string)
		if !strings.Contains(originDescription, "dynamic_dns") || !strings.Contains(originDescription, "TCP") {
			t.Errorf("%s: upstreams[].origin_domain 描述未说明 dynamic_dns/TCP 规则不支持", name)
		}
	}
}
