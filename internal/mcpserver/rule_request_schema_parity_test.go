package mcpserver

// 请求结构 → 工具 schema 的反向对账门：工具 schema 的既有门都是「声明的
// pathArgs/queryArgs 必须在 schema 里」（正向），反向缺口从来没有门——REST 请求
// 结构里真实存在的字段可以在 schema 里完全缺席，而转发层会把未登记为
// path/query 的参数原样搬进 body：字段「能生效但契约宣称不存在」，Agent 永远
// 看不到它（规则版本前置条件 expected_updated_at 就是从这条缺口漏出去的）。
// 本门用反射取 models.*Request 的 JSON 字段集，断言每个字段都在对应工具 schema
// 的 properties 中；新增 REST 请求字段时 schema 必须同步，或在此显式豁免并写
// 理由。

import (
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// requestSchemaExemptions 登记「请求结构字段刻意不进工具 schema」的例外
// （键=结构名.字段），必须写理由；不存在的豁免由下方反向断言清除。
var requestSchemaExemptions = map[string]string{}

// jsonFieldNames 收集结构体顶层 JSON 字段名（跳过 `-`、空标签与无标签字段）。
func jsonFieldNames(t *testing.T, sample any) []string {
	t.Helper()
	typ := reflect.TypeOf(sample)
	if typ.Kind() != reflect.Struct {
		t.Fatalf("sample 必须是结构体，got %s", typ.Kind())
	}
	names := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func TestRuleToolSchemasCoverRequestStructFields(t *testing.T) {
	cases := []struct {
		tool     string
		schema   string
		request  any
		required int
	}{
		{tool: "create_rule", schema: createRuleSchema, request: models.CreateRuleRequest{}, required: 40},
		{tool: "update_rule", schema: updateRuleSchema, request: models.UpdateRuleRequest{}, required: 50},
	}

	for _, tc := range cases {
		properties := decodeRuleSchema(t, tc.tool, tc.schema)
		fields := jsonFieldNames(t, tc.request)
		if len(fields) < tc.required {
			t.Fatalf("%s 的请求结构字段只取到 %d 个（want ≥%d）：反射形态漂移会让本门空转", tc.tool, len(fields), tc.required)
		}
		for _, field := range fields {
			if reason, exempt := requestSchemaExemptions[tc.tool+"."+field]; exempt {
				if reason == "" {
					t.Errorf("豁免 %s.%s 缺理由", tc.tool, field)
				}
				continue
			}
			if _, ok := properties[field]; !ok {
				t.Errorf("%s 的 input_schema 缺少请求字段 %q（后端接受却对 Agent 不可见，转发层会把未登记参数搬进 body）", tc.tool, field)
			}
		}
	}

	// 反向：豁免表里的键必须仍然真实存在，避免陈旧豁免长期掩盖新的漂移。
	for key := range requestSchemaExemptions {
		t.Errorf("陈旧豁免 %q：请确认该字段仍需豁免，否则删除（本断言只在表非空时命中）", key)
	}
}
