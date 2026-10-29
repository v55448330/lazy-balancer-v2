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
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// requestSchemaExemptions 登记「请求结构字段刻意不进工具 schema」的例外
// （键=结构名.字段），必须写理由；不存在的豁免由下方反向断言清除。
var requestSchemaExemptions = map[string]string{
	"create_block_page.id":             "服务端分配，handler 显式拒绝指定 id",
	"create_block_page.is_default":     "默认页由系统管理，handler 显式拒绝创建",
	"create_block_page.is_builtin":     "内置页由系统管理，handler 显式拒绝创建",
	"create_block_page.created_by":     "服务端从会话写入，不接受请求体",
	"create_block_page.created_at":     "服务端时间戳，不接受请求体",
	"create_block_page.updated_by":     "服务端从会话写入，不接受请求体",
	"create_block_page.updated_at":     "服务端时间戳，不接受请求体",
	"create_block_page.rule_ref_count": "列表派生统计字段，不参与创建",
}

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

// anonymousRequestFields 从 handler 内真实匿名请求结构派生 JSON 字段集。
// update_user/update_block_page 的绑定体是函数内匿名 struct，没有可反射的
// 命名类型；在测试里另写一份镜像字段表会制造第二事实源，故直接读 AST。
func anonymousRequestFields(t *testing.T, path, function string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.FromSlash(path), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var fields []string
	ast.Inspect(file, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != function || fn.Body == nil {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			spec, ok := inner.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "req" || len(spec.Values) != 0 {
				return true
			}
			structure, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range structure.Fields.List {
				if field.Tag == nil {
					continue
				}
				tag, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					continue
				}
				jsonTag := reflect.StructTag(tag).Get("json")
				name := strings.Split(jsonTag, ",")[0]
				if name != "" && name != "-" {
					fields = append(fields, name)
				}
			}
			return false
		})
		return false
	})
	if len(fields) == 0 {
		t.Fatalf("%s 的 %s 未找到匿名 req struct 字段", path, function)
	}
	return fields
}

func TestRuleToolSchemasCoverRequestStructFields(t *testing.T) {
	cases := []struct {
		tool     string
		schema   string
		request  any
		fields   []string
		required int
	}{
		{tool: "create_rule", schema: createRuleSchema, request: models.CreateRuleRequest{}, required: 40},
		{tool: "update_rule", schema: updateRuleSchema, request: models.UpdateRuleRequest{}, required: 50},
		{tool: "create_security_policy", schema: createSecurityPolicySchema, request: models.CreateSecurityPolicyRequest{}, required: 28},
		{tool: "update_security_policy", schema: updateSecurityPolicySchema, request: models.UpdateSecurityPolicyRequest{}, required: 28},
		{tool: "create_custom_rule", schema: createCustomRuleSchema, request: models.CreateCustomRuleRequest{}, required: 7},
		{tool: "update_custom_rule", schema: updateCustomRuleSchema, request: models.UpdateCustomRuleRequest{}, required: 7},
		{tool: "create_block_page", schema: createBlockPageSchema, request: models.SecurityBlockPage{}, required: 12},
		{tool: "update_block_page", schema: updateBlockPageSchema, fields: anonymousRequestFields(t, "../handlers/security.go", "UpdateSecurityBlockPage"), required: 4},
		{tool: "create_ip_list", schema: createIPListSchema, request: models.CreateIPListRequest{}, required: 4},
		{tool: "update_ip_list", schema: updateIPListSchema, request: models.UpdateIPListRequest{}, required: 4},
		{tool: "create_certificate_config", schema: createCertificateConfigSchema, request: models.CreateCertificateConfigRequest{}, required: 4},
		{tool: "update_certificate_config", schema: updateCertificateConfigSchema, request: models.UpdateCertificateConfigRequest{}, required: 4},
		{tool: "create_user", schema: createUserSchema, request: models.CreateUserRequest{}, required: 4},
		{tool: "update_user", schema: updateUserSchema, fields: anonymousRequestFields(t, "../handlers/users.go", "UpdateUser"), required: 4},
		{tool: "create_api_key", schema: createAPIKeySchema, request: models.CreateAPIKeyRequest{}, required: 5},
		{tool: "update_api_key_status", schema: updateAPIKeyStatusSchema, request: models.UpdateAPIKeyRequest{}, required: 4},
		{tool: "update_config", schema: updateConfigSchema, request: models.UpdateConfigRequest{}, required: 45},
		{tool: "preview_config", schema: previewConfigSchema, request: models.UpdateConfigRequest{}, required: 45},
	}

	usedExemptions := map[string]bool{}
	for _, tc := range cases {
		properties := decodeRuleSchema(t, tc.tool, tc.schema)
		fields := tc.fields
		if fields == nil {
			fields = jsonFieldNames(t, tc.request)
		}
		if len(fields) < tc.required {
			t.Fatalf("%s 的请求结构字段只取到 %d 个（want ≥%d）：反射形态漂移会让本门空转", tc.tool, len(fields), tc.required)
		}
		for _, field := range fields {
			if reason, exempt := requestSchemaExemptions[tc.tool+"."+field]; exempt {
				if reason == "" {
					t.Errorf("豁免 %s.%s 缺理由", tc.tool, field)
				}
				usedExemptions[tc.tool+"."+field] = true
				continue
			}
			if _, ok := properties[field]; !ok {
				t.Errorf("%s 的 input_schema 缺少请求字段 %q（后端接受却对 Agent 不可见，转发层会把未登记参数搬进 body）", tc.tool, field)
			}
		}
	}

	// 反向：豁免表里的键必须仍然真实存在，避免陈旧豁免长期掩盖新的漂移。
	for key := range requestSchemaExemptions {
		if !usedExemptions[key] {
			t.Errorf("陈旧豁免 %q：请确认该字段仍需豁免，否则删除", key)
		}
	}
}

// content_type 的 enum 必须由 models 白名单注入：手抄副本在白名单增删值后
// 不会变红，Agent 只能看到旧集合（运行期无 schema 校验，不会 400）。
func TestBlockPageSchemaContentTypeEnumMatchesModelWhitelist(t *testing.T) {
	want := models.BlockPageContentTypeWhitelist()
	for _, tc := range []struct {
		tool   string
		schema string
	}{
		{tool: "create_block_page", schema: createBlockPageSchema},
		{tool: "update_block_page", schema: updateBlockPageSchema},
	} {
		properties := decodeRuleSchema(t, tc.tool, tc.schema)
		contentType, ok := properties["content_type"].(map[string]any)
		if !ok {
			t.Fatalf("%s schema 缺 content_type 属性", tc.tool)
		}
		raw, ok := contentType["enum"].([]any)
		if !ok || len(raw) == 0 {
			t.Fatalf("%s content_type.enum=%v, want 非空白名单", tc.tool, contentType["enum"])
		}
		got := make([]string, len(raw))
		for i, value := range raw {
			item, ok := value.(string)
			if !ok {
				t.Fatalf("%s content_type.enum[%d]=%v, want string", tc.tool, i, value)
			}
			got[i] = item
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s content_type.enum=%v, want %v（须由 BlockPageContentTypeWhitelist 注入）", tc.tool, got, want)
		}
	}
}
