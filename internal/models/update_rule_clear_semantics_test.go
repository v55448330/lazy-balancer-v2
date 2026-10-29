package models

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// ruleUpdateNonClearableFields 登记 UpdateRuleRequest 中「值类型、零值=保留
// 原值」的字段：它们没有「显式清空」形态，API/MCP 客户端提交空串/0 只会被
// 写侧当作「未提交」合并存量（internal/handlers/rules.go 的 UpdateRule 合并
// 块）。指针化字段才是三态（省略=保留、显式零值=清空），集合字段用
// nil/空数组区分——两者不需要登记。
//
// 新增值类型字段会让「本族可清空」与「本族不可清空」两套语义混在同一个
// 请求结构体里且无文档可依，属隐性契约漂移：必须先决定语义（指针化，或
// 登记在此并在 UpdateRuleRequest 的类型注释里写明），否则本测试红。
var ruleUpdateNonClearableFields = map[string]string{
	"Name":                "空串=保留存量名（规则名必填，无清空语义）",
	"Protocol":            "空串=保留存量协议（协议切换只能靠显式新值）",
	"Domain":              "空串=保留存量域名（HTTP 规则必填、TCP 规则零消费）",
	"ListenPort":          "0=保留存量端口（端口 NOT NULL 且必须 >0，0 是未提交哨兵）",
	"Strategy":            "空串=保留存量策略（保存终态必须是合法策略）",
	"DnsFamily":           "空串=保留存量族（创建默认 ipv4）",
	"HealthCheckInterval": "0=保留存量（值域 >0 由写侧校验）",
	"HealthCheckTimeout":  "0=保留存量（值域 >0 由写侧校验）",
	"TLSSource":           "空串=保留存量来源（证书材料清理由 tls_source 分支驱动）",
	"ACMEConfigID":        "0=保留存量（非 acme_dns 来源随后统一清零）",
	"TLSCert":             "空串=保留存量证书（手动证书留空=沿用，清除靠切换 tls_source）",
	"TLSKey":              "空串=保留存量私钥（同上）",
	"CompressTypes":       "空串=保留存量（关闭压缩由 enable_compress 表达，创建默认 gzip）",
	"ExpectedUpdatedAt":   "不落库：仅事务内乐观并发前置条件，空串=不校验",
}

// 清空语义必须可查：值类型字段族逐条登记在类型注释里，登记表与注释同源
// （本测试同时校验两处一致），否则「哪些字段能清空」只能靠读 handler 合并块
// 逆推。
func TestUpdateRuleRequest_clearSemanticsRegisteredAndDocumented(t *testing.T) {
	typ := reflect.TypeOf(UpdateRuleRequest{})
	documented := updateRuleRequestTypeDoc(t)

	seen := make(map[string]bool, len(ruleUpdateNonClearableFields))
	for i := range typ.NumField() {
		field := typ.Field(i)
		// 指针与集合字段天然三态（省略=保留、显式零值/空集合=清空）。
		switch field.Type.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Map:
			continue
		}
		reason, ok := ruleUpdateNonClearableFields[field.Name]
		if !ok {
			t.Errorf("UpdateRuleRequest.%s 是值类型（零值=写侧按「未提交」合并存量），既未指针化也未登记为「不可清空」——新增字段必须显式决定清空语义并写进类型注释", field.Name)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("UpdateRuleRequest.%s 的登记原因为空", field.Name)
		}
		if !strings.Contains(documented, field.Name) {
			t.Errorf("UpdateRuleRequest.%s 未写入类型注释：不可清空字段族必须在注释里逐条列出（当前注释缺失该字段名）", field.Name)
		}
		seen[field.Name] = true
	}
	for name := range ruleUpdateNonClearableFields {
		if !seen[name] {
			t.Errorf("登记表含不存在或已指针化的字段 %s：清空语义登记必须与结构体一致", name)
		}
	}
}

// updateRuleRequestTypeDoc 返回 UpdateRuleRequest 类型声明上方的文档注释。
func updateRuleRequestTypeDoc(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "models.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("解析 models.go: %v", err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "UpdateRuleRequest" {
				continue
			}
			if gen.Doc == nil {
				return ""
			}
			return gen.Doc.Text()
		}
	}
	t.Fatalf("models.go 中未找到 UpdateRuleRequest 类型声明")
	return ""
}
