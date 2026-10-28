package models

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// SyncErrorCode 的取值有两个事实源：Go 常量与 ClusterReport 上的 gin binding
// oneof 标签（struct tag 无法由常量拼出）。任一侧新增/改名而另一侧没跟上，
// 后果都不小——漏进 oneof 会让从节点上报整包 400（该节点的同步失败原因永远
// 报不上来），多出来的 oneof 成员则是永不产生的死词。本测试把两侧钉成同一
// 集合，新增错误码忘记同步标签会直接红。
func TestSyncErrorCodeMatchesBindingOneof(t *testing.T) {
	declared, err := syncErrorCodeConstants("cluster.go")
	if err != nil {
		t.Fatalf("解析 cluster.go 的 SyncErrorCode 常量: %v", err)
	}
	if len(declared) == 0 {
		t.Fatal("未从 cluster.go 解析出任何 SyncErrorCode 常量（解析口径失效，测试无效）")
	}
	oneof, err := bindingOneofValues(reflect.TypeOf(ClusterReport{}), "SyncErrorCode")
	if err != nil {
		t.Fatalf("读取 ClusterReport.SyncErrorCode 的 oneof 标签: %v", err)
	}

	for _, code := range declared {
		if _, ok := oneof[code]; !ok {
			t.Errorf("常量 %q 未出现在 binding oneof 中（从节点上报该错误码会 400）", code)
		}
	}
	for code := range oneof {
		if !contains(declared, code) {
			t.Errorf("binding oneof 成员 %q 没有对应的 SyncErrorCode 常量（死词或拼写漂移）", code)
		}
	}
}

// syncErrorCodeConstants 解析声明 SyncErrorCode 常量的字符串取值（const 组内
// 省略类型时按 Go 的隐式继承规则沿用上一行的类型）。
func syncErrorCodeConstants(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		carried := ""
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if ident, ok := valueSpec.Type.(*ast.Ident); ok {
				carried = ident.Name
			}
			if carried != "SyncErrorCode" {
				continue
			}
			for _, value := range valueSpec.Values {
				literal, ok := value.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					continue
				}
				values = append(values, text)
			}
		}
	}
	return values, nil
}

// bindingOneofValues 返回结构体字段 binding 标签里 oneof= 的取值集合。
func bindingOneofValues(structType reflect.Type, fieldName string) (map[string]struct{}, error) {
	field, ok := structType.FieldByName(fieldName)
	if !ok {
		return nil, errNoField{structType.Name(), fieldName}
	}
	values := make(map[string]struct{})
	for _, rule := range strings.Split(field.Tag.Get("binding"), ",") {
		rule = strings.TrimSpace(rule)
		member, found := strings.CutPrefix(rule, "oneof=")
		if !found {
			continue
		}
		for _, value := range strings.Fields(member) {
			values[value] = struct{}{}
		}
	}
	if len(values) == 0 {
		return nil, errNoField{structType.Name(), fieldName + " (oneof)"}
	}
	return values, nil
}

type errNoField struct {
	structName string
	fieldName  string
}

func (e errNoField) Error() string {
	return e.structName + "." + e.fieldName + " 不存在或缺少 oneof 标签"
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
