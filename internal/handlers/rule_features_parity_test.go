package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// createRuleFeatures 与 updateRuleFeatures 是同一 ruleFeatureInput 的两条投影
// （创建用请求值，编辑用存量基线 + 指针覆盖）。新增规则字段时若只改一侧，
// Create 落 schema 默认、Update 沿用存量，形成「新建与编辑终态不同」的静默
// 分叉且单侧测试不会变红。本门禁分别识别基线复合字面量键与指针覆盖赋值，
// 既对账两侧完整投影，也对账 UpdateRuleRequest 中所有 ruleFeatureInput 指针字段。
func TestRuleFeatureProjections_assignEveryField(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rule_features.go", nil, 0)
	if err != nil {
		t.Fatalf("parse rule_features.go: %v", err)
	}
	want := map[string]bool{}
	structType := reflect.TypeOf(ruleFeatureInput{})
	for i := range structType.NumField() {
		want[structType.Field(i).Name] = true
	}
	if len(want) == 0 {
		t.Fatal("ruleFeatureInput 无字段（门禁失效）")
	}

	// Update 请求里的非 ruleFeatureInput 字段（名称、证书材料、并发版本等）
	// 显式排除；凡指针字段在 ruleFeatureInput 中有同名投影，就必须有覆盖块。
	wantOverrides := map[string]bool{}
	nonPointerRequestFields := map[string]bool{}
	requestType := reflect.TypeOf(models.UpdateRuleRequest{})
	for i := range requestType.NumField() {
		field := requestType.Field(i)
		if !want[field.Name] {
			continue
		}
		if field.Type.Kind() == reflect.Pointer {
			wantOverrides[field.Name] = true
		} else {
			// handler 预合并的非指针字段允许覆盖，但不能替任何指针字段抵账。
			nonPointerRequestFields[field.Name] = true
		}
	}
	if len(wantOverrides) == 0 {
		t.Fatal("UpdateRuleRequest 未识别到 ruleFeatureInput 指针字段（门禁失效）")
	}

	for _, fnName := range []string{"createRuleFeatures", "updateRuleFeatures"} {
		literalFields, overrideFields := featureProjectionFields(t, file, fnName)
		assigned := map[string]bool{}
		for field := range literalFields {
			assigned[field] = true
		}
		for field := range overrideFields {
			assigned[field] = true
		}
		for field := range want {
			if !assigned[field] {
				t.Errorf("%s 未投影字段 %s（新增字段必须两侧同步）", fnName, field)
			}
		}
		for field := range assigned {
			if !want[field] {
				t.Errorf("%s 投影了 ruleFeatureInput 不存在的字段 %s", fnName, field)
			}
		}
		if fnName != "updateRuleFeatures" {
			continue
		}
		for field := range wantOverrides {
			if !overrideFields[field] {
				t.Errorf("updateRuleFeatures 缺少请求指针字段 %s 的覆盖（存量基线不能代替覆盖）", field)
			}
		}
		for field := range overrideFields {
			if !wantOverrides[field] && !nonPointerRequestFields[field] {
				t.Errorf("updateRuleFeatures 覆盖了非 UpdateRuleRequest 投影字段 %s", field)
			}
		}
	}
}

// featureProjectionFields 分别返回 ruleFeatureInput 复合字面量键（create 返回、
// update 存量基线）与 `input.Field = …` 指针覆盖字段，避免基线键掩盖覆盖缺失。
func featureProjectionFields(t *testing.T, file *ast.File, fnName string) (literalFields, overrideFields map[string]bool) {
	t.Helper()
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		declFn, ok := decl.(*ast.FuncDecl)
		if ok && declFn.Name.Name == fnName {
			fn = declFn
			break
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatalf("未找到函数 %s 的函数体", fnName)
	}
	literalFields = map[string]bool{}
	overrideFields = map[string]bool{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CompositeLit:
			ident, ok := typed.Type.(*ast.Ident)
			if !ok || ident.Name != "ruleFeatureInput" {
				return true
			}
			for _, element := range typed.Elts {
				if kv, ok := element.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						literalFields[key.Name] = true
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range typed.Lhs {
				selector, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if base, ok := selector.X.(*ast.Ident); ok && base.Name == "input" {
					overrideFields[selector.Sel.Name] = true
				}
			}
		}
		return true
	})
	if len(literalFields)+len(overrideFields) == 0 {
		t.Fatalf("%s 未识别到任何字段投影（门禁失效）", fnName)
	}
	return literalFields, overrideFields
}
