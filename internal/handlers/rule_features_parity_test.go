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
	// 赋值来源对账：键名对账只证明「字段被写到」，不证明「写对了来源」——
	// 同类型字段交叉接线（ProxyReadTimeout 取 req.ProxyWriteTimeout）此前全绿。
	for _, fnName := range []string{"createRuleFeatures", "updateRuleFeatures"} {
		for _, problem := range literalRHSFieldCrossWires(t, file, fnName, "ruleFeatureInput", want) {
			t.Errorf("%s 字段来源交叉接线: %s（键与 RHS 引用的同族字段不一致）", fnName, problem)
		}
	}
	for _, problem := range overrideRHSFieldCrossWires(t, file, "updateRuleFeatures", "input", want) {
		t.Errorf("updateRuleFeatures 指针覆盖来源交叉接线: %s（键与 RHS 引用的同族字段不一致）", problem)
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

// crossWiredField 在 RHS 表达式里寻找「与键不同名的同族字段」选择子。
// 只看 selector 的字段名（ruleField 同族集合）——标识符（如 enabledUpstreams）、
// 函数调用（normalizePathRules）与异族选择子（models.X / req 之外的接收者）不参与，
// 因此不会对合法形态误报。
func crossWiredField(expr ast.Expr, owner string, known map[string]bool) string {
	cross := ""
	ast.Inspect(expr, func(node ast.Node) bool {
		if cross != "" {
			return false
		}
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := selector.Sel.Name
		if known[name] && name != owner {
			cross = name
			return false
		}
		return true
	})
	return cross
}

// literalRHSFieldCrossWires 校验 typeName 复合字面量 `Key: RHS` 的赋值来源。
func literalRHSFieldCrossWires(t *testing.T, file *ast.File, fnName, typeName string, known map[string]bool) []string {
	t.Helper()
	fn := findFuncDecl(file, fnName)
	if fn == nil || fn.Body == nil {
		t.Fatalf("未找到函数 %s 的函数体", fnName)
	}
	var problems []string
	literals := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typeIdent, ok := literal.Type.(*ast.Ident)
		if !ok || typeIdent.Name != typeName {
			return true
		}
		literals++
		for _, element := range literal.Elts {
			kv, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			if cross := crossWiredField(kv.Value, key.Name, known); cross != "" {
				problems = append(problems, key.Name+" <- "+cross)
			}
		}
		return true
	})
	if literals == 0 {
		t.Fatalf("%s 未识别到 %s 复合字面量（来源对账门失效）", fnName, typeName)
	}
	return problems
}

// overrideRHSFieldCrossWires 校验 `<receiver>.Key = RHS` 指针覆盖的赋值来源。
func overrideRHSFieldCrossWires(t *testing.T, file *ast.File, fnName, receiver string, known map[string]bool) []string {
	t.Helper()
	fn := findFuncDecl(file, fnName)
	if fn == nil || fn.Body == nil {
		t.Fatalf("未找到函数 %s 的函数体", fnName)
	}
	var problems []string
	assignments := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, lhs := range assign.Lhs {
			selector, ok := lhs.(*ast.SelectorExpr)
			if !ok || index >= len(assign.Rhs) {
				continue
			}
			base, ok := selector.X.(*ast.Ident)
			if !ok || base.Name != receiver {
				continue
			}
			assignments++
			if cross := crossWiredField(assign.Rhs[index], selector.Sel.Name, known); cross != "" {
				problems = append(problems, receiver+"."+selector.Sel.Name+" <- "+cross)
			}
		}
		return true
	})
	if assignments == 0 {
		t.Fatalf("%s 未识别到 %s.<Field> 指针覆盖（来源对账门失效）", fnName, receiver)
	}
	return problems
}
