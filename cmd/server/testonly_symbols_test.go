package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestMainPackageHasNoProductionTestOnlyEntryPoints 产品文件（非 *_test.go）
// 不得承载只被测试消费的入口或顶层常量/变量。固定预算、路径等测试支撑值
// 一旦留在产品符号表，既构成死配置，也容易被后续生产代码误当真实默认值。
// 与 internal/services / internal/config 的同型守卫对齐。
func TestMainPackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	productionNames := make(map[string]token.Pos)
	productionUses := make(map[string]int)
	testUses := make(map[string]int)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		isTest := strings.HasSuffix(name, "_test.go")
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if !isTest {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Name.Name != "Shutdown" {
					continue
				}
				receiver := ""
				if len(fn.Recv.List) == 1 {
					switch expr := fn.Recv.List[0].Type.(type) {
					case *ast.StarExpr:
						if ident, ok := expr.X.(*ast.Ident); ok {
							receiver = ident.Name
						}
					case *ast.Ident:
						receiver = expr.Name
					}
				}
				if receiver == "runtimeLifecycle" {
					t.Errorf("%s:%d 产品文件声明 test-only 入口 runtimeLifecycle.Shutdown——请移到 *_test.go（shutdownForTest）",
						name, fset.Position(fn.Pos()).Line)
				}
			}
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || isTest || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, ident := range value.Names {
					productionNames[ident.Name] = ident.Pos()
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if isTest {
				testUses[ident.Name]++
			} else {
				productionUses[ident.Name]++
			}
			return true
		})
	}
	for name, pos := range productionNames {
		// 声明自身的标识符计一次；生产侧零额外引用且测试侧有引用即 test-only。
		if productionUses[name] == 1 && testUses[name] > 0 {
			t.Errorf("%s:%d 顶层常量/变量 %s 仅被测试消费——请移到 *_test.go",
				fset.Position(pos).Filename, fset.Position(pos).Line, name)
		}
	}
}
