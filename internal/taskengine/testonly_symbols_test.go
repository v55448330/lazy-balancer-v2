package taskengine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints 非 *_test.go
// 产品文件不得调用 test-only 入口：Trigger/RunAsync/Stats24h 只为测试同步
// 驱动保留（生产消费方分别是 RunAsyncResult/RunSync/Stats24hHourlySeries，
// 见各自 doc 注释的「测试专供」标记）。声明保留在 engine.go——跨包测试经
// 导出方法调用；本守卫钉的是「生产零调用」：产品文件新增调用即把已收口的
// 入口拉回主链，且无调用点可核对。白名单符号若被改名/删除，声明计数断言
// 会让守卫响亮失效，防止清单空转。
func TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints(t *testing.T) {
	testOnly := map[string]bool{
		"Trigger":  true,
		"RunAsync": true,
		"Stats24h": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	declared := map[string]int{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if testOnly[node.Name.Name] {
					declared[node.Name.Name]++
				}
			case *ast.CallExpr:
				switch fun := node.Fun.(type) {
				case *ast.Ident:
					if testOnly[fun.Name] {
						t.Errorf("%s:%d 产品文件调用 test-only 入口 %s", name, fset.Position(node.Pos()).Line, fun.Name)
					}
				case *ast.SelectorExpr:
					if testOnly[fun.Sel.Name] {
						t.Errorf("%s:%d 产品文件调用 test-only 入口 .%s", name, fset.Position(node.Pos()).Line, fun.Sel.Name)
					}
				}
			}
			return true
		})
	}
	for name := range testOnly {
		if declared[name] == 0 {
			t.Errorf("test-only 入口 %s 在产品文件中无声明——白名单已过期，请更新守卫清单", name)
		}
	}
}
