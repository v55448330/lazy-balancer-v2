package taskengine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints 产品文件
// （本包 + 跨包）不得调用 test-only 入口：Trigger/RunAsync/Stats24h/TeeTaskLog
// 只为测试同步驱动保留（生产消费方分别是 RunAsyncResult/RunSync/
// Stats24hHourlySeries/TeeTaskLogTime*，见各自 doc 注释的「测试专供」标记）。
// 声明保留在 engine.go——跨包测试经导出方法调用；本守卫钉的是「生产零调用」：
// 产品文件新增调用即把已收口的入口拉回主链。扫描面=本包产品文件 + 仓库
// internal/ 与 cmd/ 全部产品文件（跨包接线同样不得消费 test-only 入口；
// 此前只扫本包，跨包违规不红）。白名单符号若被改名/删除，声明计数断言
// 会让守卫响亮失效，防止清单空转。
func TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints(t *testing.T) {
	testOnly := map[string]bool{
		"Trigger":    true,
		"RunAsync":   true,
		"Stats24h":   true,
		"TeeTaskLog": true,
	}
	fset := token.NewFileSet()
	declared := map[string]int{}
	scanFile := func(path, display string) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
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
						t.Errorf("%s:%d 产品文件调用 test-only 入口 %s", display, fset.Position(node.Pos()).Line, fun.Name)
					}
				case *ast.SelectorExpr:
					if testOnly[fun.Sel.Name] {
						t.Errorf("%s:%d 产品文件调用 test-only 入口 .%s", display, fset.Position(node.Pos()).Line, fun.Sel.Name)
					}
				}
			}
			return true
		})
	}
	// 本包产品文件（声明计数来源）。
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanFile(name, name)
	}
	// 跨包产品文件：internal/ 与 cmd/ 全量（测试 cwd=包目录，仓库根=../..）。
	scanned := 0
	for _, root := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			scanned++
			rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
			scanFile(path, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatalf("守卫扫描 %s 失败: %v", root, err)
		}
	}
	if scanned == 0 {
		t.Fatal("跨包守卫零命中——扫描路径失效，须修正守卫而非空转放行")
	}
	for name := range testOnly {
		if declared[name] == 0 {
			t.Errorf("test-only 入口 %s 在产品文件中无声明——白名单已过期，请更新守卫清单", name)
		}
	}
}
