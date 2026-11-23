package taskengine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testOnlyEntryPoints 只为测试同步驱动保留的导出入口（生产消费方分别是
// RunAsyncResult/RunSync/Stats24hHourlySeries/TeeTaskLogTime*，见各自 doc
// 注释的「测试专供」标记）。声明保留在 engine.go——跨包测试经导出方法调用；
// 本守卫钉的是「生产零调用」：产品文件新增调用即把已收口的入口拉回主链。
var testOnlyEntryPoints = map[string]bool{
	"Trigger":    true,
	"RunAsync":   true,
	"Stats24h":   true,
	"TeeTaskLog": true,
}

// taskEngineImportPath 守卫识别的包路径（别名解析用）。
const taskEngineImportPath = "lazy-balancer-v2/internal/taskengine"

// testOnlyViolations 语法级检测（回归） 全量附录：旧守卫按裸名字/AST 缺口）：
//   - 裸名字只在本包内判定，且包级同名函数存在时不判（本地 helper 不是入口消费）；
//   - 选择器调用保持「任意接收者」宽匹配（接收者静态类型无法在纯语法层解析，
//     生产真名调用一律需改走 Result 入口）；
//   - 方法表达式 `Engine.Trigger` / `(*Engine).Trigger` /
//     `taskengine.Engine.RunAsync` 不是 CallExpr.Fun，旧守卫漏检；
//   - 点导入 taskengine 会让裸名字调用逃逸，直接判违规。
func testOnlyViolations(fset *token.FileSet, file *ast.File, display string, inPackage bool, localFuncs map[string]bool) []string {
	aliases := map[string]bool{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path != taskEngineImportPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "." {
				return []string{display + ":1 点导入 " + taskEngineImportPath + "（裸名字调用绕过 test-only 守卫）"}
			}
			aliases[imp.Name.Name] = true
			continue
		}
		aliases[path[strings.LastIndex(path, "/")+1:]] = true
	}
	var out []string
	report := func(n ast.Node, how string) {
		out = append(out, display+":"+strconv.Itoa(fset.Position(n.Pos()).Line)+" 产品文件"+how)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			switch fun := node.Fun.(type) {
			case *ast.Ident:
				if inPackage && testOnlyEntryPoints[fun.Name] && !localFuncs[fun.Name] {
					report(node, "调用 test-only 入口 "+fun.Name)
				}
			case *ast.SelectorExpr:
				if testOnlyEntryPoints[fun.Sel.Name] {
					report(node, "调用 test-only 入口 ."+fun.Sel.Name)
				}
			}
		case *ast.SelectorExpr:
			// 方法表达式（非调用）：接收者形如 Engine / (*Engine) /
			// taskengine.Engine——普通 `rc.Trigger` 字段访问不命中。
			if !testOnlyEntryPoints[node.Sel.Name] {
				return true
			}
			if isEngineTypeExpr(node.X, aliases, inPackage) {
				report(node, "引用 test-only 入口方法表达式 ."+node.Sel.Name)
			}
		}
		return true
	})
	return out
}

// isEngineTypeExpr 判断选择器的接收者是否 Engine 类型表达式（方法表达式
// 形态），而非普通值（变量/字段访问）。
func isEngineTypeExpr(x ast.Expr, aliases map[string]bool, inPackage bool) bool {
	switch v := x.(type) {
	case *ast.ParenExpr:
		return isEngineTypeExpr(v.X, aliases, inPackage)
	case *ast.StarExpr:
		return isEngineTypeExpr(v.X, aliases, inPackage)
	case *ast.Ident:
		return inPackage && v.Name == "Engine"
	case *ast.SelectorExpr:
		if id, ok := v.X.(*ast.Ident); ok && aliases[id.Name] && v.Sel.Name == "Engine" {
			return true
		}
	}
	return false
}

// TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints 产品文件
// （本包 + 跨包）不得调用 test-only 入口。扫描面=本包产品文件 + 仓库
// internal/ 与 cmd/ 全部产品文件（跨包接线同样不得消费 test-only 入口；
// 此前只扫本包，跨包违规不红）。白名单声明计数只统计本包产品文件——
// 他包同名 FuncDecl 不得顶替本包声明（否则本包入口被删时守卫仍绿，
// 白名单过期检查空转）。符号若被改名/删除，声明计数断言会让守卫响亮失效。
func TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints(t *testing.T) {
	fset := token.NewFileSet()
	declared := map[string]int{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// 先收集本包包级函数名：裸名字调用可能是本地同名 helper（非入口消费）。
	localFuncs := map[string]bool{}
	var productFiles []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		productFiles = append(productFiles, name)
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if testOnlyEntryPoints[fn.Name.Name] {
				declared[fn.Name.Name]++
			}
			// 裸名字只可能解析到包级函数；方法名不算本地 helper。
			if fn.Recv == nil {
				localFuncs[fn.Name.Name] = true
			}
		}
	}
	for _, name := range productFiles {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, v := range testOnlyViolations(fset, file, name, true, localFuncs) {
			t.Error(v)
		}
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
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			for _, v := range testOnlyViolations(fset, file, filepath.ToSlash(rel), false, nil) {
				t.Error(v)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("守卫扫描 %s 失败: %v", root, err)
		}
	}
	if scanned == 0 {
		t.Fatal("跨包守卫零命中——扫描路径失效，须修正守卫而非空转放行")
	}
	for name := range testOnlyEntryPoints {
		if declared[name] == 0 {
			t.Errorf("test-only 入口 %s 在产品文件中无声明——白名单已过期，请更新守卫清单", name)
		}
	}
}

// TestTestOnlyViolations_astShapes 守卫自检：钉三点——①本地同名包级函数不
// 误报裸名字；②方法表达式（Engine/指针/包限定）必须命中；③普通值字段访问
// （rc.Trigger）不得误报。
func TestTestOnlyViolations_astShapes(t *testing.T) {
	inPkg := `package taskengine
func Trigger() {}
func use(e *Engine) {
	Trigger()
	e.Trigger()
	_ = Engine.RunAsync
	_ = (*Engine).Stats24h
}`
	crossPkg := `package x
import "lazy-balancer-v2/internal/taskengine"
func use(e *taskengine.Engine, rc taskengine.RunContext) {
	_ = rc.Trigger
	_ = (*taskengine.Engine).TeeTaskLog
	e.RunAsync()
}`
	dotPkg := `package x
import . "lazy-balancer-v2/internal/taskengine"
var _ = Trigger
`
	cases := []struct {
		name      string
		src       string
		inPackage bool
		want      int
	}{
		{"本包：本地函数不误报、成员与方法表达式命中", inPkg, true, 3},
		{"跨包：字段访问不误报、方法表达式与调用命中", crossPkg, false, 2},
		{"点导入直接判违规", dotPkg, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "fixture.go", tc.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			local := map[string]bool{}
			if tc.inPackage {
				local["Trigger"] = true
			}
			got := testOnlyViolations(fset, file, "fixture.go", tc.inPackage, local)
			if len(got) != tc.want {
				t.Fatalf("违规数=%d, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}
