package taskengine

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
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

// ---- 扫描面 ----

// repositoryScanRoots 跨包守卫的扫描根（相对 repoRoot）：根模块的 internal/ 与
// cmd/，加上根目录下每个自带 go.mod 的嵌套模块（lbhuman/caddygeoip/lbreqmon/
// wafiplist/caddyl4sec/geoipnames/caddydeps——module path 为
// lazy-balancer-v2/<dir>，Go 的 internal 规则允许它们 import 本包）。此前只扫
// internal/ 与 cmd/：这些模块不在守卫内，加入依赖后调用 test-only 入口仍绿。
// 根模块的其余顶层目录无 Go 源（新顶层包目录须显式加入本清单）。
func repositoryScanRoots(repoRoot string) ([]string, error) {
	roots := []string{"internal", "cmd"}
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if _, statErr := os.Stat(filepath.Join(repoRoot, entry.Name(), "go.mod")); statErr != nil {
			continue
		}
		roots = append(roots, entry.Name())
	}
	sort.Strings(roots)
	return roots, nil
}

// productGoFiles 扫描根下的产品 .go 文件（跳过 _test.go、testdata 与隐藏目录）。
func productGoFiles(repoRoot, root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// ---- 语法层检测 ----

// testOnlyViolations 语法级检测（回归） 全量附录：旧守卫按裸名字/AST 缺口）：
//   - 裸名字只在本包内判定，且包级同名函数存在时不判（本地 helper 不是入口消费）；
//   - 选择器调用保持「任意接收者」宽匹配（接收者静态类型无法在纯语法层解析，
//     生产真名调用一律需改走 Result 入口）；
//   - 方法表达式 `Engine.Trigger` / `(*Engine).Trigger` /
//     `taskengine.Engine.RunAsync` 不是 CallExpr.Fun，旧守卫漏检；
//   - 点导入 taskengine 会让裸名字调用逃逸，直接判违规。
//
// 方法值形态（`fn := e.Trigger`）不是调用、接收者也不是类型表达式，纯语法层
// 无法与同名结构体字段（RunContext.Trigger/RunRecord.Trigger）区分——由
// testOnlyCandidates 收集、类型层判定（见 resolveMethodValueCandidates）。
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

// testOnlyCandidate 待类型层判定的方法值候选：语法上是一个「非调用的入口名
// 选择器」（如 `e.Trigger` 取值），接收者类型静态不可知。
type testOnlyCandidate struct {
	absPath string
	line    int
	col     int
	name    string
}

// testOnlyCandidates 收集方法值候选：Sel 为入口名、不在 CallExpr.Fun 位置、
// 接收者也不是 Engine 类型表达式（后者已由语法层直接判违规）。类型层据
// MethodVal 选择种类与接收者类型决定是否为违规。
func testOnlyCandidates(fset *token.FileSet, file *ast.File, absPath string, inPackage bool, localFuncs map[string]bool) []testOnlyCandidate {
	aliases := map[string]bool{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path != taskEngineImportPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "." {
				return nil // 点导入已由语法层直接判违规
			}
			aliases[imp.Name.Name] = true
			continue
		}
		aliases[path[strings.LastIndex(path, "/")+1:]] = true
	}
	called := map[*ast.SelectorExpr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				called[sel] = true
			}
		}
		return true
	})
	var out []testOnlyCandidate
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !testOnlyEntryPoints[sel.Sel.Name] || called[sel] || isEngineTypeExpr(sel.X, aliases, inPackage) {
			return true
		}
		pos := fset.Position(sel.Pos())
		out = append(out, testOnlyCandidate{absPath: absPath, line: pos.Line, col: pos.Column, name: sel.Sel.Name})
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

// ---- 类型层判定（方法值形态） ----

// isTestOnlyEntryMethodSelection 判定类型信息中的一次选择是否指向本包 test-only
// 入口方法：选择种类必须是方法值/方法表达式（结构体同名字段是 FieldVal——
// RunContext.Trigger / RunRecord.Trigger 不得误报），且方法接收者基类型是
// *Engine/Engine（嵌入提升同样命中：判据取自方法签名而非选择接收者）。
func isTestOnlyEntryMethodSelection(selection *types.Selection) (*types.Func, bool) {
	if selection.Kind() != types.MethodVal && selection.Kind() != types.MethodExpr {
		return nil, false
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || !testOnlyEntryPoints[fn.Name()] {
		return nil, false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return nil, false
	}
	recvType := recv.Type()
	if ptr, ok := recvType.(*types.Pointer); ok {
		recvType = ptr.Elem()
	}
	named, ok := recvType.(*types.Named)
	if !ok {
		return nil, false
	}
	obj := named.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != taskEngineImportPath || obj.Name() != "Engine" {
		return nil, false
	}
	return fn, true
}

// moduleRootOf 从目录向上找到最近的 go.mod 所在目录（该包所属模块根）。
func moduleRootOf(dir string) (string, error) {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("目录 %s 向上未找到 go.mod（无法确定所属模块）", dir)
		}
		dir = parent
	}
}

// resolveMethodValueCandidates 对含候选的包做一次类型检查，判定候选是否指向
// test-only 入口方法（方法值 `fn := e.Trigger` 形态）。语法层无法区分 Engine
// 方法与同名结构体字段，故以类型信息的选择种类为唯一判据。加载/类型检查失败
// 必须响亮失败——静默跳过会让该形态重新逃逸。
func resolveMethodValueCandidates(t *testing.T, repoRoot string, candidates []testOnlyCandidate) []string {
	t.Helper()
	if len(candidates) == 0 {
		return nil
	}
	absRepoRoot := absPathOrSelf(repoRoot)
	wanted := make(map[string]testOnlyCandidate, len(candidates))
	for _, c := range candidates {
		wanted[fmt.Sprintf("%s:%d:%d", c.absPath, c.line, c.col)] = c
	}
	// 按模块聚合候选包（go/packages 的 pattern 相对模块根）。
	modulePatterns := map[string][]string{}
	seen := map[string]bool{}
	for _, c := range candidates {
		dir := filepath.Dir(c.absPath)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		moduleRoot, err := moduleRootOf(dir)
		if err != nil {
			t.Fatalf("方法值候选定位模块失败（%s）: %v", c.absPath, err)
		}
		rel, err := filepath.Rel(moduleRoot, dir)
		if err != nil {
			t.Fatalf("候选包相对路径计算失败（%s）: %v", dir, err)
		}
		modulePatterns[moduleRoot] = append(modulePatterns[moduleRoot], "./"+filepath.ToSlash(rel))
	}
	var out []string
	for moduleRoot, patterns := range modulePatterns {
		sort.Strings(patterns)
		pkgs, err := packages.Load(&packages.Config{
			Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo,
			Dir:  moduleRoot,
		}, patterns...)
		if err != nil {
			t.Fatalf("方法值候选类型检查加载失败（模块 %s，patterns=%v）: %v", moduleRoot, patterns, err)
		}
		loaded := 0
		for _, pkg := range pkgs {
			if len(pkg.Errors) > 0 {
				t.Fatalf("方法值候选类型检查失败（%s，拒绝静默放行）: %v", pkg.ID, pkg.Errors[0])
			}
			if pkg.TypesInfo == nil {
				t.Fatalf("方法值候选类型检查信息缺失（%s，加载模式漂移）", pkg.ID)
			}
			loaded++
			for sel, selection := range pkg.TypesInfo.Selections {
				fn, ok := isTestOnlyEntryMethodSelection(selection)
				if !ok {
					continue
				}
				pos := pkg.Fset.Position(sel.Pos())
				abs, err := filepath.Abs(pos.Filename)
				if err != nil {
					t.Fatalf("类型层位置解析失败（%s）: %v", pos.Filename, err)
				}
				candidate, isCandidate := wanted[fmt.Sprintf("%s:%d:%d", abs, pos.Line, pos.Column)]
				if !isCandidate {
					continue // 调用/方法表达式已由语法层报出（不重复计数）
				}
				display, relErr := filepath.Rel(absRepoRoot, candidate.absPath)
				if relErr != nil {
					display = candidate.absPath
				}
				out = append(out, fmt.Sprintf("%s:%d 产品文件引用 test-only 入口 .%s（类型层：方法值形态）",
					filepath.ToSlash(display), candidate.line, fn.Name()))
			}
		}
		if loaded == 0 {
			t.Fatalf("方法值候选类型检查零包命中（模块 %s，patterns=%v）——扫描面失效须修正守卫", moduleRoot, patterns)
		}
	}
	sort.Strings(out)
	return out
}

// ---- 守卫 ----

// testOnlyScan 一次扫描的产物。
type testOnlyScan struct {
	roots      []string
	violations []string
	candidates []testOnlyCandidate
	scanned    map[string]int
	declared   map[string]int
}

// scanTestOnlyReferences 对仓库根下所有模块的产品文件做语法层扫描（本包产品
// 文件用更严的 inPackage 判据，跨包文件不重复扫本包目录）。
func scanTestOnlyReferences(repoRoot string) (testOnlyScan, error) {
	var scan testOnlyScan
	scan.scanned = map[string]int{}
	scan.declared = map[string]int{}
	roots, err := repositoryScanRoots(repoRoot)
	if err != nil {
		return scan, err
	}
	scan.roots = roots
	fset := token.NewFileSet()
	ownDir := filepath.Join(repoRoot, "internal", "taskengine")
	ownFiles, err := productGoFiles(repoRoot, filepath.Join("internal", "taskengine"))
	if err != nil {
		return scan, err
	}
	// 先收本包包级函数名：裸名字调用可能是本地同名 helper（非入口消费）。
	localFuncs := map[string]bool{}
	for _, path := range ownFiles {
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return scan, fmt.Errorf("parse %s: %w", path, parseErr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if testOnlyEntryPoints[fn.Name.Name] {
				scan.declared[fn.Name.Name]++
			}
			if fn.Recv == nil {
				localFuncs[fn.Name.Name] = true
			}
		}
	}
	for _, path := range ownFiles {
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return scan, fmt.Errorf("parse %s: %w", path, parseErr)
		}
		scan.scanned["internal/taskengine"]++
		scan.violations = append(scan.violations, testOnlyViolations(fset, file, filepath.ToSlash(mustRel(repoRoot, path)), true, localFuncs)...)
		scan.candidates = append(scan.candidates, testOnlyCandidates(fset, file, absPathOrSelf(path), true, localFuncs)...)
	}
	for _, root := range roots {
		files, walkErr := productGoFiles(repoRoot, root)
		if walkErr != nil {
			return scan, walkErr
		}
		for _, path := range files {
			if strings.HasPrefix(path, ownDir+string(filepath.Separator)) {
				continue // 本包已用 inPackage 判据扫过
			}
			file, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return scan, fmt.Errorf("parse %s: %w", path, parseErr)
			}
			display := filepath.ToSlash(mustRel(repoRoot, path))
			scan.scanned[root]++
			scan.violations = append(scan.violations, testOnlyViolations(fset, file, display, false, nil)...)
			scan.candidates = append(scan.candidates, testOnlyCandidates(fset, file, absPathOrSelf(path), false, nil)...)
		}
	}
	return scan, nil
}

func mustRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return rel
}

// absPathOrSelf 类型层的位置匹配以绝对路径为键（go/packages 返回的
// pkg.Fset 文件名是绝对路径）——候选收集阶段统一归一。
func absPathOrSelf(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints 产品文件
// （本包 + 仓库内所有模块）不得调用/取值 test-only 入口。扫描面=根模块
// internal/ 与 cmd/ + 根目录下所有自带 go.mod 的嵌套模块（见
// repositoryScanRoots）；语法层拦调用/方法表达式/裸名字/点导入，类型层拦
// 方法值（`fn := e.Trigger`）。白名单声明计数只统计本包产品文件——他包同名
// FuncDecl 不得顶替本包声明（否则本包入口被删时守卫仍绿）。符号若被改名/
// 删除，声明计数断言会让守卫响亮失效。
func TestEnginePackageHasNoProductionReferencesToTestOnlyEntryPoints(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	scan, err := scanTestOnlyReferences(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scan.violations {
		t.Error(v)
	}
	for _, v := range resolveMethodValueCandidates(t, repoRoot, scan.candidates) {
		t.Error(v)
	}
	// 扫描面必须实际覆盖到每个模块：空目录/路径失效不得静默放行。
	for _, root := range scan.roots {
		if scan.scanned[root] == 0 {
			t.Errorf("扫描根 %s 零产品文件命中——扫描路径失效，须修正守卫而非空转放行", root)
		}
	}
	for name := range testOnlyEntryPoints {
		if scan.declared[name] == 0 {
			t.Errorf("test-only 入口 %s 在产品文件中无声明——白名单已过期，请更新守卫清单", name)
		}
	}
}

// ---- 自检 ----

// TestTestOnlyViolations_astShapes 守卫自检：钉四点——①本地同名包级函数不
// 误报裸名字；②方法表达式（Engine/指针/包限定）必须命中；③普通值字段访问
// （rc.Trigger）语法层不得误报；④非调用的入口名选择器（方法值 `_ = e.TeeTaskLog`
// 与字段 `_ = rc.Trigger` 在语法层不可分）全部进入类型层候选，字段由类型层
// 筛掉（见 TestTestOnlyEntryMethodSelection_taskengineEngine）。
func TestTestOnlyViolations_astShapes(t *testing.T) {
	inPkg := `package taskengine
func Trigger() {}
func use(e *Engine) {
	Trigger()
	e.Trigger()
	_ = Engine.RunAsync
	_ = (*Engine).Stats24h
	_ = e.TeeTaskLog
}`
	crossPkg := `package x
import "lazy-balancer-v2/internal/taskengine"
func use(e *taskengine.Engine, rc taskengine.RunContext) {
	_ = rc.Trigger
	_ = (*taskengine.Engine).TeeTaskLog
	e.RunAsync()
	_ = e.Stats24h
}`
	dotPkg := `package x
import . "lazy-balancer-v2/internal/taskengine"
var _ = Trigger
`
	cases := []struct {
		name       string
		src        string
		inPackage  bool
		want       int
		candidates int
	}{
		{"本包：本地函数不误报、成员与方法表达式命中", inPkg, true, 3, 1},
		// 候选=语法层无法判定的非调用选择器：`rc.Trigger`（字段）与
		// `e.Stats24h`（方法值）都进候选，由类型层筛掉字段。
		{"跨包：字段访问不误报、方法表达式与调用命中", crossPkg, false, 2, 2},
		{"点导入直接判违规", dotPkg, false, 1, 0},
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
			candidates := testOnlyCandidates(fset, file, "fixture.go", tc.inPackage, local)
			if len(candidates) != tc.candidates {
				t.Fatalf("方法值候选数=%d, want %d: %+v", len(candidates), tc.candidates, candidates)
			}
		})
	}
}

// TestTestOnlyEntryMethodSelection_taskengineEngine 类型层判据自检：Engine 方法
// 值/方法表达式命中，同名字段（RunContext.Trigger 形态）不命中——这是
// 「方法值形态可拦、字段访问不误报」的机器钉。
func TestTestOnlyEntryMethodSelection_taskengineEngine(t *testing.T) {
	src := `package taskengine

type Engine struct{}

func (e *Engine) Trigger(id, trigger, operator string) error { return nil }

type RunContext struct{ Trigger string }

func use(e *Engine, rc RunContext) {
	fn := e.Trigger // 方法值：必须命中
	_ = fn
	_ = (*Engine).Trigger // 方法表达式：必须命中
	_ = rc.Trigger        // 字段访问：不得命中
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
	conf := types.Config{Error: func(error) {}}
	if _, err := conf.Check(taskEngineImportPath, fset, []*ast.File{file}, info); err != nil {
		t.Fatalf("合成夹具类型检查失败: %v", err)
	}
	hits := 0
	for _, selection := range info.Selections {
		if _, ok := isTestOnlyEntryMethodSelection(selection); ok {
			hits++
		}
	}
	if hits != 2 {
		t.Fatalf("Engine 方法值/方法表达式命中数=%d, want 2（字段访问不得计入）", hits)
	}
}

// TestRepositoryScanRoots_coversNestedModules 扫描面自检：根级嵌套模块（自带
// go.mod 的同前缀模块）必须进扫描面——临时树里放一个违规夹具即红，删除夹具
// 即绿。Testdata/隐藏目录/无 go.mod 的普通目录不进扫描面。
func TestRepositoryScanRoots_coversNestedModules(t *testing.T) {
	repoRoot := t.TempDir()
	write := func(rel, content string) string {
		t.Helper()
		path := filepath.Join(repoRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("go.mod", "module lazy-balancer-v2\n")
	write("internal/taskengine/engine.go", "package taskengine\n\ntype Engine struct{}\n\nfunc (e *Engine) Trigger(id, trigger, operator string) error { return nil }\n")
	write("internal/plain/plain.go", "package plain\n")
	write("cmd/server/main.go", "package main\n\nfunc main() {}\n")
	write("modnest/go.mod", "module lazy-balancer-v2/modnest\n")
	fixture := write("modnest/consumer.go", `package modnest

import "lazy-balancer-v2/internal/taskengine"

func consume(e *taskengine.Engine) { _ = e.Trigger("a", "b", "c") }
`)
	write("modnest/testdata/bad.go", "package testdata\n\nfunc x() {}\n")
	write("nomod/loose.go", "package loose\n")
	write(".hidden/go.mod", "module hidden\n")
	write(".hidden/h.go", "package hidden\n")

	roots, err := repositoryScanRoots(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(roots, ",")
	for _, want := range []string{"internal", "cmd", "modnest"} {
		if !strings.Contains(","+joined+",", ","+want+",") {
			t.Fatalf("扫描根 %v 缺 %s（根级嵌套模块须进扫描面）", roots, want)
		}
	}
	for _, skip := range []string{"nomod", ".hidden"} {
		if strings.Contains(","+joined+",", ","+skip+",") {
			t.Fatalf("扫描根 %v 不应包含 %s", roots, skip)
		}
	}

	// 红：嵌套模块内的违规夹具必须被拦。
	scan, err := scanTestOnlyReferences(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !anyContains(scan.violations, "modnest/consumer.go:5") {
		t.Fatalf("嵌套模块夹具未进违规集（扫描面缺口）: %v", scan.violations)
	}
	if anyContains(scan.violations, "testdata") || anyContains(scan.violations, ".hidden") || anyContains(scan.violations, "nomod") {
		t.Fatalf("testdata/隐藏目录/无 go.mod 目录不得进扫描面: %v", scan.violations)
	}
	// 绿：删除夹具后同一扫描零违规。
	if err := os.Remove(fixture); err != nil {
		t.Fatal(err)
	}
	scan, err = scanTestOnlyReferences(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.violations) != 0 {
		t.Fatalf("删除夹具后仍报违规: %v", scan.violations)
	}
}

func anyContains(items []string, substr string) bool {
	for _, item := range items {
		if strings.Contains(item, substr) {
			return true
		}
	}
	return false
}
