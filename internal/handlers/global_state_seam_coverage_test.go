package handlers

// seam 完备登记门（类型派生）：「凡测试可直接赋值的函数缝均入册」的声称
// 必须机器成立——用 go/packages 对本包生产源码做完整类型检查，从
// types.Info 取每个包级 var 的**实际类型**（而非 AST 形态猜测），与
// captureHandlerGlobalSeams 登记表对账。漏登一个即对写侧隔离静态门不可见
// （历史形态一：手工清单漂移；历史形态二：AST 判据只看显式类型/函数字面量，
// `var x = pkg.Func` 函数引用初始化整体逃逸，约 20 个在用缝不可见）。
//
// 判据（类型级，零形态盲区）：
//   - 底层类型为 *types.Signature 的函数缝（含 sync.OnceValue 包装等一切
//     可调用初始化形态）；
//   - *http.Client / *http.Transport 可替换客户端缝；
//   - 标量旋钮缝：string/bool/数值（整型/浮点/time.Duration）——登记表
//     自身语义已收数值旋钮（systemMetricsCommandTimeout 等），类型门必须
//     同口径，否则测试注入旋钮对写侧隔离静态门不可见。标量判据收窄为
//     「有测试写点的包级 var」：生产配置常量（路径/列投影/预算上限等）
//     同为标量但测试从不赋值，不构成隔离对象；一旦新增测试写点，门立即
//     要求补登（写点扫描与写侧隔离静态门同口径：赋值 LHS）。
//
// 非 seam 的可赋值包级 var（error 哨兵、路由表/词表/常量映射、regexp、
// TTL 缓存指针、sync 原语等）由类型判据自然排除；无测试写点的标量由写点
// 判据排除——均不需要人工豁免表（豁免表条目会随定义删除而死化，曾残留
// 两条零定义豁免）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// isSeamVarType 报告包级 var 的实际类型是否构成「测试可直接赋值的缝」。
func isSeamVarType(typ types.Type) bool {
	switch u := typ.Underlying().(type) {
	case *types.Signature:
		return true
	case *types.Basic:
		// 标量旋钮缝（string/bool/数值；time.Duration 等命名数值类型经
		// Underlying 归一到 Basic）——与登记表「函数指针 + 数值旋钮」语义同口径。
		return u.Info()&(types.IsString|types.IsBoolean|types.IsNumeric) != 0
	case *types.Pointer:
		if named, ok := u.Elem().(*types.Named); ok {
			obj := named.Obj()
			if obj.Pkg() != nil && obj.Pkg().Path() == "net/http" &&
				(obj.Name() == "Client" || obj.Name() == "Transport") {
				return true
			}
		}
	}
	return false
}

// isSeamVarType 的标量判据自证：string/bool/数值/time.Duration 旋钮与函数/
// 客户端缝同为「测试可直接赋值的缝」；复合结构（map/slice/struct/接口/chan/
// 非客户端指针）不是旋钮，不得入册（生产配置表/词表由此自然排除）。
func TestIsSeamVarType_scalarKnobs(t *testing.T) {
	scalar := func(k types.BasicKind) types.Type { return types.Typ[k] }
	duration := types.NewNamed(types.NewTypeName(0, types.NewPackage("time", "time"), "Duration", nil), types.Typ[types.Int64], nil)
	for _, typ := range []types.Type{
		scalar(types.String), scalar(types.Bool), scalar(types.Int), scalar(types.Int64),
		scalar(types.Uint64), scalar(types.Float64), scalar(types.Float32), duration,
	} {
		if !isSeamVarType(typ) {
			t.Errorf("isSeamVarType(%s)=false, want true（标量旋钮缝）", typ)
		}
	}
	for _, typ := range []types.Type{
		types.NewMap(types.Typ[types.String], types.Typ[types.Bool]),
		types.NewSlice(types.Typ[types.String]),
		types.NewChan(types.SendRecv, types.Typ[types.Int]),
		types.NewPointer(types.Typ[types.Int]),
	} {
		if isSeamVarType(typ) {
			t.Errorf("isSeamVarType(%s)=true, want false（非标量旋钮）", typ)
		}
	}
}

// scalarSeamTestWriters 扫描本包全部 *_test.go，收集「被测试赋值的包级名」
// （赋值 LHS 标识符，含 := 之外的 = 与复合赋值；与写侧隔离静态门
// TestHandlerGlobalSeamWritersUseIsolatedGlobal 的写点口径一致）。标量
// 旋钮的登记判据用它收窄：生产配置 var 无测试写点即不入册。
func scalarSeamTestWriters(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	written := make(map[string]bool)
	fset := token.NewFileSet()
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.Tok == token.DEFINE {
				return true
			}
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					written[ident.Name] = true
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何测试文件——写点扫描面为空（目录/后缀漂移）")
	}
	return written
}

func TestHandlerGlobalSeamRegistryCoversAllAssignableVars(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   cwd,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	registered := make(map[string]bool)
	for name := range captureHandlerGlobalSeams() {
		registered[name] = true
	}
	testWriters := scalarSeamTestWriters(t)
	var missing []string
	scanned := 0
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			// 类型检查失败会让判据静默失真——必须 fail-loud。
			for _, e := range pkg.Errors {
				t.Errorf("type check %s: %v", pkg.ID, e)
			}
			t.FailNow()
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.VAR {
					continue
				}
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, ident := range vs.Names {
						if ident.Name == "_" {
							continue
						}
						obj := pkg.TypesInfo.Defs[ident]
						if obj == nil {
							continue
						}
						scanned++
						if registered[ident.Name] || !isSeamVarType(obj.Type()) {
							continue
						}
						if _, isBasic := obj.Type().Underlying().(*types.Basic); isBasic && !testWriters[ident.Name] {
							// 标量但无测试写点=生产配置 var，非隔离对象。
							continue
						}
						pos := pkg.Fset.Position(ident.Pos())
						missing = append(missing, pos.Filename+":"+ident.Name)
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何包级 var——门禁扫描面为空（加载模式/目录漂移）")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("以下可赋值 seam 未入 captureHandlerGlobalSeams 登记（写侧隔离静态门对其不可见）——补登记:\n  %s",
			strings.Join(missing, "\n  "))
	}
}
