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
//   - *http.Client / *http.Transport 可替换客户端缝。
//
// 非 seam 的可赋值包级 var（error 哨兵、路由表/词表/常量映射、regexp、
// TTL 缓存指针、sync 原语等）由类型判据自然排除，不再需要人工豁免表——
// 豁免表条目会随定义删除而死化（曾残留两条零定义豁免）。

import (
	"go/ast"
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
