package handlers

// seam 完备登记门（AST 派生）：「凡测试可直接赋值的函数缝均入册」的声称
// 必须机器成立——从生产源码 AST 提取全部可赋值包级 var（函数指针/客户端
// 缝），与 captureHandlerGlobalSeams 登记表对账。漏登一个即对写侧隔离
// 静态门不可见（历史形态：手工清单漂移，约 18 个 seam 逃逸）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestHandlerGlobalSeamRegistryCoversAllAssignableVars(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	registered := make(map[string]bool)
	for name := range captureHandlerGlobalSeams() {
		registered[name] = true
	}
	// 豁免：非 seam 的可赋值包级 var（路由表/词表/常量映射等——测试改写
	// 它们属夹具形态，由各自专项守卫管辖，不入写侧隔离门）。
	exempt := map[string]string{
		"caddyLogPaths":       "日志路径表夹具（caddy_logs_tail_test 专项守卫）",
		"caddyLogTypesOrder":  "日志类型序派生表",
		"handlerSuiteGlobals": "suite 级终态检查表（非用例级 seam）",
	}
	fset := token.NewFileSet()
	var missing []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
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
				for i, ident := range vs.Names {
					if ident.Name == "_" || registered[ident.Name] {
						continue
					}
					if _, ok := exempt[ident.Name]; ok {
						continue
					}
					// 可赋值 seam 判据：函数类型（含客户端 *http.Client 等
					// 指针接口缝）或显式初始化为函数字面量/可替换客户端。
					isFunc := false
					if vs.Type != nil {
						switch vs.Type.(type) {
						case *ast.FuncType:
							isFunc = true
						case *ast.StarExpr:
							isFunc = true // *http.Client/*sql.DB 等客户端缝
						case *ast.InterfaceType:
							isFunc = true
						}
					}
					if !isFunc && i < len(vs.Values) {
						switch vs.Values[i].(type) {
						case *ast.FuncLit:
							isFunc = true
						}
					}
					if isFunc {
						missing = append(missing, name+":"+ident.Name)
					}
				}
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("以下可赋值 seam 未入 captureHandlerGlobalSeams 登记（写侧隔离静态门对其不可见）——补登记或列入豁免（附理由）:\n  %s",
			strings.Join(missing, "\n  "))
	}
}
