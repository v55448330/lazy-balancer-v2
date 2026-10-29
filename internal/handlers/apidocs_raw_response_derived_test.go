package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// handlerFuncDeclsForTest 解析本包生产源码的全部函数声明，供文档派生门按
// handler 函数名读取真实响应形态（不复制 handler 清单或媒体类型）。
func handlerFuncDeclsForTest(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read handlers directory: %v", err)
	}
	decls := map[string]*ast.FuncDecl{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				decls[fn.Name.Name] = fn
			}
		}
	}
	if len(decls) == 0 {
		t.Fatal("handlers 源码未解析出任何函数")
	}
	return decls
}

// handlerMediaTypes 从 handler（含一层本地 helper 调用）的 c.Data /
// c.DataFromReader 实参派生实际响应媒体类型。
func handlerMediaTypes(t *testing.T, fn *ast.FuncDecl, decls map[string]*ast.FuncDecl, seen map[string]bool) []string {
	t.Helper()
	if seen[fn.Name.Name] {
		return nil
	}
	seen[fn.Name.Name] = true
	var media []string
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			index := -1
			switch selector.Sel.Name {
			case "Data":
				index = 1
			case "DataFromReader":
				index = 2
			case "Header":
				// 流式交付（io.Copy 直写 c.Writer）用 Header("Content-Type", …) 声明
				// 媒体类型——与 c.Data/DataFromReader 同属「handler 实际发射面」，
				// 必须同样派生，否则改用流式后该端点的文档契约失去对表。
				if len(call.Args) == 2 {
					key, keyOK := call.Args[0].(*ast.BasicLit)
					value, valueOK := call.Args[1].(*ast.BasicLit)
					if keyOK && valueOK && key.Kind == token.STRING && value.Kind == token.STRING {
						if name, err := strconv.Unquote(key.Value); err == nil && strings.EqualFold(name, "Content-Type") {
							if mediaType, verr := strconv.Unquote(value.Value); verr == nil {
								media = append(media, mediaType)
							}
						}
					}
				}
				return true
			}
			if index >= 0 && len(call.Args) > index {
				if literal, ok := call.Args[index].(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if value, err := strconv.Unquote(literal.Value); err == nil {
						media = append(media, value)
					}
				}
			}
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok {
			if helper, ok := decls[ident.Name]; ok {
				media = append(media, handlerMediaTypes(t, helper, decls, seen)...)
			}
		}
		return true
	})
	return media
}

// 文档显式登记的非 JSON 媒体类型必须与 handler 实际 c.Data/DataFromReader
// 实参逐字一致；契约与生成 YAML 的一致性由 apidocs_test 的同族门覆盖。
func TestAPIDocRawResponseMediaTypesMatchHandlers(t *testing.T) {
	registrations := middlewareRouteRegistrations(t, middlewareSourceForTest(t))
	decls := handlerFuncDeclsForTest(t)
	checked := 0
	for _, route := range apiDocRoutes {
		key := route.Method + " " + route.Path
		contract, ok := apiDocContracts[key]
		if !ok || !contract.rawResponse || contract.responseContentType == "" {
			continue
		}
		registration, ok := registrations[key]
		if !ok || registration.handler == "" {
			t.Errorf("%s 未在 middleware 注册派生出 handler", key)
			continue
		}
		handler, ok := decls[registration.handler]
		if !ok {
			t.Fatalf("%s 的 handler %s 不在 handlers 源码中", key, registration.handler)
		}
		media := handlerMediaTypes(t, handler, decls, map[string]bool{})
		if len(media) == 0 {
			t.Errorf("%s（%s）未派生到 c.Data/DataFromReader 媒体类型", key, registration.handler)
			continue
		}
		matched := false
		for _, value := range media {
			if value == contract.responseContentType {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s 契约 media type=%q, handler %s 实际=%v", key, contract.responseContentType, registration.handler, media)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("非 JSON raw 路由派生覆盖为 0——扫描器失效")
	}
}
