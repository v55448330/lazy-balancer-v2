package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// sensitiveExportGetRoutesForDocs 从 middleware 的 sensitiveExportGetRoutes
// 单源派生文档侧守卫名单（去掉 /api/v1 前缀）。includeAdminSecretReads 时
// 追加 admin 组中调用 canReadSensitiveSecrets 的 GET handler——这些读取与
// 导出 GET 一样对非管理员/只读 Key 恒 403，不能靠文档手抄补入。
func sensitiveExportGetRoutesForDocs(t *testing.T, includeAdminSecretReads bool) map[string]bool {
	t.Helper()
	source := middlewareSourceForTest(t)
	file, err := parser.ParseFile(token.NewFileSet(), "middleware.go", source, 0)
	if err != nil {
		t.Fatalf("parse middleware.go: %v", err)
	}
	routes := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "sensitiveExportGetRoutes" || len(spec.Values) != 1 {
			return true
		}
		literal, ok := spec.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range literal.Elts {
			kv, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING {
				continue
			}
			path, err := strconv.Unquote(key.Value)
			if err != nil {
				continue
			}
			routes[strings.TrimPrefix(path, "/api/v1")] = true
		}
		return false
	})
	if len(routes) == 0 {
		t.Fatal("sensitiveExportGetRoutes 派生为空——middleware 声明形态漂移")
	}
	if !includeAdminSecretReads {
		return routes
	}

	decls := handlerFuncDeclsForTest(t)
	added := 0
	for key, registration := range middlewareRouteRegistrations(t, source) {
		if !strings.HasPrefix(key, "GET ") || registration.group != "admin" {
			continue
		}
		handler, ok := decls[registration.handler]
		if !ok || !handlerCallsFunction(handler, "canReadSensitiveSecrets") {
			continue
		}
		_, path, found := strings.Cut(key, " ")
		if !found {
			continue
		}
		if !routes[path] {
			added++
		}
		routes[path] = true
	}
	if added == 0 {
		t.Fatal("admin 组敏感读取派生为 0——canReadSensitiveSecrets 扫描器失效")
	}
	return routes
}

func handlerCallsFunction(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
