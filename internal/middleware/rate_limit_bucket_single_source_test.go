package middleware

// 限流桶「取得或创建」必须是单源：此前
// acquireRateLimitBucket 与 reserveRateLimitBucket 各自内联了一份「容量满
// 淘汰 + 建桶 + lastUsed 刷新」——两份实现里任何一处漏掉 LRU 刷新都会让淘汰
// 选错受害者、漏掉淘汰会让 1024 容量上限失效，而两处行为等价性没有任何
// 断言能及时发现（现有用例只覆盖各自路径的成功分支）。
//
// 本守卫按 AST 钉住结构而不是行为：
//  1. 全文件只有一处 &loginRateBucket{...} 建桶字面量，且必须位于
//     getOrCreateRateLimitBucketLocked 内；
//  2. 两个入口（acquireRateLimitBucket / reserveRateLimitBucket）都必须调用
//     该 helper——任一入口退回内联实现即红。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

const rateLimitBucketHelperName = "getOrCreateRateLimitBucketLocked"

func TestRateLimitBucketCreationIsSingleSource(t *testing.T) {
	source, err := os.ReadFile("middleware.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "middleware.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}

	creationSites := map[string]int{}
	helperCallers := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.UnaryExpr:
				// &loginRateBucket{...}
				if composite, ok := n.X.(*ast.CompositeLit); ok && compositeNamedType(composite.Type, "loginRateBucket") {
					creationSites[name]++
				}
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok && ident.Name == rateLimitBucketHelperName {
					helperCallers[name] = true
				}
			}
			return true
		})
	}

	if len(creationSites) != 1 || creationSites[rateLimitBucketHelperName] != 1 {
		t.Fatalf("建桶字面量位置=%v，want 仅在 %s 一处（平行实现会让淘汰/容量/lastUsed 语义分叉）", creationSites, rateLimitBucketHelperName)
	}
	for _, entry := range []string{"acquireRateLimitBucket", "reserveRateLimitBucket"} {
		if !helperCallers[entry] {
			t.Fatalf("%s 未调用 %s（取桶逻辑必须单源）", entry, rateLimitBucketHelperName)
		}
	}
}

// compositeNamedType 判断复合字面量类型是否为给定名字（含 &T{} 与 T{} 形态）。
func compositeNamedType(expr ast.Expr, want string) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == want
	case *ast.StarExpr:
		return compositeNamedType(t.X, want)
	}
	return false
}
