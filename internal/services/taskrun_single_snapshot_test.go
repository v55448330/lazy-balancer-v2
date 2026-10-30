package services

// 单次快照守卫：updateRunRole / taskRunStartedAt 的「角色判定/
// started_at 读取」必须与后续使用共用同一个 db.DB 快照——函数体内对 db.DB 的
// 读取各只允许一次（读入局部句柄后全程复用）。两次读 db.DB 之间句柄被置 nil
// （关库/停引擎竞态）时，RoleOf/QueryRow 会带着 nil 句柄进入并 panic；
// 「判定读一次、使用再读一次」的直读写法正是该竞态的形态。本守卫按 AST 钉住
// 结构：任一守卫函数体内出现第二个 db.DB 选择器（回退成多次直读）即红；
// 函数被删除/重命名同样红（守卫对象漂移不得静默空转）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// countTaskRunDBDBReads 统计 taskrun.go 中指定函数体内 `db.DB` 选择器的出现
// 次数。注释中的提及不构成 AST 节点，天然不计数；字符串字面量 "db.DB" 是
// BasicLit 而非 SelectorExpr，同样不计数——口径即「真实的句柄直读次数」。
func countTaskRunDBDBReads(t *testing.T, funcName string) int {
	t.Helper()
	source, err := os.ReadFile("taskrun.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "taskrun.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == funcName {
			target = fn
			break
		}
	}
	if target == nil || target.Body == nil {
		t.Fatalf("taskrun.go 缺少函数 %s——守卫对象漂移，请随重构更新守卫目标", funcName)
	}
	count := 0
	ast.Inspect(target.Body, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "db" && selector.Sel.Name == "DB" {
				count++
			}
		}
		return true
	})
	return count
}

// TestTaskRunSingleSnapshot_roleAndStartedAtReadDBOnce 锁定单次快照不变量：
// 两个函数体内的 db.DB 各恰出现一次。
func TestTaskRunSingleSnapshot_roleAndStartedAtReadDBOnce(t *testing.T) {
	for _, funcName := range []string{"updateRunRole", "taskRunStartedAt"} {
		if got := countTaskRunDBDBReads(t, funcName); got != 1 {
			t.Errorf("%s 体内 db.DB 出现 %d 次（必须恰 1 次：单次快照，判定与使用共用同一句柄，多次直读会在关库竞态下带 nil 句柄 panic）", funcName, got)
		}
	}
}
