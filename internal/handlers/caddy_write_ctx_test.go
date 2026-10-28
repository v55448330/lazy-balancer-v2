package handlers

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Caddy 写事务的 ctx 契约是「BEGIN 与全部语句同一口径」：事务用
// context.WithoutCancel 开始，语句却仍绑请求 ctx 时，客户端断连会精确落在写库
// 段把已开始的渲染/校验/提交链中止——解耦只覆盖了 BEGIN，注释承诺（已开始的
// 渲染、CLI 校验与 /load 必须在同一数据库视图完成）在运行期不成立。
func TestBeginCaddyWriteTx_statementsSurviveRequestCancellation(t *testing.T) {
	newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPut, "/config", nil).WithContext(ctx)

	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		t.Fatalf("begin caddy write tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// When 客户端在写库段断连
	cancel()

	// Then 语句必须仍可执行（与 BEGIN 同口径），事务可正常提交
	var one int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("写事务语句被请求取消拖死: %v", err)
	}
	if _, err := tx.ExecContext(caddyWriteCtx(c), "UPDATE global_config SET updated_at=updated_at WHERE id=1"); err != nil {
		t.Fatalf("写事务 UPDATE 被请求取消拖死: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// 意义性控制（teeth）：同一取消状态下若语句退回请求 ctx，必须真的失败——
	// 证明上面的断言不是「取消没生效」造成的假绿。
	tx2, err := beginCaddyWriteTx(c)
	if err != nil {
		t.Fatalf("begin second tx: %v", err)
	}
	defer func() { _ = tx2.Rollback() }()
	if err := tx2.QueryRowContext(c.Request.Context(), "SELECT 1").Scan(&one); err == nil {
		t.Fatal("请求 ctx 已取消，语句却成功——夹具失效（取消未传播）")
	}
}

// 源码门禁：凡消费 beginCaddyWriteTx 的文件，其事务语句/写后置动作都不得
// 绑定请求 ctx（含 `ctx := c.Request.Context()` 别名与换行/中间变量）。
// AST 扫描自动发现消费文件，避免固定文件清单让新增写点逃逸。
func TestCaddyWriteStatements_doNotBindRequestContext(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read handlers dir: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		usesWriteTx, violations, err := scanCaddyWriteContextViolations(name, source)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if !usesWriteTx {
			continue
		}
		scanned++
		for _, violation := range violations {
			t.Errorf("%s: %s", name, violation)
		}
	}
	if scanned == 0 {
		t.Fatal("未发现任何 beginCaddyWriteTx 消费文件——门禁扫描面为空")
	}
	// 正向控制：helper 与 BEGIN 使用点必须在树（否则门禁形同虚设）。
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	for _, want := range []string{"func caddyWriteCtx(c *gin.Context) context.Context", "db.DB.BeginTx(caddyWriteCtx(c), nil)"} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("handlers.go 缺少 ctx 单源实现: %q", want)
		}
	}
}

// scanCaddyWriteContextViolations 返回文件是否消费 beginCaddyWriteTx，以及
// 绑定了请求 ctx（直接/别名/派生调用）的事务语句与写后置动作。
func scanCaddyWriteContextViolations(filename string, source []byte) (bool, []string, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, source, 0)
	if err != nil {
		return false, nil, err
	}
	usesWriteTx := false
	violations := []string{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		txVars := map[string]bool{}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for index, rhs := range assignment.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != "beginCaddyWriteTx" {
					continue
				}
				usesWriteTx = true
				if index < len(assignment.Lhs) {
					if txIdent, ok := assignment.Lhs[index].(*ast.Ident); ok {
						txVars[txIdent.Name] = true
					}
				}
			}
			return true
		})
		if len(txVars) == 0 {
			continue
		}
		requestCtxVars := map[string]bool{}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for index, rhs := range assignment.Rhs {
				if !exprUsesRequestContext(rhs, requestCtxVars) {
					continue
				}
				if index < len(assignment.Lhs) {
					if ident, ok := assignment.Lhs[index].(*ast.Ident); ok {
						requestCtxVars[ident.Name] = true
					}
				}
				for _, lhs := range assignment.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						requestCtxVars[ident.Name] = true
					}
				}
			}
			return true
		})
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !caddyWriteGuardCall(call.Fun, txVars) {
				return true
			}
			for _, arg := range call.Args {
				if exprUsesRequestContext(arg, requestCtxVars) {
					position := fileSet.Position(call.Pos())
					violations = append(violations, fmt.Sprintf("%s 第 %d 行事务语句绑定请求 ctx（必须用 caddyWriteCtx(c)）", function.Name.Name, position.Line))
					break
				}
			}
			return true
		})
	}
	return usesWriteTx, violations, nil
}

func caddyWriteGuardCall(fun ast.Expr, txVars map[string]bool) bool {
	switch typed := fun.(type) {
	case *ast.SelectorExpr:
		if !strings.HasSuffix(typed.Sel.Name, "Context") {
			return false
		}
		receiver, ok := typed.X.(*ast.Ident)
		return ok && txVars[receiver.Name]
	case *ast.Ident:
		switch typed.Name {
		case "BumpClusterVersion", "rejectMixedPolicies", "setRulePoliciesInTx", "countStage2Policies":
			return true
		}
	}
	return false
}

func exprUsesRequestContext(expr ast.Expr, requestCtxVars map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.Ident:
			if requestCtxVars[typed.Name] {
				found = true
			}
		case *ast.SelectorExpr:
			if typed.Sel.Name == "Context" {
				if inner, ok := typed.X.(*ast.SelectorExpr); ok {
					if base, ok := inner.X.(*ast.Ident); ok && base.Name == "c" && inner.Sel.Name == "Request" {
						found = true
					}
				}
			}
		}
		return !found
	})
	return found
}

func TestCaddyWriteContextScanner_detectsAliasesAndDerivedContexts(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want int
	}{
		{name: "直接请求 ctx", src: `package handlers
func f(c *gin.Context,tx *sql.Tx){ tx, _ = beginCaddyWriteTx(c); tx.ExecContext(c.Request.Context(), "UPDATE x") }`, want: 1},
		{name: "别名请求 ctx", src: `package handlers
func f(c *gin.Context,tx *sql.Tx){ tx, _ = beginCaddyWriteTx(c); ctx := c.Request.Context(); tx.QueryContext(ctx, "SELECT 1") }`, want: 1},
		{name: "派生的请求 ctx", src: `package handlers
func f(c *gin.Context,tx *sql.Tx){ tx, _ = beginCaddyWriteTx(c); ctx, cancel := context.WithCancel(c.Request.Context()); defer cancel(); tx.QueryRowContext(ctx, "SELECT 1") }`, want: 1},
		{name: "写后置动作请求 ctx", src: `package handlers
func f(c *gin.Context,tx *sql.Tx){ tx, _ = beginCaddyWriteTx(c); BumpClusterVersion(c.Request.Context(), tx) }`, want: 1},
		{name: "caddyWriteCtx 正形状", src: `package handlers
func f(c *gin.Context,tx *sql.Tx){ tx, _ = beginCaddyWriteTx(c); ctx := caddyWriteCtx(c); tx.ExecContext(ctx, "UPDATE x") }`, want: 0},
		{name: "无关键 helper 不误报", src: `package handlers
func f(c *gin.Context,tx *sql.Tx){ tx, _ = beginCaddyWriteTx(c); helper(c.Request.Context()); _ = tx }`, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uses, violations, err := scanCaddyWriteContextViolations(tt.name+".go", []byte(tt.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if uses != strings.Contains(tt.src, "beginCaddyWriteTx") {
				t.Fatalf("usesWriteTx=%v, source=%q", uses, tt.src)
			}
			if len(violations) != tt.want {
				t.Fatalf("violations=%v, want %d", violations, tt.want)
			}
		})
	}
}
