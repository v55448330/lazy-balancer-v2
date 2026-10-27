package handlers

import (
	"context"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// 源码门禁：caddy 写路径（beginCaddyWriteTx 的消费文件）内不得再出现
// `tx.*Context(c.Request.Context()` / `BumpClusterVersion(c.Request.Context()`
// ——新增语句退回请求 ctx 会让上面的行为钉测与注释契约同时失效。
func TestCaddyWriteStatements_doNotBindRequestContext(t *testing.T) {
	files := []string{"caddy.go", "rules.go", "security.go", "securityiplists.go"}
	patterns := []string{
		"tx.ExecContext(c.Request.Context()",
		"tx.QueryContext(c.Request.Context()",
		"tx.QueryRowContext(c.Request.Context()",
		"BumpClusterVersion(c.Request.Context()",
	}
	scanned := 0
	for _, name := range files {
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// 只为证明文件被真实读到：解析必须成功（避免路径/编码问题假绿）。
		if _, err := parser.ParseFile(token.NewFileSet(), name, source, 0); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, pattern := range patterns {
			if strings.Contains(string(source), pattern) {
				t.Errorf("%s 仍存在 %s——Caddy 写事务语句必须用 caddyWriteCtx(c)（与 BEGIN 同口径）", name, pattern)
			}
		}
	}
	if scanned != len(files) {
		t.Fatalf("扫描文件数=%d, want %d", scanned, len(files))
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
