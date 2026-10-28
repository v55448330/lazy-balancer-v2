package handlers

// 从节点服务控制审计是全员可读面（GET /audit-logs 在 business 组）：Caddy
// 应用失败的错误原文来自指向 admin 端点的 *url.Error（请求地址 + 拨号地址），
// 直接写入 detail 等于把内部控制面地址与端口披露给任意登录用户（含只读
// API Key）。detail 落盘前必须经唯一剥离点；返回给主节点管理员的响应保持
// 原文不变（排障契约）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRecordClusterServiceControlAudit_redactsCaddyAdminEndpoint(t *testing.T) {
	setupClusterServiceControlDB(t)
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/service-control", nil)

	recordClusterServiceControlAuditBy(ctx, "start_caddy",
		`失败：Caddy 已启动；但 Caddy 配置应用失败：Post "http://10.20.30.40:2019/load": dial tcp 10.20.30.40:2019: connect: connection refused`,
		"master-ops")

	details := auditDetailsServiceControlRows(t)
	if len(details) != 1 {
		t.Fatalf("审计行=%d, want 1", len(details))
	}
	detail := details[0]
	if strings.Contains(detail, "10.20.30.40") || strings.Contains(detail, ":2019") {
		t.Fatalf("detail=%q 泄露 Caddy admin 端点原文（全员可读面）", detail)
	}
	if !strings.Contains(detail, "<Caddy admin 端点>") {
		t.Fatalf("detail=%q 必须保留占位短语便于排障", detail)
	}
	// 原始失败原因与既有字段清洗契约不回归。
	if !strings.Contains(detail, "connection refused") || !strings.Contains(detail, "Caddy 配置应用失败") {
		t.Fatalf("detail=%q 丢失原始失败原因", detail)
	}
	if !strings.Contains(detail, "操作：start_caddy") || !strings.Contains(detail, "来源：主节点") {
		t.Fatalf("detail=%q 既有 action/operator 归属不得回归", detail)
	}
}
