package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 安全测试事件端点（R45 验证辅助）：注册断言 + 权限门（无凭证 401、非管理员
// 403、管理员放行）——仿 metrics_routes_test 模式。审计分类由
// TestSetupRouter_writeRoutesHaveExplicitAuditRelation 与 auditpolicy 登记共同
// 承担；MCP 豁免由 mcp_routes_parity_test 反断言钉住。
func TestSecurityTestEvents_routes_registerAndGateByRole(t *testing.T) {
	// Given the full router with the two test-event routes registered
	router := newMiddlewareTestRouter(t)
	routes := make(map[string]bool)
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	if !routes["POST /api/v1/security/test-events"] || !routes["DELETE /api/v1/security/test-events"] {
		t.Fatal("security test-events routes are not registered in the admin group")
	}

	// Then unauthenticated requests are rejected with 401
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/security/test-events", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated status=%d body=%s, want 401", method, rec.Code, rec.Body.String())
		}
	}

	// And non-admin API keys are rejected with 403 (adminOnly)
	userKey := "lb_sk_test-events-viewer"
	addClusterRouteTestAPIKey(t, 108, "test-events-viewer", "user", userKey)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rec := requestWithAPIKey(router, method, "/api/v1/security/test-events", userKey)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s non-admin status=%d body=%s, want 403", method, rec.Code, rec.Body.String())
		}
	}

	// And the admin key passes the permission gate (200 from the handler)
	adminKey := "lb_sk_test-events-admin"
	addClusterRouteTestAPIKey(t, 109, "test-events-admin", "admin", adminKey)
	rec := requestWithAPIKey(router, http.MethodDelete, "/api/v1/security/test-events", adminKey)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("admin delete blocked at permission gate: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
