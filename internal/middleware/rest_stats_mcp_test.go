package middleware

// MCP 内部回环转发到 REST 的子调用不得计入 REST 接入统计
// （与 api_call_stats「MCP 路由不记入」口径一致；否则与 mcp_tool_stats 双记）。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/services"
)

func TestRESTCallStats_excludesInternalMCPForward(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const key = "lb-rest-stats-key-0123456789"
	addClusterRouteTestAPIKey(t, 9901, "stats-admin", "admin", key)

	before := services.GetRESTCallOverview().TodayCalls
	if rec := requestWithAPIKey(router, http.MethodGet, "/api/v1/cluster/status", key); rec.Code != http.StatusOK {
		t.Fatalf("普通 REST 调用 status=%d body=%s", rec.Code, rec.Body.String())
	}
	afterExternal := services.GetRESTCallOverview().TodayCalls
	if afterExternal != before+1 {
		t.Fatalf("普通 REST 调用计数增量=%d，want 1", afterExternal-before)
	}

	// 内部回环（MCP 工具转发）：同一 API Key + 网关内部认证头。
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	req.Header.Set("X-API-Key", key)
	req.Header.Set(mcpserver.InternalAuthHeader, internalMCPAuthSecret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("内部回环调用 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.GetRESTCallOverview().TodayCalls; got != afterExternal {
		t.Fatalf("内部 MCP 转发计入 REST 统计（%d → %d），应保持 %d", afterExternal, got, afterExternal)
	}
}
