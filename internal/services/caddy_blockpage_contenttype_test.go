package services

// 拦截页渲染（2026-09-25 用户裁定）：各错误路由的
// 响应头跟随页面配置（默认 text/html; charset=utf-8），不再恒 text/html。

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

func blockPageTestCtx() *securityPolicyContext {
	return &securityPolicyContext{
		policyByRule: map[string][]*models.SecurityPolicy{
			"lb_ct": {{ID: 7, BlockPageID: 42, BlockStatusCode: 403}},
		},
		blockPageByID:     map[int]string{42: "{\"error\":\"blocked\"}"},
		blockPageTypeByID: map[int]string{42: "application/json; charset=utf-8"},
	}
}

func errorRouteContentType(t *testing.T, route map[string]interface{}) string {
	t.Helper()
	handle := route["handle"].([]interface{})[0].(map[string]interface{})
	headers := handle["headers"].(map[string]interface{})
	values := headers["Content-Type"].([]string)
	return values[0]
}

func TestBuildBlockPageErrorRoute_usesPageContentType(t *testing.T) {
	routes := buildBlockPageErrorRoute("lb_ct", []string{"ct.example.test"}, blockPageTestCtx())
	route := routes[len(routes)-1]
	if route == nil {
		t.Fatal("兜底路由未生成")
	}
	if got := errorRouteContentType(t, route); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type=%q, want application/json; charset=utf-8", got)
	}
}

func TestBuildBlockPageAttributionRoute_usesPageContentType(t *testing.T) {
	routes := buildBlockPageAttributionRoute(483, "{\"error\":\"blocked\"}", "", 403, "text/plain; charset=utf-8", "auto")
	route := routes[len(routes)-1]
	if got := errorRouteContentType(t, route); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type=%q, want text/plain; charset=utf-8", got)
	}
}

func TestBuildBlockPageErrorRoute_emptyTypeFallsBackHTML(t *testing.T) {
	ctx := blockPageTestCtx()
	ctx.blockPageTypeByID = map[int]string{}
	routes := buildBlockPageErrorRoute("lb_ct", []string{"ct.example.test"}, ctx)
	route := routes[len(routes)-1]
	if got := errorRouteContentType(t, route); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type=%q, want 空类型回退 text/html; charset=utf-8", got)
	}
}
