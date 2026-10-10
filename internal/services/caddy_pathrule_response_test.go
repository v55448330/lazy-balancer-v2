package services

import (
	"testing"
)

// 自定义路由「直接返回/301 跳转」渲染（2026-10-10 用户裁定，全原生
// http.handlers.static_response）：response_mode='' 转发现状零漂移；
// static=status_code+body+Content-Type；redirect=301+Location。

// generateHTTPRouteObjects 需要完整规则形态；此处聚焦路径路由渲染分支。
// 通过最小规则（无安全策略、无 TLS）构造，pathRules 自定义路由开启。

func buildPathRuleRoutesForTest(t *testing.T, rule SingleRuleConfig) []map[string]interface{} {
	t.Helper()
	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generateHTTPRouteObjects: %v", err)
	}
	return routes
}

func findPathRoute(routes []map[string]interface{}, suffix string) map[string]interface{} {
	for _, route := range routes {
		if id, ok := route["@id"].(string); ok && id == "lb_prresp_"+suffix {
			return route
		}
	}
	return nil
}

func staticResponseOf(t *testing.T, route map[string]interface{}) map[string]interface{} {
	t.Helper()
	if route == nil {
		t.Fatal("path route not found")
	}
	handle, ok := route["handle"].([]interface{})
	if !ok || len(handle) == 0 {
		t.Fatalf("route handle missing: %#v", route)
	}
	first, ok := handle[0].(map[string]interface{})
	if !ok {
		t.Fatalf("handler shape: %#v", handle[0])
	}
	return first
}

// Given: 转发模式路径规则（response_mode 空，现状回归钉）
// When: 生成路由
// Then: handle 链尾仍是 reverse_proxy，无 static_response
func TestPathRuleRoute_forwardModeUnchanged(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_prresp", Protocol: "http", ListenPort: 8080, Domain: "prresp.example.test",
		CustomRoutesEnabled: true,
		Upstreams:           []UpstreamConfig{{Host: "10.0.0.1", Port: 9000, Weight: 1, Enabled: true}},
		PathRules: []PathRuleConfig{
			{SortOrder: 0, MatchType: "prefix", Path: "/api/", ResponseMode: ""},
		},
	}
	routes := buildPathRuleRoutesForTest(t, rule)
	route := findPathRoute(routes, "path_0")
	if route == nil {
		t.Fatalf("path_0 route missing: %#v", routes)
	}
	handle := route["handle"].([]interface{})
	last := handle[len(handle)-1].(map[string]interface{})
	if last["handler"] != "reverse_proxy" {
		t.Fatalf("forward mode must keep reverse_proxy chain tail, got %#v", last["handler"])
	}
	for _, h := range handle {
		if h.(map[string]interface{})["handler"] == "static_response" {
			t.Fatal("forward mode must not emit static_response")
		}
	}
}

// Given: static 模式路径规则（自定义状态码+文本+JSON 格式）
// When: 生成路由
// Then: 路由仅 static_response 一个 handler，不经 reverse_proxy/改写/安全链
func TestPathRuleRoute_staticModeEmitsStaticResponse(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_prresp", Protocol: "http", ListenPort: 8080, Domain: "prresp.example.test",
		CustomRoutesEnabled: true,
		Upstreams:           []UpstreamConfig{{Host: "10.0.0.1", Port: 9000, Weight: 1, Enabled: true}},
		PathRules: []PathRuleConfig{
			{SortOrder: 0, MatchType: "exact", Path: "/maint", ResponseMode: "static",
				ResponseStatus: 418, ResponseBody: `{"error":"teapot"}`, ResponseContentType: "application/json"},
		},
	}
	routes := buildPathRuleRoutesForTest(t, rule)
	route := findPathRoute(routes, "path_0")
	h := staticResponseOf(t, route)
	if h["handler"] != "static_response" {
		t.Fatalf("handler=%#v, want static_response", h["handler"])
	}
	if h["status_code"] != 418 {
		t.Fatalf("status_code=%#v, want 418", h["status_code"])
	}
	if h["body"] != `{"error":"teapot"}` {
		t.Fatalf("body=%#v", h["body"])
	}
	headers, ok := h["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers missing: %#v", h)
	}
	ct, ok := headers["Content-Type"].([]string)
	if !ok || len(ct) != 1 || ct[0] != "application/json" {
		t.Fatalf("Content-Type=%#v, want [application/json]", headers["Content-Type"])
	}
	handle := route["handle"].([]interface{})
	if len(handle) != 1 {
		t.Fatalf("static route must contain exactly one handler, got %d", len(handle))
	}
}

// Given: redirect 模式路径规则
// When: 生成路由
// Then: static_response 301 + Location 头指向目标
func TestPathRuleRoute_redirectModeEmits301Location(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_prresp", Protocol: "http", ListenPort: 8080, Domain: "prresp.example.test",
		CustomRoutesEnabled: true,
		Upstreams:           []UpstreamConfig{{Host: "10.0.0.1", Port: 9000, Weight: 1, Enabled: true}},
		PathRules: []PathRuleConfig{
			{SortOrder: 0, MatchType: "prefix", Path: "/old/", ResponseMode: "redirect", RedirectTo: "https://new.example.com/landing"},
		},
	}
	routes := buildPathRuleRoutesForTest(t, rule)
	route := findPathRoute(routes, "path_0")
	h := staticResponseOf(t, route)
	if h["handler"] != "static_response" {
		t.Fatalf("handler=%#v, want static_response", h["handler"])
	}
	if h["status_code"] != 301 {
		t.Fatalf("status_code=%#v, want 301", h["status_code"])
	}
	headers, ok := h["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers missing: %#v", h)
	}
	loc, ok := headers["Location"].([]string)
	if !ok || len(loc) != 1 || loc[0] != "https://new.example.com/landing" {
		t.Fatalf("Location=%#v", headers["Location"])
	}
	if _, hasBody := h["body"]; hasBody && h["body"] != "" {
		t.Fatalf("redirect must not carry body, got %#v", h["body"])
	}
}

// Given: static 模式缺省状态码/格式（0 值与同义空串）
// When: 生成路由
// Then: 渲染兜底 200 + text/plain
func TestPathRuleRoute_staticModeDefaults(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_prresp", Protocol: "http", ListenPort: 8080, Domain: "prresp.example.test",
		CustomRoutesEnabled: true,
		Upstreams:           []UpstreamConfig{{Host: "10.0.0.1", Port: 9000, Weight: 1, Enabled: true}},
		PathRules: []PathRuleConfig{
			{SortOrder: 0, MatchType: "exact", Path: "/ping", ResponseMode: "static", ResponseBody: "pong"},
		},
	}
	routes := buildPathRuleRoutesForTest(t, rule)
	h := staticResponseOf(t, findPathRoute(routes, "path_0"))
	if h["status_code"] != 200 {
		t.Fatalf("status_code=%#v, want 200（缺省兜底）", h["status_code"])
	}
	ct := h["headers"].(map[string]interface{})["Content-Type"].([]string)
	if len(ct) != 1 || ct[0] != "text/plain" {
		t.Fatalf("Content-Type=%#v, want [text/plain]（缺省兜底）", ct)
	}
}
