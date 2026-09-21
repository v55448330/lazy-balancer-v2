package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// 上游 path 改写（upstream_path）渲染切片：路径规则携带 upstream_path 时，
// 在该路径路由链的 reverse_proxy 之前插入改写 handler——前缀匹配=剥前缀+
// 前置；精确匹配=整体替换。形状经 caddy 2.11.4 容器行为实证（strip_path_prefix
// 剥前缀、rewrite uri 前置/替换均保留 query；此处字符串断言仅为回归钉）。
func upstreamPathRouteByID(t *testing.T, routes []map[string]interface{}, id string) map[string]interface{} {
	t.Helper()
	for _, route := range routes {
		if routeID, _ := route["@id"].(string); routeID == id {
			return route
		}
	}
	t.Fatalf("route %s not found among %d routes", id, len(routes))
	return nil
}

// handlerPositions 返回链内 reverse_proxy 与 rewrite handler 的下标。
func handlerPositions(t *testing.T, route map[string]interface{}) (proxyIndex int, rewriteIndexes []int) {
	t.Helper()
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("route handle has type %T", route["handle"])
	}
	proxyIndex = -1
	for index, handlerValue := range handlers {
		handler, ok := handlerValue.(map[string]interface{})
		if !ok {
			t.Fatalf("handler #%d has type %T", index, handlerValue)
		}
		switch handler["handler"] {
		case "reverse_proxy":
			proxyIndex = index
		case "rewrite":
			rewriteIndexes = append(rewriteIndexes, index)
		}
	}
	return proxyIndex, rewriteIndexes
}

func marshalChain(t *testing.T, route map[string]interface{}) string {
	t.Helper()
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("route handle has type %T", route["handle"])
	}
	raw, err := json.Marshal(handlers)
	if err != nil {
		t.Fatalf("marshal handlers: %v", err)
	}
	return string(raw)
}

func TestGenerateHTTPRouteObjects_upstreamPathPrefix_stripsAndPrependsBeforeReverseProxy(t *testing.T) {
	// Given：前缀匹配 /api + upstream_path /v1（引擎实证：/api/users?x=1 → /v1/users?x=1）
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 1, MatchType: "prefix", Path: "/api", UpstreamPath: "/v1",
		Upstreams: []UpstreamConfig{{Host: "10.0.1.20", Port: 9090, Weight: 1, Enabled: true}},
	}}

	// When
	routes, mainRoute, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}

	// Then：路径路由链含 strip_path_prefix 与前置 uri，且全部位于 reverse_proxy 之前
	pathRoute := upstreamPathRouteByID(t, routes, "rule-http_path_0")
	proxyIndex, rewriteIndexes := handlerPositions(t, pathRoute)
	if proxyIndex < 0 {
		t.Fatal("path route chain missing reverse_proxy")
	}
	if len(rewriteIndexes) != 2 {
		t.Fatalf("rewrite handler count=%d, want 2 (strip + prepend): %s", len(rewriteIndexes), marshalChain(t, pathRoute))
	}
	for _, index := range rewriteIndexes {
		if index > proxyIndex {
			t.Fatalf("rewrite handler #%d after reverse_proxy #%d: %s", index, proxyIndex, marshalChain(t, pathRoute))
		}
	}
	handlers := pathRoute["handle"].([]interface{})
	strip := handlers[rewriteIndexes[0]].(map[string]interface{})
	prepend := handlers[rewriteIndexes[1]].(map[string]interface{})
	if strip["strip_path_prefix"] != "/api" {
		t.Fatalf("strip_path_prefix=%v, want /api", strip["strip_path_prefix"])
	}
	if prepend["uri"] != "/v1{http.request.uri}" {
		t.Fatalf("prepend uri=%v, want /v1{http.request.uri}", prepend["uri"])
	}
	// 回归钉：引擎实证形状的字符串断言（容器行为证据另附实现报告）
	chainJSON := marshalChain(t, pathRoute)
	if !strings.Contains(chainJSON, `"strip_path_prefix":"/api"`) || !strings.Contains(chainJSON, `"uri":"/v1{http.request.uri}"`) {
		t.Fatalf("chain JSON missing finalized rewrite shape: %s", chainJSON)
	}

	// 主路由零改写（回归）
	mainProxyIndex, mainRewrites := handlerPositions(t, mainRoute)
	if mainProxyIndex < 0 || len(mainRewrites) != 0 {
		t.Fatalf("main route must not carry rewrite handlers, got rewrites=%v", mainRewrites)
	}
}

func TestGenerateHTTPRouteObjects_upstreamPathExact_replacesPathWithSingleRewrite(t *testing.T) {
	// Given：精确匹配 /old + upstream_path /new（引擎实证：/old?a=b → /new?a=b，query 保留）
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 1, MatchType: "exact", Path: "/old", UpstreamPath: "/new",
		Upstreams: []UpstreamConfig{{Host: "10.0.1.20", Port: 9090, Weight: 1, Enabled: true}},
	}}

	// When
	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}

	// Then：单一 rewrite 整体替换 path，无 strip handler，位于 reverse_proxy 之前
	pathRoute := upstreamPathRouteByID(t, routes, "rule-http_path_0")
	proxyIndex, rewriteIndexes := handlerPositions(t, pathRoute)
	if proxyIndex < 0 {
		t.Fatal("path route chain missing reverse_proxy")
	}
	if len(rewriteIndexes) != 1 {
		t.Fatalf("rewrite handler count=%d, want 1 (exact replace): %s", len(rewriteIndexes), marshalChain(t, pathRoute))
	}
	if rewriteIndexes[0] > proxyIndex {
		t.Fatalf("rewrite handler #%d after reverse_proxy #%d", rewriteIndexes[0], proxyIndex)
	}
	handlers := pathRoute["handle"].([]interface{})
	rewrite := handlers[rewriteIndexes[0]].(map[string]interface{})
	if rewrite["uri"] != "/new" {
		t.Fatalf("rewrite uri=%v, want /new", rewrite["uri"])
	}
	if _, hasStrip := rewrite["strip_path_prefix"]; hasStrip {
		t.Fatalf("exact rewrite must not strip: %s", marshalChain(t, pathRoute))
	}
}

func TestGenerateHTTPRouteObjects_upstreamPathRootPrefix_prependsWithoutStrip(t *testing.T) {
	// Given：前缀 / （root 归一为空，无可剥前缀）+ upstream_path /v9
	// （引擎实证：/anything?z=3 → /v9/anything?z=3）
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 1, MatchType: "prefix", Path: "/", UpstreamPath: "/v9",
		Upstreams: []UpstreamConfig{{Host: "10.0.1.20", Port: 9090, Weight: 1, Enabled: true}},
	}}

	// When
	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}

	// Then：仅前置 uri，无 strip_path_prefix
	pathRoute := upstreamPathRouteByID(t, routes, "rule-http_path_0")
	proxyIndex, rewriteIndexes := handlerPositions(t, pathRoute)
	if proxyIndex < 0 || len(rewriteIndexes) != 1 {
		t.Fatalf("proxy=%d rewrites=%v, want single prepend before proxy", proxyIndex, rewriteIndexes)
	}
	handlers := pathRoute["handle"].([]interface{})
	rewrite := handlers[rewriteIndexes[0]].(map[string]interface{})
	if rewrite["uri"] != "/v9{http.request.uri}" {
		t.Fatalf("rewrite uri=%v, want /v9{http.request.uri}", rewrite["uri"])
	}
	if _, hasStrip := rewrite["strip_path_prefix"]; hasStrip {
		t.Fatalf("root prefix must not strip: %s", marshalChain(t, pathRoute))
	}
}

func TestGenerateHTTPRouteObjects_upstreamPathEmpty_chainByteIdenticalWithLegacy(t *testing.T) {
	// Given：upstream_path 空串（默认）——链必须与现状逐字节一致（零插入回归）。
	// 路径规则不带自定义上游（回退主上游），与主路由同链形。
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 1, MatchType: "prefix", Path: "/api",
	}}

	// When
	routes, mainRoute, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}

	// Then：路径路由链与主路由链同为零 rewrite 形状，且 JSON 逐字节一致
	pathRoute := upstreamPathRouteByID(t, routes, "rule-http_path_0")
	if _, rewrites := handlerPositions(t, pathRoute); len(rewrites) != 0 {
		t.Fatalf("empty upstream_path must not insert rewrites: %s", marshalChain(t, pathRoute))
	}
	if pathJSON, mainJSON := marshalChain(t, pathRoute), marshalChain(t, mainRoute); pathJSON != mainJSON {
		t.Fatalf("empty upstream_path chain diverged from main chain:\npath: %s\nmain: %s", pathJSON, mainJSON)
	}
}
