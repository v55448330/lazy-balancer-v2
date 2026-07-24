package services

import (
	"reflect"
	"testing"
)

func TestGenerateSingleRuleCaddyConfig_HTTPAllowACL_appendsForbiddenFallback(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.IPACLMode = "allow"
	rule.IPACLList = []string{"10.0.0.0/8", "2001:db8::/32"}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	if len(routes) != 2 {
		t.Fatalf("expected main and fallback routes, got %d", len(routes))
	}
	mainMatcher := routeMatcher(t, routes[0])
	assertEqual(t, mainMatcher["host"], []string{"example.com", "www.example.com"})
	assertIPRanges(t, mainMatcher["client_ip"], rule.IPACLList)

	fallbackMatcher := routeMatcher(t, routes[1])
	assertEqual(t, fallbackMatcher["host"], []string{"example.com", "www.example.com"})
	if _, exists := fallbackMatcher["client_ip"]; exists {
		t.Fatal("allow fallback unexpectedly includes client_ip matcher")
	}
	response := firstHandler(t, routes[1])
	if response["handler"] != "static_response" || response["status_code"] != 403 || response["body"] != "Forbidden" {
		t.Fatalf("unexpected allow fallback handler: %#v", response)
	}
}

func TestGenerateSingleRuleCaddyConfig_HTTPDenyACL_prependsForbiddenRoute(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.IPACLMode = "deny"
	rule.IPACLList = []string{"192.0.2.0/24"}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	if len(routes) != 2 {
		t.Fatalf("expected deny and main routes, got %d", len(routes))
	}
	denyMatcher := routeMatcher(t, routes[0])
	assertEqual(t, denyMatcher["host"], []string{"example.com", "www.example.com"})
	assertIPRanges(t, denyMatcher["client_ip"], rule.IPACLList)
	response := firstHandler(t, routes[0])
	if response["handler"] != "static_response" || response["status_code"] != 403 {
		t.Fatalf("unexpected deny handler: %#v", response)
	}

	mainMatcher := routeMatcher(t, routes[1])
	if _, exists := mainMatcher["client_ip"]; exists {
		t.Fatal("deny main route unexpectedly includes client_ip matcher")
	}
}

func TestGenerateRouteObject_L4ACL_rendersRemoteIPMatcher(t *testing.T) {
	for _, mode := range []string{"allow", "deny"} {
		t.Run(mode, func(t *testing.T) {
			// Given
			rule := SingleRuleConfig{
				CaddyID: "rule-tcp", Protocol: "tcp",
				Upstreams: []UpstreamConfig{{Host: "10.0.0.20", Port: 3306, Weight: 1, Enabled: true}},
			}
			rule.IPACLMode = mode
			rule.IPACLList = []string{"10.0.0.0/8"}

			// When
			route, err := GenerateRouteObject(rule)
			if err != nil {
				t.Fatalf("generate route: %v", err)
			}

			// Then
			matchers, ok := route["match"].([]interface{})
			if !ok || len(matchers) != 1 {
				t.Fatalf("unexpected L4 matchers: %#v", route["match"])
			}
			want := map[string]interface{}{"remote_ip": map[string]interface{}{"ranges": rule.IPACLList}}
			if mode == "deny" {
				want = map[string]interface{}{"not": []interface{}{want}}
			}
			assertEqual(t, matchers[0], want)
		})
	}
}

func TestGenerateSingleRuleCaddyConfig_CustomPathRules_ordersAndSelectsUpstreams(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.IPACLMode = "allow"
	rule.IPACLList = []string{"10.0.0.0/8"}
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{
		{SortOrder: 20, MatchType: "exact", Path: "/health", Upstreams: []UpstreamConfig{
			{Host: "10.0.1.20", Port: 9090, Weight: 3, Enabled: true},
			{Host: "10.0.1.21", Port: 9090, Weight: 6, Enabled: true},
		}},
		{SortOrder: 10, MatchType: "prefix", Path: "/api/"},
	}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	if len(routes) != 4 {
		t.Fatalf("expected two path routes, main route, and ACL fallback; got %d", len(routes))
	}
	apiMatcher := routeMatcher(t, routes[0])
	assertEqual(t, apiMatcher["path"], []string{"/api/*"})
	assertIPRanges(t, apiMatcher["client_ip"], rule.IPACLList)
	apiProxy := reverseProxyHandler(t, routes[0])
	assertUpstreamDials(t, apiProxy["upstreams"], []string{"10.0.0.10:8080", "10.0.0.11:8080"})

	healthMatcher := routeMatcher(t, routes[1])
	assertEqual(t, healthMatcher["path"], []string{"/health"})
	assertIPRanges(t, healthMatcher["client_ip"], rule.IPACLList)
	healthProxy := reverseProxyHandler(t, routes[1])
	assertUpstreamDials(t, healthProxy["upstreams"], []string{"10.0.1.20:9090", "10.0.1.21:9090"})
	loadBalancing := mustMap(t, healthProxy["load_balancing"], "load_balancing")
	selection := mustMap(t, loadBalancing["selection_policy"], "selection_policy")
	assertEqual(t, selection["weights"], []int{1, 2})

	mainMatcher := routeMatcher(t, routes[2])
	if _, exists := mainMatcher["path"]; exists {
		t.Fatal("main route unexpectedly includes path matcher")
	}
	fallback := firstHandler(t, routes[3])
	if fallback["status_code"] != 403 {
		t.Fatalf("expected terminal ACL fallback, got %#v", fallback)
	}
}

func TestGenerateRouteObject_ProxyTimeouts_resolveRuleThenGlobal(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.ProxyDialTimeout = 3
	rule.GlobalProxyDialTimeout = 13
	rule.GlobalProxyResponseHeaderTimeout = 14
	rule.ProxyReadTimeout = 5
	rule.GlobalProxyReadTimeout = 15
	rule.GlobalProxyWriteTimeout = 16
	rule.ProxyStreamTimeout = 7
	rule.GlobalProxyStreamTimeout = 17

	// When
	route, err := GenerateRouteObject(rule)
	if err != nil {
		t.Fatalf("generate route: %v", err)
	}

	// Then
	proxy := reverseProxyHandler(t, route)
	transport := mustMap(t, proxy["transport"], "transport")
	assertEqual(t, transport, map[string]interface{}{
		"protocol":                "http",
		"dial_timeout":            "3s",
		"response_header_timeout": "14s",
		"read_timeout":            "5s",
		"write_timeout":           "16s",
	})
	if proxy["stream_timeout"] != "7s" {
		t.Fatalf("expected rule stream timeout, got %#v", proxy["stream_timeout"])
	}
}

func TestGenerateRouteObject_HealthCheckTimeout_doesNotSetTransportDialTimeout(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.EnableActiveHealthCheck = true
	rule.HealthCheckTimeout = 9
	rule.HealthCheckInterval = 10

	// When
	route, err := GenerateRouteObject(rule)
	if err != nil {
		t.Fatalf("generate route: %v", err)
	}

	// Then
	proxy := reverseProxyHandler(t, route)
	if _, exists := proxy["transport"]; exists {
		t.Fatalf("health check timeout unexpectedly created transport: %#v", proxy["transport"])
	}
	healthChecks := mustMap(t, proxy["health_checks"], "health_checks")
	active := mustMap(t, healthChecks["active"], "active health check")
	if active["timeout"] != "9s" {
		t.Fatalf("expected active health timeout to remain 9s, got %#v", active["timeout"])
	}
}

func baseHTTPRule() SingleRuleConfig {
	return SingleRuleConfig{
		CaddyID:    "rule-http",
		Protocol:   "http",
		Domain:     "example.com, www.example.com",
		ListenPort: 80,
		Strategy:   "weighted_round_robin",
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.10", Port: 8080, Weight: 2, Protocol: "http", Enabled: true},
			{Host: "10.0.0.11", Port: 8080, Weight: 4, Protocol: "http", Enabled: true},
		},
	}
}

func renderedHTTPRoutes(t *testing.T, config map[string]interface{}) []interface{} {
	t.Helper()
	apps := mustMap(t, config["apps"], "apps")
	httpApp := mustMap(t, apps["http"], "http app")
	servers := mustMap(t, httpApp["servers"], "http servers")
	server := mustMap(t, servers["http_80"], "http server")
	routes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes has type %T", server["routes"])
	}
	return routes
}

func routeMatcher(t *testing.T, routeValue interface{}) map[string]interface{} {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	matchers, ok := route["match"].([]interface{})
	if !ok || len(matchers) != 1 {
		t.Fatalf("unexpected route matchers: %#v", route["match"])
	}
	return mustMap(t, matchers[0], "matcher")
}

func firstHandler(t *testing.T, routeValue interface{}) map[string]interface{} {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok || len(handlers) == 0 {
		t.Fatalf("unexpected route handlers: %#v", route["handle"])
	}
	return mustMap(t, handlers[0], "handler")
}

func reverseProxyHandler(t *testing.T, routeValue interface{}) map[string]interface{} {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("handlers has type %T", route["handle"])
	}
	for _, handlerValue := range handlers {
		handler := mustMap(t, handlerValue, "handler")
		if handler["handler"] == "reverse_proxy" {
			return handler
		}
	}
	t.Fatal("reverse_proxy handler not found")
	return nil
}

func mustMap(t *testing.T, value interface{}, name string) map[string]interface{} {
	t.Helper()
	result, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("%s has type %T", name, value)
	}
	return result
}

func assertIPRanges(t *testing.T, value interface{}, want []string) {
	t.Helper()
	clientIP := mustMap(t, value, "IP matcher")
	assertEqual(t, clientIP["ranges"], want)
}

func assertUpstreamDials(t *testing.T, value interface{}, want []string) {
	t.Helper()
	upstreams, ok := value.([]interface{})
	if !ok || len(upstreams) != len(want) {
		t.Fatalf("unexpected upstreams: %#v", value)
	}
	for i, upstreamValue := range upstreams {
		upstream := mustMap(t, upstreamValue, "upstream")
		if upstream["dial"] != want[i] {
			t.Fatalf("upstream %d: want dial %q, got %#v", i, want[i], upstream["dial"])
		}
	}
}

func assertEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %#v, got %#v", want, got)
	}
}
