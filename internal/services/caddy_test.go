package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
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

func TestSetConfigByID_replacesOwnedRouteSet_andPreservesSiblingRoutes(t *testing.T) {
	// Given
	defaultRoute := runningDefaultRoute()
	current := testHTTPConfig([]interface{}{
		map[string]interface{}{"@id": "rule-target_acl_deny"},
		map[string]interface{}{"@id": "rule-sibling_path_0"},
		map[string]interface{}{"@id": "rule-target"},
		map[string]interface{}{"@id": "rule-target_acl_allow"},
		map[string]interface{}{"handle": []interface{}{map[string]interface{}{"handler": "headers"}}},
		defaultRoute,
	})
	replacement := map[string]interface{}{"@id": "rule-target", "handle": []interface{}{map[string]interface{}{"handler": "subroute"}}}
	var applied map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/config/":
			if err := json.NewEncoder(writer).Encode(current); err != nil {
				t.Errorf("encode current config: %v", err)
			}
		case request.Method == http.MethodPost && request.URL.Path == "/config/":
			if err := json.NewDecoder(request.Body).Decode(&applied); err != nil {
				t.Errorf("decode applied config: %v", err)
			}
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).SetConfigByID("rule-target", replacement)

	// Then
	if err != nil {
		t.Fatalf("replace route set: %v", err)
	}
	routes := httpRoutesFromConfig(t, applied)
	assertRouteIDs(t, routes, []string{"rule-sibling_path_0", "rule-target", "", ""})
}

func TestSetConfigByID_preservesTLSRedirectOnHTTPServer(t *testing.T) {
	// Given
	current := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"http_80": map[string]interface{}{"routes": []interface{}{
						map[string]interface{}{"@id": "rule-target_redirect"},
						runningDefaultRoute(),
					}},
					"http_443": map[string]interface{}{"routes": []interface{}{
						map[string]interface{}{"@id": "rule-target"},
						map[string]interface{}{"@id": "rule-sibling"},
					}},
				},
			},
		},
	}
	replacement := map[string]interface{}{"@id": "rule-target", "handle": []interface{}{map[string]interface{}{"handler": "subroute"}}}
	var applied map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			if err := json.NewEncoder(writer).Encode(current); err != nil {
				t.Errorf("encode current config: %v", err)
			}
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&applied); err != nil {
			t.Errorf("decode applied config: %v", err)
		}
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).SetConfigByID("rule-target", replacement)

	// Then
	if err != nil {
		t.Fatalf("replace TLS route: %v", err)
	}
	assertRouteIDs(t, httpRoutesFromServer(t, applied, "http_80"), []string{"rule-target_redirect", ""})
	assertRouteIDs(t, httpRoutesFromServer(t, applied, "http_443"), []string{"rule-target", "rule-sibling"})
}

func TestGenerateCaddyConfig_propagatesCertificateMaterializationFailure(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enable_tls,tls_source,tls_cert,tls_key) VALUES ('../invalid','invalid cert','http','example.com',443,'weighted_round_robin','',1,'manual','new-cert','new-key')`); err != nil {
		t.Fatalf("seed invalid certificate rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('../invalid','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatalf("seed invalid certificate upstream: %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).ApplyConfig(GenerateCaddyConfig(&config.Config{}))

	// Then
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected materialization error for invalid rule ID, got %v", err)
	}
	if requests != 0 {
		t.Fatalf("Caddy received %d requests after certificate materialization failed", requests)
	}
}

func TestGenerateCaddyConfig_restoresCertificateSnapshotWhenMaterializationFails(t *testing.T) {
	// Given
	oldCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = oldCertDir })
	_, database := newClusterTestService(t)
	for _, ruleID := range []string{"a-valid", "z-fail"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enable_tls,tls_source,tls_cert,tls_key) VALUES (?,?, 'http','example.com',443,'weighted_round_robin','',1,'manual','new-cert','new-key')`, ruleID, ruleID); err != nil {
			t.Fatalf("seed certificate rule %s: %v", ruleID, err)
		}
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',8080,1,1,'http')`, ruleID); err != nil {
			t.Fatalf("seed certificate upstream %s: %v", ruleID, err)
		}
	}
	validCertPath, validKeyPath := CertFilePaths("a-valid")
	if err := os.WriteFile(validCertPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("seed old certificate: %v", err)
	}
	if err := os.WriteFile(validKeyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}
	_, failingKeyPath := CertFilePaths("z-fail")
	if err := os.Mkdir(failingKeyPath+".tmp", 0700); err != nil {
		t.Fatalf("block failing key temporary path: %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).ApplyConfig(GenerateCaddyConfig(&config.Config{}))

	// Then
	if err == nil {
		t.Fatal("expected certificate materialization failure")
	}
	cert, readErr := os.ReadFile(validCertPath)
	if readErr != nil {
		t.Fatalf("read restored certificate: %v", readErr)
	}
	key, readErr := os.ReadFile(validKeyPath)
	if readErr != nil {
		t.Fatalf("read restored key: %v", readErr)
	}
	assertEqual(t, string(cert), "old-cert")
	assertEqual(t, string(key), "old-key")
	if requests != 0 {
		t.Fatalf("Caddy received %d requests after certificate rollback", requests)
	}
}

func TestDeleteRouteByID_removesOnlyOwnedRouteSet(t *testing.T) {
	// Given
	current := testHTTPConfig([]interface{}{
		map[string]interface{}{"@id": "rule-target_acl_deny"},
		map[string]interface{}{"@id": "rule-target_path_0"},
		map[string]interface{}{"@id": "rule-target"},
		map[string]interface{}{"@id": "rule-sibling"},
		runningDefaultRoute(),
	})
	var applied map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			if err := json.NewEncoder(writer).Encode(current); err != nil {
				t.Errorf("encode current config: %v", err)
			}
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&applied); err != nil {
			t.Errorf("decode applied config: %v", err)
		}
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).DeleteRouteByID("http_80", "rule-target")

	// Then
	if err != nil {
		t.Fatalf("delete route set: %v", err)
	}
	assertRouteIDs(t, httpRoutesFromConfig(t, applied), []string{"rule-sibling", ""})
}

func TestPrependRouteToServer_insertsBeforeCatchAll_regardlessOfCatchAllIndex(t *testing.T) {
	// Given
	existing := map[string]interface{}{"@id": "rule-existing"}
	catchAll := runningDefaultRoute()
	current := testHTTPConfig([]interface{}{existing, catchAll})
	var applied map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			if err := json.NewEncoder(writer).Encode(current); err != nil {
				t.Errorf("encode current config: %v", err)
			}
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&applied); err != nil {
			t.Errorf("decode applied config: %v", err)
		}
	}))
	defer server.Close()
	newRoute := map[string]interface{}{"@id": "rule-new"}

	// When
	err := NewCaddyService(server.URL).PrependRouteToServer("http_80", newRoute)

	// Then
	if err != nil {
		t.Fatalf("prepend route: %v", err)
	}
	assertRouteIDs(t, httpRoutesFromConfig(t, applied), []string{"rule-existing", "rule-new", ""})
}

func TestValidateRouteMergedConfig_insertsBeforeCatchAll_regardlessOfCatchAllIndex(t *testing.T) {
	// Given
	current := testHTTPConfig([]interface{}{map[string]interface{}{"@id": "rule-existing"}, runningDefaultRoute()})
	var validated map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			if err := json.NewEncoder(writer).Encode(current); err != nil {
				t.Errorf("encode current config: %v", err)
			}
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&validated); err != nil {
			t.Errorf("decode validation config: %v", err)
		}
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).ValidateRouteMergedConfig("http_80", map[string]interface{}{"@id": "rule-new"}, "validation-id")

	// Then
	if err != nil {
		t.Fatalf("validate merged route: %v", err)
	}
	assertRouteIDs(t, httpRoutesFromConfig(t, validated), []string{"rule-existing", "rule-new", ""})
}

func TestGenerateSingleRuleCaddyConfig_tagsEveryOwnedAuxiliaryRoute(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.EnableTLS = true
	rule.TLSHTTPRedirect = true
	rule.IPACLMode = "deny"
	rule.IPACLList = []string{"192.0.2.0/24"}
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{SortOrder: 10, MatchType: "prefix", Path: "/api/"}}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	assertRouteIDs(t, routes, []string{"rule-http_redirect", "rule-http_acl_deny", "rule-http_path_0", "rule-http"})
}

func TestGenerateHTTPRouteObjects_tagsEveryOwnedAuxiliaryRoute(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.IPACLMode = "allow"
	rule.IPACLList = []string{"192.0.2.0/24"}
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{SortOrder: 10, MatchType: "prefix", Path: "/api/"}}

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}
	routeValues := make([]interface{}, len(routes))
	for index, route := range routes {
		routeValues[index] = route
	}
	assertRouteIDs(t, routeValues, []string{"rule-http_path_0", "rule-http", "rule-http_acl_allow"})
}

func TestDecodePathUpstreams_preservesHTTPSProtocol_andDefaultsEmptyProtocol(t *testing.T) {
	// Given
	raw := `[{"address":"secure.internal","port":443,"weight":2,"protocol":"https"},{"address":"plain.internal","port":8080,"weight":1}]`

	// When
	upstreams, err := decodePathUpstreams(raw)

	// Then
	if err != nil {
		t.Fatalf("decode path upstreams: %v", err)
	}
	assertEqual(t, upstreams, []UpstreamConfig{
		{Host: "secure.internal", Port: 443, Weight: 2, Protocol: "https", Enabled: true},
		{Host: "plain.internal", Port: 8080, Weight: 1, Protocol: "http", Enabled: true},
	})
}

func TestBuildTCPProxyRoute_omitsActivePort_withoutExplicitOverride(t *testing.T) {
	// Given
	rule := SingleRuleConfig{
		CaddyID: "rule-tcp", Protocol: "tcp", EnableActiveHealthCheck: true,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.10", Port: 3306, Enabled: true},
			{Host: "10.0.0.11", Port: 3307, Enabled: true},
		},
	}

	// When
	route := buildTCPProxyRoute(rule)

	// Then
	proxy := firstHandler(t, route)
	healthChecks := mustMap(t, proxy["health_checks"], "health checks")
	active := mustMap(t, healthChecks["active"], "active health check")
	if _, exists := active["port"]; exists {
		t.Fatalf("implicit active health port should be omitted, got %#v", active["port"])
	}

	rule.TCPHealthCheckPort = 13306
	active = mustMap(t, mustMap(t, firstHandler(t, buildTCPProxyRoute(rule))["health_checks"], "health checks")["active"], "active health check")
	assertEqual(t, active["port"], 13306)
}

func TestWriteCertPair_restoresPreviousCertificate_whenKeyDeployFails(t *testing.T) {
	// Given
	directory := t.TempDir()
	certPath := filepath.Join(directory, "rule.crt")
	keyPath := filepath.Join(directory, "rule.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("write old cert: %v", err)
	}
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatalf("create blocking key directory: %v", err)
	}

	// When
	err := writeCertPair(certPath, keyPath, "new-cert", "new-key")

	// Then
	if err == nil {
		t.Fatal("expected key deployment to fail")
	}
	cert, readErr := os.ReadFile(certPath)
	if readErr != nil {
		t.Fatalf("read restored cert: %v", readErr)
	}
	assertEqual(t, string(cert), "old-cert")
}

func TestWriteCertPair_removesNewCertificate_whenKeyDeployFailsWithoutPreviousCertificate(t *testing.T) {
	// Given
	directory := t.TempDir()
	certPath := filepath.Join(directory, "rule.crt")
	keyPath := filepath.Join(directory, "rule.key")
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatalf("create blocking key directory: %v", err)
	}

	// When
	err := writeCertPair(certPath, keyPath, "new-cert", "new-key")

	// Then
	if err == nil {
		t.Fatal("expected key deployment to fail")
	}
	if _, statErr := os.Stat(certPath); !os.IsNotExist(statErr) {
		t.Fatalf("new certificate remained after rollback: %v", statErr)
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

func runningDefaultRoute() map[string]interface{} {
	return map[string]interface{}{
		"handle": []interface{}{map[string]interface{}{
			"handler": "static_response",
			"body":    "Lazy Balancer V2 is running!",
		}},
	}
}

func testHTTPConfig(routes []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"http_80": map[string]interface{}{"routes": routes},
				},
			},
		},
	}
}

func httpRoutesFromConfig(t *testing.T, config map[string]interface{}) []interface{} {
	t.Helper()
	return httpRoutesFromServer(t, config, "http_80")
}

func httpRoutesFromServer(t *testing.T, config map[string]interface{}, serverName string) []interface{} {
	t.Helper()
	apps := mustMap(t, config["apps"], "apps")
	httpApp := mustMap(t, apps["http"], "http app")
	servers := mustMap(t, httpApp["servers"], "servers")
	server := mustMap(t, servers[serverName], serverName)
	routes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes has type %T", server["routes"])
	}
	return routes
}

func assertRouteIDs(t *testing.T, routes []interface{}, want []string) {
	t.Helper()
	got := make([]string, 0, len(routes))
	for _, routeValue := range routes {
		route := mustMap(t, routeValue, "route")
		id, _ := route["@id"].(string)
		got = append(got, id)
	}
	assertEqual(t, got, want)
}
