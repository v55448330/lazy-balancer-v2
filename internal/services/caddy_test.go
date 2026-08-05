package services

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type countingCaddyStore struct {
	*sql.DB
	queryCalls    int
	queryRowCalls int
}

func (s *countingCaddyStore) Query(query string, args ...any) (*sql.Rows, error) {
	s.queryCalls++
	return s.DB.Query(query, args...)
}

func (s *countingCaddyStore) QueryRow(query string, args ...any) *sql.Row {
	s.queryRowCalls++
	return s.DB.QueryRow(query, args...)
}

func TestCaddyService_GenerateAndApplyConfig_generates_after_waiting_for_config_lock(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_atomic_reload", false)
	if _, err := database.Exec("UPDATE lb_rules SET domain='old.example.test' WHERE caddy_id='lb_atomic_reload'"); err != nil {
		t.Fatalf("seed old rule domain: %v", err)
	}
	applied := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read applied config: %v", err)
			return
		}
		applied <- string(body)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)
	service.mu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- service.GenerateAndApplyConfig()
	}()
	if _, err := database.Exec("UPDATE lb_rules SET domain='new.example.test' WHERE caddy_id='lb_atomic_reload'"); err != nil {
		service.mu.Unlock()
		t.Fatalf("write new rule domain: %v", err)
	}

	// When
	service.mu.Unlock()
	err := <-done

	// Then
	if err != nil {
		t.Fatalf("generate and apply current config: %v", err)
	}
	body := <-applied
	if !strings.Contains(body, "new.example.test") || strings.Contains(body, "old.example.test") {
		t.Fatalf("applied config does not match current DB: %s", body)
	}
}

func TestGenerateCaddyConfig_upstream_scan_error_returns_generation_failure(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,strategy,health_check_path,enabled) VALUES ('lb_bad_upstream','bad upstream','http',8080,'weighted_round_robin','',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_bad_upstream','127.0.0.1','not-a-port',1)`); err != nil {
		t.Fatalf("seed invalid upstream: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	message, ok := generated[caddyConfigGenerationErrorKey].(string)
	if !ok || !strings.Contains(message, "scan upstream") {
		t.Fatalf("generation result=%#v, want upstream scan error", generated)
	}
}

func TestGenerateCaddyConfig_ignores_malformed_upstream_for_disabled_rule(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_enabled", false)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_disabled','disabled','http',8081,0)`); err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_disabled','127.0.0.1','not-a-port',1)`); err != nil {
		t.Fatalf("seed malformed disabled upstream: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("disabled upstream blocked config generation: %s", message)
	}
}

func TestGenerateCaddyConfig_ignores_malformed_path_rule_for_disabled_rule(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_enabled_routes", true)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,custom_routes_enabled) VALUES ('lb_disabled_routes','disabled routes','http',8081,0,1)`); err != nil {
		t.Fatalf("seed disabled custom-route rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_disabled_routes','not-an-order','prefix','/disabled')`); err != nil {
		t.Fatalf("seed malformed disabled path rule: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("disabled path rule blocked config generation: %s", message)
	}
}

func TestGenerateCaddyConfig_ignores_malformed_path_rule_when_custom_routes_disabled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_enabled_routes", true)
	seedGenerationRule(t, database, "lb_routes_off", false)
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_routes_off','not-an-order','prefix','/disabled')`); err != nil {
		t.Fatalf("seed malformed inactive path rule: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("inactive path rule blocked config generation: %s", message)
	}
}

func TestGenerateCaddyConfig_fail_closed_errors_do_not_call_load(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *sql.DB)
		want  string
	}{
		{name: "rule query", setup: func(t *testing.T, database *sql.DB) {
			if _, err := database.Exec("DROP TABLE lb_rules"); err != nil {
				t.Fatal(err)
			}
		}, want: "query enabled rules"},
		{name: "rule scan", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_rule_scan", false)
			if _, err := database.Exec("UPDATE lb_rules SET health_check_interval='bad' WHERE caddy_id='lb_rule_scan'"); err != nil {
				t.Fatal(err)
			}
		}, want: "scan enabled rule"},
		{name: "ACL JSON", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_acl_json", false)
			if _, err := database.Exec("UPDATE lb_rules SET ip_acl_list='{' WHERE caddy_id='lb_acl_json'"); err != nil {
				t.Fatal(err)
			}
		}, want: "decode ACL"},
		{name: "path query", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_path_query", true)
			if _, err := database.Exec("DROP TABLE path_rules"); err != nil {
				t.Fatal(err)
			}
		}, want: "query path rules"},
		{name: "path scan", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_path_scan", true)
			if _, err := database.Exec("INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_path_scan','bad','prefix','/api')"); err != nil {
				t.Fatal(err)
			}
		}, want: "scan path rule"},
		{name: "path JSON", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_path_json", true)
			if _, err := database.Exec("INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json) VALUES ('lb_path_json',1,'prefix','/api','{')"); err != nil {
				t.Fatal(err)
			}
		}, want: "decode path upstreams"},
		{name: "HTTP route", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_route", true)
			if _, err := database.Exec("INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json) VALUES ('lb_route',1,'prefix','/api','[]')"); err != nil {
				t.Fatal(err)
			}
		}, want: "generate HTTP routes"},
		{name: "global config", setup: func(t *testing.T, database *sql.DB) {
			if _, err := database.Exec("DELETE FROM global_config"); err != nil {
				t.Fatal(err)
			}
		}, want: "load global config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			test.setup(t, database)
			var loads int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/load" {
					loads++
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			generated := generateCaddyConfigFromStore(database)
			message, ok := generated[caddyConfigGenerationErrorKey].(string)
			if !ok || !strings.Contains(message, test.want) {
				t.Fatalf("generation result=%#v, want %q failure", generated, test.want)
			}
			if err := NewCaddyService(server.URL).ApplyConfig(generated); err == nil {
				t.Fatal("generation failure was applied")
			}
			if loads != 0 {
				t.Fatalf("Caddy /load calls=%d, want 0", loads)
			}
		})
	}
}

func TestGenerateCaddyConfig_usesConstantQueries_whenRuleCountGrows(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "example.test")
	seed := func(ruleID string) {
		t.Helper()
		seedGenerationRule(t, database, ruleID, true)
		if _, err := database.Exec("UPDATE lb_rules SET enable_tls=1,tls_source='acme_dns' WHERE caddy_id=?", ruleID); err != nil {
			t.Fatalf("enable ACME for %s: %v", ruleID, err)
		}
		if _, err := database.Exec("INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES (?,1,'prefix','/api')", ruleID); err != nil {
			t.Fatalf("seed path rule for %s: %v", ruleID, err)
		}
		if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES (?,'example.test','issued',?,?)", ruleID, certPEM, keyPEM); err != nil {
			t.Fatalf("seed certificate for %s: %v", ruleID, err)
		}
	}
	seed("lb_query_one")
	store := &countingCaddyStore{DB: database}
	first := generateCaddyConfigFromStore(store)
	if message, failed := first[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate one-rule config: %s", message)
	}
	wantQueries, wantQueryRows := store.queryCalls, store.queryRowCalls
	for _, ruleID := range []string{"lb_query_two", "lb_query_three"} {
		seed(ruleID)
	}
	store.queryCalls = 0
	store.queryRowCalls = 0

	// When
	generated := generateCaddyConfigFromStore(store)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate three-rule config: %s", message)
	}
	if store.queryCalls != wantQueries || store.queryRowCalls != wantQueryRows {
		t.Fatalf("query calls grew from Query=%d QueryRow=%d to Query=%d QueryRow=%d", wantQueries, wantQueryRows, store.queryCalls, store.queryRowCalls)
	}
}

func seedGenerationRule(t *testing.T, database *sql.DB, ruleID string, customRoutes bool) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,health_check_interval,enabled,custom_routes_enabled)
		VALUES (?,?,'http','example.test',8080,'weighted_round_robin','',10,1,?)`, ruleID, ruleID, customRoutes); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,'http')", ruleID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

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
	assertEqual(t, apiMatcher["path"], []string{"/api", "/api/*"})
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

func TestGenerateRouteObject_prefixPath_matchesRootAndDescendants(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{
		{SortOrder: 1, MatchType: "prefix", Path: "/api"},
		{SortOrder: 2, MatchType: "prefix", Path: "/"},
	}

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	assertEqual(t, routes[0]["match"].([]interface{})[0].(map[string]interface{})["path"], []string{"/api", "/api/*"})
	assertEqual(t, routes[1]["match"].([]interface{})[0].(map[string]interface{})["path"], []string{"/*"})
}

func TestGenerateRouteObject_rejectsMultiplePathUpstreams_whenDynamicDNS(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.DynamicDNS = true
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 1,
		MatchType: "prefix",
		Path:      "/api",
		Upstreams: []UpstreamConfig{
			{Host: "one.example.test", Port: 8080, Enabled: true},
			{Host: "two.example.test", Port: 8080, Enabled: true},
		},
	}}

	// When
	_, err := GenerateRouteObject(rule)

	// Then
	if err == nil || !strings.Contains(err.Error(), "dynamic DNS") {
		t.Fatalf("error=%v, want explicit dynamic DNS multi-upstream rejection", err)
	}
}

func TestGenerateRouteObject_joinsIPv6UpstreamAddresses(t *testing.T) {
	// Given
	httpRule := baseHTTPRule()
	httpRule.Upstreams = []UpstreamConfig{{Host: "2001:db8::1", Port: 8080, Weight: 1, Enabled: true}}
	httpRule.CustomRoutesEnabled = true
	httpRule.PathRules = []PathRuleConfig{{
		SortOrder: 1,
		MatchType: "exact",
		Path:      "/v6",
		Upstreams: []UpstreamConfig{{Host: "2001:db8::2", Port: 9090, Weight: 1, Enabled: true}},
	}}
	tcpRule := SingleRuleConfig{
		CaddyID:   "rule-v6-tcp",
		Protocol:  "tcp",
		Upstreams: []UpstreamConfig{{Host: "2001:db8::3", Port: 3306, Weight: 1, Enabled: true}},
	}

	// When
	httpRoutes, _, httpErr := generateHTTPRouteObjects(httpRule)
	tcpRoute, tcpErr := GenerateRouteObject(tcpRule)

	// Then
	if httpErr != nil || tcpErr != nil {
		t.Fatalf("generate IPv6 routes: HTTP=%v TCP=%v", httpErr, tcpErr)
	}
	assertUpstreamDials(t, reverseProxyHandler(t, httpRoutes[0])["upstreams"], []string{"[2001:db8::2]:9090"})
	assertUpstreamDials(t, reverseProxyHandler(t, httpRoutes[1])["upstreams"], []string{"[2001:db8::1]:8080"})
	tcpProxy := firstHandler(t, tcpRoute)
	tcpUpstreams := tcpProxy["upstreams"].([]interface{})
	assertEqual(t, tcpUpstreams[0].(map[string]interface{})["dial"], []string{"[2001:db8::3]:3306"})
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
	err := NewCaddyService(server.URL).ApplyConfig(GenerateCaddyConfig())

	// Then
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected materialization error for invalid rule ID, got %v", err)
	}
	if requests != 0 {
		t.Fatalf("Caddy received %d requests after certificate materialization failed", requests)
	}
}

func TestGenerateCaddyConfig_loads_certificate_for_canonical_multi_domain_job(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_tls,tls_source)
		VALUES ('lb-multi-domain','multi-domain','http','www.example.com, example.com',443,'weighted_round_robin','',1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed multi-domain rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb-multi-domain','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatalf("seed multi-domain upstream: %v", err)
	}
	issuedCert, issuedKey := matchingCertificatePair(t, "example.com", "www.example.com")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem)
		VALUES ('lb-multi-domain','example.com,www.example.com','issued',?,?)`, issuedCert, issuedKey); err != nil {
		t.Fatalf("seed multi-domain certificate job: %v", err)
	}

	// When
	generated := GenerateCaddyConfig()

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate Caddy config: %s", message)
	}
	certPath, keyPath := CertFilePaths("lb-multi-domain")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read materialized certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read materialized key: %v", err)
	}
	if string(certPEM) != issuedCert || string(keyPEM) != issuedKey {
		t.Fatalf("materialized pair=(%q,%q), want issued multi-domain pair", certPEM, keyPEM)
	}
}

func TestGenerateCaddyConfig_does_not_select_single_domain_certificate_after_domain_expansion(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_tls,tls_source)
		VALUES ('lb-expanded-domain','expanded','http','example.com,www.example.com',443,'weighted_round_robin','',1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed expanded rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb-expanded-domain','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatalf("seed expanded upstream: %v", err)
	}
	oldCert, oldKey := matchingCertificatePair(t, "example.com")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem)
		VALUES ('lb-expanded-domain','example.com','issued',?,?)`, oldCert, oldKey); err != nil {
		t.Fatalf("seed old certificate: %v", err)
	}

	// When
	generated := GenerateCaddyConfig()

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate Caddy config: %s", message)
	}
	certPath, keyPath := CertFilePaths("lb-expanded-domain")
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("single-domain certificate was materialized: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("single-domain key was materialized: %v", err)
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
	err := NewCaddyService(server.URL).ApplyConfig(GenerateCaddyConfig())

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

func TestApplyConfig_restoresCertificateSnapshotWhenLoadRejects(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enable_tls,tls_source,tls_cert,tls_key) VALUES ('lb-rejected','rejected cert','http','example.com',443,'weighted_round_robin','',1,'manual','new-cert','new-key')`); err != nil {
		t.Fatalf("seed certificate rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb-rejected','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatalf("seed certificate upstream: %v", err)
	}
	certPath, keyPath := CertFilePaths("lb-rejected")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("seed old certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "load rejected", http.StatusBadRequest)
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).ApplyConfig(GenerateCaddyConfig())

	// Then
	if err == nil {
		t.Fatal("Caddy load rejection reported success")
	}
	cert, certErr := os.ReadFile(certPath)
	if certErr != nil {
		t.Fatalf("read restored certificate: %v", certErr)
	}
	key, keyErr := os.ReadFile(keyPath)
	if keyErr != nil {
		t.Fatalf("read restored key: %v", keyErr)
	}
	assertEqual(t, string(cert), "old-cert")
	assertEqual(t, string(key), "old-key")
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

func TestDeleteRouteByID_withoutMatchingRoute_skipsApply(t *testing.T) {
	// Given
	current := testHTTPConfig([]interface{}{
		map[string]interface{}{"@id": "rule-other"},
		runningDefaultRoute(),
	})
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			if err := json.NewEncoder(writer).Encode(current); err != nil {
				t.Errorf("encode current config: %v", err)
			}
			return
		}
		posts++
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).DeleteRouteByID("http_80", "rule-missing")

	// Then
	if err != nil {
		t.Fatalf("delete missing route set: %v", err)
	}
	if posts != 0 {
		t.Fatalf("delete without matching route issued %d config posts, want 0", posts)
	}
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
	err := NewCaddyService(server.URL).ValidateRouteMergedConfig("http_80", map[string]interface{}{"@id": "rule-new"})

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

func TestGenerateSingleRuleCaddyConfig_dynamicDNS_emitsResolverInsideDynamicUpstreams(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.DynamicDNS = true
	rule.EnableDnsServer = true
	rule.DnsServer = "10.0.0.53:53"
	rule.Upstreams = []UpstreamConfig{{Host: "dynamic.example.test", Port: 8080, Enabled: true}}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	proxy := reverseProxyHandler(t, routes[len(routes)-1])
	dynamic := mustMap(t, proxy["dynamic_upstreams"], "dynamic upstreams")
	resolver := mustMap(t, dynamic["resolver"], "dynamic upstream resolver")
	assertEqual(t, resolver["addresses"], []string{"10.0.0.53:53"})
}

func TestGenerateRouteObject_dynamicDNS_emitsResolverInsideDynamicUpstreams(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.DynamicDNS = true
	rule.EnableDnsServer = true
	rule.DnsServer = "10.0.0.53:53"
	rule.Upstreams = []UpstreamConfig{{Host: "dynamic.example.test", Port: 8080, Enabled: true}}

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	proxy := reverseProxyHandler(t, routes[len(routes)-1])
	dynamic := mustMap(t, proxy["dynamic_upstreams"], "dynamic upstreams")
	resolver := mustMap(t, dynamic["resolver"], "dynamic upstream resolver")
	assertEqual(t, resolver["addresses"], []string{"10.0.0.53:53"})
}

func TestGenerateSingleRuleCaddyConfig_httpsRedirect_includesNonStandardListenPort(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.EnableTLS = true
	rule.TLSHTTPRedirect = true
	rule.ListenPort = 8443

	// When
	config := GenerateSingleRuleCaddyConfig(rule)

	// Then
	routes := httpRoutesFromServer(t, config, "http_8443")
	response := firstHandler(t, routes[0])
	if response["handler"] != "static_response" || response["status_code"] != 301 {
		t.Fatalf("unexpected redirect handler: %#v", response)
	}
	headers := mustMap(t, response["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://example.com:8443"})

	// When the rule listens on the default HTTPS port
	rule.ListenPort = 443
	config = GenerateSingleRuleCaddyConfig(rule)

	// Then the port is omitted
	routes = httpRoutesFromServer(t, config, "http_443")
	headers = mustMap(t, firstHandler(t, routes[0])["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://example.com"})
}

func TestGenerateCaddyConfig_httpsRedirect_includesNonStandardListenPort(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "tls.example.test")
	seedGenerationRule(t, database, "lb_tls_redirect", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='tls.example.test', listen_port=8443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_tls_redirect'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_80")
	response := firstHandler(t, routes[0])
	if response["handler"] != "static_response" || response["status_code"] != 301 {
		t.Fatalf("unexpected redirect handler: %#v", response)
	}
	headers := mustMap(t, response["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://tls.example.test:8443"})
}

func TestGenerateCaddyConfig_skipsRulesWithoutUpstreams(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_healthy", false)
	certPEM, keyPEM := matchingCertificatePair(t, "empty.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
		VALUES ('lb_empty','lb_empty','http','empty.example.test',8443,'weighted_round_robin',1,1,'manual',?,?,1)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed zero-upstream TLS rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_empty_tcp','lb_empty_tcp','tcp','',9000,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed zero-upstream TCP rule: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	apps := mustMap(t, generated["apps"], "apps")
	httpApp := mustMap(t, apps["http"], "http app")
	servers := mustMap(t, httpApp["servers"], "http servers")
	if _, exists := servers["http_8080"]; !exists {
		t.Fatal("healthy rule server missing")
	}
	if _, exists := servers["http_8443"]; exists {
		t.Fatal("zero-upstream rule server was generated")
	}
	assertRouteIDs(t, httpRoutesFromServer(t, generated, "http_80"), []string{""})
	if _, exists := apps["layer4"]; exists {
		t.Fatal("zero-upstream TCP rule server was generated")
	}
}
