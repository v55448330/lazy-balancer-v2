package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
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
		// Round 32 F-3: 原用例以 path_rules 空数组 upstreams_json='[]' 触发
		// "generate HTTP routes" 失败——该场景现按修复语义回退主上游（与 nil 同口径，
		// 见 TestGenerateSingleRuleCaddyConfig_pathRuleEmptyUpstreamArray_...），
		// 改用 dynamic-DNS 双上游维持 fail-closed 校验覆盖。
		{name: "HTTP route", setup: func(t *testing.T, database *sql.DB) {
			seedGenerationRule(t, database, "lb_route", true)
			if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_route','127.0.0.1',9001,1,'http')"); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec("UPDATE lb_rules SET dynamic_dns=1 WHERE caddy_id='lb_route'"); err != nil {
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

func TestGenerateSingleRuleCaddyConfig_CustomPathRules_ordersAndSelectsUpstreams(t *testing.T) {
	// Given
	rule := baseHTTPRule()
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
	if len(routes) != 3 {
		t.Fatalf("expected two path routes and main route; got %d", len(routes))
	}
	apiMatcher := routeMatcher(t, routes[0])
	assertEqual(t, apiMatcher["path"], []string{"/api", "/api/*"})
	apiProxy := reverseProxyHandler(t, routes[0])
	assertUpstreamDials(t, apiProxy["upstreams"], []string{"10.0.0.10:8080", "10.0.0.11:8080"})

	healthMatcher := routeMatcher(t, routes[1])
	assertEqual(t, healthMatcher["path"], []string{"/health"})
	healthProxy := reverseProxyHandler(t, routes[1])
	assertUpstreamDials(t, healthProxy["upstreams"], []string{"10.0.1.20:9090", "10.0.1.21:9090"})
	loadBalancing := mustMap(t, healthProxy["load_balancing"], "load_balancing")
	selection := mustMap(t, loadBalancing["selection_policy"], "selection_policy")
	assertEqual(t, selection["weights"], []int{1, 2})

	mainMatcher := routeMatcher(t, routes[2])
	if _, exists := mainMatcher["path"]; exists {
		t.Fatal("main route unexpectedly includes path matcher")
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

// R44 B1: 校验侧与全量渲染「非 http 即 TCP」对齐——遗留 https 不再被当作 HTTP
// 通过（渲染会静默丢弃域名匹配）；http/tcp 仍正常生成。
func TestGenerateRouteObject_rejectsLegacyHTTPSProtocol(t *testing.T) {
	// Given
	httpsRule := baseHTTPRule()
	httpsRule.Protocol = "https"

	// When
	_, err := GenerateRouteObject(httpsRule)

	// Then
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("error=%v, want unsupported protocol rejection", err)
	}

	// And http/tcp 口径不变
	if _, err := GenerateRouteObject(baseHTTPRule()); err != nil {
		t.Fatalf("http rule rejected: %v", err)
	}
	tcpRule := SingleRuleConfig{CaddyID: "rule-tcp", Protocol: "tcp", Upstreams: []UpstreamConfig{{Host: "127.0.0.1", Port: 3306, Weight: 1, Enabled: true}}}
	if _, err := GenerateRouteObject(tcpRule); err != nil {
		t.Fatalf("tcp rule rejected: %v", err)
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
	rule.ProxyFlushInterval = -1
	rule.ProxyStreamCloseDelay = 5

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
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{SortOrder: 10, MatchType: "prefix", Path: "/api/"}}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	assertRouteIDs(t, routes, []string{"rule-http_redirect", "rule-http_path_0", "rule-http"})
}

func TestGenerateHTTPRouteObjects_tagsEveryOwnedAuxiliaryRoute(t *testing.T) {
	// Given
	rule := baseHTTPRule()
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
	assertRouteIDs(t, routeValues, []string{"rule-http_path_0", "rule-http"})
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
	// Location 使用 {http.request.host} 占位符：static_response 的 headers 会经过
	// Caddy replacer 替换（v2.11.4 modules/caddyhttp/staticresp.go），
	// 多域名规则（本例 example.com + www.example.com）访问任一域名都跳回该域名，
	// 而不是被劫持到首个域名；非 443 监听端口追加端口后缀。
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}:8443"})

	// When the rule listens on the default HTTPS port
	rule.ListenPort = 443
	config = GenerateSingleRuleCaddyConfig(rule)

	// Then the port is omitted
	routes = httpRoutesFromServer(t, config, "http_443")
	headers = mustMap(t, firstHandler(t, routes[0])["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}"})
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
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}:8443"})
}

func TestGenerateCaddyConfig_httpsRedirect_multiDomainUsesRequestHostPlaceholder(t *testing.T) {
	// Given: 多域名规则（a.example.test,b.example.test）访问 b.example.test 时
	// 必须跳回 b.example.test，而不是被固定劫持到首个域名，因此 Location 使用
	// {http.request.host} 占位符（Caddy static_response headers 支持占位符替换）。
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "a.example.test", "b.example.test")
	seedGenerationRule(t, database, "lb_tls_redirect_multi", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='a.example.test, b.example.test', listen_port=443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_tls_redirect_multi'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then: 443 监听端口省略端口后缀
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_80")
	response := firstHandler(t, routes[0])
	if response["handler"] != "static_response" || response["status_code"] != 301 {
		t.Fatalf("unexpected redirect handler: %#v", response)
	}
	headers := mustMap(t, response["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}"})
}

func TestGenerateSingleRuleCaddyConfig_httpsRedirect_multiDomainUsesRequestHostPlaceholder(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.Domain = "a.example.test, b.example.test"
	rule.EnableTLS = true
	rule.TLSHTTPRedirect = true
	rule.ListenPort = 8443

	// When
	config := GenerateSingleRuleCaddyConfig(rule)

	// Then: 非 443 监听端口追加端口后缀，且不固定为首个域名
	routes := httpRoutesFromServer(t, config, "http_8443")
	response := firstHandler(t, routes[0])
	if response["handler"] != "static_response" || response["status_code"] != 301 {
		t.Fatalf("unexpected redirect handler: %#v", response)
	}
	headers := mustMap(t, response["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}:8443"})
}

func TestGenerateSingleRuleCaddyConfig_serverTokensHiddenDefersServerHeaderDelete(t *testing.T) {
	// Given a rule with server tokens hidden (rule-level override = force hide)
	rule := baseHTTPRule()
	rule.ServerTokensHidden = 1

	// When
	config := GenerateSingleRuleCaddyConfig(rule)

	// Then the emitted headers handler deletes Server with deferred=true：
	// 非 deferred 的 response 头操作在路由调度阶段（reverse_proxy 执行之前）应用，
	// reverseproxy 复制上游响应头时会把上游的 Server 头重新写回，隐藏永远不生效；
	// deferred 使删除推迟到上游响应写入之后（Caddy v2.11.4 headers.go +
	// reverseproxy.go copyHeader）。
	routes := httpRoutesFromServer(t, config, "http_80")
	route := mustMap(t, routes[0], "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("unexpected route handlers: %#v", route["handle"])
	}
	headersIndex, proxyIndex := -1, -1
	for i, handlerValue := range handlers {
		handler := mustMap(t, handlerValue, "handler")
		switch handler["handler"] {
		case "headers":
			if headersIndex < 0 {
				headersIndex = i
			}
		case "reverse_proxy":
			if proxyIndex < 0 {
				proxyIndex = i
			}
		}
	}
	if headersIndex < 0 {
		t.Fatalf("server_tokens_hidden must emit a headers handler: %#v", route["handle"])
	}
	if proxyIndex < 0 {
		t.Fatalf("route must emit a reverse_proxy handler: %#v", route["handle"])
	}
	// headers 必须位于 reverse_proxy 之前（重构护栏）：reverse_proxy 是终结
	// handler，排在它之后的 handler 永不执行，deferred 删除所依赖的响应包裹
	// 也不会被安装，Server 头隐藏将整体失效。
	if headersIndex >= proxyIndex {
		t.Fatalf("headers handler (index %d) must precede reverse_proxy (index %d): %#v", headersIndex, proxyIndex, route["handle"])
	}
	headersOps := mustMap(t, handlers[headersIndex], "headers handler")
	response := mustMap(t, headersOps["response"], "headers response ops")
	assertEqual(t, response["deferred"], true)
	assertEqual(t, response["delete"], []string{"Server"})
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

func seedWafRuleRow(t *testing.T, database *sql.DB, caddyID, protocol string) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES (?,?,?,8080,1)`, caddyID, "waf-test-"+caddyID, protocol); err != nil {
		t.Fatalf("seed %s rule row: %v", protocol, err)
	}
}

func seedBoundSecurityPolicy(t *testing.T, database *sql.DB, ruleCaddyID, mode string, enabled bool) {
	t.Helper()
	enabledValue := 0
	if enabled {
		enabledValue = 1
	}
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,enabled) VALUES (?,?,?)`, "policy-"+ruleCaddyID, mode, enabledValue)
	if err != nil {
		t.Fatalf("seed security policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read security policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind security policy: %v", err)
	}
}

func handlerChainNames(t *testing.T, routeValue interface{}) []string {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("handlers has type %T", route["handle"])
	}
	names := make([]string, 0, len(handlers))
	for _, handlerValue := range handlers {
		names = append(names, mustMap(t, handlerValue, "handler")["handler"].(string))
	}
	return names
}

func indexOfHandler(names []string, name string) int {
	for i, candidate := range names {
		if candidate == name {
			return i
		}
	}
	return -1
}

func findChainHandler(t *testing.T, routeValue interface{}, name string) map[string]interface{} {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("handlers has type %T", route["handle"])
	}
	for _, handlerValue := range handlers {
		handler := mustMap(t, handlerValue, "handler")
		if handler["handler"] == name {
			return handler
		}
	}
	return nil
}

func TestGenerateRouteObject_placesWafHandlerFirst_whenBlockingPolicyBound(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicy(t, database, "rule-http", "blocking", true)
	rule := baseHTTPRule()
	rule.RequestBodyMaxSizeMB = 8

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	names := handlerChainNames(t, routes[0])
	wafIndex := indexOfHandler(names, "waf")
	if wafIndex != 0 {
		t.Fatalf("waf handler index=%d, want first position in chain %v", wafIndex, names)
	}
	if proxyIndex := indexOfHandler(names, "reverse_proxy"); proxyIndex <= wafIndex {
		t.Fatalf("waf must execute before reverse_proxy: chain %v", names)
	}
	if bodyIndex := indexOfHandler(names, "request_body"); bodyIndex <= wafIndex {
		t.Fatalf("waf must execute before request_body: chain %v", names)
	}
}

func TestGenerateRouteObject_rendersWafDetectionOnlyDirectives_whenDetectionPolicyBound(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicy(t, database, "rule-http", "detection", true)
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	waf := findChainHandler(t, routes[0], "waf")
	if waf == nil {
		t.Fatal("waf handler missing from handle chain")
	}
	directives, ok := waf["directives"].(string)
	if !ok || !strings.Contains(directives, "ctl:ruleEngine=DetectionOnly") || !strings.Contains(directives, "SecRuleEngine On") {
		t.Fatalf("waf directives=%#v, want engine On with DetectionOnly switch", waf["directives"])
	}
}

func TestGenerateRouteObject_omitsWafHandler_whenBoundPolicyDisabled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicy(t, database, "rule-http", "blocking", false)
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	if waf := findChainHandler(t, routes[0], "waf"); waf != nil {
		t.Fatalf("waf handler present for disabled policy: %#v", waf)
	}
}

func TestGenerateRouteObject_omitsWafHandler_whenRuleHasNoPolicyBinding(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,enabled) VALUES ('unbound-policy','blocking',1)`); err != nil {
		t.Fatalf("seed unbound policy: %v", err)
	}
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	if waf := findChainHandler(t, routes[0], "waf"); waf != nil {
		t.Fatalf("waf handler present for unbound rule: %#v", waf)
	}
}

func TestGenerateSingleRuleCaddyConfig_omitsWafHandler_whenRuleIsTCP(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-tcp", "tcp")
	seedBoundSecurityPolicy(t, database, "rule-tcp", "blocking", true)
	rule := SingleRuleConfig{
		CaddyID:    "rule-tcp",
		Protocol:   "tcp",
		ListenPort: 3306,
		Upstreams:  []UpstreamConfig{{Host: "10.0.0.20", Port: 3306, Weight: 1, Enabled: true}},
	}

	// When
	config := GenerateSingleRuleCaddyConfig(rule)

	// Then
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal TCP rule config: %v", err)
	}
	if strings.Contains(string(encoded), `"handler":"waf"`) {
		t.Fatalf("waf handler leaked into TCP rule config: %s", encoded)
	}
}

// TestGenerateSingleRuleCaddyConfig_parityWithProductionBuilders asserts that
// GenerateSingleRuleCaddyConfig delegates to the production builders so its
// per-rule routes are byte-identical to generateHTTPRouteObjects / buildTCPServer.
func TestGenerateSingleRuleCaddyConfig_parityWithProductionBuilders(t *testing.T) {
	strategies := []string{"weighted_round_robin", "least_conn", "ip_hash", "cookie", "random", "first"}

	for _, strategy := range strategies {
		for _, withPaths := range []bool{false, true} {
			for _, withExtras := range []bool{false, true} {
				name := fmt.Sprintf("http/%s/paths=%v/extras=%v", strategy, withPaths, withExtras)
				t.Run(name, func(t *testing.T) {
					rule := baseHTTPRule()
					rule.Strategy = strategy
					if withPaths {
						rule.CustomRoutesEnabled = true
						rule.PathRules = []PathRuleConfig{{
							SortOrder: 1, MatchType: "prefix", Path: "/api",
							Upstreams: []UpstreamConfig{{Host: "10.0.1.20", Port: 9090, Weight: 3, Enabled: true}},
						}}
					}
					if withExtras {
						rule.HostHeader = "backend.internal"
						rule.HealthCheckInterval = 30
						rule.EnableActiveHealthCheck = true
						rule.HealthCheckPath = "/healthz"
					}

					gotRoutes := httpRoutesFromServer(t, GenerateSingleRuleCaddyConfig(rule), fmt.Sprintf("http_%d", rule.ListenPort))
					wantRoutes, _, err := generateHTTPRouteObjects(rule)
					if err != nil {
						t.Fatalf("generateHTTPRouteObjects: %v", err)
					}
					want := make([]interface{}, len(wantRoutes))
					for i, r := range wantRoutes {
						want[i] = r
					}
					assertEqual(t, gotRoutes, want)
				})
			}
		}

		t.Run("tcp/"+strategy, func(t *testing.T) {
			rule := SingleRuleConfig{
				CaddyID: "rule-tcp", Protocol: "tcp", ListenPort: 3306, Strategy: strategy,
				Upstreams: []UpstreamConfig{{Host: "10.0.0.10", Port: 3306, Weight: 2, Enabled: true}},
			}
			config := GenerateSingleRuleCaddyConfig(rule)
			apps := mustMap(t, config["apps"], "apps")
			layer4 := mustMap(t, apps["layer4"], "layer4 app")
			servers := mustMap(t, layer4["servers"], "layer4 servers")
			assertEqual(t, servers["tcp_3306"], buildTCPServer(rule))
		})
	}
}

func TestBuildWafHandler_nilMatrix(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "waf-http-blocking", "http")
	seedBoundSecurityPolicy(t, database, "waf-http-blocking", "blocking", true)
	seedWafRuleRow(t, database, "waf-http-detection", "http")
	seedBoundSecurityPolicy(t, database, "waf-http-detection", "detection", true)
	seedWafRuleRow(t, database, "waf-http-disabled", "http")
	seedBoundSecurityPolicy(t, database, "waf-http-disabled", "blocking", false)
	seedWafRuleRow(t, database, "waf-http-unbound", "http")
	seedWafRuleRow(t, database, "waf-http-off", "http")
	seedBoundSecurityPolicy(t, database, "waf-http-off", "off", true)
	seedWafRuleRow(t, database, "waf-tcp", "tcp")
	seedBoundSecurityPolicy(t, database, "waf-tcp", "blocking", true)

	cases := []struct {
		name      string
		caddyID   string
		wantWaf   bool
		directive string
	}{
		{"blocking policy bound to http rule", "waf-http-blocking", true, "SecRuleEngine On"},
		{"detection policy bound to http rule", "waf-http-detection", true, "ctl:ruleEngine=DetectionOnly"},
		{"disabled policy", "waf-http-disabled", false, ""},
		{"unbound http rule", "waf-http-unbound", false, ""},
		{"policy with mode off yields empty directives", "waf-http-off", false, ""},
		{"tcp rule", "waf-tcp", false, ""},
		{"unknown rule", "waf-missing", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When（Round 34 F-6: buildWafHandler 已删，协议门控在生产调用点，
			// 测试复刻调用点语义：仅 http 规则经 WithPolicy 变体构建）
			var protocol string
			if err := database.QueryRow(`SELECT protocol FROM lb_rules WHERE caddy_id=?`, tc.caddyID).Scan(&protocol); err != nil || protocol != "http" {
				protocol = "tcp"
			}
			handler := buildWafHandlerWithPolicy(tc.caddyID, GetSecurityPolicyForRule(tc.caddyID))
			if protocol != "http" {
				handler = nil
			}

			// Then
			if !tc.wantWaf {
				if handler != nil {
					t.Fatalf("buildWafHandlerWithPolicy(%q, policy)=%#v, want nil", tc.caddyID, handler)
				}
				return
			}
			if handler == nil {
				t.Fatalf("buildWafHandlerWithPolicy(%q, policy)=nil, want waf handler", tc.caddyID)
			}
			if handler["handler"] != "waf" {
				t.Fatalf("handler name=%#v, want waf", handler["handler"])
			}
			directives, _ := handler["directives"].(string)
			if !strings.Contains(directives, tc.directive) {
				t.Fatalf("directives=%q, want substring %q", directives, tc.directive)
			}
		})
	}
}

func seedBoundSecurityPolicyWithRateLimit(t *testing.T, database *sql.DB, ruleCaddyID, mode string, rps, burst int) {
	t.Helper()
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,rate_limit_enabled,rate_limit_rps,rate_limit_burst,enabled) VALUES (?,?,1,?,?,1)`, "policy-rl-"+ruleCaddyID, mode, rps, burst)
	if err != nil {
		t.Fatalf("seed rate-limit policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read rate-limit policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind rate-limit policy: %v", err)
	}
}

func TestGenerateRouteObject_placesRateLimitBeforeWaf_whenPolicyEnablesRateLimit(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicyWithRateLimit(t, database, "rule-http", "blocking", 100, 50)
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	names := handlerChainNames(t, routes[0])
	rateLimitIndex := indexOfHandler(names, "rate_limit")
	wafIndex := indexOfHandler(names, "waf")
	proxyIndex := indexOfHandler(names, "reverse_proxy")
	if rateLimitIndex < 0 {
		t.Fatalf("rate_limit handler missing from chain %v", names)
	}
	if wafIndex < 0 {
		t.Fatalf("waf handler missing from chain %v", names)
	}
	if !(rateLimitIndex < wafIndex && wafIndex < proxyIndex) {
		t.Fatalf("want rate_limit < waf < reverse_proxy, got chain %v", names)
	}
	rateLimit := findChainHandler(t, routes[0], "rate_limit")
	zones := mustMap(t, rateLimit["rate_limits"], "rate_limits")
	if len(zones) != 2 {
		t.Fatalf("want exactly two rate limit zones (sec/min) when burst > 0, got %v", zones)
	}
	secZone := mustMap(t, zones["rule-http-sec"], "sec rate limit zone")
	assertEqual(t, secZone["key"], "{http.request.remote.host}")
	assertEqual(t, secZone["window"], "1s")
	assertEqual(t, secZone["max_events"], 150)
	minZone := mustMap(t, zones["rule-http-min"], "min rate limit zone")
	assertEqual(t, minZone["key"], "{http.request.remote.host}")
	assertEqual(t, minZone["window"], "60s")
	assertEqual(t, minZone["max_events"], 6000)
}

func TestGenerateRouteObject_rendersSingleRateLimitZone_whenBurstZero(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicyWithRateLimit(t, database, "rule-http", "blocking", 20, 0)
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	rateLimit := findChainHandler(t, routes[0], "rate_limit")
	zones := mustMap(t, rateLimit["rate_limits"], "rate_limits")
	if len(zones) != 1 {
		t.Fatalf("want exactly one rate limit zone when burst is zero, got %v", zones)
	}
	zone := mustMap(t, zones["rule-http"], "rate limit zone")
	assertEqual(t, zone["key"], "{http.request.remote.host}")
	assertEqual(t, zone["window"], "1s")
	assertEqual(t, zone["max_events"], 20)
}

func TestGenerateRouteObject_omitsRateLimitHandler_whenPolicyRateLimitDisabled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicy(t, database, "rule-http", "blocking", true)
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	names := handlerChainNames(t, routes[0])
	if indexOfHandler(names, "rate_limit") >= 0 {
		t.Fatalf("rate_limit handler present for policy without rate limiting: chain %v", names)
	}
	if indexOfHandler(names, "waf") < 0 {
		t.Fatalf("waf handler missing from chain %v", names)
	}
}

func TestGenerateRouteObject_rendersRateLimitWithoutWaf_whenPolicyModeOff(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	seedBoundSecurityPolicyWithRateLimit(t, database, "rule-http", "off", 20, 0)
	rule := baseHTTPRule()

	// When
	routes, _, err := generateHTTPRouteObjects(rule)

	// Then
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	names := handlerChainNames(t, routes[0])
	rateLimitIndex := indexOfHandler(names, "rate_limit")
	if rateLimitIndex < 0 {
		t.Fatalf("rate_limit handler missing for mode-off policy with rate limiting: chain %v", names)
	}
	if indexOfHandler(names, "waf") >= 0 {
		t.Fatalf("waf handler present for mode-off policy: chain %v", names)
	}
	rateLimit := findChainHandler(t, routes[0], "rate_limit")
	zone := mustMap(t, mustMap(t, rateLimit["rate_limits"], "rate_limits")["rule-http"], "rate limit zone")
	assertEqual(t, zone["max_events"], 20)
}

func seedHTTPRuleForGeneration(t *testing.T, database *sql.DB, caddyID, domain string, listenPort int) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled) VALUES (?,?,'http',?,?,'weighted_round_robin',1)`, caddyID, caddyID, domain, listenPort); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func seedBoundSecurityPolicyWithBlockPage(t *testing.T, database *sql.DB, ruleCaddyID string, blockPageID, blockStatusCode int) {
	t.Helper()
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,block_page_id,block_status_code,enabled) VALUES (?,'blocking',?,?,1)`, "policy-bp-"+ruleCaddyID, blockPageID, blockStatusCode)
	if err != nil {
		t.Fatalf("seed block-page policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read block-page policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind block-page policy: %v", err)
	}
}

func seedSecurityBlockPage(t *testing.T, database *sql.DB, id int, content string) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,content) VALUES (?,?,?)`, id, "page", content); err != nil {
		t.Fatalf("seed block page: %v", err)
	}
}

func seedBoundSecurityPolicyWithRateLimitAndBlockPage(t *testing.T, database *sql.DB, ruleCaddyID string, blockPageID, blockStatusCode, rps, burst int) {
	t.Helper()
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,block_page_id,block_status_code,rate_limit_enabled,rate_limit_rps,rate_limit_burst,enabled) VALUES (?,'blocking',?,?,1,?,?,1)`, "policy-rlbp-"+ruleCaddyID, blockPageID, blockStatusCode, rps, burst)
	if err != nil {
		t.Fatalf("seed rate-limit block-page policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read rate-limit block-page policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind rate-limit block-page policy: %v", err)
	}
}

func serverErrorRoutes(t *testing.T, config map[string]interface{}, serverName string) ([]interface{}, map[string]interface{}) {
	t.Helper()
	apps := mustMap(t, config["apps"], "apps")
	httpApp := mustMap(t, apps["http"], "http app")
	servers := mustMap(t, httpApp["servers"], "servers")
	server := mustMap(t, servers[serverName], serverName)
	errorsValue, exists := server["errors"]
	if !exists {
		return nil, server
	}
	routes, ok := mustMap(t, errorsValue, "errors")["routes"].([]interface{})
	if !ok {
		t.Fatalf("errors.routes has unexpected type: %#v", errorsValue)
	}
	return routes, server
}

func TestGenerateCaddyConfig_rendersBlockPageErrorRoute_whenBoundPolicyHasBlockPage(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_blocked", "blocked.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>branded-block</html>")
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_blocked", 7, 451)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	if len(errorRoutes) != 1 {
		t.Fatalf("want exactly one error route, got %#v", errorRoutes)
	}
	route := mustMap(t, errorRoutes[0], "error route")
	matcher := routeMatcher(t, route)
	assertEqual(t, matcher["host"], []string{"blocked.example.test"})
	// The matcher targets coraza's deny status (403, message "interruption
	// triggered") and GeoIP's block status (block_status_code, message
	// "GeoIP blocked"); the response renders the policy's block_status_code
	// (default 403 when unset).
	assertEqual(t, matcher["expression"], "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered') || ({http.error.status_code} == 451 && {http.error.message} == 'GeoIP blocked')")
	handler := firstHandler(t, route)
	assertEqual(t, handler["handler"], "static_response")
	assertEqual(t, handler["body"], "<html>branded-block</html>")
	assertEqual(t, handler["status_code"], 451)
	if route["terminal"] != true {
		t.Fatalf("error route must be terminal: %#v", route)
	}
}

func TestGenerateCaddyConfig_rendersOneErrorRoutePerRule_whenServerHasMultipleBlockPagePolicies(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_alpha", "alpha.example.test", 8080)
	seedHTTPRuleForGeneration(t, database, "lb_beta", "beta.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>alpha-block</html>")
	seedSecurityBlockPage(t, database, 8, "<html>beta-block</html>")
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_alpha", 7, 451)
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_beta", 8, 0)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	if len(errorRoutes) != 2 {
		t.Fatalf("want two host-matched error routes, got %#v", errorRoutes)
	}
	byHost := make(map[string]map[string]interface{}, len(errorRoutes))
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		matcher := routeMatcher(t, route)
		hosts, ok := matcher["host"].([]string)
		if !ok || len(hosts) != 1 {
			t.Fatalf("error route matcher host=%#v, want single host", matcher["host"])
		}
		byHost[hosts[0]] = route
	}
	alpha := byHost["alpha.example.test"]
	if alpha == nil {
		t.Fatalf("no error route matched for alpha.example.test: %#v", errorRoutes)
	}
	assertEqual(t, routeMatcher(t, alpha)["expression"], "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered') || ({http.error.status_code} == 451 && {http.error.message} == 'GeoIP blocked')")
	alphaHandler := firstHandler(t, alpha)
	assertEqual(t, alphaHandler["body"], "<html>alpha-block</html>")
	assertEqual(t, alphaHandler["status_code"], 451)
	beta := byHost["beta.example.test"]
	if beta == nil {
		t.Fatalf("no error route matched for beta.example.test: %#v", errorRoutes)
	}
	betaHandler := firstHandler(t, beta)
	assertEqual(t, betaHandler["body"], "<html>beta-block</html>")
	assertEqual(t, betaHandler["status_code"], 403)
}

func TestGenerateCaddyConfig_omitsErrorRoutes_whenRuleHasNoPolicyBinding(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_plain", "plain.example.test", 8080)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	_, server := serverErrorRoutes(t, generated, "http_8080")
	if _, exists := server["errors"]; exists {
		t.Fatalf("server errors config present for unbound rule: %#v", server["errors"])
	}
}

// TestGenerateCaddyConfig_blockPageErrorRoute_usesHighestPolicyID verifies the
// block-page error route resolves the highest-policy_id binding (mirroring
// GetSecurityPolicyForRule), so a newer bound policy wins over an older one.
func TestGenerateCaddyConfig_blockPageErrorRoute_usesHighestPolicyID(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_multi", "multi.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>older-block</html>")
	seedSecurityBlockPage(t, database, 8, "<html>newer-block</html>")
	// 同一规则绑定两条策略（policy_id 递增），须取 policy_id 最大者。
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_multi", 7, 451)
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_multi", 8, 503)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	if len(errorRoutes) != 1 {
		t.Fatalf("want exactly one error route, got %#v", errorRoutes)
	}
	handler := firstHandler(t, errorRoutes[0])
	assertEqual(t, handler["body"], "<html>newer-block</html>")
	assertEqual(t, handler["status_code"], 503)
}

// TestGenerateCaddyConfig_rateLimitErrorRoute_usesHighestPolicyID verifies the
// rate-limit error route also resolves the highest-policy_id binding.
func TestGenerateCaddyConfig_rateLimitErrorRoute_usesHighestPolicyID(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_rl_multi", "rl-multi.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>older-rl-block</html>")
	seedSecurityBlockPage(t, database, 8, "<html>newer-rl-block</html>")
	// 同一规则绑定两条限流策略（policy_id 递增），须取 policy_id 最大者。
	seedBoundSecurityPolicyWithRateLimitAndBlockPage(t, database, "lb_rl_multi", 7, 451, 100, 50)
	seedBoundSecurityPolicyWithRateLimitAndBlockPage(t, database, "lb_rl_multi", 8, 503, 100, 50)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	route := findRateLimitErrorRoute(t, generated)
	handler := firstHandler(t, route)
	assertEqual(t, handler["body"], "<html>newer-rl-block</html>")
	assertEqual(t, handler["status_code"], 503)
}

func TestGenerateCaddyConfig_rendersRateLimitErrorRoute_defaultsTo429(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_rl", "rl.example.test", 8080)
	seedSecurityBlockPage(t, database, 9, "<html>ratelimit-block</html>")
	seedBoundSecurityPolicyWithRateLimitAndBlockPage(t, database, "lb_rl", 9, 0, 100, 50)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	route := findRateLimitErrorRoute(t, generated)
	handler := firstHandler(t, route)
	assertEqual(t, handler["handler"], "static_response")
	assertEqual(t, handler["body"], "<html>ratelimit-block</html>")
	assertEqual(t, handler["status_code"], 429)
}

func TestGenerateCaddyConfig_rendersRateLimitErrorRoute_honorsBlockStatusCode(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_rl", "rl.example.test", 8080)
	seedSecurityBlockPage(t, database, 9, "<html>ratelimit-block</html>")
	seedBoundSecurityPolicyWithRateLimitAndBlockPage(t, database, "lb_rl", 9, 451, 100, 50)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	route := findRateLimitErrorRoute(t, generated)
	assertEqual(t, firstHandler(t, route)["status_code"], 451)
}

func findRateLimitErrorRoute(t *testing.T, generated map[string]interface{}) map[string]interface{} {
	t.Helper()
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		if expr, ok := routeMatcher(t, route)["expression"].(string); ok && expr == "{http.error.status_code} == 429" {
			return route
		}
	}
	t.Fatalf("rate-limit error route (matcher == 429) not found: %#v", errorRoutes)
	return nil
}

func TestBuildCorazaDirectives_emitsAclExclusionsThresholdAndBlockStatus(t *testing.T) {
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,crs_excluded_rules,block_page_id,enabled)
		VALUES ('full-policy','blocking',10,'deny','["203.0.113.0/24"]',1,'["942100"]',1,1)`)
	if err != nil {
		t.Fatalf("seed full policy: %v", err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_full',?)`, policyID); err != nil {
		t.Fatalf("bind full policy: %v", err)
	}

	policy := GetSecurityPolicyForRule("lb_full")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	if !policy.IPACLEnabled || policy.IPACLMode != "deny" {
		t.Fatalf("ip acl fields not loaded: enabled=%v mode=%q", policy.IPACLEnabled, policy.IPACLMode)
	}
	if len(policy.CRSExcludedRules) == 0 || policy.BlockPageID != 1 {
		t.Fatalf("exclusions/block page not loaded: excluded=%s block_page_id=%d", policy.CRSExcludedRules, policy.BlockPageID)
	}

	directives := BuildCorazaDirectives(policy)
	for _, want := range []string{
		"@ipMatch 203.0.113.0/24",
		"SecRuleRemoveById 942100",
		"setvar:tx.inbound_anomaly_score_threshold=10",
	} {
		if !strings.Contains(directives, want) {
			t.Fatalf("directives missing %q:\n%s", want, directives)
		}
	}
	// SecDefaultAction must NOT be emitted: crs-setup.conf already defines one
	// per phase and coraza rejects duplicates; blocking rides CRS 949 instead.
	if strings.Contains(directives, "SecDefaultAction") {
		t.Fatalf("directives must not redefine SecDefaultAction:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_allowModeDeniesNonListedIPs(t *testing.T) {
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_acl_mode,ip_acl_list,ip_acl_enabled,enabled)
		VALUES ('allow-policy','blocking','allow','["198.51.100.7"]',1,1)`)
	if err != nil {
		t.Fatalf("seed allow policy: %v", err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_allow',?)`, policyID); err != nil {
		t.Fatalf("bind allow policy: %v", err)
	}

	directives := BuildCorazaDirectives(GetSecurityPolicyForRule("lb_allow"))
	if !strings.Contains(directives, `!@ipMatch 198.51.100.7`) {
		t.Fatalf("allow mode must deny non-listed IPs via negated match:\n%s", directives)
	}
	if strings.Contains(directives, "@noMatch") {
		t.Fatalf("allow mode must not use the never-firing @noMatch operator:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_chainedCustomRuleCarriesActionsOnlyOnStarter(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:          "blocking",
		CRSRuleGroups: json.RawMessage(`["9"]`),
		CustomRules: json.RawMessage(`[{"id":7,"name":"链式验证","enabled":true,"action":"block","conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/admin"},` +
			`{"target":"args","operator":"contains","pattern":"debug=1"},` +
			`{"target":"user_agent","operator":"contains","pattern":"sqlmap"}]` +
			`}]`),
	}
	directives := BuildCorazaDirectives(policy)
	lines := strings.Split(directives, "\n")
	var chainLines []string
	for _, line := range lines {
		if strings.Contains(line, "id:10007") || (strings.Contains(line, "SecRule") && strings.Contains(line, "phase:1") && strings.Contains(line, "chain")) || strings.Contains(line, `"phase:1"`) {
			chainLines = append(chainLines, line)
		}
	}
	if len(chainLines) != 3 {
		t.Fatalf("want 3 chained SecRule lines, got %d:\n%s", len(chainLines), directives)
	}
	if !strings.Contains(chainLines[0], "id:10007") || !strings.Contains(chainLines[0], "deny") || !strings.Contains(chainLines[0], ",chain") {
		t.Fatalf("starter must carry id+disruptive+chain: %s", chainLines[0])
	}
	for i, line := range chainLines[1:] {
		if strings.Contains(line, "deny") || strings.Contains(line, "msg:") || strings.Contains(line, "id:") {
			t.Fatalf("non-starter line %d carries disruptive/meta actions (rejected by coraza v3): %s", i+1, line)
		}
	}
	if !strings.Contains(chainLines[1], ",chain") {
		t.Fatalf("intermediate rule must carry chain: %s", chainLines[1])
	}
	if strings.Contains(chainLines[2], ",chain") {
		t.Fatalf("final rule must not carry chain: %s", chainLines[2])
	}
}

func TestGenerateCaddyConfig_skips_redirect_route_when_same_domain_port80_rule_exists(t *testing.T) {
	useTemporaryCertDir(t)
	certPEM, keyPEM := matchingCertificatePair(t, "shadow.test")
	seed := func(t *testing.T, database *sql.DB, caddyID, domain string, listenPort int, tlsRedirect bool) {
		t.Helper()
		enableTLS, redirect := 0, 0
		tlsCert, tlsKey := "", ""
		if tlsRedirect {
			enableTLS, redirect = 1, 1
			tlsCert, tlsKey = certPEM, keyPEM
		}
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,'http',?,?,'weighted_round_robin',1,1,?,'manual',?,?,?)`,
			caddyID, caddyID, domain, listenPort, enableTLS, tlsCert, tlsKey, redirect); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')", caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	render := func(t *testing.T, seedFn func(*sql.DB)) string {
		t.Helper()
		_, database := newClusterTestService(t)
		seedFn(database)
		generated := generateCaddyConfigFromStore(database)
		if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("generate config: %s", message)
		}
		configJSON, err := json.Marshal(generated)
		if err != nil {
			t.Fatalf("marshal generated config: %v", err)
		}
		return string(configJSON)
	}

	t.Run("同域名 80 规则存在时跳过跳转路由生成", func(t *testing.T) {
		configJSON := render(t, func(database *sql.DB) {
			seed(t, database, "lb_redir_same", "shadow.test", 443, true)
			seed(t, database, "lb_80_same", "shadow.test", 80, false)
		})
		if strings.Contains(configJSON, "lb_redir_same_redirect") {
			t.Fatalf("同域名 80 规则存在时不应生成跳转路由: %s", configJSON)
		}
	})

	t.Run("不同域名正常生成跳转路由", func(t *testing.T) {
		configJSON := render(t, func(database *sql.DB) {
			seed(t, database, "lb_redir_other", "redirect.test", 443, true)
			seed(t, database, "lb_80_other", "plain.test", 80, false)
		})
		if !strings.Contains(configJSON, "lb_redir_other_redirect") {
			t.Fatalf("不同域名应生成跳转路由: %s", configJSON)
		}
	})
}

// R63 C-N2：DynamicDNS + weighted_round_robin 不再发射 weights=[1]——Caddy 的
// WeightedRoundRobinSelection 对 len(Weights)<2 早退恒选 pool[0]（不做可用性
// 检查），流量被钉死在解析列表首个 IP、其余 A 记录零流量，首 IP 宕机时
// try_duration 内重试全撞同一 IP 后 502。改发内建 random（按 Available() 过滤
// 后蓄水池随机）；静态规则仍发射权重表。
func TestGenerateSingleRuleCaddyConfig_dynamicDNS_selectionPolicy(t *testing.T) {
	// Given 动态 DNS 规则（单启用上游，策略为默认 weighted_round_robin）
	rule := baseHTTPRule()
	rule.DynamicDNS = true
	rule.Upstreams = rule.Upstreams[:1]

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	proxy := reverseProxyHandler(t, routes[0])
	lb := mustMap(t, proxy["load_balancing"], "load_balancing")
	selection := mustMap(t, lb["selection_policy"], "selection_policy")

	// Then 策略改发 random 且不携带 weights
	assertEqual(t, selection["policy"], "random")
	if _, has := selection["weights"]; has {
		t.Fatalf("dynamic-dns selection policy unexpectedly carries weights: %#v", selection)
	}
	if _, has := proxy["dynamic_upstreams"]; !has {
		t.Fatal("dynamic-dns proxy missing dynamic_upstreams")
	}

	// And 静态规则保持 weighted_round_robin + 权重表（回归保护）
	staticRoutes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(baseHTTPRule()))
	staticProxy := reverseProxyHandler(t, staticRoutes[0])
	staticLB := mustMap(t, staticProxy["load_balancing"], "load_balancing")
	staticSelection := mustMap(t, staticLB["selection_policy"], "selection_policy")
	assertEqual(t, staticSelection["policy"], "weighted_round_robin")
	assertEqual(t, staticSelection["weights"], []int{1, 2})
}

func TestApplyConfig_forceReloadHeader(t *testing.T) {
	// R72 二十五次：数据类更新（xdb/CRS/证书文件）不改变配置 JSON，Caddy 对字节
	// 相同的 /load 短路跳过 provision（errSameConfig）——force 变体必须带
	// Cache-Control: must-revalidate 绕过短路；常规 apply 不得带（避免无谓的
	// 全量重载开销）。
	var loads int
	var lastCacheControl string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			loads++
			lastCacheControl = r.Header.Get("Cache-Control")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	svc := NewCaddyService(server.URL)
	config := map[string]interface{}{"apps": map[string]interface{}{}}

	if err := svc.ApplyConfig(config); err != nil {
		t.Fatalf("regular apply: %v", err)
	}
	if loads != 1 {
		t.Fatalf("loads=%d, want 1", loads)
	}
	if lastCacheControl != "" {
		t.Fatalf("regular apply must not force reload, got Cache-Control=%q", lastCacheControl)
	}

	if err := svc.ApplyConfigForce(config); err != nil {
		t.Fatalf("force apply: %v", err)
	}
	if loads != 2 {
		t.Fatalf("loads=%d, want 2", loads)
	}
	if lastCacheControl != "must-revalidate" {
		t.Fatalf("force apply must send Cache-Control: must-revalidate, got %q", lastCacheControl)
	}
}

func TestApplyConfig_autoForceOnCertSnapshot(t *testing.T) {
	// R72 二十六次 W1-1：生成期 MaterializeCertPairs 写盘了证书文件（快照非空）
	// 时即使调用方走常规 ApplyConfig 也必须自动带 Cache-Control: must-revalidate
	// ——证书路径确定性意味着重传证书不改变 JSON，不强制会被 errSameConfig
	// 短路（旧证书继续服务）。快照为空时不得强制（避免冗余全量重载）。
	var lastCacheControl string
	forced := []bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			lastCacheControl = r.Header.Get("Cache-Control")
			forced = append(forced, lastCacheControl == "must-revalidate")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	svc := NewCaddyService(server.URL)

	base := map[string]interface{}{"apps": map[string]interface{}{}}
	withSnapshot := map[string]interface{}{"apps": map[string]interface{}{}}
	withSnapshot[caddyCertFilesSnapshotKey] = CertFilesSnapshot{"rule-1": {}}

	if err := svc.ApplyConfig(base); err != nil {
		t.Fatalf("plain apply: %v", err)
	}
	if len(forced) != 1 || forced[0] {
		t.Fatalf("plain config must not force reload, forced=%v", forced)
	}
	if err := svc.ApplyConfig(withSnapshot); err != nil {
		t.Fatalf("snapshot apply: %v", err)
	}
	if len(forced) != 2 || !forced[1] {
		t.Fatalf("non-empty cert snapshot must auto-force reload, forced=%v", forced)
	}
}
