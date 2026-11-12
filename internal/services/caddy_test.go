package services

import (
	"time"

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
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		// GET /config/ = 同字节短路门的只读快照（2026-09-25 审计真实性改造）——
		// 回 {}（与渲染必然不同、不触发短路），不占用 applied 缓冲（原实现把
		// 空 body 也写入容量 1 的 channel，后续 /load POST 卡死在写入端）。
		if request.Method == http.MethodGet && request.URL.Path == "/config/" {
			_, _ = response.Write([]byte(`{}`))
			return
		}
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

func TestGenerateCaddyConfig_defaultsNullStrategy(t *testing.T) {
	// Given an enabled legacy row whose nullable strategy was never backfilled.
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_null_strategy", false)
	if _, err := database.Exec("UPDATE lb_rules SET strategy=NULL WHERE caddy_id='lb_null_strategy'"); err != nil {
		t.Fatalf("seed null strategy: %v", err)
	}

	// When rendering the complete configuration.
	generated := generateCaddyConfigFromStore(database)

	// Then the row uses the schema default instead of poisoning the whole render.
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("null strategy blocked config generation: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_8080")
	proxy := reverseProxyHandler(t, routes[0])
	loadBalancing := mustMap(t, proxy["load_balancing"], "load balancing")
	selection := mustMap(t, loadBalancing["selection_policy"], "selection policy")
	if selection["policy"] != "weighted_round_robin" {
		t.Fatalf("selection policy=%v, want weighted_round_robin", selection["policy"])
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
		// 原用例以 path_rules 空数组 upstreams_json='[]' 触发
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

func TestGenerateCaddyConfig_propagatesCertificateMaterializationFailure(t *testing.T) {
	// Given 合法 PEM + 逃逸规则编号：错误只可能来自路径逃逸拒绝分支
	// （密钥对校验在前，非法 PEM 会让 ID 分支永不执行）。
	certDir := useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enable_tls,tls_source,tls_cert,tls_key) VALUES ('../invalid','invalid cert','http','example.com',443,'weighted_round_robin','',1,'manual',?,?)`, certPEM, keyPEM); err != nil {
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
	if err == nil || !strings.Contains(err.Error(), "非法的规则编号") {
		t.Fatalf("expected invalid rule ID rejection, got %v", err)
	}
	entries, readErr := os.ReadDir(certDir)
	if readErr != nil {
		t.Fatalf("read certificate directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid rule ID materialized %d files: %v", len(entries), entries)
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
	// Given 真实密钥对（非法 PEM 会在写盘前被拒，快照恒空 → 恢复分支零执行），
	// 第二对私钥的临时路径被目录占位 → 第一对已写盘后失败。
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "example.com")
	for _, ruleID := range []string{"a-valid", "z-fail"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enable_tls,tls_source,tls_cert,tls_key) VALUES (?,?, 'http','example.com',443,'weighted_round_robin','',1,'manual',?,?)`, ruleID, ruleID, certPEM, keyPEM); err != nil {
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
	// Given 真实密钥对：物化先写盘（快照非空），/load 被拒后 defer 必须恢复。
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enable_tls,tls_source,tls_cert,tls_key) VALUES ('lb-rejected','rejected cert','http','example.com',443,'weighted_round_robin','',1,'manual',?,?)`, certPEM, keyPEM); err != nil {
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
	loadRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/load" {
			loadRequests++
			http.Error(writer, "load rejected", http.StatusBadRequest)
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).ApplyConfig(GenerateCaddyConfig())

	// Then
	if err == nil {
		t.Fatal("Caddy load rejection reported success")
	}
	if loadRequests != 1 {
		t.Fatalf("Caddy /load received %d requests, want 1 (apply rejection branch)", loadRequests)
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

func TestGenerateSingleRuleCaddyConfig_tagsEveryOwnedAuxiliaryRoute(t *testing.T) {
	// Given（单规则形态仅服务预检，不插 HTTP→HTTPS 跳转分支——跳转由全量
	// 渲染 redirectRoutes 统一生成；辅助路由打钉覆盖路径路由形态）
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{SortOrder: 10, MatchType: "prefix", Path: "/api/"}}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then
	assertRouteIDs(t, routes, []string{"rule-http_path_0", "rule-http"})
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
	// 库值唯一真相批 1+2：健康检查族为值型列，构造即带有效值（0 值渲染报错）。
	rule := SingleRuleConfig{
		CaddyID: "rule-tcp", Protocol: "tcp", EnableActiveHealthCheck: true,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.10", Port: 3306, Enabled: true},
			{Host: "10.0.0.11", Port: 3307, Enabled: true},
		},
	}

	// When
	route, routeErr := buildTCPProxyRoute(rule)
	if routeErr != nil {
		t.Fatalf("buildTCPProxyRoute: %v", routeErr)
	}

	// Then
	proxy := firstHandler(t, route)
	healthChecks := mustMap(t, proxy["health_checks"], "health checks")
	active := mustMap(t, healthChecks["active"], "active health check")
	if _, exists := active["port"]; exists {
		t.Fatalf("implicit active health port should be omitted, got %#v", active["port"])
	}

	rule.TCPHealthCheckPort = 13306
	portRoute, portRouteErr := buildTCPProxyRoute(rule)
	if portRouteErr != nil {
		t.Fatalf("buildTCPProxyRoute with port: %v", portRouteErr)
	}
	active = mustMap(t, mustMap(t, firstHandler(t, portRoute)["health_checks"], "health checks")["active"], "active health check")
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
		// 库值唯一真相批 1+2：健康检查族为值型列，渲染直读零兜底——测试规则
		// 构造即带库态有效值（0 值渲染显性报错）。
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		GlobalRequestBodyMaxSizeMB:    128,
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
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}:8443{http.request.uri}"})
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
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}{http.request.uri}"})
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
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
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
	// 链首是 X-LB-Rule-ID 注入（headers），waf 紧随其后
	if names[0] != "headers" {
		t.Fatalf("chain head=%q, want headers (X-LB-Rule-ID inject) in %v", names[0], names)
	}
	// 新-1:request_body 限额前移至 waf 之前(coraza 读体无界)
	bodyIndex := indexOfHandler(names, "request_body")
	wafIndex := indexOfHandler(names, "waf")
	// 两个 handler 都在场是顺序断言的前提：request_body 整体消失时
	// 「-1 > wafIndex」恒假，顺序断言会静默通过（性质主体消失反而变绿）。
	if bodyIndex < 0 || wafIndex < 0 {
		t.Fatalf("request_body/waf 必须同时在链中: chain %v", names)
	}
	if bodyIndex > wafIndex {
		t.Fatalf("request_body must precede waf (coraza read-body DoS guard): chain %v", names)
	}
	if proxyIndex := indexOfHandler(names, "reverse_proxy"); proxyIndex <= wafIndex {
		t.Fatalf("waf must execute before reverse_proxy: chain %v", names)
	}
}

func TestGenerateRouteObject_rendersWafDetectionOnlyDirectives_whenDetectionPolicyBound(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
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
	// 缺库降级下任何策略都不会发射 waf——不桩库时本用例对门控零保护。
	stubSecurityLibsAvailable(t)
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
	// 缺库降级下 waf 恒缺席，桩库后本用例才真正验证「无绑定不发射」。
	stubSecurityLibsAvailable(t)
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
	// 缺库降级下 waf 恒缺席；桩库后「TCP 链不发射 waf」才具备证伪力。
	stubSecurityLibsAvailable(t)
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
// GenerateSingleRuleCaddyConfig delegates to the production builders and that
// its per-rule routes carry independent, hand-written expectations (selection
// policy / weights / health checks) plus a full-render (DB → generateCaddyConfig)
// byte comparison. The pure delegation comparison alone can only detect the
// delegation link being removed——两侧同源同参时任何渲染回归都同步漂移仍绿。
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

					// 独立期望（不经过生成器）：策略直映射、权重 gcd 约分、
					// 被动熔断窗口 = 间隔×3、主动检查路径直读。
					proxy := findChainHandler(t, ruleMainRoute(t, gotRoutes, rule.CaddyID), "reverse_proxy")
					if proxy == nil {
						t.Fatalf("reverse_proxy handler missing for rule route: %v", gotRoutes)
					}
					loadBalancing := mustMap(t, proxy["load_balancing"], "load_balancing")
					selectionPolicy := mustMap(t, loadBalancing["selection_policy"], "selection_policy")
					if got := selectionPolicy["policy"]; got != strategy {
						t.Fatalf("selection policy=%v, want %s", got, strategy)
					}
					if strategy == "weighted_round_robin" {
						// 上游权重 2/4 → gcd 约分 1/2。
						if got := fmt.Sprint(selectionPolicy["weights"]); got != "[1 2]" {
							t.Fatalf("weights=%s, want [1 2]（gcd 约分）", got)
						}
					}
					healthChecks := mustMap(t, proxy["health_checks"], "health_checks")
					passive := mustMap(t, healthChecks["passive"], "passive")
					if got, wantDuration := passive["fail_duration"], fmt.Sprintf("%ds", rule.HealthCheckInterval*3); got != wantDuration {
						t.Fatalf("passive fail_duration=%v, want %s", got, wantDuration)
					}
					if withExtras {
						active := mustMap(t, healthChecks["active"], "active")
						if got := active["uri"]; got != rule.HealthCheckPath {
							t.Fatalf("active health check uri=%v, want %s", got, rule.HealthCheckPath)
						}
					}
				})
			}
		}

		t.Run("tcp/"+strategy, func(t *testing.T) {
			rule := SingleRuleConfig{
				CaddyID: "rule-tcp", Protocol: "tcp", ListenPort: 3306, Strategy: strategy,
				HealthCheckInterval:           10,
				HealthCheckTimeout:            2,
				HealthCheckUnhealthyThreshold: 3,
				HealthCheckHealthyThreshold:   2,
				Upstreams: []UpstreamConfig{
					{Host: "10.0.0.10", Port: 3306, Weight: 2, Enabled: true},
					{Host: "10.0.0.11", Port: 3306, Weight: 1, Enabled: true},
				},
			}
			config := GenerateSingleRuleCaddyConfig(rule)
			apps := mustMap(t, config["apps"], "apps")
			layer4 := mustMap(t, apps["layer4"], "layer4 app")
			servers := mustMap(t, layer4["servers"], "layer4 servers")
			wantServer, serverErr := buildTCPServer(rule)
			if serverErr != nil {
				t.Fatalf("buildTCPServer: %v", serverErr)
			}
			assertEqual(t, servers["tcp_3306"], wantServer)
			// 独立期望：TCP 选择策略同样直映射。
			routes, ok := mustMap(t, servers["tcp_3306"], "tcp server")["routes"].([]interface{})
			if !ok || len(routes) == 0 {
				t.Fatalf("tcp server routes missing: %#v", servers["tcp_3306"])
			}
			proxy := findChainHandler(t, routes[0], "proxy")
			if proxy == nil {
				t.Fatalf("layer4 proxy handler missing: %#v", routes[0])
			}
			loadBalancing := mustMap(t, proxy["load_balancing"], "load_balancing")
			selection := mustMap(t, loadBalancing["selection"], "selection")
			wantPolicy := strategy
			if strategy == "cookie" {
				// layer4 无 cookie 策略：渲染回落 weighted_round_robin（如实映射）。
				wantPolicy = "weighted_round_robin"
			}
			if got := selection["policy"]; got != wantPolicy {
				t.Fatalf("tcp selection policy=%v, want %s", got, wantPolicy)
			}
		})
	}

	// 全量渲染路径（DB → generateCaddyConfigFromStore）与单规则预览的字节对照：
	// 覆盖委托比较看不到的组装差异（服务选择/发布集/证书门）。
	t.Run("full render parity", func(t *testing.T) {
		_, database := newClusterTestService(t)
		rule := baseHTTPRule()
		rule.Strategy = "least_conn"
		rule.ListenPort = 8099
		if _, err := database.Exec(`INSERT INTO lb_rules
			(caddy_id, name, protocol, domain, listen_port, strategy, enabled,
			 health_check_interval, health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold)
			VALUES (?, ?, 'http', ?, ?, 'least_conn', 1, 10, 2, 3, 2)`,
			rule.CaddyID, rule.CaddyID, rule.Domain, rule.ListenPort); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
		for _, upstream := range rule.Upstreams {
			if _, err := database.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, enabled, protocol) VALUES (?, ?, ?, ?, 1, 'http')`,
				rule.CaddyID, upstream.Host, upstream.Port, upstream.Weight); err != nil {
				t.Fatalf("seed upstream: %v", err)
			}
		}
		full := generateCaddyConfigFromStore(database)
		var filtered []interface{}
		for _, routeValue := range httpRoutesFromServer(t, full, "http_8099") {
			id, _ := mustMap(t, routeValue, "route")["@id"].(string)
			if RouteIDBelongsToRule(id, rule.CaddyID) {
				filtered = append(filtered, routeValue)
			}
		}
		if len(filtered) == 0 {
			t.Fatal("全量渲染未生成该规则路由——对照面为空")
		}
		single := httpRoutesFromServer(t, GenerateSingleRuleCaddyConfig(rule), "http_8099")
		assertEqual(t, filtered, single)
	})
}

// ruleMainRoute 在路由列表中按 @id 精确取主规则路由（规则路由可能伴随
// 跳转/路径/归因兄弟路由）。
func ruleMainRoute(t *testing.T, routes []interface{}, ruleID string) interface{} {
	t.Helper()
	ids := make([]string, 0, len(routes))
	for _, routeValue := range routes {
		id, _ := mustMap(t, routeValue, "route")["@id"].(string)
		ids = append(ids, id)
		if id == ruleID {
			return routeValue
		}
	}
	t.Fatalf("route %q not found: %v", ruleID, ids)
	return nil
}

func TestBuildWafHandler_nilMatrix(t *testing.T) {
	// 生产链的安全段受缺库降级门控，断言渲染前先桩库可用。
	stubSecurityLibsAvailable(t)
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
			// When：走生产构建路径（协议门控/策略绑定/可见性判定全在生产代码里，
			// 不在测试中复刻——此前自建门副本会掩盖生产门裂化）。
			var handler map[string]interface{}
			switch tc.caddyID {
			case "waf-tcp":
				// TCP 规则由 TCP 构建路径出配置（生产从不调用 WAF 构建器）。
				rule := SingleRuleConfig{
					CaddyID: "waf-tcp", Protocol: "tcp", ListenPort: 3306, Strategy: "weighted_round_robin",
					HealthCheckInterval: 10, HealthCheckTimeout: 2,
					HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
					Upstreams: []UpstreamConfig{{Host: "10.0.0.10", Port: 3306, Weight: 2, Enabled: true}},
				}
				server, tcpErr := buildTCPServer(rule)
				if tcpErr != nil {
					t.Fatalf("buildTCPServer: %v", tcpErr)
				}
				raw, marshalErr := json.Marshal(server)
				if marshalErr != nil {
					t.Fatalf("marshal tcp server: %v", marshalErr)
				}
				if strings.Contains(string(raw), `"handler":"waf"`) {
					t.Fatalf("TCP 构建路径不得发射 waf handler: %s", raw)
				}
				return
			default:
				rule := baseHTTPRule()
				rule.CaddyID = tc.caddyID
				chain, chainErr := buildHTTPHandleChain(rule, rule.Upstreams)
				if chainErr != nil {
					t.Fatalf("buildHTTPHandleChain(%q): %v", tc.caddyID, chainErr)
				}
				handler = findHandlerRecursive(chain, "waf")
			}

			// Then
			if !tc.wantWaf {
				if handler != nil {
					t.Fatalf("生产链(%q) 发射了 waf handler，want nil: %#v", tc.caddyID, handler)
				}
				return
			}
			if handler == nil {
				t.Fatalf("生产链(%q) 缺 waf handler，want waf", tc.caddyID)
			}
			directives, _ := handler["directives"].(string)
			if !strings.Contains(directives, tc.directive) {
				t.Fatalf("directives 不含 %q:\n%s", tc.directive, directives)
			}
		})
	}
}

// findHandlerRecursive 在构建产物（含 subroute 嵌套）中查找首个指定 handler 名。
func findHandlerRecursive(value interface{}, name string) map[string]interface{} {
	switch node := value.(type) {
	case map[string]interface{}:
		if node["handler"] == name {
			return node
		}
		for _, child := range node {
			if found := findHandlerRecursive(child, name); found != nil {
				return found
			}
		}
	case []interface{}:
		for _, child := range node {
			if found := findHandlerRecursive(child, name); found != nil {
				return found
			}
		}
	}
	return nil
}

func seedBoundSecurityPolicyWithRateLimit(t *testing.T, database *sql.DB, ruleCaddyID, mode string, rps, burst int) int {
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
	return int(policyID)
}

func TestGenerateRouteObject_omitsRateLimitHandler_whenPolicyRateLimitDisabled(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
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
	// 拦截页归因后：403 兜底（host 限定）+ 483 归因（该策略合成码，无 host）
	if len(errorRoutes) != 8 {
		t.Fatalf("want 8 error routes (3 JSON 变体 + HTML × [403 fallback + 483 attribution]), got %#v", errorRoutes)
	}
	var route, attrRoute map[string]interface{}
	for _, routeValue := range errorRoutes {
		r := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, r)["expression"].(string)
		if strings.Contains(expr, "== 403") {
			route = r
		} else if strings.Contains(expr, "== 483") {
			attrRoute = r
		}
	}
	if route == nil || attrRoute == nil {
		t.Fatalf("missing route kind: fallback=%v attribution=%v", route != nil, attrRoute != nil)
	}
	matcher := routeMatcher(t, route)
	assertEqual(t, matcher["host"], []string{"blocked.example.test"})
	// 兜底路由匹配 coraza 缺省 deny（403, message "interruption triggered"）——
	// 承接预检/无页策略中断；本策略自身 deny 已抬码 483 走归因路由。
	assertEqual(t, matcher["expression"], "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')")
	handler := firstHandler(t, route)
	assertEqual(t, handler["handler"], "static_response")
	assertEqual(t, handler["body"], "<html>branded-block</html>")
	assertEqual(t, handler["status_code"], 451)
	if route["terminal"] != true {
		t.Fatalf("error route must be terminal: %#v", route)
	}
	// 归因路由：483 子句、无 host、同页同码、terminal
	if _, hasHost := routeMatcher(t, attrRoute)["host"]; hasHost {
		t.Fatalf("attribution route must not carry host matcher: %#v", routeMatcher(t, attrRoute))
	}
	assertEqual(t, routeMatcher(t, attrRoute)["expression"], "({http.error.status_code} == 483 && {http.error.message} == 'interruption triggered')")
	attrHandler := firstHandler(t, attrRoute)
	assertEqual(t, attrHandler["body"], "<html>branded-block</html>")
	assertEqual(t, attrHandler["status_code"], 451)
	if attrRoute["terminal"] != true {
		t.Fatalf("attribution route must be terminal: %#v", attrRoute)
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
	// 每规则 1 条 403 兜底（host 限定）+ 每策略 1 条归因（483/484，无 host）
	if len(errorRoutes) != 16 {
		t.Fatalf("want 16 error routes (3 JSON 变体 + HTML × [2 fallback + 2 attribution]), got %#v", errorRoutes)
	}
	byHost := make(map[string]map[string]interface{}, len(errorRoutes))
	bySynthetic := make(map[string]map[string]interface{}, 2)
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		matcher := routeMatcher(t, route)
		expr, _ := matcher["expression"].(string)
		if hosts, ok := matcher["host"].([]string); ok && len(hosts) == 1 {
			byHost[hosts[0]] = route
			continue
		}
		for _, code := range []string{"483", "484"} {
			if strings.Contains(expr, "== "+code+" &&") {
				bySynthetic[code] = route
			}
		}
	}
	alpha := byHost["alpha.example.test"]
	if alpha == nil {
		t.Fatalf("no error route matched for alpha.example.test: %#v", errorRoutes)
	}
	// alpha 兜底：统一 403 WAF 中断子句（首绑定策略页）
	assertEqual(t, routeMatcher(t, alpha)["expression"], "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')")
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
	// 归因路由：483=alpha 策略（451），484=beta 策略（block_status_code 0 归一 403）
	attr481 := bySynthetic["483"]
	if attr481 == nil {
		t.Fatalf("no 483 attribution route: %#v", errorRoutes)
	}
	attr481Handler := firstHandler(t, attr481)
	assertEqual(t, attr481Handler["body"], "<html>alpha-block</html>")
	assertEqual(t, attr481Handler["status_code"], 451)
	attr482 := bySynthetic["484"]
	if attr482 == nil {
		t.Fatalf("no 484 attribution route: %#v", errorRoutes)
	}
	attr482Handler := firstHandler(t, attr482)
	assertEqual(t, attr482Handler["body"], "<html>beta-block</html>")
	assertEqual(t, attr482Handler["status_code"], 403)
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

// TestGenerateCaddyConfig_blockPageErrorRoute_usesFirstBoundPolicy verifies the
// 403 fallback error route renders the first-bound (lowest policy_id) enabled
// policy's page under v2.2.0 multi-policy binding — the fallback serves
// unattributable interruptions (merged IP precheck / page-less policies), while
// each page-bearing policy additionally gets its own synthetic-code attribution
// route (481/482) rendering its own page.
func TestGenerateCaddyConfig_blockPageErrorRoute_usesFirstBoundPolicy(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_multi", "multi.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>older-block</html>")
	seedSecurityBlockPage(t, database, 8, "<html>newer-block</html>")
	// 同一规则绑定两条策略（policy_id 递增），须取首绑定（policy_id 最小者）。
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_multi", 7, 451)
	seedBoundSecurityPolicyWithBlockPage(t, database, "lb_multi", 8, 503)

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	// 1 条 403 兜底（首绑定=older）+ 2 条归因（483=older, 484=newer）
	if len(errorRoutes) != 12 {
		t.Fatalf("want 12 error routes (3 JSON 变体 + HTML × [fallback + 2 attribution]), got %#v", errorRoutes)
	}
	var fallback map[string]interface{}
	bySynthetic := make(map[string]map[string]interface{}, 2)
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, route)["expression"].(string)
		if strings.Contains(expr, "== 403") {
			fallback = route
			continue
		}
		for _, code := range []string{"483", "484"} {
			if strings.Contains(expr, "== "+code+" &&") {
				bySynthetic[code] = route
			}
		}
	}
	if fallback == nil {
		t.Fatalf("missing 403 fallback route: %#v", errorRoutes)
	}
	handler := firstHandler(t, fallback)
	assertEqual(t, handler["body"], "<html>older-block</html>")
	assertEqual(t, handler["status_code"], 451)
	// 归因路由逐策略渲染各自拦截页（older=483/451，newer=484/503）
	h483 := firstHandler(t, bySynthetic["483"])
	assertEqual(t, h483["body"], "<html>older-block</html>")
	assertEqual(t, h483["status_code"], 451)
	h484 := firstHandler(t, bySynthetic["484"])
	assertEqual(t, h484["body"], "<html>newer-block</html>")
	assertEqual(t, h484["status_code"], 503)
}

// TestGenerateCaddyConfig_rateLimitErrorRoute_usesFirstBoundPolicy verifies the
// rate-limit error route also renders the first-bound enabled policy's page
// (lowest policy_id with BlockPageID > 0).
func findRateLimitErrorRoute(t *testing.T, generated map[string]interface{}) map[string]interface{} {
	t.Helper()
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		matcher := routeMatcher(t, route)
		// 双档：JSON 变体带 header matcher；HTML 主档是最后一条（无 header）。
		if expr, ok := matcher["expression"].(string); ok && expr == "{http.error.status_code} == 429" {
			if _, hasHeader := matcher["header"]; !hasHeader {
				return route
			}
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

	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	for _, want := range []string{
		"@ipListFast ",
		"SecRuleRemoveById 942100",
		"setvar:tx.inbound_anomaly_score_threshold=10",
	} {
		if !strings.Contains(directives, want) {
			t.Fatalf("directives missing %q:\n%s", want, directives)
		}
	}
	// ACL 名单内容钉：投影文件须含 203.0.113.0/24
	if got := readRenderedIPList(t, directives, "-acl"); !strings.Contains(got, "203.0.113.0/24") {
		t.Fatalf("ACL 名单文件须含 203.0.113.0/24: %q", got)
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

	directives := mustDirectives(BuildCorazaDirectives(GetSecurityPolicyForRule("lb_allow"), nil, "", false, 0, "lb_test"))
	if !strings.Contains(directives, `!@ipListFast `) {
		t.Fatalf("allow mode must deny non-listed IPs via negated match:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "-acl"); got != "198.51.100.7/32\n" {
		t.Fatalf("allow 名单文件=%q, want 仅 198.51.100.7/32", got)
	}
	if strings.Contains(directives, "@noMatch") {
		t.Fatalf("allow mode must not use the never-firing @noMatch operator:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_chainedCustomRuleCarriesActionsOnlyOnStarter(t *testing.T) {
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "blocking",
		CRSRuleGroups:    json.RawMessage(`["9"]`),
		CustomRules: json.RawMessage(`[{"id":7,"name":"链式验证","enabled":true,"action":"block","conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/admin"},` +
			`{"target":"args","operator":"contains","pattern":"debug=1"},` +
			`{"target":"user_agent","operator":"contains","pattern":"sqlmap"}]` +
			`}]`),
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	lines := strings.Split(directives, "\n")
	var chainLines []string
	for _, line := range lines {
		// id:9/id:10 body processor 激活规则同为 phase:1 SecRule，但与本测试
		// 关注的自定义链形状无关（2026-09-09 引入），按 ctl 标记排除。
		if strings.Contains(line, "ctl:requestBodyProcessor") {
			continue
		}
		if strings.Contains(line, "id:10007") || (strings.Contains(line, "SecRule") && strings.Contains(line, "phase:1")) {
			chainLines = append(chainLines, line)
		}
	}
	if len(chainLines) != 3 {
		t.Fatalf("want 3 chained SecRule lines, got %d:\n%s", len(chainLines), directives)
	}
	if !strings.Contains(chainLines[0], "id:10007") || !strings.Contains(chainLines[0], "deny") || !strings.Contains(chainLines[0], ",chain") {
		t.Fatalf("starter must carry id+disruptive+chain: %s", chainLines[0])
	}
	// 多条件链的 setvar 挪到末条——起始条命中而后续条件未命中时
	// coraza 已执行起始条非破坏性动作，起始条携带 setvar 会泄漏幽灵异常分。
	if strings.Contains(chainLines[0], "setvar:") {
		t.Fatalf("starter must not carry setvar (leaks on failed chain, 历史修复): %s", chainLines[0])
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
	if !strings.Contains(chainLines[2], "setvar:tx.inbound_anomaly_score_pl1=+0") {
		t.Fatalf("final rule must carry the setvar tail (历史修复): %s", chainLines[2])
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

// DynamicDNS + weighted_round_robin 不再发射 weights=[1]——Caddy 的
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
	// 数据类更新（xdb/CRS/证书文件）不改变配置 JSON，Caddy 对字节
	// 相同的 /load 短路跳过 provision（errSameConfig）——force 变体必须带
	// must-revalidate 绕过短路；常规 apply 不得带（避免无谓的
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
	// 生成期 MaterializeCertPairs 写盘了证书文件（快照非空）
	// 时即使调用方走常规 ApplyConfig 也必须自动带: must-revalidate
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

func TestHttpsRedirectLocationPreservesURI(t *testing.T) {
	// 补正：301 Location 必须携带 {http.request.uri}（path+query）——
	// v2.1.11 首发时该修复因实施脚本断言中止丢失且无测试兜底，发布信息与代码
	// 不一致。本断言锁定占位符在位，防止再次静默丢失。
	for _, port := range []int{443, 8443} {
		loc := httpsRedirectLocation(port)
		if !strings.Contains(loc, "{http.request.uri}") {
			t.Fatalf("httpsRedirectLocation(%d)=%q missing {http.request.uri}", port, loc)
		}
		if !strings.Contains(loc, "{http.request.host}") {
			t.Fatalf("httpsRedirectLocation(%d)=%q missing {http.request.host}", port, loc)
		}
	}
}

// 80/443 同样整体禁用 autoHTTPS——disable_certificates
// 下引擎仍恒向 http_80 追加被项目落地页遮蔽的 catch-all 308(死路由+
// superfluous WriteHeader 日志噪音+未来 terminal 化后盲导 443 的地雷);
// 跳转完全由项目自有 redirectRoutes 管理(TLSHTTPRedirect,任意端口)。
func TestGenerateCaddyConfig_autoHTTPSFullyDisabled(t *testing.T) {
	// 443 规则只在证书可用时进入发布集（无证书整条不发布），故物化真实密钥对，
	// 使 http_80 与 http_443 两个 server 同时在场参与断言。
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enable_tls,tls_source,tls_cert,tls_key,enabled) VALUES ('lb-autohttps','autohttps','http','example.com',443,'weighted_round_robin',1,'manual',?,?,1)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb-autohttps','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	config := GenerateCaddyConfig()
	if message, failed := config[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate: %s", message)
	}
	servers := config["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	for _, required := range []string{"http_80", "http_443"} {
		if _, exists := servers[required]; !exists {
			t.Fatalf("server %s missing: 断言前置不成立（servers=%v）", required, servers)
		}
	}
	for name, sv := range servers {
		server, ok := sv.(map[string]interface{})
		if !ok {
			continue
		}
		ah, ok := server["automatic_https"].(map[string]interface{})
		if !ok {
			continue
		}
		if ah["disable"] != true {
			t.Errorf("server %s automatic_https=%v, want disable:true (历史问题: 死路由消除)", name, ah)
		}
	}
}

// 2026-09-17 用户裁定:WAF 按请求量的拦截日志(WARN 引擎 debug + ERROR 插件
// 硬编码,同属 http.handlers.waf 命名空间)不得写入 caddy-server.log——事件
// 采集走 SecAuditLog→安全事件页(独立链路),服务器运行日志只留服务器事件。
func TestGenerateCaddyConfig_wafNamespaceExcludedFromServerLog(t *testing.T) {
	// Given 任意有效配置(需 DB 视图)
	newClusterTestService(t)
	cfg := GenerateCaddyConfig()
	// When 读取 caddy_server 日志条目
	logging, ok := cfg["logging"].(map[string]interface{})
	if !ok {
		t.Fatalf("logging missing in config")
	}
	logs, ok := logging["logs"].(map[string]interface{})
	if !ok {
		t.Fatalf("logging.logs missing")
	}
	server, ok := logs["caddy_server"].(map[string]interface{})
	if !ok {
		t.Fatalf("logs.caddy_server missing")
	}
	excludes, _ := server["exclude"].([]string)
	// Then exclude 必须包含 http.handlers.waf(WARN/ERROR 两行同源该命名空间)
	found := false
	for _, e := range excludes {
		if e == "http.handlers.waf" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("caddy_server exclude missing http.handlers.waf: %v", excludes)
	}
}

// Given 后台 Force 重载与 handler 写路径（原 caddyOpMu——现共享 CaddyOpLock）。
// When 两类写者并发。
// Then 全程互斥（曾后台仅持 s.mu，apply→commit 边界混合态窗口——
// 此处钉「同一把锁」的结构事实：Force 持锁期间 handler 侧锁必须等待）。
func TestCaddyOpLockSharedBetweenForceAndHandlers(t *testing.T) {
	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		CaddyOpLock.Lock()
		close(acquired)
		<-released
		CaddyOpLock.Unlock()
	}()
	<-acquired
	// handler 侧尝试取锁（带超时证阻塞）
	locked := make(chan struct{})
	go func() {
		CaddyOpLock.Lock()
		close(locked)
		CaddyOpLock.Unlock()
	}()
	select {
	case <-locked:
		close(released)
		t.Fatal("Force 持锁期间 handler 侧不应获得锁（跨层互斥失效）")
	case <-time.After(150 * time.Millisecond):
	}
	close(released)
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("释放后 handler 侧应获得锁")
	}
}

// ExtractMetricLabel
// 边界感知收敛——裸子串匹配会把 peer_upstream 等
// 前缀兄弟标签的值误归到 upstream（现实标签集暂无前缀兄弟，防御性收敛）。
func TestExtractMetricLabel_boundaryAware(t *testing.T) {
	sibling := `caddy_reverse_proxy_upstreams_healthy{peer_upstream="10.0.0.1:80",upstream="10.0.0.2:80"} 1`
	if got := ExtractMetricLabel(sibling, "upstream"); got != "10.0.0.2:80" {
		t.Fatalf("upstream=%q, want 10.0.0.2:80（peer_upstream 不得误命中）", got)
	}
	if got := ExtractMetricLabel(sibling, "peer_upstream"); got != "10.0.0.1:80" {
		t.Fatalf("peer_upstream=%q, want 10.0.0.1:80", got)
	}
	first := `caddy_layer4_proxy_upstream_healthy{upstream="10.0.0.3:80"} 0`
	if got := ExtractMetricLabel(first, "upstream"); got != "10.0.0.3:80" {
		t.Fatalf("首标签边界（{upstream=\"）失效: %q", got)
	}
	absent := `caddy_reverse_proxy_upstreams_healthy{other="x"} 1`
	if got := ExtractMetricLabel(absent, "upstream"); got != "" {
		t.Fatalf("无目标标签应返回空串: %q", got)
	}
	unterminated := `caddy_reverse_proxy_upstreams_healthy{upstream="10.0.0.4`
	if got := ExtractMetricLabel(unterminated, "upstream"); got != "" {
		t.Fatalf("值未闭合应返回空串: %q", got)
	}
}

// ---- 回归钉 ----

// 候选装载阶段必须预解析 Leaf（disabled 候选除外），供
// selectCertificate 走快路径并供过期回退复用。
func TestACMECertCandidatesForRule_preparses_leaf(t *testing.T) {
	_, database := newClusterTestService(t)
	seedRuleWithCAProvider(t, "lb_leaf", "leaf.example.test", 0)
	certPEM, keyPEM := matchingCertificatePair(t, "leaf.example.test")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_leaf','leaf.example.test','issued',?,?),
		('lb_leaf','disabled.leaf.example.test','disabled',?,?)`, certPEM, keyPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}

	// When
	candidates := acmeCertCandidatesForRule(database, "lb_leaf")

	// Then
	if len(candidates) != 2 {
		t.Fatalf("candidates=%d, want 2", len(candidates))
	}
	for _, candidate := range candidates {
		if candidate.Status == "disabled" {
			if candidate.Leaf != nil {
				t.Fatal("disabled candidate must skip leaf pre-parse")
			}
			continue
		}
		if candidate.Leaf == nil {
			t.Fatal("issued candidate leaf not pre-parsed")
		}
		if candidate.Leaf.Subject.CommonName != "leaf.example.test" {
			t.Fatalf("leaf CN=%q, want leaf.example.test", candidate.Leaf.Subject.CommonName)
		}
	}
}

// 健康聚合单飞必须 panic 安全：聚合内部 panic 若直接冲出，healthInflight
// 永久驻留 → 所有后续调用阻塞在 <-call.done 上（健康面板永久悬挂、无法自愈）。
func TestUpstreamHealthSingleflight_panicDoesNotStrandInflight(t *testing.T) {
	s := NewCaddyService("http://127.0.0.1:1")
	defer func() {
		if recover() == nil {
			t.Fatal("panic 必须向首个调用方传播")
		}
		// panic 之后单飞槽位必须已释放：下一次调用发起新的聚合并返回值。
		// 超时判定用 goroutine：旧实现（槽位未清）会让该调用永久阻塞，测试
		// 必须显式失败而不是挂到全局超时。
		type result struct {
			health map[string]map[string]*UpstreamHealthDetail
			err    error
		}
		done := make(chan result, 1)
		go func() {
			health, err := s.aggregateUpstreamHealthWithSingleflight(func() (map[string]map[string]*UpstreamHealthDetail, error) {
				return map[string]map[string]*UpstreamHealthDetail{"srv": {"1.2.3.4:80": {Healthy: true}}}, nil
			})
			done <- result{health, err}
		}()
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatalf("post-panic call err=%v", got.err)
			}
			if got.health["srv"]["1.2.3.4:80"] == nil || !got.health["srv"]["1.2.3.4:80"].Healthy {
				t.Fatalf("post-panic aggregate=%+v", got.health)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("panic 后单飞槽位仍被占用（后续调用永久阻塞）")
		}
	}()
	s.aggregateUpstreamHealthWithSingleflight(func() (map[string]map[string]*UpstreamHealthDetail, error) {
		panic("boom")
	})
}

// 全局链钉测试：global_config.server_tokens_hidden=1（全局
// TRUE）→ 全量渲染为规则发射 deferred Server 删除 headers handler。规则级
// 覆盖（0/1/2）已有 TestGenerateSingleRuleCaddyConfig_serverTokensHidden*
// 钉，本测试钉「全局列 → resolveRuleOverrides → handler 发射」链路本身。
func TestGenerateCaddyConfig_globalServerTokensHiddenEmitsDeleteHandler(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_server_tokens", false)
	if _, err := database.Exec("UPDATE global_config SET server_tokens_hidden=1 WHERE id=1"); err != nil {
		t.Fatalf("set global server_tokens_hidden: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("config generation failed: %s", message)
	}

	routes := httpRoutesFromServer(t, generated, "http_8080")
	hasServerDelete := func(routes []interface{}) bool {
		for _, routeValue := range routes {
			route := mustMap(t, routeValue, "route")
			handlers, ok := route["handle"].([]interface{})
			if !ok {
				continue
			}
			for _, handlerValue := range handlers {
				handler := mustMap(t, handlerValue, "handler")
				if handler["handler"] != "headers" {
					continue
				}
				response := mustMap(t, handler["response"], "headers response ops")
				if response["deferred"] == true {
					if deletes, ok := response["delete"].([]string); ok && len(deletes) == 1 && deletes[0] == "Server" {
						return true
					}
				}
			}
		}
		return false
	}
	if !hasServerDelete(routes) {
		t.Fatalf("global server_tokens_hidden=1 must emit deferred Server delete handler: %#v", routes)
	}

	// 负对照：全局关闭时不得发射该 handler（防恒真钉测）。
	if _, err := database.Exec("UPDATE global_config SET server_tokens_hidden=0 WHERE id=1"); err != nil {
		t.Fatalf("clear global server_tokens_hidden: %v", err)
	}
	generatedOff := generateCaddyConfigFromStore(database)
	if hasServerDelete(httpRoutesFromServer(t, generatedOff, "http_8080")) {
		t.Fatal("global server_tokens_hidden=0 must not emit Server delete handler")
	}
}
