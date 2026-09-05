package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestRuleFeatures_rejects_invalid_path_rule_inputs(t *testing.T) {
	tests := []struct {
		name      string
		input     ruleFeatureInput
		wantError string
	}{
		{
			name: "path rules while disabled",
			input: ruleFeatureInput{Protocol: "http", PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "/metrics/",
			}}},
			wantError: "自定义路径规则未启用",
		},
		{
			name: "path without slash",
			input: ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "metrics/",
			}}},
			wantError: "必须以 / 开头",
		},
		{
			name: "invalid match type",
			input: ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "regex",
				Path:      "/metrics/",
			}}},
			wantError: "匹配类型",
		},
		{
			name: "blank custom upstream address",
			input: ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "/metrics/",
				Upstreams: []models.PathRuleUpstream{{Address: " ", Port: 9090, Weight: 1}},
			}}},
			wantError: "上游地址不能为空",
		},
		{
			name: "custom upstream port out of range",
			input: ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "/metrics/",
				Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 65536, Weight: 1}},
			}}},
			wantError: "端口必须在 1-65535",
		},
		{
			name: "negative custom upstream weight",
			input: ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "exact",
				Path:      "/health",
				Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9090, Weight: -1}},
			}}},
			wantError: "权重不能为负数",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			err := validateRuleFeatures(test.input)

			// Then
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateRuleFeatures_protocol_aware_strategy_whitelist(t *testing.T) {
	tests := []struct {
		name      string
		input     ruleFeatureInput
		wantError string
	}{
		{
			name:      "TCP with cookie rejected",
			input:     ruleFeatureInput{Protocol: "tcp", Strategy: "cookie"},
			wantError: "TCP 规则仅支持",
		},
		{
			name:      "HTTP with cookie allowed",
			input:     ruleFeatureInput{Protocol: "http", Strategy: "cookie"},
			wantError: "",
		},
		{
			name:      "TCP with weighted_round_robin allowed",
			input:     ruleFeatureInput{Protocol: "tcp", Strategy: "weighted_round_robin"},
			wantError: "",
		},
		{
			name:      "HTTP with bogus strategy rejected",
			input:     ruleFeatureInput{Protocol: "http", Strategy: "bogus"},
			wantError: "HTTP 规则仅支持",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRuleFeatures(test.input)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateRuleFeatures() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateRuleFeatures_rejects_tcp_with_dynamic_dns(t *testing.T) {
	tests := []struct {
		name      string
		input     ruleFeatureInput
		wantError string
	}{
		{
			name:      "TCP with dynamic DNS rejected",
			input:     ruleFeatureInput{Protocol: "tcp", DynamicDNS: true},
			wantError: "TCP 规则不支持动态上游",
		},
		{
			name:      "HTTP with dynamic DNS allowed",
			input:     ruleFeatureInput{Protocol: "http", DynamicDNS: true, EnabledUpstreamCount: 1},
			wantError: "",
		},
		{
			name:      "TCP without dynamic DNS allowed",
			input:     ruleFeatureInput{Protocol: "tcp"},
			wantError: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			err := validateRuleFeatures(test.input)

			// Then
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateRuleFeatures() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestDuplicateRule_rejects_TCP_with_cookie_strategy(t *testing.T) {
	// Given：源规则为 TCP + cookie 策略，复制时必须拒绝（cookie 仅 HTTP 支持）
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,strategy,enabled,enable_compress) VALUES ('lb_duptcpcookie','tcp-cookie','tcp',13010,'cookie',1,1)`); err != nil {
		t.Fatalf("seed tcp cookie rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_duptcpcookie','127.0.0.1',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", func(c *gin.Context) {
		c.Set("user_id", 1)
		handler.DuplicateRule(c)
	})
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_duptcpcookie/duplicate", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "TCP 规则仅支持") {
		t.Fatalf("duplicate tcp+cookie status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id != 'lb_duptcpcookie'`).Scan(&count); err != nil {
		t.Fatalf("count duplicated rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("duplicated rule count=%d, want 0", count)
	}
}

func TestCreateRule_rejects_empty_domain_for_HTTP(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"no-domain","protocol":"http","listen_port":8080,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名不能为空") {
		t.Fatalf("create empty-domain status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestUpdateRule_rejects_empty_domain_for_HTTP(t *testing.T) {
	// Given：存量空域名 HTTP 规则（历史/导入数据），更新后仍为空域名必须拒绝
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress) VALUES ('lb_nodomain','legacy','','http','',8080,'weighted_round_robin','',1,1)`); err != nil {
		t.Fatalf("seed legacy empty-domain rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_nodomain','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_nodomain", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名不能为空") {
		t.Fatalf("update empty-domain status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestCreateRule_rejects_manual_TLS_without_certificate(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"manual-nocert","protocol":"http","domain":"manual-nocert.example.test","listen_port":8443,"enable_tls":true,"tls_source":"manual","upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "手动证书模式下必须提供 TLS 证书和私钥") {
		t.Fatalf("create manual TLS without material status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestCreateRule_rejects_unknown_tls_source(t *testing.T) {
	// Given：启用 TLS 时证书来源必须为 manual 或 acme_dns，否则保存为无证书材料的死 TLS
	tests := []struct {
		name      string
		tlsSource string
		domain    string
	}{
		{name: "empty source", tlsSource: "", domain: "tls-empty-source.example.test"},
		{name: "bogus source", tlsSource: "bogus", domain: "tls-bogus-source.example.test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newRuleFeatureTestHandlers(t)
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/rules", handler.CreateRule)
			body := fmt.Sprintf(`{"name":"tls-source","protocol":"http","domain":%q,"listen_port":0,"enable_tls":true,"tls_source":%q,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, test.domain, test.tlsSource)
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "证书来源") {
				t.Fatalf("create tls_source=%q status=%d body=%s, want 400", test.tlsSource, response.Code, response.Body.String())
			}
		})
	}
}

func TestUpdateRule_replaces_path_rules_wholesale_within_rule_save(t *testing.T) {
	// Given
	handler, postedConfig := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress) VALUES ('lb_updatepaths','paths','','http','example.test',8080,'weighted_round_robin','',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_updatepaths','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_updatepaths',0,'prefix','/old-a/'),('lb_updatepaths',1,'exact','/old-b')`); err != nil {
		t.Fatalf("seed path rules: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_updatepaths", strings.NewReader(`{"custom_routes_enabled":true,"path_rules":[{"sort_order":5,"match_type":"prefix","path":"/new/","upstreams":null}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var path string
	var count int
	if err := db.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_updatepaths'),(SELECT path FROM path_rules WHERE rule_id='lb_updatepaths') FROM lb_rules WHERE caddy_id='lb_updatepaths'`).Scan(&count, &path); err != nil {
		t.Fatalf("read updated rule features: %v", err)
	}
	if count != 1 || path != "/new/" {
		t.Fatalf("updated rule features count=%d path=%q", count, path)
	}
	if !strings.Contains(*postedConfig, `"/new/*"`) {
		t.Fatalf("posted Caddy config missing path route: %s", *postedConfig)
	}
}

func newRuleFeatureTestHandlers(t *testing.T) *Handlers {
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	return handler
}

func newRuleFeatureTestHandlersWithCapture(t *testing.T) (*Handlers, *string) {
	t.Helper()
	initializeRuleFeatureTestDB(t)
	fullConfig := `{"apps":{"http":{"servers":{"http_8080":{"routes":[{"@id":"lb_updatepaths","handle":[]}]}}}}}`
	postedConfig := ""
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/id/") {
			_, _ = response.Write([]byte(`{"@id":"lb_updatepaths","handle":[]}`))
			return
		}
		if request.Method == http.MethodGet && request.URL.Path == "/config/" {
			_, _ = response.Write([]byte(fullConfig))
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/config/" {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			postedConfig = string(body)
		}
		if request.Method == http.MethodPost && request.URL.Path == "/load" {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			postedConfig = string(body)
			fullConfig = string(body)
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	return &Handlers{
		cfg:            cfg,
		caddyService:   services.NewCaddyService(fakeCaddy.URL),
		clusterService: services.NewClusterService(db.DB, nil),
	}, &postedConfig
}

func TestCreateRule_accepts_API_key_user_ID_and_succeeds_with_all_feature_columns(t *testing.T) {
	// Given：全列 INSERT（曾出现 44/45 占位符不匹配，防回归）
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", func(c *gin.Context) {
		c.Set("user_id", 1)
		handler.CreateRule(c)
	})
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"全字段 TCP 规则","protocol":"tcp","listen_port":13000,
		"tcp_health_check_port":9000,"tcp_proxy_protocol":true,"tcp_try_duration":5,"tcp_try_interval":250,
		"upstreams":[{"host":"127.0.0.1","port":9000,"weight":1,"enabled":true}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var name string
	var proxyProtocol bool
	var createdBy int64
	if err := db.DB.QueryRow(`SELECT name, COALESCE(tcp_proxy_protocol,0), created_by FROM lb_rules WHERE listen_port=13000`).Scan(&name, &proxyProtocol, &createdBy); err != nil {
		t.Fatalf("read created rule: %v", err)
	}
	if !proxyProtocol || createdBy != 1 {
		t.Fatalf("created rule proxy_protocol=%v created_by=%d", proxyProtocol, createdBy)
	}
}

func TestDuplicateRule_accepts_API_key_user_ID_and_copies_rule_upstreams_and_path_rules(t *testing.T) {
	// Given：复制规则全链路（曾出现 48/46 与 9/10 占位符不匹配，防回归）
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,dns_server,dns_family,
		health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,
		enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,
		request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,
		enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,
		enable_compress,compress_types,enabled,created_by,updated_by,host_header,log_enabled,
		custom_routes_enabled,
		proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay)
		VALUES ('lb_dupsrc','源规则','','http','dup.example.test',8080,'weighted_round_robin',0,0,'','ipv4',
		'',10,5,3,2,0,0,0,5,250,0,0,0,1,'manual',0,0,'','',0,1,'gzip',1,1,1,'',1,
		1,5,15,30,30,0,0,0)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_dupsrc','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_dupsrc',0,'prefix','/metrics/')`); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", func(c *gin.Context) {
		c.Set("user_id", 1)
		handler.DuplicateRule(c)
	})
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_dupsrc/duplicate", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("duplicate status=%d body=%s", response.Code, response.Body.String())
	}
	var newID string
	var upstreamCount, pathCount, customRoutes int
	var createdBy, updatedBy int64
	if err := db.DB.QueryRow(`SELECT caddy_id, custom_routes_enabled, created_by, updated_by,
		(SELECT COUNT(*) FROM upstreams WHERE rule_id=lb_rules.caddy_id),
		(SELECT COUNT(*) FROM path_rules WHERE rule_id=lb_rules.caddy_id)
		FROM lb_rules WHERE caddy_id != 'lb_dupsrc'`).Scan(&newID, &customRoutes, &createdBy, &updatedBy, &upstreamCount, &pathCount); err != nil {
		t.Fatalf("read duplicated rule: %v", err)
	}
	if newID == "" || customRoutes != 1 || createdBy != 1 || updatedBy != 1 || upstreamCount != 1 || pathCount != 1 {
		t.Fatalf("duplicated rule incomplete: id=%q custom=%d created_by=%d updated_by=%d ups=%d paths=%d", newID, customRoutes, createdBy, updatedBy, upstreamCount, pathCount)
	}
}

func TestCreateRule_persists_requested_DNS_family(t *testing.T) {
	tests := []struct {
		family string
		port   int
	}{
		{family: "ipv6", port: 13001},
		{family: "both", port: 13002},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			// Given
			handler, _ := newRuleFeatureTestHandlersWithCapture(t)
			router := gin.New()
			router.POST("/rules", handler.CreateRule)
			// N+12 G8-S1：TCP+dynamic_dns 保存侧已拒绝，dns_family 持久化改用 HTTP 载体。
			body := strings.NewReader(fmt.Sprintf(`{"name":"dns-%s","protocol":"http","domain":"dns-%s.example.test","listen_port":%d,"dynamic_dns":true,"dns_family":"%s","upstreams":[{"host":"example.test","port":9000,"enabled":true}]}`, test.family, test.family, test.port, test.family))
			request := httptest.NewRequest(http.MethodPost, "/rules", body)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusCreated {
				t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
			}
			var family string
			if err := db.DB.QueryRow("SELECT dns_family FROM lb_rules WHERE listen_port = ?", test.port).Scan(&family); err != nil {
				t.Fatalf("read dns_family: %v", err)
			}
			if family != test.family {
				t.Fatalf("dns_family=%q, want %q", family, test.family)
			}
		})
	}
}

func TestCreateRule_does_not_require_CA_provider_outside_ACME(t *testing.T) {
	tests := []struct {
		name string
		body func(t *testing.T) string
		port int
	}{
		{
			name: "TCP rule",
			body: func(*testing.T) string {
				return `{"name":"tcp-no-ca","protocol":"tcp","listen_port":13003,"ca_provider_id":999,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
			},
			port: 13003,
		},
		{
			name: "manual TLS rule",
			body: func(t *testing.T) string {
				certPEM, keyPEM, err := generateTestCert("manual.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
				if err != nil {
					t.Fatalf("generate certificate: %v", err)
				}
				payload, err := json.Marshal(map[string]any{
					"name": "manual-no-ca", "protocol": "http", "domain": "manual.example.test", "listen_port": 13004,
					"enable_tls": true, "tls_source": "manual", "tls_cert": certPEM, "tls_key": keyPEM,
					"upstreams": []map[string]any{{"host": "127.0.0.1", "port": 9000, "enabled": true}},
				})
				if err != nil {
					t.Fatalf("encode request: %v", err)
				}
				return string(payload)
			},
			port: 13004,
		},
		{
			name: "HTTP rule without TLS",
			body: func(*testing.T) string {
				return `{"name":"http-no-ca","protocol":"http","domain":"plain.example.test","listen_port":13005,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
			},
			port: 13005,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			oldCertDir := testServicesCertDir
			testServicesCertDir = t.TempDir()
			t.Cleanup(func() { testServicesCertDir = oldCertDir })
			handler, _ := newRuleFeatureTestHandlersWithCapture(t)
			if _, err := db.DB.Exec("UPDATE ca_providers SET enabled=0"); err != nil {
				t.Fatalf("disable CA providers: %v", err)
			}
			router := gin.New()
			router.POST("/rules", handler.CreateRule)
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(test.body(t)))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusCreated {
				t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
			}
			var providerID int
			if err := db.DB.QueryRow("SELECT ca_provider_id FROM lb_rules WHERE listen_port=?", test.port).Scan(&providerID); err != nil {
				t.Fatalf("read persisted CA provider: %v", err)
			}
			if providerID != 0 {
				t.Fatalf("persisted provider=%d, want 0", providerID)
			}
		})
	}
}

func TestCreateRule_resolves_default_CA_provider_for_ACME(t *testing.T) {
	// Given
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	var defaultProviderID int
	if err := db.DB.QueryRow("SELECT default_ca_provider_id FROM global_config WHERE id=1").Scan(&defaultProviderID); err != nil {
		t.Fatalf("read default CA provider: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('default-ca-dns','dnspod','{"token":"test"}',1)`)
	if err != nil {
		t.Fatalf("seed DNS provider: %v", err)
	}
	dnsConfigID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read DNS provider ID: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	requestBody := fmt.Sprintf(`{"name":"default-ca","protocol":"http","domain":"default-ca.example.test","listen_port":13006,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, dnsConfigID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var providerID int
	if err := db.DB.QueryRow("SELECT ca_provider_id FROM lb_rules WHERE listen_port=13006").Scan(&providerID); err != nil {
		t.Fatalf("read persisted CA provider: %v", err)
	}
	if providerID != defaultProviderID || providerID == 0 {
		t.Fatalf("persisted provider=%d, want resolved default %d", providerID, defaultProviderID)
	}
}

func TestReplacePathRulesTx_replaces_all_rows_and_preserves_nullable_upstreams(t *testing.T) {
	// Given
	database := initializeRuleFeatureTestDB(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_paths1','paths','http',8080)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json) VALUES
		('lb_paths1',0,'prefix','/old-a/',NULL),
		('lb_paths1',1,'exact','/old-b','[]')`); err != nil {
		t.Fatalf("seed path rules: %v", err)
	}
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	newRules := []models.PathRule{
		{SortOrder: 10, MatchType: "prefix", Path: "/inherited/", Upstreams: nil},
		{SortOrder: 20, MatchType: "exact", Path: "/custom", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9100, Weight: 2}}},
	}

	// When
	if err := replacePathRulesTx(context.Background(), tx, "lb_paths1", newRules); err != nil {
		_ = tx.Rollback()
		t.Fatalf("replace path rules: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit replacement: %v", err)
	}
	loaded, err := loadPathRules(context.Background(), database, "lb_paths1")

	// Then
	if err != nil {
		t.Fatalf("load path rules: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("path rule count = %d, want 2", len(loaded))
	}
	if loaded[0].Path != "/inherited/" || loaded[0].Upstreams != nil {
		t.Fatalf("inherited path rule = %#v", loaded[0])
	}
	if loaded[1].Path != "/custom" || len(loaded[1].Upstreams) != 1 || loaded[1].Upstreams[0].Port != 9100 {
		t.Fatalf("custom path rule = %#v", loaded[1])
	}
}

// Round 35 F-1: loader 与渲染侧同口径（NULL 视禁用）——此前 COALESCE(enabled,1)
// 把遗留 NULL 行视为启用，UI 显示与生成配置分裂。
func TestLoadUpstreamsBatch_defaults_NULL_enabled_to_false(t *testing.T) {
	// Given
	database := initializeRuleFeatureTestDB(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_null_upstream','nullable upstream','http',8080)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	simulateLegacyNullableUpstreams(t, database)
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_null_upstream','127.0.0.1',9000,NULL)`); err != nil {
		t.Fatalf("seed nullable upstream: %v", err)
	}

	// When
	upstreams, err := loadUpstreamsBatch(context.Background(), []string{"lb_null_upstream"})

	// Then NULL 视禁用（与渲染 IIF(enabled IN ('1',1),1,0) 一致）
	if err != nil {
		t.Fatalf("load upstreams: %v", err)
	}
	if len(upstreams["lb_null_upstream"]) != 1 || upstreams["lb_null_upstream"][0].Enabled {
		t.Fatalf("loaded upstreams = %#v, want one disabled upstream", upstreams["lb_null_upstream"])
	}
}

// Round 35 F-1: 存量库的 NULL enabled 上游在初始化迁移后归一化为 0（NULL 视禁用），
// 不再存在 NULL 行；迁移幂等，重跑无副作用。
func TestMigration_upstreamsEnabledNullNormalizedToDisabled(t *testing.T) {
	// Given 模拟迁移前的存量库：先初始化建表，再回退为可空 enabled 并写入 NULL 行
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if err := db.Initialize(dir); err != nil {
		t.Fatalf("first initialize: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_null_mig','nullable','http',8081)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	simulateLegacyNullableUpstreams(t, db.DB)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_null_mig','127.0.0.1',9000,NULL), ('lb_null_mig','127.0.0.1',9001,1)`); err != nil {
		t.Fatalf("seed nullable upstreams: %v", err)
	}

	// When 再次初始化触发迁移（UPDATE upstreams SET enabled=0 WHERE enabled IS NULL）
	if err := db.Initialize(dir); err != nil {
		t.Fatalf("second initialize (migration): %v", err)
	}

	// Then NULL 行消失，原 NULL 行走 0，正常行保持 1
	var nullCount, enabledSum int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE rule_id='lb_null_mig' AND enabled IS NULL`).Scan(&nullCount); err != nil {
		t.Fatalf("count null upstreams: %v", err)
	}
	if nullCount != 0 {
		t.Fatalf("null enabled rows=%d, want 0 after migration", nullCount)
	}
	if err := db.DB.QueryRow(`SELECT SUM(enabled) FROM upstreams WHERE rule_id='lb_null_mig'`).Scan(&enabledSum); err != nil {
		t.Fatalf("sum enabled upstreams: %v", err)
	}
	if enabledSum != 1 {
		t.Fatalf("enabled sum=%d, want 1 (NULL→0, 1 保持)", enabledSum)
	}
}

// Round 36 F-A: 存量库的 NULL enabled 规则在初始化迁移后归一化为 0（NULL 视禁用，
// 与渲染侧 WHERE enabled=1 口径一致），不再存在 NULL 行；迁移幂等，重跑无副作用。
func TestMigration_lbRulesEnabledNullNormalizedToDisabled(t *testing.T) {
	// Given 模拟迁移前的存量库：先初始化建表，再回退为可空 enabled 并写入 NULL 行
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if err := db.Initialize(dir); err != nil {
		t.Fatalf("first initialize: %v", err)
	}
	simulateLegacyNullableLbRules(t, db.DB)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES
		('lb_null_mig2','nullable','http',8082,NULL), ('lb_null_mig2b','normal','http',8083,1)`); err != nil {
		t.Fatalf("seed nullable rules: %v", err)
	}

	// When 再次初始化触发迁移（UPDATE lb_rules SET enabled=0 WHERE enabled IS NULL）
	if err := db.Initialize(dir); err != nil {
		t.Fatalf("second initialize (migration): %v", err)
	}

	// Then NULL 行消失，原 NULL 行走 0，正常行保持 1
	var nullCount, enabledSum int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN ('lb_null_mig2','lb_null_mig2b') AND enabled IS NULL`).Scan(&nullCount); err != nil {
		t.Fatalf("count null rules: %v", err)
	}
	if nullCount != 0 {
		t.Fatalf("null enabled rows=%d, want 0 after migration", nullCount)
	}
	if err := db.DB.QueryRow(`SELECT SUM(enabled) FROM lb_rules WHERE caddy_id IN ('lb_null_mig2','lb_null_mig2b')`).Scan(&enabledSum); err != nil {
		t.Fatalf("sum enabled rules: %v", err)
	}
	if enabledSum != 1 {
		t.Fatalf("enabled sum=%d, want 1 (NULL→0, 1 保持)", enabledSum)
	}
}

// Round 36 F-A: 列表/详情读取点（lbRuleListColumns + scanLbRules，即 ListRules/GetRule
// 路径）与渲染侧同口径（NULL 视禁用）——此前 COALESCE(enabled,1) 把遗留 NULL 行视为
// 启用，UI 显示与生成配置分裂。
func TestListRules_defaults_NULL_enabled_to_false(t *testing.T) {
	// Given 回退为迁移前的可空 enabled 结构并写入 NULL 行
	database := initializeRuleFeatureTestDB(t)
	simulateLegacyNullableLbRules(t, database)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES
		('lb_null_rule','nullable','http',8084,NULL), ('lb_on_rule','normal','http',8085,1)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	// When 走 ListRules 的读取路径
	rows, err := database.Query(`SELECT ` + lbRuleListColumns + ` FROM lb_rules WHERE caddy_id IN ('lb_null_rule','lb_on_rule') ORDER BY caddy_id`)
	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	defer rows.Close()
	rules, err := scanLbRules(rows)

	// Then NULL 视禁用（与渲染 IIF(enabled IN ('1',1),1,0) 一致），enabled=1 正常显示启用
	if err != nil {
		t.Fatalf("scan rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rule count=%d, want 2", len(rules))
	}
	if rules[0].Enabled {
		t.Fatalf("NULL-enabled rule shows enabled, want disabled (rules[0]=%#v)", rules[0])
	}
	if !rules[1].Enabled {
		t.Fatalf("enabled=1 rule shows disabled, want enabled (rules[1]=%#v)", rules[1])
	}
}

// simulateLegacyNullableLbRules 把 lb_rules 回退为迁移前的可空 enabled 结构
// （schema 已 NOT NULL，NULL 仅存在于迁移前存量库），供测试构造遗留 NULL 行。
// 列结构与 migrateLbRulesPrimaryKey 重建 DDL 一致（caddy_id 主键，enabled 可空）。
func simulateLegacyNullableLbRules(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE lb_rules (
		id INTEGER,
		name VARCHAR(100) NOT NULL,
		description VARCHAR(300),
		protocol VARCHAR(10) NOT NULL,
		domain VARCHAR(255),
		listen_port INTEGER NOT NULL,
		strategy VARCHAR(20) DEFAULT 'weighted_round_robin',
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enable_dns_server BOOLEAN DEFAULT FALSE,
		dns_server VARCHAR(255) DEFAULT '',
		dns_family VARCHAR(20) DEFAULT 'ipv4',
		health_check_path VARCHAR(255),
		health_check_interval INTEGER DEFAULT 10,
		health_check_timeout INTEGER DEFAULT 5,
		health_check_unhealthy_threshold INTEGER DEFAULT 3,
		health_check_healthy_threshold INTEGER DEFAULT 2,
		enable_active_health_check BOOLEAN DEFAULT FALSE,
		tcp_health_check_port INTEGER DEFAULT 0,
		tcp_proxy_protocol BOOLEAN DEFAULT 0,
		tcp_try_duration INTEGER DEFAULT 0,
		tcp_try_interval INTEGER DEFAULT 250,
		request_body_max_size_mb INTEGER DEFAULT 0,
		upstream_keepalive_timeout INTEGER DEFAULT 0,
		server_tokens_hidden INTEGER DEFAULT 0,
		custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
		proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_flush_interval INTEGER NOT NULL DEFAULT 0,
		proxy_stream_close_delay INTEGER NOT NULL DEFAULT 0,
		host_header VARCHAR(255),
		enable_tls BOOLEAN DEFAULT FALSE,
		tls_cert TEXT,
		tls_key TEXT,
		tls_http_redirect BOOLEAN DEFAULT FALSE,
		tls_source VARCHAR(20) DEFAULT 'manual',
		acme_config_id INTEGER DEFAULT 0,
		ca_provider_id INTEGER DEFAULT 0,
		enable_compress BOOLEAN DEFAULT FALSE,
		compress_types VARCHAR(100) DEFAULT 'gzip',
		enabled BOOLEAN DEFAULT TRUE,
		log_enabled BOOLEAN DEFAULT 0,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		updated_by INTEGER,
		caddy_id VARCHAR(20) PRIMARY KEY
	)`); err != nil {
		t.Fatalf("recreate legacy lb_rules: %v", err)
	}
}

// simulateLegacyNullableUpstreams 把 upstreams 回退为迁移前的可空 enabled 结构
// （schema 已 NOT NULL，NULL 仅存在于迁移前存量库），供测试构造遗留 NULL 行。
func simulateLegacyNullableUpstreams(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`DROP TABLE upstreams`); err != nil {
		t.Fatalf("drop upstreams: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN DEFAULT TRUE,
		protocol VARCHAR(10) DEFAULT 'http',
		max_connections INTEGER DEFAULT 0,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	)`); err != nil {
		t.Fatalf("recreate legacy upstreams: %v", err)
	}
}

func initializeRuleFeatureTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	return database
}
