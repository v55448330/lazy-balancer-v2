package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestRuleFeatures_rejects_invalid_ACL_and_path_rule_inputs(t *testing.T) {
	tests := []struct {
		name      string
		input     ruleFeatureInput
		wantError string
	}{
		{
			name:      "invalid ACL mode",
			input:     ruleFeatureInput{IPACLMode: "block"},
			wantError: "IP 访问控制模式",
		},
		{
			name:      "invalid CIDR",
			input:     ruleFeatureInput{IPACLMode: "allow", IPACLList: []string{"192.0.2.1"}},
			wantError: "CIDR",
		},
		{
			name:      "ACL list without mode",
			input:     ruleFeatureInput{IPACLList: []string{"192.0.2.0/24"}},
			wantError: "模式为空",
		},
		{
			name: "path rules while disabled",
			input: ruleFeatureInput{PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "/metrics/",
			}}},
			wantError: "自定义路径规则未启用",
		},
		{
			name: "path without slash",
			input: ruleFeatureInput{CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "metrics/",
			}}},
			wantError: "必须以 / 开头",
		},
		{
			name: "invalid match type",
			input: ruleFeatureInput{CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "regex",
				Path:      "/metrics/",
			}}},
			wantError: "匹配类型",
		},
		{
			name: "blank custom upstream address",
			input: ruleFeatureInput{CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "/metrics/",
				Upstreams: []models.PathRuleUpstream{{Address: " ", Port: 9090, Weight: 1}},
			}}},
			wantError: "上游地址不能为空",
		},
		{
			name: "custom upstream port out of range",
			input: ruleFeatureInput{CustomRoutesEnabled: true, PathRules: []models.PathRule{{
				MatchType: "prefix",
				Path:      "/metrics/",
				Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 65536, Weight: 1}},
			}}},
			wantError: "端口必须在 1-65535",
		},
		{
			name: "negative custom upstream weight",
			input: ruleFeatureInput{CustomRoutesEnabled: true, PathRules: []models.PathRule{{
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

func TestCreateRule_rejects_invalid_IP_ACL_mode(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"invalid-acl","protocol":"http","listen_port":8080,"ip_acl_mode":"block","upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "IP 访问控制模式") {
		t.Fatalf("create invalid ACL status=%d body=%s", response.Code, response.Body.String())
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
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_updatepaths", strings.NewReader(`{"ip_acl_mode":"allow","ip_acl_list":["192.0.2.0/24"],"custom_routes_enabled":true,"path_rules":[{"sort_order":5,"match_type":"prefix","path":"/new/","upstreams":null}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var mode, listJSON, path string
	var count int
	if err := db.DB.QueryRow(`SELECT ip_acl_mode,ip_acl_list,(SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_updatepaths'),(SELECT path FROM path_rules WHERE rule_id='lb_updatepaths') FROM lb_rules WHERE caddy_id='lb_updatepaths'`).Scan(&mode, &listJSON, &count, &path); err != nil {
		t.Fatalf("read updated rule features: %v", err)
	}
	if mode != "allow" || listJSON != `["192.0.2.0/24"]` || count != 1 || path != "/new/" {
		t.Fatalf("updated rule features mode=%q list=%q count=%d path=%q", mode, listJSON, count, path)
	}
	if !strings.Contains(*postedConfig, `"client_ip"`) || !strings.Contains(*postedConfig, `"/new/*"`) {
		t.Fatalf("posted Caddy config missing ACL/path route: %s", *postedConfig)
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
		"ip_acl_mode":"deny","ip_acl_list":["203.0.113.0/24"],
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
		ip_acl_mode,ip_acl_list,custom_routes_enabled,
		proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout)
		VALUES ('lb_dupsrc','源规则','','http','dup.example.test',8080,'weighted_round_robin',0,0,'','ipv4',
		'',10,5,3,2,0,0,0,5,250,0,0,0,1,'manual',0,0,'','',0,1,'gzip',1,1,1,'',1,
		'allow','["192.0.2.0/24"]',1,5,15,30,30,0)`); err != nil {
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
	var newID, aclMode string
	var upstreamCount, pathCount, customRoutes int
	var createdBy, updatedBy int64
	if err := db.DB.QueryRow(`SELECT caddy_id, ip_acl_mode, custom_routes_enabled, created_by, updated_by,
		(SELECT COUNT(*) FROM upstreams WHERE rule_id=lb_rules.caddy_id),
		(SELECT COUNT(*) FROM path_rules WHERE rule_id=lb_rules.caddy_id)
		FROM lb_rules WHERE caddy_id != 'lb_dupsrc'`).Scan(&newID, &aclMode, &customRoutes, &createdBy, &updatedBy, &upstreamCount, &pathCount); err != nil {
		t.Fatalf("read duplicated rule: %v", err)
	}
	if newID == "" || aclMode != "allow" || customRoutes != 1 || createdBy != 1 || updatedBy != 1 || upstreamCount != 1 || pathCount != 1 {
		t.Fatalf("duplicated rule incomplete: id=%q acl=%q custom=%d created_by=%d updated_by=%d ups=%d paths=%d", newID, aclMode, customRoutes, createdBy, updatedBy, upstreamCount, pathCount)
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
			body := strings.NewReader(fmt.Sprintf(`{"name":"dns-%s","protocol":"tcp","listen_port":%d,"dynamic_dns":true,"dns_family":"%s","upstreams":[{"host":"example.test","port":9000,"enabled":true}]}`, test.family, test.port, test.family))
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

func TestCreateRule_resolves_default_CA_provider_before_persisting(t *testing.T) {
	// Given
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	var defaultProviderID int
	if err := db.DB.QueryRow("SELECT default_ca_provider_id FROM global_config WHERE id=1").Scan(&defaultProviderID); err != nil {
		t.Fatalf("read default CA provider: %v", err)
	}
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"default-ca","protocol":"tcp","listen_port":13003,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var providerID int
	if err := db.DB.QueryRow("SELECT ca_provider_id FROM lb_rules WHERE listen_port=13003").Scan(&providerID); err != nil {
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

func TestLoadUpstreamsBatch_defaults_NULL_enabled_to_true(t *testing.T) {
	// Given
	database := initializeRuleFeatureTestDB(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_null_upstream','nullable upstream','http',8080)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_null_upstream','127.0.0.1',9000,NULL)`); err != nil {
		t.Fatalf("seed nullable upstream: %v", err)
	}

	// When
	upstreams, err := loadUpstreamsBatch(context.Background(), []string{"lb_null_upstream"})

	// Then
	if err != nil {
		t.Fatalf("load upstreams: %v", err)
	}
	if len(upstreams["lb_null_upstream"]) != 1 || !upstreams["lb_null_upstream"][0].Enabled {
		t.Fatalf("loaded upstreams = %#v, want one enabled upstream", upstreams["lb_null_upstream"])
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
