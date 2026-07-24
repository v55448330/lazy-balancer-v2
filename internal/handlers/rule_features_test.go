package handlers

import (
	"context"
	"database/sql"
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
