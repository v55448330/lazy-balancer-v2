package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestValidateRuleFeatures_rejects_prefix_exact_shadowing_on_same_path(t *testing.T) {
	tests := []struct {
		name      string
		pathRules []models.PathRule
		wantError string
	}{
		{
			name: "prefix /api plus exact /api rejected",
			pathRules: []models.PathRule{
				{SortOrder: 0, MatchType: "prefix", Path: "/api", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9100, Weight: 1}}},
				{SortOrder: 1, MatchType: "exact", Path: "/api", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9101, Weight: 1}}},
			},
			wantError: "同一路径同时存在前缀与精确匹配规则会造成遮蔽",
		},
		{
			name: "prefix /api plus exact /api/v2 allowed",
			pathRules: []models.PathRule{
				{SortOrder: 0, MatchType: "prefix", Path: "/api", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9100, Weight: 1}}},
				{SortOrder: 1, MatchType: "exact", Path: "/api/v2", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9101, Weight: 1}}},
			},
			wantError: "",
		},
		{
			name: "same path different order still rejected",
			pathRules: []models.PathRule{
				{SortOrder: 0, MatchType: "exact", Path: "/api", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9101, Weight: 1}}},
				{SortOrder: 1, MatchType: "prefix", Path: "/api", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9100, Weight: 1}}},
			},
			wantError: "同一路径同时存在前缀与精确匹配规则会造成遮蔽",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given / When
			err := validateRuleFeatures(ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: test.pathRules})

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

func TestValidateRuleFeatures_rejects_path_rule_with_empty_upstreams(t *testing.T) {
	tests := []struct {
		name      string
		pathRules []models.PathRule
		wantError string
	}{
		{
			name: "empty upstream array rejected",
			pathRules: []models.PathRule{
				{MatchType: "prefix", Path: "/api", Upstreams: []models.PathRuleUpstream{}},
			},
			wantError: "路径规则至少需要配置一个上游",
		},
		{
			name: "nil upstreams inherits main upstreams and stays allowed",
			pathRules: []models.PathRule{
				{MatchType: "prefix", Path: "/api"},
			},
			wantError: "",
		},
		{
			name: "one upstream allowed",
			pathRules: []models.PathRule{
				{MatchType: "prefix", Path: "/api", Upstreams: []models.PathRuleUpstream{{Address: "127.0.0.1", Port: 9100, Weight: 1}}},
			},
			wantError: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given / When
			err := validateRuleFeatures(ruleFeatureInput{Protocol: "http", CustomRoutesEnabled: true, PathRules: test.pathRules})

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

func TestCreateRule_rejects_path_rule_with_empty_upstreams_array(t *testing.T) {
	// Given：路径规则携带空上游数组（区别于 null 的继承语义），必须在保存前拒绝
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"empty-path-upstreams","protocol":"http","domain":"empty-paths.example.test","listen_port":13010,
		"custom_routes_enabled":true,
		"path_rules":[{"sort_order":0,"match_type":"prefix","path":"/api","upstreams":[]}],
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "路径规则至少需要配置一个上游") {
		t.Fatalf("create empty-upstream path rule status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestCreateRule_rejects_port_80_tls_redirect_self_loop(t *testing.T) {
	// Given：HTTP 规则 80 端口 + TLS + 跳转，https://host:80 会指回自身监听器
	certPEM, keyPEM, err := generateTestCert("tls-loop.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{
		"name":"tls-loop-80","protocol":"http","domain":"tls-loop.example.test","listen_port":80,
		"enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q,"tls_http_redirect":true,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`, certPEM, keyPEM)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "80 端口开启 TLS 跳转无意义") {
		t.Fatalf("create port-80 TLS redirect status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestCreateRule_accepts_port_443_tls_redirect(t *testing.T) {
	// Given：443 端口 + TLS + 跳转是合法组合（跳转目标即本规则 TLS 监听）
	certPEM, keyPEM, err := generateTestCert("tls-ok.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{
		"name":"tls-ok-443","protocol":"http","domain":"tls-ok.example.test","listen_port":443,
		"enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q,"tls_http_redirect":true,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`, certPEM, keyPEM)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("create port-443 TLS redirect status=%d body=%s, want 2xx", response.Code, response.Body.String())
	}
}

func TestUpdateRule_rejects_port_80_tls_redirect_self_loop(t *testing.T) {
	// Given：存量 HTTP 规则更新为 80 端口 + TLS + 跳转
	certPEM, keyPEM, err := generateTestCert("tls-update.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress) VALUES ('lb_tlsloop','tls-loop','','http','tls-update.example.test',80,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tlsloop','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	body := fmt.Sprintf(`{
		"name":"tls-loop-80","protocol":"http","domain":"tls-update.example.test","listen_port":80,
		"enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q,"tls_http_redirect":true
	}`, certPEM, keyPEM)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tlsloop", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "80 端口开启 TLS 跳转无意义") {
		t.Fatalf("update to port-80 TLS redirect status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}
