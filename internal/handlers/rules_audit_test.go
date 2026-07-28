package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestListRules_uses_schema_defaults_when_nullable_columns_are_NULL(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enabled)
		VALUES ('lb_nulls','nullable','http',8080,NULL,NULL,NULL,NULL,NULL,NULL)`); err != nil {
		t.Fatalf("seed nullable rule: %v", err)
	}
	router := gin.New()
	router.GET("/rules", handler.ListRules)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	for _, expected := range []string{`"health_check_path":""`, `"health_check_interval":10`, `"health_check_timeout":5`, `"health_check_unhealthy_threshold":3`, `"health_check_healthy_threshold":2`, `"enabled":true`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("list body missing %s: %s", expected, response.Body.String())
		}
	}
}

func TestUpdateRule_rejects_duplicate_domain_after_merging_existing_protocol(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	seedAuditRule(t, "lb_existing", "existing", "duplicate.example.test", 8080, true, "manual", false)
	seedAuditRule(t, "lb_target", "target", "old.example.test", 8080, true, "manual", false)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_target','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed target upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_target", strings.NewReader(`{"domain":"duplicate.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被") {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var domain string
	if err := db.DB.QueryRow("SELECT domain FROM lb_rules WHERE caddy_id='lb_target'").Scan(&domain); err != nil {
		t.Fatalf("read target domain: %v", err)
	}
	if domain != "old.example.test" {
		t.Fatalf("target domain=%q, want unchanged", domain)
	}
}

func TestUpdateRule_stops_when_existing_upstream_scan_fails(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	seedAuditRule(t, "lb_badupstream", "before", "scan.example.test", 8080, true, "manual", false)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_badupstream','127.0.0.1','bad-port',1,1,'http')`); err != nil {
		t.Fatalf("seed malformed upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_badupstream", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_badupstream'").Scan(&name); err != nil {
		t.Fatalf("read rule name: %v", err)
	}
	if name != "before" {
		t.Fatalf("rule name=%q, want unchanged", name)
	}
}

func TestDeleteRule_rolls_back_database_and_runtime_when_Caddy_rejects_config(t *testing.T) {
	// Given
	handler, loadCalls, lastLoad := newAuditRuleHandlers(t, 1)
	seedAuditRule(t, "lb_delete", "delete", "delete.example.test", 8080, true, "manual", false)
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_delete", nil))

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("delete unexpectedly succeeded: %s", response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_delete'").Scan(&count); err != nil {
		t.Fatalf("read deleted rule: %v", err)
	}
	if count != 1 {
		t.Fatalf("rule count=%d, want rollback", count)
	}
	if loadCalls.Load() != 2 || !strings.Contains(*lastLoad, `"old":true`) {
		t.Fatalf("Caddy load calls=%d last=%s, want failed apply plus runtime restore", loadCalls.Load(), *lastLoad)
	}
}

func TestCreateRule_removes_rule_and_restores_Caddy_when_ACME_queue_is_unavailable(t *testing.T) {
	// Given
	handler, loadCalls, _ := newAuditRuleHandlers(t, 0)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"acme-create","protocol":"http","domain":"create.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":1,"ca_provider_id":1,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='create.example.test'").Scan(&count); err != nil {
		t.Fatalf("read created rule: %v", err)
	}
	if count != 0 || loadCalls.Load() == 0 {
		t.Fatalf("rule count=%d Caddy loads=%d, want zero change compensation", count, loadCalls.Load())
	}
}

func TestEnableRule_restores_disabled_state_when_ACME_queue_is_unavailable(t *testing.T) {
	// Given
	handler, loadCalls, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_enable_acme", "enable", "enable.example.test", 8080, false, "acme_dns", true)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_acme/enable", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("enable status=%d body=%s", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_enable_acme'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled || loadCalls.Load() < 2 {
		t.Fatalf("enabled=%v Caddy loads=%d, want disabled with runtime rollback", enabled, loadCalls.Load())
	}
}

func TestRuleToggle_is_idempotent_when_rule_already_has_target_state(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		path    string
		mount   func(*gin.RouterGroup, *Handlers)
	}{
		{name: "enable enabled rule", enabled: true, path: "/rules/lb_toggle/enable", mount: func(group *gin.RouterGroup, handler *Handlers) { group.POST("/:caddy_id/enable", handler.EnableRule) }},
		{name: "disable disabled rule", enabled: false, path: "/rules/lb_toggle/disable", mount: func(group *gin.RouterGroup, handler *Handlers) { group.POST("/:caddy_id/disable", handler.DisableRule) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			handler, loadCalls, _ := newAuditRuleHandlers(t, 0)
			seedAuditRule(t, "lb_toggle", "toggle", "toggle.example.test", 8080, test.enabled, "manual", false)
			router := gin.New()
			test.mount(router.Group("/rules"), handler)
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, test.path, nil))

			// Then
			if response.Code != http.StatusOK || loadCalls.Load() != 0 {
				t.Fatalf("toggle status=%d loads=%d body=%s", response.Code, loadCalls.Load(), response.Body.String())
			}
		})
	}
}

func TestRuleToggle_restores_original_state_when_Caddy_apply_fails(t *testing.T) {
	tests := []struct {
		name          string
		originalState bool
		path          string
		mount         func(*gin.RouterGroup, *Handlers)
	}{
		{name: "enable", originalState: false, path: "/rules/lb_toggle_fail/enable", mount: func(group *gin.RouterGroup, handler *Handlers) { group.POST("/:caddy_id/enable", handler.EnableRule) }},
		{name: "disable", originalState: true, path: "/rules/lb_toggle_fail/disable", mount: func(group *gin.RouterGroup, handler *Handlers) { group.POST("/:caddy_id/disable", handler.DisableRule) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			handler, _, _ := newAuditRuleHandlers(t, 1)
			seedAuditRule(t, "lb_toggle_fail", "toggle", "toggle-fail.example.test", 8080, test.originalState, "manual", false)
			router := gin.New()
			test.mount(router.Group("/rules"), handler)
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, test.path, nil))

			// Then
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("toggle status=%d body=%s", response.Code, response.Body.String())
			}
			var enabled bool
			if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_toggle_fail'").Scan(&enabled); err != nil {
				t.Fatalf("read enabled state: %v", err)
			}
			if enabled != test.originalState {
				t.Fatalf("enabled=%v, want original %v", enabled, test.originalState)
			}
		})
	}
}

func TestDisableRule_returns_error_instead_of_panicking_when_cert_job_update_fails(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_disable_cert", "disable", "disable.example.test", 8080, true, "acme_dns", true)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_disable_cert','disable.example.test','queued')`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_cert_disable BEFORE UPDATE ON cert_jobs BEGIN SELECT RAISE(ABORT,'cert update failed'); END`); err != nil {
		t.Fatalf("create cert trigger: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_disable_cert/disable", nil))

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "证书任务") {
		t.Fatalf("disable status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateRuleACL_reports_database_restore_failure_separately(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 1)
	seedAuditRule(t, "lb_acl_restore", "acl", "acl.example.test", 8080, true, "manual", false)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET ip_acl_mode='allow',ip_acl_list='["192.0.2.0/24"]' WHERE caddy_id='lb_acl_restore'`); err != nil {
		t.Fatalf("seed ACL: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_acl_restore BEFORE UPDATE ON lb_rules WHEN OLD.ip_acl_mode='deny' AND NEW.ip_acl_mode='allow' BEGIN SELECT RAISE(ABORT,'restore failed'); END`); err != nil {
		t.Fatalf("create ACL trigger: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id/acl", handler.UpdateRuleACL)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acl_restore/acl", strings.NewReader(`{"ip_acl_mode":"deny","ip_acl_list":["198.51.100.0/24"]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "Caddy 与 DB 恢复均失败") {
		t.Fatalf("ACL update status=%d body=%s", response.Code, response.Body.String())
	}
}

func seedAuditRule(t *testing.T, id, name, domain string, port int, enabled bool, tlsSource string, enableTLS bool) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls)
		VALUES (?,?,?,?,?,?,'weighted_round_robin','',?,1,?,?)`, id, name, "", "http", domain, port, enabled, tlsSource, enableTLS); err != nil {
		t.Fatalf("seed rule %s: %v", id, err)
	}
}

func newAuditRuleHandlers(t *testing.T, failedLoads int32) (*Handlers, *atomic.Int32, *string) {
	t.Helper()
	initializeRuleFeatureTestDB(t)
	var loadCalls atomic.Int32
	lastLoad := ""
	currentConfig := `{"old":true,"apps":{"http":{"servers":{}}}}`
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/config/" {
			_, _ = response.Write([]byte(currentConfig))
			return
		}
		if request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, "/config/apps/http/servers/") {
			serverName := strings.TrimPrefix(request.URL.Path, "/config/apps/http/servers/")
			currentConfig = `{"apps":{"http":{"servers":{"` + serverName + `":{"listen":[":8080"],"routes":[]}}}}}`
			response.WriteHeader(http.StatusOK)
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/config/" {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			currentConfig = string(body)
			response.WriteHeader(http.StatusOK)
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/load" {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			lastLoad = string(body)
			call := loadCalls.Add(1)
			if call <= failedLoads {
				response.WriteHeader(http.StatusBadRequest)
				_, _ = response.Write([]byte("rejected"))
				return
			}
			currentConfig = string(body)
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
	}, &loadCalls, &lastLoad
}
