package handlers

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_nulls','127.0.0.1',9000,1,NULL,'http')`); err != nil {
		t.Fatalf("seed nullable upstream: %v", err)
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
	for _, expected := range []string{`"health_check_path":""`, `"health_check_interval":10`, `"health_check_timeout":5`, `"health_check_unhealthy_threshold":3`, `"health_check_healthy_threshold":2`, `"enabled":true`, `"host":"127.0.0.1"`} {
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

func TestEnableRule_restores_cert_job_fields_when_requeue_fails(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_enable_restore", "enable", "restore.example.test", 8080, false, "acme_dns", true)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs
		(rule_id,domain,status,message,renewal_attempts,ca_available_after,last_error_code)
		VALUES ('lb_enable_restore','restore.example.test','disabled','paused message',7,datetime('now','-1 hour'),'paused_code')`); err != nil {
		t.Fatalf("seed disabled certificate job: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	services.GetCAQueueManager().Stop()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_restore/enable", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("enable status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var enabled bool
	var status, message, errorCode string
	var attempts int
	if err := db.DB.QueryRow(`SELECT r.enabled,j.status,j.message,j.renewal_attempts,j.last_error_code
		FROM lb_rules r JOIN cert_jobs j ON j.rule_id=r.caddy_id WHERE r.caddy_id='lb_enable_restore'`).
		Scan(&enabled, &status, &message, &attempts, &errorCode); err != nil {
		t.Fatalf("read compensated state: %v", err)
	}
	if enabled || status != "disabled" || message != "paused message" || attempts != 7 || errorCode != "paused_code" {
		t.Fatalf("compensated state=(%v,%q,%q,%d,%q), want original", enabled, status, message, attempts, errorCode)
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
	var enabled bool
	var jobStatus string
	if err := db.DB.QueryRow(`SELECT r.enabled,j.status FROM lb_rules r JOIN cert_jobs j ON j.rule_id=r.caddy_id WHERE r.caddy_id='lb_disable_cert'`).Scan(&enabled, &jobStatus); err != nil {
		t.Fatalf("read compensated rule and cert job: %v", err)
	}
	if !enabled || jobStatus != "queued" {
		t.Fatalf("enabled=%v job status=%q, want original enabled/queued state", enabled, jobStatus)
	}
}

func TestUpdateRule_preserves_omitted_boolean_fields(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_bool_keep", 0, false)
	handler, currentConfig := harness.handler, harness.currentConfig
	seedAuditRule(t, "lb_bool_keep", "before", "bool-keep.example.test", 8080, true, "manual", true)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET dynamic_dns=1,enable_dns_server=1,enable_active_health_check=1,tcp_proxy_protocol=1,tls_http_redirect=1,enable_compress=1,log_enabled=1 WHERE caddy_id='lb_bool_keep'`); err != nil {
		t.Fatalf("seed boolean fields: %v", err)
	}
	seedAuditUpstream(t, "lb_bool_keep")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_bool_keep", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var dynamicDNS, dnsServer, activeHealth, proxyProtocol, enableTLS, redirect, compress, enabled, logEnabled bool
	if err := db.DB.QueryRow(`SELECT dynamic_dns,enable_dns_server,enable_active_health_check,tcp_proxy_protocol,enable_tls,tls_http_redirect,enable_compress,enabled,log_enabled FROM lb_rules WHERE caddy_id='lb_bool_keep'`).Scan(
		&dynamicDNS, &dnsServer, &activeHealth, &proxyProtocol, &enableTLS, &redirect, &compress, &enabled, &logEnabled); err != nil {
		t.Fatalf("read booleans: %v", err)
	}
	if !dynamicDNS || !dnsServer || !activeHealth || !proxyProtocol || !enableTLS || !redirect || !compress || !enabled || !logEnabled {
		t.Fatalf("omitted booleans changed: dynamic_dns=%v dns_server=%v active=%v proxy=%v tls=%v redirect=%v compress=%v enabled=%v log=%v", dynamicDNS, dnsServer, activeHealth, proxyProtocol, enableTLS, redirect, compress, enabled, logEnabled)
	}
	if !strings.Contains(currentConfig(), `"lb_bool_keep"`) {
		t.Fatalf("Caddy config lost updated route: %s", currentConfig())
	}
}

func TestUpdateRule_applies_explicit_false_boolean_fields(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_bool_false", 0, false)
	handler, currentConfig := harness.handler, harness.currentConfig
	seedAuditRule(t, "lb_bool_false", "before", "bool-false.example.test", 8080, true, "manual", true)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET dynamic_dns=1,enable_dns_server=1,enable_active_health_check=1,tcp_proxy_protocol=1,tls_http_redirect=1,enable_compress=1,log_enabled=1 WHERE caddy_id='lb_bool_false'`); err != nil {
		t.Fatalf("seed boolean fields: %v", err)
	}
	seedAuditUpstream(t, "lb_bool_false")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_bool_false", strings.NewReader(`{"dynamic_dns":false,"enable_dns_server":false,"enable_active_health_check":false,"tcp_proxy_protocol":false,"enable_tls":false,"tls_http_redirect":false,"enable_compress":false,"enabled":false,"log_enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var enabledCount int
	if err := db.DB.QueryRow(`SELECT dynamic_dns+enable_dns_server+enable_active_health_check+tcp_proxy_protocol+enable_tls+tls_http_redirect+enable_compress+enabled+log_enabled FROM lb_rules WHERE caddy_id='lb_bool_false'`).Scan(&enabledCount); err != nil {
		t.Fatalf("read booleans: %v", err)
	}
	if enabledCount != 0 {
		t.Fatalf("explicit false fields left %d enabled values", enabledCount)
	}
	if !strings.Contains(currentConfig(), `"lb_bool_false"`) {
		t.Fatalf("Caddy config lost updated route: %s", currentConfig())
	}
}

func TestUpdateRule_restores_database_and_Caddy_when_TLS_reload_fails(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_tls_rollback", 1, false)
	handler, loadCalls, currentConfig := harness.handler, harness.loadCalls, harness.currentConfig
	seedAuditRule(t, "lb_tls_rollback", "before", "tls-old.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_tls_rollback")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tls_rollback", strings.NewReader(`{"name":"after","enable_tls":true,"tls_source":"acme_dns","acme_config_id":1,"domain":"tls-new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("update unexpectedly succeeded: %s", response.Body.String())
	}
	var name, domain string
	var enableTLS bool
	if err := db.DB.QueryRow(`SELECT name,domain,enable_tls FROM lb_rules WHERE caddy_id='lb_tls_rollback'`).Scan(&name, &domain, &enableTLS); err != nil {
		t.Fatalf("read restored rule: %v", err)
	}
	if name != "before" || domain != "tls-old.example.test" || enableTLS {
		t.Fatalf("restored rule name=%q domain=%q tls=%v", name, domain, enableTLS)
	}
	if loadCalls.Load() != 2 || !strings.Contains(currentConfig(), `"old":true`) {
		t.Fatalf("Caddy loads=%d config=%s, want failed TLS load plus old full-config restore", loadCalls.Load(), currentConfig())
	}
}

func TestUpdateRule_restores_database_and_Caddy_when_ACME_enqueue_fails(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_acme_rollback", 0, false)
	handler, loadCalls, currentConfig := harness.handler, harness.loadCalls, harness.currentConfig
	seedAuditRule(t, "lb_acme_rollback", "before", "acme-old.example.test", 8080, true, "acme_dns", true)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=1,ca_provider_id=1 WHERE caddy_id='lb_acme_rollback'`); err != nil {
		t.Fatalf("seed ACME config: %v", err)
	}
	seedAuditUpstream(t, "lb_acme_rollback")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acme_rollback", strings.NewReader(`{"domain":"acme-new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var domain string
	if err := db.DB.QueryRow(`SELECT domain FROM lb_rules WHERE caddy_id='lb_acme_rollback'`).Scan(&domain); err != nil {
		t.Fatalf("read restored domain: %v", err)
	}
	var jobs int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_acme_rollback'`).Scan(&jobs); err != nil {
		t.Fatalf("read cert jobs: %v", err)
	}
	if domain != "acme-old.example.test" || jobs != 0 || loadCalls.Load() < 2 || !strings.Contains(currentConfig(), `"old":true`) {
		t.Fatalf("domain=%q jobs=%d loads=%d config=%s, want full compensation", domain, jobs, loadCalls.Load(), currentConfig())
	}
}

func TestUpdateRule_cancels_job_before_restore_when_create_returns_jobID_and_error(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_acme_cancel", 0, false)
	seedAuditRule(t, "lb_acme_cancel", "before", "cancel-old.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_acme_cancel")
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=1,ca_provider_id=? WHERE caddy_id='lb_acme_cancel'", providerID); err != nil {
		t.Fatalf("set rule CA provider: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldCreate := createOrRequeueCertJob
	oldCancel := cancelCertJob
	createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, error) {
		return 77, errors.New("enqueue failed")
	}
	cancelled := make(chan int, 1)
	cancelCertJob = func(_ *services.CAQueueManager, jobID int) { cancelled <- jobID }
	t.Cleanup(func() {
		createOrRequeueCertJob = oldCreate
		cancelCertJob = oldCancel
	})
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acme_cancel", strings.NewReader(`{"domain":"cancel-new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case jobID := <-cancelled:
		if jobID != 77 {
			t.Fatalf("cancelled job=%d, want 77", jobID)
		}
	default:
		t.Fatal("job was not cancelled before restore returned")
	}
}

func TestUpdateRule_cancels_requeued_job_before_restoring_when_retirement_fails(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_acme_retire", 0, false)
	seedAuditRule(t, "lb_acme_retire", "before", "old.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_acme_retire")
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=1,ca_provider_id=? WHERE caddy_id='lb_acme_retire'", providerID); err != nil {
		t.Fatalf("set rule CA provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES
		('lb_acme_retire','old.example.test','issued',?),
		('lb_acme_retire','new.example.test','failed',?)`, providerID, providerID); err != nil {
		t.Fatalf("seed certificate jobs: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_retired_cert_job BEFORE UPDATE OF status ON cert_jobs
		WHEN OLD.rule_id='lb_acme_retire' AND OLD.domain='old.example.test' AND NEW.status='disabled'
		BEGIN SELECT RAISE(ABORT,'retirement failed'); END`); err != nil {
		t.Fatalf("create retirement failure trigger: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acme_retire", strings.NewReader(`{"domain":"new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "退役旧域名证书任务失败") {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var domain string
	if err := db.DB.QueryRow("SELECT domain FROM lb_rules WHERE caddy_id='lb_acme_retire'").Scan(&domain); err != nil {
		t.Fatalf("read restored rule: %v", err)
	}
	rows, err := db.DB.Query("SELECT domain,status FROM cert_jobs WHERE rule_id='lb_acme_retire' ORDER BY domain")
	if err != nil {
		t.Fatalf("read restored certificate jobs: %v", err)
	}
	defer rows.Close()
	statuses := map[string]string{}
	for rows.Next() {
		var jobDomain, status string
		if err := rows.Scan(&jobDomain, &status); err != nil {
			t.Fatalf("scan restored certificate job: %v", err)
		}
		statuses[jobDomain] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate restored certificate jobs: %v", err)
	}
	if domain != "old.example.test" || statuses["new.example.test"] != "failed" || statuses["old.example.test"] != "issued" {
		t.Fatalf("domain=%q statuses=%v, want original DB snapshot", domain, statuses)
	}
	if harness.loadCalls.Load() < 2 || !strings.Contains(harness.currentConfig(), `"old":true`) {
		t.Fatalf("Caddy loads=%d config=%s, want runtime restoration", harness.loadCalls.Load(), harness.currentConfig())
	}
}

func TestUpdateRule_serializes_snapshot_commit_apply_and_restore(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_concurrent", 0, true)
	handler := harness.handler
	seedAuditRule(t, "lb_concurrent", "original", "concurrent.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_concurrent")
	firstRouteEntered := harness.firstRouteEntered
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	firstResponse := httptest.NewRecorder()
	secondResponse := httptest.NewRecorder()
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_concurrent", strings.NewReader(`{"name":"first"}`))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(firstResponse, request)
		close(firstDone)
	}()
	<-firstRouteEntered
	go func() {
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_concurrent", strings.NewReader(`{"name":"second"}`))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(secondResponse, request)
		close(secondDone)
	}()
	<-harness.secondValidation

	// When
	harness.release()
	<-firstDone
	<-secondDone

	// Then
	if firstResponse.Code == http.StatusOK || secondResponse.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s; second status=%d body=%s", firstResponse.Code, firstResponse.Body.String(), secondResponse.Code, secondResponse.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id='lb_concurrent'`).Scan(&name); err != nil {
		t.Fatalf("read final rule: %v", err)
	}
	if name != "second" {
		t.Fatalf("final rule name=%q, want later successful update", name)
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

func seedAuditUpstream(t *testing.T, ruleID string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'http')`, ruleID); err != nil {
		t.Fatalf("seed upstream for %s: %v", ruleID, err)
	}
}

type updateAuditHarness struct {
	handler           *Handlers
	loadCalls         *atomic.Int32
	currentConfig     func() string
	firstRouteEntered chan struct{}
	releaseFirstRoute chan struct{}
	secondValidation  chan struct{}
	blockOnRoutePost  int32
	release           func()
}

func newUpdateAuditRuleHandlers(t *testing.T, caddyID string, failedLoads int32, failFirstRoute bool) *updateAuditHarness {
	t.Helper()
	initializeRuleFeatureTestDB(t)
	var stateMu sync.Mutex
	currentConfig := `{"old":true,"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"` + caddyID + `","handle":[]}]}}}}}`
	var loadCalls atomic.Int32
	var routePosts atomic.Int32
	var validations atomic.Int32
	firstRouteEntered := make(chan struct{})
	releaseFirstRoute := make(chan struct{})
	secondValidation := make(chan struct{})
	harness := &updateAuditHarness{blockOnRoutePost: 2}
	var releaseOnce sync.Once
	harness.release = func() { releaseOnce.Do(func() { close(releaseFirstRoute) }) }
	t.Cleanup(harness.release)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/config/":
			stateMu.Lock()
			body := currentConfig
			stateMu.Unlock()
			_, _ = response.Write([]byte(body))
			return
		case request.Method == http.MethodGet && request.URL.Path == "/id/"+caddyID:
			_, _ = response.Write([]byte(`{"@id":"` + caddyID + `","handle":[]}`))
			return
		case request.Method == http.MethodPost && request.URL.Path == "/load" && request.URL.Query().Get("validate") == "true":
			if validations.Add(1) == 2 {
				close(secondValidation)
			}
			response.WriteHeader(http.StatusOK)
			return
		case request.Method == http.MethodPost && request.URL.Path == "/config/":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			if routePosts.Add(1) == harness.blockOnRoutePost && failFirstRoute {
				close(firstRouteEntered)
				<-releaseFirstRoute
				response.WriteHeader(http.StatusBadRequest)
				_, _ = response.Write([]byte("route rejected"))
				return
			}
			stateMu.Lock()
			currentConfig = string(body)
			stateMu.Unlock()
			response.WriteHeader(http.StatusOK)
			return
		case request.Method == http.MethodPost && request.URL.Path == "/load":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			if loadCalls.Add(1) <= failedLoads {
				response.WriteHeader(http.StatusBadRequest)
				_, _ = response.Write([]byte("load rejected"))
				return
			}
			stateMu.Lock()
			currentConfig = string(body)
			stateMu.Unlock()
			response.WriteHeader(http.StatusOK)
			return
		default:
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	harness.handler = &Handlers{
		cfg:            cfg,
		caddyService:   services.NewCaddyService(fakeCaddy.URL),
		clusterService: services.NewClusterService(db.DB, nil),
	}
	harness.loadCalls = &loadCalls
	harness.currentConfig = func() string {
		stateMu.Lock()
		defer stateMu.Unlock()
		return currentConfig
	}
	harness.firstRouteEntered = firstRouteEntered
	harness.releaseFirstRoute = releaseFirstRoute
	harness.secondValidation = secondValidation
	return harness
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

func TestRuleWriteEndpoints_share_one_lock_order_under_concurrency(t *testing.T) {
	// Given：同一条规则上并发执行 Update/Delete/ACL/Create，旧锁序（DB 事务→caddyOpMu
	// 与 caddyOpMu→DB 并存）会 AB-BA 循环等待；统一锁序后全部请求必须在超时内完成。
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_lockorder", "lock", "lock.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_lockorder")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	router.POST("/rules/:caddy_id/acl", handler.UpdateRuleACL)
	router.POST("/rules", handler.CreateRule)

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				switch n % 4 {
				case 0:
					body := strings.NewReader(`{"description":"u"}`)
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/rules/lb_lockorder", body))
				case 1:
					body := strings.NewReader(`{"ip_acl_mode":"allow","ip_acl_list":["192.0.2.0/24"]}`)
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/rules/lb_lockorder/acl", body))
				case 2:
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/rules/lb_lockorder", nil))
				case 3:
					body := strings.NewReader(`{"name":"newbie","protocol":"tcp","listen_port":19000,"upstreams":[{"host":"127.0.0.1","port":9001}]}`)
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/rules", body))
				}
			}(i)
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("concurrent rule write endpoints deadlocked (lock order inversion)")
	}

	var remaining int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN ('lb_lockorder','lb_newbie') OR name='newbie'`).Scan(&remaining); err != nil {
		t.Fatalf("read final rules: %v", err)
	}
	if remaining > 2 {
		t.Fatalf("unexpected rule count %d after concurrent writes", remaining)
	}
}
