package handlers

import (
	"context"
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

func TestRuleWrites_reject_overlapping_domain_lists(t *testing.T) {
	tests := []struct {
		name  string
		mount func(*gin.Engine, *Handlers)
		path  string
		body  string
	}{
		{name: "create", mount: func(router *gin.Engine, handler *Handlers) { router.POST("/rules", handler.CreateRule) }, path: "/rules", body: `{"name":"overlap","protocol":"http","domain":"a.example.test, b.example.test","listen_port":8080,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`},
		{name: "update", mount: func(router *gin.Engine, handler *Handlers) { router.PUT("/rules/:caddy_id", handler.UpdateRule) }, path: "/rules/lb_target", body: `{"domain":"a.example.test, b.example.test"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			handler := newRuleFeatureTestHandlers(t)
			seedAuditRule(t, "lb_existing", "existing", "b.example.test,c.example.test", 8081, true, "manual", false)
			if test.name == "update" {
				seedAuditRule(t, "lb_target", "target", "old.example.test", 8080, true, "manual", false)
				seedAuditUpstream(t, "lb_target")
			}
			router := gin.New()
			test.mount(router, handler)
			request := httptest.NewRequest(map[string]string{"create": http.MethodPost, "update": http.MethodPut}[test.name], test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被") {
				t.Fatalf("status=%d body=%s, want domain conflict", response.Code, response.Body.String())
			}
		})
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
	if enabled || loadCalls.Load() == 0 {
		t.Fatalf("enabled=%v Caddy loads=%d, want disabled with candidate apply", enabled, loadCalls.Load())
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

func TestUpdateRule_allows_edit_with_disabled_ACME_job(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_edit_disabled", 0, false)
	seedAuditRule(t, "lb_edit_disabled", "before", "edit.example.test", 8080, false, "acme_dns", true)
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=1,ca_provider_id=1 WHERE caddy_id='lb_edit_disabled'"); err != nil {
		t.Fatalf("seed ACME config: %v", err)
	}
	seedAuditUpstream(t, "lb_edit_disabled")
	if _, err := db.DB.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_edit_disabled','edit.example.test','disabled')"); err != nil {
		t.Fatalf("seed disabled job: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_edit_disabled", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func TestUpdateRule_reissues_when_default_CA_differs_from_latest_job_provider(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_default_ca_switch", 0, false)
	seedAuditRule(t, "lb_default_ca_switch", "before", "switch.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_default_ca_switch")
	var oldProviderID int
	if err := db.DB.QueryRow("SELECT default_ca_provider_id FROM global_config WHERE id=1").Scan(&oldProviderID); err != nil {
		t.Fatalf("read old default provider: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,enabled) VALUES ('new-default','letsencrypt','https://new.example/directory',1)`)
	if err != nil {
		t.Fatalf("seed new provider: %v", err)
	}
	newProviderID64, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read new provider ID: %v", err)
	}
	newProviderID := int(newProviderID64)
	if _, err := db.DB.Exec("UPDATE global_config SET default_ca_provider_id=? WHERE id=1", newProviderID); err != nil {
		t.Fatalf("switch default provider: %v", err)
	}
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("read dns config ID: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_default_ca_switch'`, dnsConfigID); err != nil {
		t.Fatalf("bind dns config to rule: %v", err)
	}
	certPEM, keyPEM, err := generateTestCert("switch.example.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("generate issued certificate: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id)
		VALUES ('lb_default_ca_switch','switch.example.test','issued',?,?,datetime('now','+90 days'),?)`, certPEM, keyPEM, oldProviderID); err != nil {
		t.Fatalf("seed historical certificate job: %v", err)
	}
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldCreate := createOrRequeueCertJob
	enqueuedProvider := make(chan int, 1)
	createOrRequeueCertJob = func(_ string, _ string, providerID int, _ *services.CAQueueManager) (int, error) {
		enqueuedProvider <- providerID
		return 77, nil
	}
	t.Cleanup(func() { createOrRequeueCertJob = oldCreate })
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_default_ca_switch", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case providerID := <-enqueuedProvider:
		if providerID != newProviderID {
			t.Fatalf("reissue provider=%d, want new default %d", providerID, newProviderID)
		}
	default:
		t.Fatal("ordinary edit did not trigger reissue after default CA switch")
	}
}

func TestDeleteRule_returns_timeout_and_preserves_rule_when_worker_does_not_exit(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_delete_timeout", "timeout", "timeout.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_delete_timeout")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message) VALUES ('lb_delete_timeout','timeout.example.test','creating_order','unchanged')`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	services.GetCAQueueManager().PauseAndDrain()
	oldTimeout := cancelRuleJobsTimeout
	cancelRuleJobsTimeout = 10 * time.Millisecond
	t.Cleanup(func() { cancelRuleJobsTimeout = oldTimeout })
	oldCancel := cancelRuleJobs
	drained := make(chan struct{})
	var calls atomic.Int32
	cancelRuleJobs = func(ctx context.Context, _ *services.CAQueueManager, _ string) error {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		close(drained)
		return nil
	}
	t.Cleanup(func() { cancelRuleJobs = oldCancel })
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_delete_timeout", nil))

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "取消证书任务超时") {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
	}
	var ruleCount int
	var jobStatus, jobMessage string
	if err := db.DB.QueryRow(`SELECT COUNT(*),(SELECT status FROM cert_jobs WHERE rule_id='lb_delete_timeout'),(SELECT message FROM cert_jobs WHERE rule_id='lb_delete_timeout') FROM lb_rules WHERE caddy_id='lb_delete_timeout'`).Scan(&ruleCount, &jobStatus, &jobMessage); err != nil {
		t.Fatalf("read preserved state: %v", err)
	}
	if ruleCount != 1 || jobStatus != "queued" {
		t.Fatalf("preserved state rule=%d job=(%q,%q), want rule preserved and job restored to pipeline", ruleCount, jobStatus, jobMessage)
	}
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("asynchronous cancellation drain did not finish")
	}
	deadline := time.Now().Add(2 * time.Second)
	for services.GetCAQueueManager().IsRuleBlocked("lb_delete_timeout") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEnableRule_uses_latest_job_for_current_domain(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_domain_job", "domain job", "current.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_domain_job")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at) VALUES
		('lb_domain_job','current.example.test','disabled',datetime('now','+90 days')),
		('lb_domain_job','old.example.test','queued',NULL)`); err != nil {
		t.Fatalf("seed domain jobs: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_domain_job/enable", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_domain_job' AND domain='current.example.test'").Scan(&status); err != nil {
		t.Fatalf("read current-domain job: %v", err)
	}
	if status != "issued" {
		t.Fatalf("current-domain status=%q, want issued", status)
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

func TestRuleWriteEndpoints_roll_back_database_when_Caddy_apply_fails(t *testing.T) {
	tests := []struct {
		name   string
		seed   func(*testing.T)
		mount  func(*gin.Engine, *Handlers)
		method string
		path   string
		body   string
		assert func(*testing.T)
	}{
		{
			name: "create", method: http.MethodPost, path: "/rules", body: `{"name":"candidate","protocol":"tcp","listen_port":19001,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`,
			seed: func(t *testing.T) {
				if _, err := db.DB.Exec(`CREATE TRIGGER block_create_compensation BEFORE DELETE ON lb_rules WHEN OLD.name='candidate' BEGIN SELECT RAISE(ABORT,'delete blocked'); END`); err != nil {
					t.Fatalf("create compensation blocker: %v", err)
				}
			},
			mount: func(router *gin.Engine, handler *Handlers) { router.POST("/rules", handler.CreateRule) },
			assert: func(t *testing.T) {
				var count int
				if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name='candidate'").Scan(&count); err != nil {
					t.Fatalf("count candidate rule: %v", err)
				}
				if count != 0 {
					t.Fatalf("candidate rule count=%d, want transaction rollback", count)
				}
			},
		},
		{
			name: "update", method: http.MethodPut, path: "/rules/lb_tx_update", body: `{"name":"candidate"}`,
			seed: func(t *testing.T) {
				seedAuditRule(t, "lb_tx_update", "before", "update.example.test", 19002, true, "manual", false)
				if _, err := db.DB.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tx_update','127.0.0.1',9000,1,1,'tcp')"); err != nil {
					t.Fatalf("seed TCP upstream: %v", err)
				}
				if _, err := db.DB.Exec(`UPDATE lb_rules SET protocol='tcp' WHERE caddy_id='lb_tx_update'; CREATE TRIGGER block_update_compensation BEFORE DELETE ON lb_rules WHEN OLD.name='candidate' BEGIN SELECT RAISE(ABORT,'delete blocked'); END`); err != nil {
					t.Fatalf("prepare update compensation blocker: %v", err)
				}
			},
			mount: func(router *gin.Engine, handler *Handlers) { router.PUT("/rules/:caddy_id", handler.UpdateRule) },
			assert: func(t *testing.T) {
				var name string
				if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_tx_update'").Scan(&name); err != nil {
					t.Fatalf("read updated rule: %v", err)
				}
				if name != "before" {
					t.Fatalf("rule name=%q, want transaction rollback", name)
				}
			},
		},
		{
			name: "enable", method: http.MethodPost, path: "/rules/lb_tx_enable/enable",
			seed: func(t *testing.T) {
				seedAuditRule(t, "lb_tx_enable", "enable", "enable-tx.example.test", 8080, false, "manual", false)
				seedAuditUpstream(t, "lb_tx_enable")
				if _, err := db.DB.Exec(`CREATE TRIGGER block_enable_compensation BEFORE UPDATE ON lb_rules WHEN OLD.enabled=1 AND NEW.enabled=0 BEGIN SELECT RAISE(ABORT,'restore blocked'); END`); err != nil {
					t.Fatalf("create enable compensation blocker: %v", err)
				}
			},
			mount: func(router *gin.Engine, handler *Handlers) {
				router.POST("/rules/:caddy_id/enable", handler.EnableRule)
			},
			assert: func(t *testing.T) {
				var enabled bool
				if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_tx_enable'").Scan(&enabled); err != nil {
					t.Fatalf("read enabled state: %v", err)
				}
				if enabled {
					t.Fatal("enable write remained after failed Caddy apply")
				}
			},
		},
		{
			name: "disable", method: http.MethodPost, path: "/rules/lb_tx_disable/disable",
			seed: func(t *testing.T) {
				seedAuditRule(t, "lb_tx_disable", "disable", "disable-tx.example.test", 8080, true, "manual", false)
				seedAuditUpstream(t, "lb_tx_disable")
				if _, err := db.DB.Exec(`CREATE TRIGGER block_disable_compensation BEFORE UPDATE ON lb_rules WHEN OLD.enabled=0 AND NEW.enabled=1 BEGIN SELECT RAISE(ABORT,'restore blocked'); END`); err != nil {
					t.Fatalf("create disable compensation blocker: %v", err)
				}
			},
			mount: func(router *gin.Engine, handler *Handlers) {
				router.POST("/rules/:caddy_id/disable", handler.DisableRule)
			},
			assert: func(t *testing.T) {
				var enabled bool
				if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_tx_disable'").Scan(&enabled); err != nil {
					t.Fatalf("read disabled state: %v", err)
				}
				if !enabled {
					t.Fatal("disable write remained after failed Caddy apply")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var handler *Handlers
			if test.name == "create" || test.name == "update" {
				handler = newUpdateAuditRuleHandlers(t, "lb_tx_update", 1, false).handler
			} else {
				handler, _, _ = newAuditRuleHandlers(t, 1)
			}
			test.seed(t)
			router := gin.New()
			test.mount(router, handler)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code == http.StatusOK || response.Code == http.StatusCreated {
				t.Fatalf("write unexpectedly succeeded: %s", response.Body.String())
			}
			test.assert(t)
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
	if strings.Contains(currentConfig(), `"lb_bool_false"`) {
		t.Fatalf("disabled route remained in Caddy config: %s", currentConfig())
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
	cancelCertJob = func(jobID int) { cancelled <- jobID }
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

func TestUpdateRuleACL_rolls_back_database_when_Caddy_apply_fails(t *testing.T) {
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
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("ACL update status=%d body=%s", response.Code, response.Body.String())
	}
	var mode, list string
	if err := db.DB.QueryRow("SELECT ip_acl_mode,ip_acl_list FROM lb_rules WHERE caddy_id='lb_acl_restore'").Scan(&mode, &list); err != nil {
		t.Fatalf("read ACL after failed apply: %v", err)
	}
	if mode != "allow" || list != `["192.0.2.0/24"]` {
		t.Fatalf("ACL=(%q,%q), want transaction rollback", mode, list)
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
	harness := &updateAuditHarness{blockOnRoutePost: 1}
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
			if routePosts.Add(1) == harness.blockOnRoutePost && failFirstRoute {
				close(firstRouteEntered)
				<-releaseFirstRoute
				response.WriteHeader(http.StatusBadRequest)
				_, _ = response.Write([]byte("load rejected"))
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
