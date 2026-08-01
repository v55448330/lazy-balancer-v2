package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestIssueCertificate_rejects_malformed_JSON_and_records_failure(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "请求格式错误")
}

func TestUpdateCertificateConfig_validatesEffectiveCredentials(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id, name, dns_provider, dns_credentials, enabled) VALUES
		(1, 'valid', 'dnspod', '{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}', 1),
		(2, 'invalid', 'dnspod', '{"auth_mode":"dnspod","app_id":"old-id"}', 1)`); err != nil {
		t.Fatalf("seed certificate configs: %v", err)
	}
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	tests := []struct {
		name, path, body string
	}{
		{name: "credentials only", path: "/certificate-configs/1", body: `{"dns_credentials":{"auth_mode":"dnspod","app_id":"new-id"}}`},
		{name: "provider only", path: "/certificate-configs/2", body: `{"dns_provider":"dnspod"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPut, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}
}

func TestIssueCertificate_records_queue_unavailable_failure(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "失败")
}

func TestIssueCertificate_rejects_partial_rule_selector_without_creating_jobs(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	tests := []struct {
		name      string
		body      string
		wantScope string
	}{
		{name: "only domain", body: `{"domain":"partial.example"}`, wantScope: "范围：全部 ACME 规则"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			var jobs int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs").Scan(&jobs); err != nil {
				t.Fatalf("count certificate jobs: %v", err)
			}
			if jobs != 0 {
				t.Fatalf("certificate jobs=%d, want 0", jobs)
			}
			assertLatestCertificateAudit(t, tt.wantScope, "请求格式错误")
		})
	}
}

func TestIssueCertificate_records_each_rule_and_batch_failure(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	services.GetCAQueueManager().Start()
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enabled, enable_tls, tls_source)
		VALUES ('lb_disabled', 'disabled', 'http', 'disabled.example', 8443, 0, 1, 'acme_dns'),
		       ('lb_mismatch', 'mismatch', 'http', 'expected.example', 9443, 1, 1, 'acme_dns'),
		       ('lb_job_fail', 'job-fail', 'http', 'job.example', 10443, 1, 1, 'acme_dns');
		CREATE TRIGGER fail_cert_job_insert BEFORE INSERT ON cert_jobs
		BEGIN SELECT RAISE(ABORT, 'cert job insert failed'); END;
	`); err != nil {
		t.Fatalf("seed certificate rules: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantScope  string
	}{
		{name: "missing rule", body: `{"caddy_id":"lb_missing","domain":"missing.example"}`, wantStatus: http.StatusNotFound, wantScope: "规则：lb_missing"},
		{name: "invalid state", body: `{"caddy_id":"lb_disabled","domain":"disabled.example"}`, wantStatus: http.StatusBadRequest, wantScope: "规则：lb_disabled"},
		{name: "domain mismatch", body: `{"caddy_id":"lb_mismatch","domain":"other.example"}`, wantStatus: http.StatusBadRequest, wantScope: "规则：lb_mismatch"},
		{name: "single task failure", body: `{"caddy_id":"lb_job_fail","domain":"job.example"}`, wantStatus: http.StatusInternalServerError, wantScope: "规则：lb_job_fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)

			// Then
			if response.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantStatus)
			}
			assertLatestCertificateAudit(t, tt.wantScope, "失败")
		})
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("all-task failure status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "失败")

	if _, err := db.DB.Exec("DROP TRIGGER fail_cert_job_insert; DROP TABLE lb_rules"); err != nil {
		t.Fatalf("force batch query failure: %v", err)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("batch query status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "失败")
}

func TestIssueCertificate_rejects_recent_running_job_without_requeue(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_running','running','http','running.example',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at)
		VALUES ('lb_running','running.example','creating_order','active message',datetime('now'));
	`); err != nil {
		t.Fatalf("seed running certificate job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_running","domain":"running.example"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s, want 429", response.Code, response.Body.String())
	}
	var status, message string
	if err := db.DB.QueryRow("SELECT status,message FROM cert_jobs WHERE rule_id='lb_running'").Scan(&status, &message); err != nil {
		t.Fatalf("read running job: %v", err)
	}
	if status != "creating_order" || message != "active message" {
		t.Fatalf("running job=(%q,%q), want unchanged", status, message)
	}
}

func TestIssueCertificate_targeted_dual_domain_rule_queues_complete_domain_set(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dual','dual','http','WWW.Example.com, example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed dual-domain rule: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_dual"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var domain string
	if err := db.DB.QueryRow("SELECT domain FROM cert_jobs WHERE rule_id='lb_dual'").Scan(&domain); err != nil {
		t.Fatalf("read dual-domain certificate job: %v", err)
	}
	if domain != "example.com,www.example.com" {
		t.Fatalf("queued domain=%q, want complete normalized set", domain)
	}
}

func TestIssueCertificate_batch_preserves_running_jobs(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES
			('lb_batch_order','order','http','order.example',8443,1,1,'acme_dns'),
			('lb_batch_download','download','http','download.example',9443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at) VALUES
			('lb_batch_order','order.example','creating_order','active message',datetime('now')),
			('lb_batch_download','download.example','downloaded','active message',datetime('now'));
	`); err != nil {
		t.Fatalf("seed running jobs: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":0`) {
		t.Fatalf("body=%s, want no unchanged running jobs counted as queued", response.Body.String())
	}
	for ruleID, wantStatus := range map[string]string{"lb_batch_order": "creating_order", "lb_batch_download": "downloaded"} {
		var status, message string
		if err := db.DB.QueryRow("SELECT status,message FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status, &message); err != nil {
			t.Fatalf("read %s job: %v", ruleID, err)
		}
		if status != wantStatus || message != "active message" {
			t.Fatalf("%s job=(%q,%q), want (%q,%q)", ruleID, status, message, wantStatus, "active message")
		}
	}
}

func assertLatestCertificateAudit(t *testing.T, wantScope, wantResult string) {
	t.Helper()
	var action, detail string
	if err := db.AuditDB.QueryRow("SELECT action, detail FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &detail); err != nil {
		t.Fatalf("read latest certificate audit: %v", err)
	}
	if action != "触发签发" || !strings.Contains(detail, wantScope) || !strings.Contains(detail, wantResult) {
		t.Fatalf("audit action=%q detail=%q, want scope %q result %q", action, detail, wantScope, wantResult)
	}
}
