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
		{name: "only caddy ID", body: `{"caddy_id":"lb_partial"}`, wantScope: "规则：lb_partial"},
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
