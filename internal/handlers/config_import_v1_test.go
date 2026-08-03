package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	_ "unsafe"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

//go:linkname testServicesCertDir lazy-balancer-v2/internal/services.certDir
var testServicesCertDir string

type importRollbackHarness struct {
	handler       *Handlers
	certDir       string
	currentConfig func() string
	loadCalls     func() int
	failRestore   func()
}

func newImportRollbackHarness(t *testing.T) importRollbackHarness {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })

	var stateMu sync.Mutex
	currentConfig := `{"marker":"before-import"}`
	loads := 0
	rejectLoads := false
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/config/":
			stateMu.Lock()
			body := currentConfig
			stateMu.Unlock()
			_, _ = response.Write([]byte(body))
		case request.Method == http.MethodPost && request.URL.Path == "/load":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			stateMu.Lock()
			loads++
			if rejectLoads {
				stateMu.Unlock()
				response.WriteHeader(http.StatusInternalServerError)
				_, _ = response.Write([]byte("restore rejected"))
				return
			}
			currentConfig = string(body)
			stateMu.Unlock()
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	return importRollbackHarness{
		handler: &Handlers{
			cfg:            cfg,
			caddyService:   services.NewCaddyService(fakeCaddy.URL),
			clusterService: services.NewClusterService(db.DB, nil),
		},
		certDir: testServicesCertDir,
		currentConfig: func() string {
			stateMu.Lock()
			defer stateMu.Unlock()
			return currentConfig
		},
		loadCalls: func() int {
			stateMu.Lock()
			defer stateMu.Unlock()
			return loads
		},
		failRestore: func() {
			stateMu.Lock()
			rejectLoads = true
			stateMu.Unlock()
		},
	}
}

func TestImportV1Config_rolls_back_when_certificate_materialization_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old_v1', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old_v1'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if oldRules != 1 {
		t.Fatalf("old rule count=%d, want 1", oldRules)
	}
}

func TestValidateConfigImport_rejects_disabled_v1_rule_with_out_of_range_port(t *testing.T) {
	tests := []struct {
		name       string
		listenPort int
		upstream   int
	}{
		{name: "zero listen port", listenPort: 0, upstream: 9000},
		{name: "listen port above maximum", listenPort: 65536, upstream: 9000},
		{name: "zero upstream port", listenPort: 8080, upstream: 0},
		{name: "upstream port above maximum", listenPort: 8080, upstream: 65536},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			backup := fmt.Sprintf(`{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"disabled","protocol":true,"listen":%d,"server_name":"disabled.example.test","status":false,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":%d,"weight":100}}]}}`, test.listenPort, test.upstream)
			router := gin.New()
			router.POST("/config/validate", h.ValidateConfigImport)
			request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			var envelope struct {
				Data importValidateResponse `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode validation response: %v", err)
			}
			if envelope.Data.Valid {
				t.Fatalf("validation accepted invalid disabled rule: %s", response.Body.String())
			}
		})
	}
}

func TestImportV1Config_requeues_original_non_terminal_jobs_after_rollback(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	services.GetCAQueueManager().PauseAndDrain()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_requeue_v1','old-rule','http','old.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_requeue_v1','old.example.test','creating_order',999999)`); err != nil {
		t.Fatalf("seed original non-terminal job: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	block := make(chan struct{})
	acmeMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	t.Cleanup(func() { close(block); services.GetCAQueueManager().PauseAndDrain(); acmeMock.Close() })
	if _, err := db.DB.Exec("UPDATE ca_providers SET provider='letsencrypt', directory_url=? WHERE enabled=1", acmeMock.URL); err != nil {
		t.Fatalf("redirect ACME directory: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='acme@example.test' WHERE id=1"); err != nil {
		t.Fatalf("set ACME email: %v", err)
	}

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import unexpectedly succeeded: %s", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_requeue_v1'").Scan(&status); err != nil {
		t.Fatalf("read recovered original job: %v", err)
	}
	if status != "queued" && status != "creating_account" {
		t.Fatalf("recovered original job status=%q, want queued or creating_account (pipeline active)", status)
	}
}

func TestImportV1Config_reports_partial_failure_when_certificate_job_recovery_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "配置已导入但证书任务恢复失败") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestImportV1Config_joins_import_and_certificate_job_recovery_failures(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"bad","protocol":true,"listen":8443,"server_name":"bad.example","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "invalid certificate") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s, want joined failures", response.Code, response.Body.String())
	}
}

func TestImportV1Config_restores_partial_certificate_materialization(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old_v1_partial', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	validCert, validKey, err := generateTestCert("v1-partial.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("generate valid certificate: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"first-rule","protocol":true,"listen":8443,"server_name":"v1-partial.example.test","ssl":true,"ssl_cert":` + stringMustMarshal(t, validCert) + `,"ssl_key":` + stringMustMarshal(t, validKey) + `,"status":true,"upstream_list":[1]}},
			{"pk":2,"fields":{"proxy_name":"second-rule","protocol":true,"listen":9443,"server_name":"v1-invalid.example.test","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[2]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}},
			{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", harness.handler.ImportV1Config)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules, importedRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old_v1_partial'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id<>'lb_old_v1_partial'").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if oldRules != 1 || importedRules != 0 {
		t.Fatalf("rules after failed import: old=%d imported=%d", oldRules, importedRules)
	}
	entries, err := os.ReadDir(harness.certDir)
	if err != nil {
		t.Fatalf("read certificate directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("certificate directory contains %d files after rollback, want none", len(entries))
	}
	if harness.loadCalls() != 1 || harness.currentConfig() != `{"marker":"before-import"}` {
		t.Fatalf("Caddy loads=%d config=%s, want one restore to pre-import config", harness.loadCalls(), harness.currentConfig())
	}
}

func TestImportV1Config_reports_import_and_runtime_restore_failures(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	harness.failRestore()
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"bad-cert","protocol":true,"listen":8443,"server_name":"bad.example","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", harness.handler.ImportV1Config)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusInternalServerError || !strings.Contains(body, "invalid certificate") || !strings.Contains(body, "restore rejected") {
		t.Fatalf("status=%d body=%s, want joined import and restore errors", response.Code, body)
	}
	if strings.Contains(body, "已回滚") {
		t.Fatalf("response falsely claims rollback success: %s", body)
	}
}

func TestRestoreImportRuntime_reports_certificate_restore_failure(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	snapshot := importRuntimeSnapshot{
		caddyConfig: map[string]interface{}{"marker": "before-import"},
		certFiles: services.CertFilesSnapshot{
			"../invalid": {},
		},
	}

	// When
	err := harness.handler.restoreImportRuntime(snapshot)

	// Then
	if err == nil || !strings.Contains(err.Error(), "非法的规则编号") {
		t.Fatalf("restore error=%v, want certificate restore failure", err)
	}
}

func stringMustMarshal(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal string: %v", err)
	}
	return string(data)
}
