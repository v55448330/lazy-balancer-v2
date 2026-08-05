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

func TestImportV1Config_removes_orphaned_path_rules(t *testing.T) {
	// Given：导入前存在规则及其路径规则，v1 导入覆盖后不得留下孤儿 path_rules
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enabled) VALUES ('lb_orphan_v1', 'old-rule', 'http', 'orphan.example.test', 8080, 1);
		INSERT INTO path_rules (rule_id, sort_order, match_type, path) VALUES ('lb_orphan_v1', 0, 'prefix', '/legacy/')`); err != nil {
		t.Fatalf("seed rule with path rules: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var pathRuleCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM path_rules").Scan(&pathRuleCount); err != nil {
		t.Fatalf("count path_rules: %v", err)
	}
	if pathRuleCount != 0 {
		t.Fatalf("orphaned path_rules count=%d, want 0", pathRuleCount)
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

func TestImportV1Config_skips_empty_domain_HTTP_rules(t *testing.T) {
	// Given：v1 备份中一条 HTTP 规则域名为空（无法创建的死规则），一条 HTTP 规则正常，一条 TCP 规则无域名
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"empty-domain","protocol":true,"listen":8441,"server_name":"","status":true,"upstream_list":[1]}},
			{"pk":2,"fields":{"proxy_name":"valid-rule","protocol":true,"listen":8442,"server_name":"valid.example.test","status":true,"upstream_list":[2]}},
			{"pk":3,"fields":{"proxy_name":"tcp-rule","protocol":false,"listen":8443,"server_name":"","status":true,"upstream_list":[3]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}},
			{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9002,"weight":100}},
			{"pk":3,"fields":{"status":true,"address":"127.0.0.1","port":9003,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：空域名 HTTP 规则跳过并告警，其余规则正常导入
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "域名为空") {
		t.Fatalf("import response missing skip warning: %s", response.Body.String())
	}
	var emptyDomainRules, importedRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name='empty-domain'").Scan(&emptyDomainRules); err != nil {
		t.Fatalf("count skipped rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name IN ('valid-rule','tcp-rule')").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if emptyDomainRules != 0 || importedRules != 2 {
		t.Fatalf("rules after import: empty-domain=%d imported=%d, want 0 skipped and 2 imported", emptyDomainRules, importedRules)
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
