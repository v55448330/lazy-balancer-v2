package handlers

import (
	"encoding/json"
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

func stringMustMarshal(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal string: %v", err)
	}
	return string(data)
}
