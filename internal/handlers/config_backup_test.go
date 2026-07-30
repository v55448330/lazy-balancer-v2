package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestUpdateUser_rejects_invalid_id_and_body(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "invalid id", path: "/users/not-a-number", body: `{}`},
		{name: "invalid body", path: "/users/1", body: `{"role":`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name')"); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			router := gin.New()
			router.PUT("/users/:id", h.UpdateUser)
			request := httptest.NewRequest(http.MethodPut, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")

			// When
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			assertUserState(t, "original", "admin", "Original Name", "original-hash")
		})
	}
}

func TestUpdateUser_preserves_omitted_display_name(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(`{"role":"user"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "user", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_password_hashing_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	body := `{"username":"changed","role":"user","display_name":"Changed Name","password":"` + strings.Repeat("p", 73) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "admin", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_update_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("CREATE TRIGGER fail_user_role_update BEFORE UPDATE ON users WHEN NEW.role='user' BEGIN SELECT RAISE(ABORT,'role update failed'); END"); err != nil {
		t.Fatalf("create update failure trigger: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(`{"username":"changed","role":"user","display_name":"Changed Name"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "admin", "Original Name", "original-hash")
}

func assertUserState(t *testing.T, username, role, displayName, passwordHash string) {
	t.Helper()
	var gotUsername, gotRole, gotDisplayName, gotPasswordHash string
	if err := db.DB.QueryRow("SELECT username, role, COALESCE(display_name,''), password_hash FROM users WHERE id=1").Scan(&gotUsername, &gotRole, &gotDisplayName, &gotPasswordHash); err != nil {
		t.Fatalf("query user state: %v", err)
	}
	if gotUsername != username || gotRole != role || gotDisplayName != displayName || gotPasswordHash != passwordHash {
		t.Fatalf("user state=(%q,%q,%q,%q), want (%q,%q,%q,%q)", gotUsername, gotRole, gotDisplayName, gotPasswordHash, username, role, displayName, passwordHash)
	}
}

func newBackupTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	return &Handlers{
		cfg:            cfg,
		caddyService:   services.NewCaddyService(fakeCaddy.URL),
		clusterService: services.NewClusterService(db.DB, nil),
	}
}

func completeBackupJSON(t *testing.T, tables map[string][]map[string]any) string {
	t.Helper()
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	for table, rows := range tables {
		completeTables[table] = rows
	}
	data, err := json.Marshal(configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1},
		Config: map[string]any{},
		Tables: completeTables,
	})
	if err != nil {
		t.Fatalf("marshal complete backup: %v", err)
	}
	return string(data)
}

func TestConfigBackup_export_import_roundtrip(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('keep', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_bak1', 'backup-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES ('ci', 'kh', 'lb_sk_x', 1)"); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET log_level='debug', sync_interval=45 WHERE id=1"); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When: export
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then
	if exportResponse.Code != http.StatusOK || !strings.Contains(exportResponse.Body.String(), "lazy-balancer-v2") {
		t.Fatalf("export status=%d body=%.200s", exportResponse.Code, exportResponse.Body.String())
	}
	backup := exportResponse.Body.String()

	// Given: destructive change
	if _, err := db.DB.Exec("DELETE FROM lb_rules; DELETE FROM users; UPDATE global_config SET log_level='error', sync_interval=10, cluster_version=99 WHERE id=1"); err != nil {
		t.Fatalf("destructive change: %v", err)
	}

	// When: import
	importResponse := httptest.NewRecorder()
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResponse, importRequest)

	// Then
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%.300s", importResponse.Code, importResponse.Body.String())
	}
	var userCount, ruleCount, keyCount int
	var logLevel string
	var syncInterval, clusterVersion int
	if err := db.DB.QueryRow("SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM lb_rules), (SELECT COUNT(*) FROM api_keys), log_level, sync_interval, cluster_version FROM global_config WHERE id=1").Scan(&userCount, &ruleCount, &keyCount, &logLevel, &syncInterval, &clusterVersion); err != nil {
		t.Fatalf("verify restored data: %v", err)
	}
	if userCount != 1 || ruleCount != 1 || keyCount != 1 {
		t.Fatalf("restored counts users=%d rules=%d keys=%d", userCount, ruleCount, keyCount)
	}
	if logLevel != "debug" || syncInterval != 45 {
		t.Fatalf("restored config log_level=%q sync_interval=%d", logLevel, syncInterval)
	}
	if clusterVersion == 99 {
		t.Fatal("cluster_version was overwritten by import")
	}
}

func TestImportConfigBackup_requeues_imported_non_terminal_certificate_jobs(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_requeue_v2','requeue','http','requeue.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_requeue_v2','requeue.example.test','creating_order',999999)`); err != nil {
		t.Fatalf("seed non-terminal job: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(exportResponse.Body.String()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_requeue_v2'").Scan(&status); err != nil {
		t.Fatalf("read recovered certificate job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("recovered certificate job status=%q, want queued", status)
	}
}

func TestImportConfigBackup_reports_partial_failure_when_certificate_job_recovery_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export", nil))
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(exportResponse.Body.String()))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "配置已导入但证书任务恢复失败") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestImportConfigBackup_joins_import_and_certificate_job_recovery_failures(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_bad_recovery", "name": "bad", "protocol": "http", "listen_port": 8443, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "invalid certificate") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s, want joined failures", response.Code, response.Body.String())
	}
}

func TestConfigBackup_slave_mode_forbidden(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("export on slave status = %d, want 403", response.Code)
	}
}

func TestDumpTable_uses_one_transaction_snapshot_across_tables(t *testing.T) {
	// Given
	_ = newBackupTestHandlers(t)
	if _, err := db.DB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("enable WAL: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_snapshot', 'before', 'http', 8080); INSERT INTO upstreams (rule_id, host, port) VALUES ('lb_snapshot', 'old-host', 9000)"); err != nil {
		t.Fatalf("seed snapshot data: %v", err)
	}
	tx, err := db.DB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback()
	if _, err := dumpTable(context.Background(), tx, "lb_rules"); err != nil {
		t.Fatalf("read first table: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE upstreams SET host='new-host' WHERE rule_id='lb_snapshot'"); err != nil {
		t.Fatalf("concurrent update: %v", err)
	}

	// When
	upstreams, err := dumpTable(context.Background(), tx, "upstreams")

	// Then
	if err != nil {
		t.Fatalf("read second table: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0]["host"] != "old-host" {
		t.Fatalf("upstream snapshot=%v, want old-host", upstreams)
	}
}

func TestConfigBackup_import_rejects_invalid_file(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(`{"meta":{"app":"other-app"},"tables":{}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid backup status = %d, want 400", response.Code)
	}
	var body models.APIResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if body.Message == "" || !strings.Contains(body.Message, "Lazy Balancer") {
		t.Fatalf("error message = %q, want explicit v2 backup identity rejection", body.Message)
	}
}

func TestValidateConfigImport_rejects_v2_backup_missing_required_contract(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	tests := []struct {
		name string
		body string
	}{
		{name: "unsupported version", body: `{"meta":{"app":"lazy-balancer-v2","version":2},"tables":{"lb_rules":[],"users":[]}}`},
		{name: "missing tables", body: `{"meta":{"app":"lazy-balancer-v2","version":1}}`},
		{name: "missing users", body: `{"meta":{"app":"lazy-balancer-v2","version":1},"tables":{"lb_rules":[]}}`},
		{name: "missing global config", body: `{"meta":{"app":"lazy-balancer-v2","version":1},"tables":{"lb_rules":[],"upstreams":[],"path_rules":[],"users":[],"api_keys":[],"ca_providers":[],"certificate_configs":[],"cert_jobs":[]}}`},
		{name: "missing exported table", body: `{"meta":{"app":"lazy-balancer-v2","version":1},"config":{},"tables":{"lb_rules":[],"upstreams":[],"path_rules":[],"users":[],"api_keys":[],"ca_providers":[],"certificate_configs":[]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)

			// Then
			var envelope struct {
				Data importValidateResponse `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode validation response: %v", err)
			}
			if envelope.Data.Valid {
				t.Fatalf("validation accepted invalid v2 backup: %s", response.Body.String())
			}
			if envelope.Data.Type != "v2" {
				t.Fatalf("validation type=%q, want v2", envelope.Data.Type)
			}
		})
	}
}

func TestImportConfigBackup_rolls_back_when_certificate_materialization_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('old-user', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users":    {{"id": 2, "username": "new-user", "password_hash": "hash", "role": "admin"}},
		"lb_rules": {{"caddy_id": "lb_badcert", "name": "new-rule", "protocol": "http", "listen_port": 8443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules, newRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_badcert'").Scan(&newRules); err != nil {
		t.Fatalf("count new rules: %v", err)
	}
	if oldRules != 1 || newRules != 0 {
		t.Fatalf("rules after failed import: old=%d new=%d", oldRules, newRules)
	}
}

func TestImportConfigBackup_restores_partial_certificate_materialization(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES ('old-user', 'hash', 'admin')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old_partial', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	const firstRuleID = "lb_partial_valid"
	const oldCert = "certificate-before-import"
	const oldKey = "key-before-import"
	if err := services.WriteCertFiles(firstRuleID, oldCert, oldKey); err != nil {
		t.Fatalf("seed certificate files: %v", err)
	}
	validCert, validKey, err := generateTestCert("partial.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("generate valid certificate: %v", err)
	}
	backup, err := json.Marshal(configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1},
		Config: map[string]any{},
		Tables: map[string][]map[string]any{
			"upstreams": {}, "path_rules": {}, "api_keys": {}, "ca_providers": {}, "certificate_configs": {}, "cert_jobs": {},
			"users": {{"id": 2, "username": "new-user", "password_hash": "hash", "role": "admin"}},
			"lb_rules": {
				{"caddy_id": firstRuleID, "name": "first-rule", "protocol": "http", "domain": "partial.example.test", "listen_port": 8443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": validCert, "tls_key": validKey},
				{"caddy_id": "lb_partial_invalid", "name": "second-rule", "protocol": "http", "domain": "invalid.example.test", "listen_port": 9443, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	router := gin.New()
	router.POST("/config/import", harness.handler.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(backup)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules, importedRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old_partial'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN ('lb_partial_valid','lb_partial_invalid')").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if oldRules != 1 || importedRules != 0 {
		t.Fatalf("rules after failed import: old=%d imported=%d", oldRules, importedRules)
	}
	certPath, keyPath := services.CertFilePaths(firstRuleID)
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read restored certificate: %v", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read restored key: %v", err)
	}
	if string(cert) != oldCert || string(key) != oldKey {
		t.Fatalf("restored certificate pair=(%q,%q), want (%q,%q)", cert, key, oldCert, oldKey)
	}
	if harness.loadCalls() != 1 || harness.currentConfig() != `{"marker":"before-import"}` {
		t.Fatalf("Caddy loads=%d config=%s, want one restore to pre-import config", harness.loadCalls(), harness.currentConfig())
	}
}

func TestImportConfigBackup_reports_import_and_runtime_restore_failures(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	harness.failRestore()
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_bad_restore", "name": "bad-cert", "protocol": "http", "listen_port": 8443, "enable_tls": 1, "tls_source": "manual", "tls_cert": "invalid-cert", "tls_key": "invalid-key"}},
	})
	router := gin.New()
	router.POST("/config/import", harness.handler.ImportConfigBackup)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
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
