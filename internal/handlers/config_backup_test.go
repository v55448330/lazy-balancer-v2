package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

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
	var body map[string]json.RawMessage
	_ = json.Unmarshal(response.Body.Bytes(), &body)
}
