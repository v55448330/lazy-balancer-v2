package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestSetClusterMode_returns_registration_id_when_local_transition_fails(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = db.DB.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"registration_id":73,"registration_secret":"secret"}}`))
	}))
	defer master.Close()
	cfg := &config.Config{NodeName: "node-test", Port: 8000}
	h := &Handlers{
		cfg:            cfg,
		syncService:    services.NewSyncService(db.DB, cfg, services.NewCaddyService("http://127.0.0.1:1")),
		clusterService: services.NewClusterService(db.DB, nil),
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/mode", h.SetClusterMode)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/mode", strings.NewReader(`{"mode":"slave","master_url":"`+master.URL+`","register_token":"one-time"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope models.APIResponse
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok || data["registration_id"] != float64(73) {
		t.Fatalf("response data=%#v, want registration_id 73", envelope.Data)
	}
	var action, detail string
	if err := db.AuditDB.QueryRow("SELECT action, detail FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &detail); err != nil {
		t.Fatalf("query failure audit: %v", err)
	}
	if action != "切换失败" || !strings.Contains(detail, "registration_id：73") {
		t.Fatalf("audit action=%q detail=%q", action, detail)
	}
}

func TestSetClusterMode_rejectsCredentialedMasterURLWithoutAuditingCredentials(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	master := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("credentialed master URL reached the remote server")
	}))
	defer master.Close()
	parsed, err := url.Parse(master.URL)
	if err != nil {
		t.Fatal(err)
	}
	credentialedURL := parsed.Scheme + "://audit-user:audit-password@" + parsed.Host
	cfg := &config.Config{NodeName: "node-test", Port: 8000}
	h := &Handlers{
		cfg:            cfg,
		syncService:    services.NewSyncService(db.DB, cfg, services.NewCaddyService("http://127.0.0.1:1")),
		clusterService: services.NewClusterService(db.DB, nil),
	}
	router := gin.New()
	router.POST("/cluster/mode", h.SetClusterMode)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/mode", strings.NewReader(`{"mode":"slave","master_url":"`+credentialedURL+`","register_token":"one-time"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	router.ServeHTTP(response, request)
	var auditDetail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(auditDetail, "audit-user") || strings.Contains(auditDetail, "audit-password") {
		t.Fatalf("audit leaked credentials: %q", auditDetail)
	}
	if !strings.Contains(auditDetail, parsed.Scheme+"://"+parsed.Host) {
		t.Fatalf("audit detail=%q, want canonical master host", auditDetail)
	}
}

func TestUpdateClusterSettings_sync_interval_range_validation(t *testing.T) {
	// R42 发现1：handler 必须把 ErrInvalidSyncInterval 映射为 400（原实现统一 403），
	// 合法区间仍返回 200。
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.PUT("/cluster/settings", h.UpdateClusterSettings)

	cases := []struct {
		name       string
		payload    string
		wantStatus int
		wantBody   string
	}{
		{"zero", `{"sync_interval":0}`, http.StatusBadRequest, "同步间隔需在 10-86400 秒之间"},
		{"negative", `{"sync_interval":-5}`, http.StatusBadRequest, "同步间隔需在 10-86400 秒之间"},
		{"below_min", `{"sync_interval":9}`, http.StatusBadRequest, "同步间隔需在 10-86400 秒之间"},
		{"above_max", `{"sync_interval":86401}`, http.StatusBadRequest, "同步间隔需在 10-86400 秒之间"},
		{"min_ok", `{"sync_interval":10}`, http.StatusOK, ""},
		{"max_ok", `{"sync_interval":86400}`, http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(tc.payload))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			if tc.wantBody != "" && !strings.Contains(response.Body.String(), tc.wantBody) {
				t.Fatalf("body=%s, want to contain %q", response.Body.String(), tc.wantBody)
			}
		})
	}
}
