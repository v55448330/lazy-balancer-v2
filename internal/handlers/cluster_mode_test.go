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
