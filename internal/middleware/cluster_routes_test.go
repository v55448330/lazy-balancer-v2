package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

func newMiddlewareTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		services.StopAuditCleanup()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	cfg := &config.Config{
		Port: 8000, StaticDir: t.TempDir(), CaddyAdminURL: "http://127.0.0.1:1",
		CaddyMetricsURL: "http://127.0.0.1:1/metrics", MetricsInterval: 60,
		NodeName: "node-test", JWTSecret: "test-secret",
	}
	caddy := services.NewCaddyService(cfg.CaddyAdminURL)
	handler := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddy, MetricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 60),
		SyncService: services.NewSyncService(db.DB, cfg, caddy), ClusterService: services.NewClusterService(db.DB, nil),
		CAProviderService: services.NewCAProviderService(),
	})
	return SetupRouter(handler, cfg)
}

func addClusterRouteTestAPIKey(t *testing.T, userID int, username, role, plain string) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, is_enabled) VALUES (?, ?, '', ?, 1)", userID, username, role); err != nil {
		t.Fatalf("insert %s user: %v", role, err)
	}
	hash := sha256.Sum256([]byte(plain))
	if _, err := db.DB.Exec("INSERT INTO api_keys (name, key_hash, key_prefix, created_by, is_enabled) VALUES (?, ?, ?, ?, 1)", username+"-key", hex.EncodeToString(hash[:]), plain[:12], userID); err != nil {
		t.Fatalf("insert %s API key: %v", role, err)
	}
}

func requestWithAPIKey(router *gin.Engine, method, path, key string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("X-API-Key", key)
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestSetupRouter_registers_cluster_contract_and_removes_legacy_routes(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)

	// When
	routes := make(map[string]bool)
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	// Then
	expected := []string{
		"GET /api/v1/cluster/status",
		"GET /api/v1/cluster/nodes",
		"POST /api/v1/cluster/register-tokens",
		"POST /api/v1/cluster/register",
		"GET /api/v1/cluster/register/:id/status",
		"POST /api/v1/cluster/nodes/:id/approve",
		"POST /api/v1/cluster/nodes/:id/reject",
		"DELETE /api/v1/cluster/nodes/:id",
		"POST /api/v1/cluster/mode",
		"POST /api/v1/cluster/promote",
		"GET /api/v1/cluster/sync/snapshot",
		"POST /api/v1/cluster/sync/pull",
		"POST /api/v1/cluster/nodes/report",
		"PUT /api/v1/cluster/settings",
	}
	for _, route := range expected {
		if !routes[route] {
			t.Errorf("missing route %s", route)
		}
	}
	for route := range routes {
		if route == "POST /api/v1/nodes/register" || route == "GET /api/v1/sync/status" || route == "GET /api/v1/sync/config" || route == "POST /api/v1/sync/pull" || route == "POST /api/v1/nodes/:id/heartbeat" {
			t.Errorf("legacy route remains registered: %s", route)
		}
	}
}

func TestClusterRoutesAcceptAdminAPIKey(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_admin-cluster-route-test"
	addClusterRouteTestAPIKey(t, 101, "cluster-admin", "admin", key)

	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/cluster/nodes"},
		{http.MethodPost, "/api/v1/cluster/sync/pull"},
	} {
		recorder := requestWithAPIKey(router, test.method, test.path, key)
		if recorder.Code == http.StatusUnauthorized {
			t.Errorf("%s %s returned 401 for admin API key: %s", test.method, test.path, recorder.Body.String())
		}
	}
}

func TestClusterWriteRouteRejectsUserAPIKey(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_user-cluster-route-test"
	addClusterRouteTestAPIKey(t, 102, "cluster-user", "user", key)

	recorder := requestWithAPIKey(router, http.MethodPost, "/api/v1/cluster/sync/pull", key)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
	}
}
