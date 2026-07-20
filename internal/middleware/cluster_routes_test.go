package middleware

import (
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

func TestSetupRouter_registers_cluster_contract_and_removes_legacy_routes(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	cfg := &config.Config{
		Port: 8000, StaticDir: t.TempDir(), CaddyAdminURL: "http://127.0.0.1:1",
		CaddyMetricsURL: "http://127.0.0.1:1/metrics", MetricsInterval: 60,
		NodeName: "node-test", JWTSecret: "test-secret",
	}
	caddy := services.NewCaddyService(cfg.CaddyAdminURL)
	syncService := services.NewSyncService(db.DB, cfg, caddy)
	clusterService := services.NewClusterService(db.DB, nil)
	handler := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddy, MetricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 60),
		SyncService: syncService, ClusterService: clusterService, CAProviderService: services.NewCAProviderService(),
	})

	// When
	router := SetupRouter(handler, cfg)
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
