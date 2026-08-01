package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/middleware"
	"lazy-balancer-v2/internal/services"
)

func TestOpenAPIDocumentation_covers_registeredGinAPIRoutes(t *testing.T) {
	// Given
	router := newAPIDocTestRouter(t)
	want := make(map[string]struct{})
	for _, route := range router.Routes() {
		path, found := strings.CutPrefix(route.Path, "/api/v1")
		if !found || path == "/docs" || path == "/openapi.yaml" {
			continue
		}
		want[route.Method+" "+ginPathToOpenAPI(path)] = struct{}{}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var document struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	got := make(map[string]struct{})
	for path, operations := range document.Paths {
		for method := range operations {
			got[strings.ToUpper(method)+" "+path] = struct{}{}
		}
	}
	missing, unexpected := routeSetDifference(want, got), routeSetDifference(got, want)
	if len(missing) > 0 || len(unexpected) > 0 {
		t.Fatalf("API documentation route mismatch\nmissing: %v\nunexpected: %v", missing, unexpected)
	}
}

func newAPIDocTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		services.StopAuditCleanup()
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	cfg := &config.Config{
		Port: 8000, StaticDir: t.TempDir(), CaddyAdminURL: "http://127.0.0.1:1",
		CaddyMetricsURL: "http://127.0.0.1:1/metrics", MetricsInterval: 60,
		NodeName: "apidocs-test", JWTSecret: "test-secret",
	}
	caddy := services.NewCaddyService(cfg.CaddyAdminURL)
	handler := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddy, MetricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 60),
		SyncService: services.NewSyncService(db.DB, cfg, caddy), ClusterService: services.NewClusterService(db.DB, nil),
		CAProviderService: services.NewCAProviderService(),
	})
	return middleware.SetupRouter(handler, cfg)
}

func ginPathToOpenAPI(path string) string {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if name, found := strings.CutPrefix(part, ":"); found {
			parts[index] = "{" + name + "}"
		}
	}
	return strings.Join(parts, "/")
}

func routeSetDifference(left, right map[string]struct{}) []string {
	difference := make([]string, 0)
	for route := range left {
		if _, exists := right[route]; !exists {
			difference = append(difference, route)
		}
	}
	sort.Strings(difference)
	return difference
}
