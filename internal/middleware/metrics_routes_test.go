package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupRouter_registers_authenticated_metrics_dashboard(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)

	// When
	routes := make(map[string]bool)
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	// Then
	if !routes["GET /api/v1/metrics/dashboard"] {
		t.Fatal("authenticated metrics dashboard route is not registered")
	}
}

func TestMetricsDashboard_rejects_unauthenticated_request(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/dashboard", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d; body=%s", response.Code, http.StatusUnauthorized, response.Body.String())
	}
}
