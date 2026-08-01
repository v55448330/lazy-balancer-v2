package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsDashboardToolForwardsReadOnlyRequest(t *testing.T) {
	// Given
	var received bool
	rest := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/metrics/dashboard" {
			t.Errorf("request=%s %s", request.Method, request.URL.Path)
		}
		received = true
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"code":0,"data":{"rules":[]}}`))
	}))
	defer rest.Close()

	// When
	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "get_metrics_dashboard", `{}`)

	// Then
	if !received || !strings.Contains(result, "rules") {
		t.Fatalf("received=%v result=%q", received, result)
	}
}
