package handlers

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildOpenAPIYAML_contains_cluster_contract_and_valid_yaml(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, path := range []string{"/cluster/status", "/cluster/register", "/cluster/sync/snapshot", "/cluster/nodes/report", "/cluster/promote"} {
		if !strings.Contains(openAPI, "  "+path+":") {
			t.Errorf("OpenAPI missing path %s", path)
		}
	}
	for _, legacyPath := range []string{"  /nodes/register:", "  /sync/status:", "  /sync/pull:"} {
		if strings.Contains(openAPI, legacyPath) {
			t.Errorf("OpenAPI retains legacy path %s", legacyPath)
		}
	}
	for _, scheme := range []string{"clusterToken:", "registrationSecret:"} {
		if !strings.Contains(openAPI, scheme) {
			t.Errorf("OpenAPI missing security scheme %s", scheme)
		}
	}
}
