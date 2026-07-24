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
	for _, field := range []string{
		"ip_acl_mode",
		"ip_acl_list",
		"custom_routes_enabled",
		"path_rules",
		"proxy_dial_timeout",
		"proxy_response_header_timeout",
		"proxy_read_timeout",
		"proxy_write_timeout",
		"proxy_stream_timeout",
		`"upstreams":null`,
	} {
		if !strings.Contains(openAPI, field) {
			t.Errorf("OpenAPI missing rule routing field %s", field)
		}
	}
}
