package handlers

import (
	"encoding/json"
	"sort"
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

func TestBuildOpenAPIYAML_contains_active_configuration_and_certificate_paths(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, path := range []string{"/config/import/validate", "/certificate-configs", "/certificates", "/rules/:caddy_id/cert-info"} {
		if _, exists := document.Paths[path]; !exists {
			t.Errorf("OpenAPI missing active path %s", path)
		}
	}
}

func TestAPIDocRoutes_cover_public_router_contract(t *testing.T) {
	publicRoutes := []string{
		"GET /api-keys",
		"GET /admin-tls",
		"GET /audit-logs",
		"GET /auth/setup",
		"GET /branding",
		"GET /ca-providers",
		"GET /ca-providers/:id",
		"GET /caddy/config",
		"GET /caddy/host-metrics",
		"GET /caddy/logs",
		"GET /caddy/metrics",
		"GET /caddy/status",
		"GET /certificate-configs",
		"GET /certificates",
		"GET /certificates/jobs",
		"GET /certificates/jobs/:id",
		"GET /certificates/jobs/:id/logs",
		"GET /cluster/nodes",
		"GET /cluster/register/:id/status",
		"GET /cluster/status",
		"GET /cluster/sync/snapshot",
		"GET /config",
		"GET /config/export",
		"GET /config/health",
		"GET /dns-providers",
		"GET /docs",
		"GET /metrics/connections",
		"GET /metrics/history",
		"GET /metrics/overview",
		"GET /metrics/realtime",
		"GET /metrics/rule/:caddy_id",
		"GET /rules",
		"GET /rules/:caddy_id",
		"GET /rules/:caddy_id/caddy-config",
		"GET /rules/:caddy_id/cert-info",
		"GET /rules/:caddy_id/log-stream",
		"GET /rules/:caddy_id/logs",
		"GET /rules/:caddy_id/metrics-history",
		"GET /openapi.yaml",
		"GET /system/info",
		"GET /system/logs",
		"GET /system/metrics",
		"GET /users",
		"GET /users/me",
		"GET /users/me/api-keys",
		"PATCH /api-keys/:id/status",
		"PATCH /users/me",
		"PATCH /users/me/api-keys/:id",
		"POST /api-keys",
		"POST /admin-tls/inspect",
		"POST /auth/login",
		"POST /auth/logout",
		"POST /auth/setup",
		"POST /ca-providers/:id/test",
		"POST /caddy/restart",
		"POST /caddy/start",
		"POST /caddy/stop",
		"POST /certificate-configs",
		"POST /certificate-configs/:id/test",
		"POST /certificate-configs/test",
		"POST /certificates/issue",
		"POST /certificates/jobs/:id/retry",
		"POST /certificates/parse",
		"POST /cluster/mode",
		"POST /cluster/nodes/:id/approve",
		"POST /cluster/nodes/:id/reject",
		"POST /cluster/nodes/report",
		"POST /cluster/promote",
		"POST /cluster/register",
		"POST /cluster/register-tokens",
		"POST /cluster/sync/pull",
		"POST /config/import",
		"POST /config/import/v1",
		"POST /config/import/validate",
		"POST /config/preview",
		"POST /config/reload",
		"POST /config/validate",
		"POST /rules",
		"POST /rules/:caddy_id/acl",
		"POST /rules/:caddy_id/duplicate",
		"POST /rules/:caddy_id/enable",
		"POST /rules/cert-info",
		"POST /system/restart",
		"POST /users",
		"POST /users/:id/reset-password",
		"POST /users/me/api-keys",
		"PUT /admin-tls",
		"PUT /ca-providers/:id",
		"PUT /caddy/config",
		"PUT /certificate-configs/:id",
		"PUT /cluster/settings",
		"PUT /config",
		"PUT /rules/:caddy_id",
		"PUT /rules/:caddy_id/disable",
		"PUT /users/:id",
		"PUT /users/:id/status",
		"DELETE /api-keys/:id",
		"DELETE /certificate-configs/:id",
		"DELETE /certificates/jobs/:id",
		"DELETE /cluster/nodes/:id",
		"DELETE /rules/:caddy_id",
		"DELETE /users/:id",
		"DELETE /users/me/api-keys/:id",
	}
	intentionallyUndocumented := map[string]struct{}{
		"GET /docs":         {},
		"GET /openapi.yaml": {},
	}

	want := make(map[string]struct{}, len(publicRoutes))
	for _, route := range publicRoutes {
		want[route] = struct{}{}
	}
	got := make(map[string]struct{}, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		got[route.Method+" "+route.Path] = struct{}{}
	}
	for route := range intentionallyUndocumented {
		delete(want, route)
		delete(got, route)
	}

	var missing, unexpected []string
	for route := range want {
		if _, exists := got[route]; !exists {
			missing = append(missing, route)
		}
	}
	for route := range got {
		if _, exists := want[route]; !exists {
			unexpected = append(unexpected, route)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	if len(missing) > 0 || len(unexpected) > 0 {
		t.Fatalf("API documentation route mismatch\nmissing: %v\nunexpected: %v", missing, unexpected)
	}
}

func TestAPIDocRoutes_match_snapshot_authorization_and_request_contracts(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	var snapshotExample struct {
		Data struct {
			SchemaVersion int `json:"schema_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(routes["GET /cluster/sync/snapshot"].Response), &snapshotExample); err != nil {
		t.Fatalf("parse snapshot response example: %v", err)
	}
	if snapshotExample.Data.SchemaVersion != 1 {
		t.Errorf("snapshot schema_version=%d, want 1", snapshotExample.Data.SchemaVersion)
	}

	for _, key := range []string{"GET /api-keys", "GET /config/health", "GET /cluster/nodes"} {
		route := routes[key]
		if !strings.Contains(route.Description, "所有已登录用户可读") {
			t.Errorf("%s does not document authenticated read access", key)
		}
		for _, routeError := range route.Errors {
			if strings.HasPrefix(routeError, "403 ") {
				t.Errorf("%s incorrectly documents 403: %s", key, routeError)
			}
		}
	}
	if description := routes["GET /cluster/nodes"].Description; !strings.Contains(description, "JWT") || !strings.Contains(description, "仅主节点") {
		t.Errorf("GET /cluster/nodes lost JWT or master-node semantics: %q", description)
	}
	if request := routes["POST /rules/:caddy_id/duplicate"].Request; request != "" {
		t.Errorf("duplicate rule documents unused request body: %s", request)
	}
}
