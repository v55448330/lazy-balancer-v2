package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
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
	for _, path := range []string{"/config/import/validate", "/certificate-configs", "/certificates", "/rules/{caddy_id}/cert-info"} {
		if _, exists := document.Paths[path]; !exists {
			t.Errorf("OpenAPI missing active path %s", path)
		}
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
	if snapshotExample.Data.SchemaVersion != services.CurrentSnapshotSchema {
		t.Errorf("snapshot schema_version=%d, want %d", snapshotExample.Data.SchemaVersion, services.CurrentSnapshotSchema)
	}

	for _, key := range []string{"GET /api-keys", "GET /config/health"} {
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
	for _, key := range []string{
		"GET /cluster/status",
		"GET /cluster/nodes",
		"POST /cluster/register-tokens",
		"POST /cluster/nodes/:id/approve",
		"POST /cluster/nodes/:id/reject",
		"POST /cluster/nodes/:id/login-ticket",
		"PUT /cluster/nodes/:id/access-url",
		"DELETE /cluster/nodes/:id",
		"POST /cluster/mode",
		"POST /cluster/promote",
		"POST /cluster/sync/pull",
		"PUT /cluster/settings",
	} {
		description := routes[key].Description
		if !strings.Contains(description, "JWT") || !strings.Contains(description, "API Key") {
			t.Errorf("%s does not document JWT and API Key authentication: %q", key, description)
		}
		if strings.Contains(description, "仅接受 JWT") {
			t.Errorf("%s retains JWT-only authentication description: %q", key, description)
		}
	}
	if description := routes["GET /cluster/nodes"].Description; !strings.Contains(description, "仅主节点") {
		t.Errorf("GET /cluster/nodes lost master-node semantics: %q", description)
	}
	if request := routes["POST /rules/:caddy_id/duplicate"].Request; request != "" {
		t.Errorf("duplicate rule documents unused request body: %s", request)
	}
}

func TestBuildOpenAPIYAML_documents_operation_specific_contracts(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string `yaml:"security"`
			Parameters []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
			RequestBody struct {
				Required bool                      `yaml:"required"`
				Content  map[string]map[string]any `yaml:"content"`
			} `yaml:"requestBody"`
			Responses map[string]struct {
				Content map[string]map[string]any `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}

	// When
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	if _, exists := document.Paths["/users/{id}"]; !exists {
		t.Fatal("OpenAPI does not convert Gin path parameters")
	}
	if _, exists := document.Paths["/users/:id"]; exists {
		t.Fatal("OpenAPI retains Gin path syntax")
	}
	updateUser := document.Paths["/users/{id}"]["put"]
	if len(updateUser.Parameters) != 1 || updateUser.Parameters[0].Name != "id" || updateUser.Parameters[0].In != "path" {
		t.Fatalf("update user parameters=%+v", updateUser.Parameters)
	}
	metricsHistory := document.Paths["/metrics/history"]["get"]
	if len(metricsHistory.Parameters) != 2 {
		t.Fatalf("metrics history query parameters=%+v", metricsHistory.Parameters)
	}
	if _, exists := document.Paths["/users"]["post"].Responses["201"]; !exists {
		t.Fatal("create user success response is not 201")
	}
	snapshot := document.Paths["/cluster/sync/snapshot"]["get"]
	if response, exists := snapshot.Responses["304"]; !exists || len(response.Content) != 0 {
		t.Fatalf("snapshot 304 response=%+v exists=%v", response, exists)
	}
	adminTLS := document.Paths["/admin-tls"]["put"]
	if _, exists := adminTLS.RequestBody.Content["multipart/form-data"]; !exists {
		t.Fatal("admin TLS update request is not multipart/form-data")
	}
	issue := document.Paths["/certificates/issue"]["post"]
	if issue.RequestBody.Required {
		t.Fatal("certificate issue request body is incorrectly required")
	}
}

func TestBuildOpenAPIYAML_documents_per_operation_security(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `yaml:"security"`
		} `yaml:"paths"`
		Components struct {
			SecuritySchemes map[string]any `yaml:"securitySchemes"`
		} `yaml:"components"`
	}

	// When
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, operation := range []struct {
		path   string
		method string
	}{{"/auth/login", "post"}, {"/auth/ticket-login", "post"}, {"/auth/setup", "get"}, {"/auth/setup", "post"}, {"/branding", "get"}} {
		security := document.Paths[operation.path][operation.method].Security
		if security == nil || len(security) != 0 {
			t.Errorf("%s %s security=%v, want explicit empty security", operation.method, operation.path, security)
		}
	}
	if _, exists := document.Components.SecuritySchemes["mcpApiKey"]; !exists {
		t.Fatal("OpenAPI missing independent MCP API key scheme")
	}
	mcpSecurity := document.Paths["/mcp"]["post"].Security
	if len(mcpSecurity) != 1 {
		t.Fatalf("MCP security=%v", mcpSecurity)
	}
	if _, exists := mcpSecurity[0]["mcpApiKey"]; !exists {
		t.Fatalf("MCP security=%v, want mcpApiKey", mcpSecurity)
	}
	confirmSecurity := document.Paths["/cluster/registration/confirm"]["post"].Security
	if len(confirmSecurity) != 1 {
		t.Fatalf("registration confirmation security=%v", confirmSecurity)
	}
	if _, exists := confirmSecurity[0]["clusterToken"]; !exists {
		t.Fatalf("registration confirmation security=%v, want clusterToken", confirmSecurity)
	}
	dashboardSecurity := document.Paths["/metrics/dashboard"]["get"].Security
	if len(dashboardSecurity) != 1 {
		t.Fatalf("metrics dashboard security=%v", dashboardSecurity)
	}
	if _, exists := dashboardSecurity[0]["bearerAuth"]; !exists {
		t.Fatalf("metrics dashboard security=%v, want bearerAuth", dashboardSecurity)
	}
}

func TestAPIDocRoutes_documents_registration_confirmation_lifecycle(t *testing.T) {
	// Given
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	// When
	statusDescription := routes["GET /cluster/register/:id/status"].Description

	// Then
	if !strings.Contains(statusDescription, "确认") {
		t.Fatalf("registration status description does not direct clients to confirmation: %q", statusDescription)
	}
	if strings.Contains(statusDescription, "首次成功快照同步后失效") {
		t.Fatalf("registration status description retains snapshot-based invalidation: %q", statusDescription)
	}
}

func TestBuildOpenAPIYAML_wraps_business_examples_and_documents_exceptions(t *testing.T) {
	// Given
	openAPI := buildOpenAPIYAML()
	var document struct {
		Info struct {
			Description string `yaml:"description"`
		} `yaml:"info"`
		Paths map[string]map[string]struct {
			Description string `yaml:"description"`
			Responses   map[string]struct {
				Content map[string]struct {
					Example map[string]any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}

	// When
	err := yaml.Unmarshal([]byte(openAPI), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	example := document.Paths["/config"]["get"].Responses["200"].Content["application/json"].Example
	if example["code"] != 0 || example["data"] == nil {
		t.Fatalf("business response example=%v", example)
	}
	for _, exception := range []string{"登录", "下载", "MCP", "304", "HTML", "YAML"} {
		if !strings.Contains(document.Info.Description, exception) {
			t.Errorf("general description missing response exception %q", exception)
		}
	}
	for path, methods := range document.Paths {
		for method, operation := range methods {
			if method == "post" || method == "put" || method == "delete" {
				if !strings.Contains(operation.Description, "安全重试") {
					t.Errorf("%s %s lacks retry contract: %q", method, path, operation.Description)
				}
			}
		}
	}
	fragmentContract := document.Paths["/cluster/nodes/{id}/login-ticket"]["post"].Description
	for _, fragment := range []string{"#login_ticket=", "percent-encoded", "清除 fragment"} {
		if !strings.Contains(fragmentContract, fragment) {
			t.Errorf("login ticket description missing %q: %q", fragment, fragmentContract)
		}
	}
}

func TestAPIDocRoutes_document_validation_and_error_statuses(t *testing.T) {
	// Given
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	// When
	validate := routes["POST /config/import/validate"]

	// Then
	for _, text := range []string{"200", "valid=false", "400", "413", "16 MiB"} {
		if !strings.Contains(validate.Description, text) && !containsRouteError(validate.Errors, text) {
			t.Errorf("validation contract missing %q: description=%q errors=%v", text, validate.Description, validate.Errors)
		}
	}
	for key, statuses := range map[string][]string{
		"POST /users":                       {"409"},
		"PUT /users/:id":                    {"404", "409"},
		"PUT /users/:id/status":             {"404", "409"},
		"DELETE /users/:id":                 {"404", "409"},
		"POST /users/:id/reset-password":    {"404"},
		"POST /certificates/jobs/:id/retry": {"409"},
		"POST /certificates/issue":          {"400", "404", "429", "500"},
	} {
		for _, status := range statuses {
			if !containsRouteError(routes[key].Errors, status) {
				t.Errorf("%s missing documented status %s: %v", key, status, routes[key].Errors)
			}
		}
	}
}

func TestCreateUser_returnsConflict_whenUsernameAlreadyExists(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "duplicate", "admin", true)

	// When
	response := serveUserMutation(h, http.MethodPost, "/users", `{"username":"duplicate","password":"secret","role":"user"}`, 1, h.CreateUser)

	// Then
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "用户名已存在") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestCreateUserError_usesChineseMessage(t *testing.T) {
	// Given
	h := &Handlers{}

	// When
	response := serveUserMutation(h, http.MethodPost, "/users", `{`, 1, h.CreateUser)

	// Then
	if !strings.Contains(response.Body.String(), "请求格式错误") {
		t.Fatalf("user error=%q", response.Body.String())
	}
}

func TestDeleteAPIKeyError_usesChineseMessage(t *testing.T) {
	// Given
	h := &Handlers{}
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodDelete, "/api-keys/invalid", nil)
	context.Params = gin.Params{{Key: "id", Value: "invalid"}}

	// When
	h.DeleteAPIKey(context)

	// Then
	if !strings.Contains(response.Body.String(), "ID 参数无效") {
		t.Fatalf("API key error=%q", response.Body.String())
	}
}

func TestGetBranding_returnsDefaults_withoutWritingMissingFile(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	h := NewHandlers(Dependencies{Config: &config.Config{DataDir: dataDir, Version: "test"}})
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodGet, "/branding", nil)

	// When
	h.GetBranding(context)

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":"test"`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "branding.json")); !os.IsNotExist(err) {
		t.Fatalf("GET branding wrote file: %v", err)
	}
}

func TestSeedDefaultBranding_createsFile_once(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")

	// When
	err := SeedDefaultBranding(dataDir)

	// Then
	if err != nil {
		t.Fatalf("seed default branding: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded branding: %v", err)
	}
	if !strings.Contains(string(data), `"app_name": "Lazy Balancer"`) {
		t.Fatalf("seeded branding=%q", data)
	}
}

func TestSeedDefaultBranding_preservesExistingFile(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")
	if err := os.WriteFile(path, []byte(`{"app_name":"Custom"}`), 0644); err != nil {
		t.Fatal(err)
	}

	// When
	err := SeedDefaultBranding(dataDir)

	// Then
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(path)
	if err != nil || string(preserved) != `{"app_name":"Custom"}` {
		t.Fatalf("existing branding was overwritten: data=%q err=%v", preserved, err)
	}
}

func containsRouteError(errors []string, status string) bool {
	for _, routeError := range errors {
		if strings.HasPrefix(routeError, status+" ") {
			return true
		}
	}
	return false
}
