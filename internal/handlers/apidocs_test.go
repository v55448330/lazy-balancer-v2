package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lazy-balancer-v2/internal/apipath"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/services/dnsproviders"
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
		"custom_routes_enabled",
		"path_rules",
		"proxy_dial_timeout",
		"proxy_response_header_timeout",
		"proxy_read_timeout",
		"proxy_write_timeout",
		"proxy_stream_timeout",
		"proxy_flush_interval",
		"proxy_stream_close_delay",
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
	// （2026-09-06 裁定）：批量全量重签须显式 {"all":true} 确认，请求体不再可省略
	issue := document.Paths["/certificates/issue"]["post"]
	if !issue.RequestBody.Required {
		t.Fatal("certificate issue request body must be required")
	}
}

func TestBuildOpenAPIYAML_documentsRuntimeInputsAndLimits(t *testing.T) {
	type operation struct {
		Parameters []struct {
			Name string `yaml:"name"`
			In   string `yaml:"in"`
		} `yaml:"parameters"`
		RequestBody struct {
			Content map[string]map[string]any `yaml:"content"`
		} `yaml:"requestBody"`
		Responses map[string]any `yaml:"responses"`
	}
	var document struct {
		Paths map[string]map[string]operation `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	assertQuery := func(path, method, name string) {
		t.Helper()
		for _, parameter := range document.Paths[path][method].Parameters {
			if parameter.Name == name && parameter.In == "query" {
				return
			}
		}
		t.Errorf("%s %s parameters=%+v, want query %s", method, path, document.Paths[path][method].Parameters, name)
	}
	for _, operation := range []struct {
		path   string
		method string
		name   string
	}{
		{"/certificates/jobs/{id}/retry", "post", "force"},
		{"/certificates/issue", "post", "force"},
		{"/config/import", "post", "sections"},
		{"/config/import/validate", "post", "sections"},
		{"/auth/oidc/login", "get", "return_to"},
	} {
		assertQuery(operation.path, operation.method, operation.name)
	}
	for _, path := range []string{"/config/import", "/config/import/validate"} {
		content := document.Paths[path]["post"].RequestBody.Content
		for _, contentType := range []string{"application/json", "application/octet-stream"} {
			if _, exists := content[contentType]; !exists {
				t.Errorf("POST %s request content=%v, want %s", path, content, contentType)
			}
		}
	}
	responses := document.Paths["/certificates/parse"]["post"].Responses
	for _, status := range []string{"400", "413"} {
		if _, exists := responses[status]; !exists {
			t.Errorf("POST /certificates/parse responses=%v, want %s", responses, status)
		}
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
					// /auth/oidc/login|callback 等跳转端点经
					// rawResponse 暴露裸字符串示例(302 形态),示例不再恒为
					// 对象——本测试只对 /config 的对象形状断言。
					Example any `yaml:"example"`
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
	configExample, isObject := document.Paths["/config"]["get"].Responses["200"].Content["application/json"].Example.(map[string]any)
	if !isObject || configExample["code"] != 0 || configExample["data"] == nil {
		t.Fatalf("business response example=%v, want wrapped {code,message,data} object", configExample)
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
	for _, text := range []string{"200", "valid=false", "400", "413", "128MB"} {
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

// 绊线
// export 去不可达 413(GET 无请求体);download 补 428(mfaStepUpGuard GET 特例,
// middleware.go:886-887);import 响应登记 data.summary/disabled_conflicts/warnings
// (warnings 为软跳过/会话吊销/ACME 悬挂等警告的唯一机器可读出口);promote 描述
// 对齐实现(不调 BumpClusterVersion,启动自动备份调度器);/mcp/tools 登记
// read_only 字段语义(HTTP 语义只读,不代表只读 Key 可见性)。
func TestAPIDocRoutes_importQueuePartialContract(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}
	route := routes["POST /config/import/v1"]
	if !containsRouteError(route.Errors, "409") {
		t.Fatalf("V1 import errors=%v, want certificate queue drain 409", route.Errors)
	}
	for _, field := range []string{"partial", "warnings", "disabled_conflicts"} {
		if !strings.Contains(route.Response, field) {
			t.Fatalf("V1 import response missing %s: %s", field, route.Response)
		}
	}
	if !strings.Contains(route.Description, "200") || !strings.Contains(route.Description, "partial=true") {
		t.Fatalf("V1 import description lacks committed/partial contract: %s", route.Description)
	}
}

func TestAPIDocRoutes_documentationContracts(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	for _, routeError := range routes["GET /config/export"].Errors {
		if strings.HasPrefix(routeError, "413") {
			t.Errorf("GET /config/export documents unreachable 413 (GET has no request body): %q", routeError)
		}
	}
	if !containsRouteError(routes["GET /auto-backup/:id/download"].Errors, "428") {
		t.Errorf("GET /auto-backup/:id/download errors=%v, want 428 mfa_step_up_required", routes["GET /auto-backup/:id/download"].Errors)
	}
	importRoute := routes["POST /config/import"]
	for _, field := range []string{"summary", "disabled_conflicts", "warnings"} {
		if !strings.Contains(importRoute.Response, field) {
			t.Errorf("POST /config/import response example missing data.%s: %s", field, importRoute.Response)
		}
	}
	promote := routes["POST /cluster/promote"].Description
	if strings.Contains(promote, "递增版本") {
		t.Errorf("POST /cluster/promote description retains 递增版本 (Promote does not bump cluster version): %q", promote)
	}
	if !strings.Contains(promote, "自动备份调度器") {
		t.Errorf("POST /cluster/promote description lacks auto-backup scheduler startup: %q", promote)
	}
	tools := routes["GET /mcp/tools"].Description
	// read_only 是「对只读 Key 可用」的能力语义，与
	// method==GET 不等价——描述必须点名 export_config 例外与读探测 POST，
	// 并逐工具钉死分类（弱子串断言曾把相反语义钉住）。
	for _, fragment := range []string{"read_only", "只读 API Key", "export_config", "get_caddy_config"} {
		if !strings.Contains(tools, fragment) {
			t.Errorf("GET /mcp/tools description lacks %q: %q", fragment, tools)
		}
	}
	if strings.Contains(tools, "HTTP 语义只读") || strings.Contains(tools, "method==GET") {
		t.Errorf("GET /mcp/tools description retains stale HTTP-semantics read_only: %q", tools)
	}
	// 读探测 POST 工具集取自生产单一事实源（mcpserver.ReadOnlyProbeTools），
	// 不在测试里再手写一份——手写平行清单会与生产集合同步漂移（此前正是两份）。
	// test_certificate_config 会写 DNS TXT 验证记录、test_ca_provider 会真实写
	// ca_providers.credentials，两者都不在探测集内（工具保留给管理员）。
	readOnlyProbes := mcpserver.ReadOnlyProbeTools
	specs := mcpserver.ListToolSpecs()
	if len(specs) == 0 {
		t.Fatal("ListToolSpecs returned no tools")
	}
	if len(readOnlyProbes) == 0 {
		t.Fatal("ReadOnlyProbeTools 为空——只读探测集守卫失效")
	}
	for _, spec := range specs {
		// export_config 与 get_caddy_config 的 handler 首行拒绝只读 Key（403），
		// 不计入「只读可用」——read_only 是能力语义，不是 HTTP 方法语义。
		_, probe := readOnlyProbes[spec.Name]
		wantReadOnly := probe || (spec.Method == http.MethodGet && spec.Name != "export_config" && spec.Name != "get_caddy_config")
		if spec.ReadOnly != wantReadOnly {
			t.Errorf("tool %s (%s) read_only=%v, want %v（只读 Key 可用性语义）", spec.Name, spec.Method, spec.ReadOnly, wantReadOnly)
		}
	}
	for _, hidden := range []string{"export_config", "get_caddy_config"} {
		if specsReadOnly(specs, hidden) {
			t.Errorf("%s read_only=true, want false（只读 Key 调用恒 403）", hidden)
		}
	}
	for name := range readOnlyProbes {
		if !specsReadOnly(specs, name) {
			t.Errorf("%s read_only=false, want true（读探测 POST 对只读 Key 可用）", name)
		}
	}
}

func specsReadOnly(specs []mcpserver.ToolSpec, name string) bool {
	for _, spec := range specs {
		if spec.Name == name {
			return spec.ReadOnly
		}
	}
	return false
}

// GET /mcp/tools 的响应示例是用户文档里唯一的工具清单快照：示例与
// mcpserver.ListToolSpecs 漂移（改名/改方法/改路径/read_only 翻转/用法文案）会让
// 文档把错误的能力认知教给调用方，而文档测试此前只校验描述文字。
func TestAPIDocRoutes_mcpToolsResponseExampleMatchesToolSpecs(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}
	route, ok := routes["GET /mcp/tools"]
	if !ok {
		t.Fatal("apiDocRoutes 缺少 GET /mcp/tools")
	}
	var example struct {
		Data []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Method      string `json:"method"`
			Path        string `json:"path"`
			ReadOnly    bool   `json:"read_only"`
			Usage       string `json:"usage"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(route.Response), &example); err != nil {
		t.Fatalf("parse /mcp/tools 示例响应: %v", err)
	}
	if len(example.Data) == 0 {
		t.Fatal("/mcp/tools 示例响应必须至少含一个工具条目")
	}
	specs := mcpserver.ListToolSpecs()
	for _, item := range example.Data {
		var matched *mcpserver.ToolSpec
		for i := range specs {
			if specs[i].Name == item.Name {
				matched = &specs[i]
				break
			}
		}
		if matched == nil {
			t.Fatalf("示例工具 %q 不在 ListToolSpecs 中（文档在教不存在的工具）", item.Name)
		}
		if item.Description != matched.Description {
			t.Errorf("%s 示例描述与工具注册表不一致:\n示例: %s\n注册表: %s", item.Name, item.Description, matched.Description)
		}
		if item.Method != matched.Method {
			t.Errorf("%s 示例 method=%q, want %q", item.Name, item.Method, matched.Method)
		}
		if item.Path != matched.Path {
			t.Errorf("%s 示例 path=%q, want %q", item.Name, item.Path, matched.Path)
		}
		if item.ReadOnly != matched.ReadOnly {
			t.Errorf("%s 示例 read_only=%v, want %v", item.Name, item.ReadOnly, matched.ReadOnly)
		}
		if item.Usage != matched.Usage || item.Usage == "" {
			t.Errorf("%s 示例 usage=%q, want %q（usage 恒返回）", item.Name, item.Usage, matched.Usage)
		}
	}
}

// 非 JSON 响应示例（二进制/TXT）必须登记 rawResponse 与
// 显式媒体类型——此前两个下载端点默认 application/json 且被 documentedResponse
// 包成 {"code":0,...,"data":非 JSON}，OpenAPI 消费方按 JSON 解析必失败。
func TestAPIDocs_nonJSONResponsesDeclareExplicitMediaType(t *testing.T) {
	// Given 全部路由及其生成规格
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	expected := map[string]struct {
		contentType  string
		plainExample bool
	}{
		// 备份正文示例是 JSON 形状（说明包内结构），但媒体类型是 gzip；
		// 其余三个端点的示例本身就是纯文本。
		"GET /config/export":                {"application/gzip", false},
		"GET /auto-backup/:id/download":     {"application/octet-stream", true},
		"GET /security/ip-lists/:id/export": {"text/plain; charset=utf-8", true},
		"GET /mcp/ops-playbook":             {"text/markdown; charset=utf-8", true},
	}

	// When 逐路由检查非 JSON 响应示例（合法 JSON 数组/对象由生成器包成
	// {code,message,data} 信封；{...} 形态为文档占位符，同样按 JSON 处理；
	// 只有纯文本/二进制形态才必须显式登记）
	for _, route := range apiDocRoutes {
		response := strings.TrimSpace(route.Response)
		if response == "" || strings.HasPrefix(response, "{") || strings.HasPrefix(response, "[") || json.Valid([]byte(response)) {
			continue
		}
		key := route.Method + " " + route.Path
		contract := apiDocContracts[key]
		if !contract.rawResponse {
			t.Errorf("%s response example %q lacks rawResponse registration（会被包成 JSON 信封）", key, response)
		}
		if contract.responseContentType == "" {
			t.Errorf("%s response example %q lacks explicit responseContentType", key, response)
		}
	}

	// Then 已知 raw 端点：契约与生成的 YAML 媒体类型一致；纯文本端点
	// 还须保证示例不是被包成 JSON 对象。
	for key, want := range expected {
		contentType := want.contentType
		contract := apiDocContracts[key]
		if !contract.rawResponse || contract.responseContentType != contentType {
			t.Errorf("%s contract=%+v, want rawResponse with %s", key, contract, contentType)
		}
		method, path := splitRouteKey(t, key)
		operation := document.Paths[apipath.ToOpenAPI(path)][strings.ToLower(method)]
		media := operation.Responses["200"].Content
		if _, ok := media[contentType]; !ok {
			t.Errorf("%s 200 content=%v, want %s", key, mediaTypeKeys(media), contentType)
		}
		if _, isJSON := media["application/json"]; isJSON {
			t.Errorf("%s still documents application/json response", key)
		}
		if want.plainExample {
			for _, entry := range media {
				if _, isMap := entry.Example.(map[string]any); isMap {
					t.Errorf("%s example=%v, want plain-text example (not JSON object)", key, entry.Example)
				}
			}
		}
	}
}

func splitRouteKey(t *testing.T, key string) (string, string) {
	t.Helper()
	method, path, found := strings.Cut(key, " ")
	if !found {
		t.Fatalf("malformed route key %q", key)
	}
	return method, path
}

func mediaTypeKeys(media map[string]struct {
	Example any `yaml:"example"`
}) []string {
	keys := make([]string, 0, len(media))
	for key := range media {
		keys = append(keys, key)
	}
	return keys
}

// 媒体类型与示例形态须自洽——ops-playbook 声明
// text/markdown; charset=utf-8 却给 JSON 示例；/admin-tls 与
// /admin-tls/inspect 只登记 multipart，遗漏 MCP 通道唯一的
// application/json 变体。
func TestBuildOpenAPIYAML_documentsMarkdownAndAdminTLSContentVariants(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"requestBody"`
			Responses map[string]struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}

	// Then ops-playbook 示例是 markdown 正文而非 JSON 对象（媒体类型与
	// handler 实际响应头一致，含 charset）。
	playbook := document.Paths["/mcp/ops-playbook"]["get"].Responses["200"].Content
	markdown, ok := playbook["text/markdown; charset=utf-8"]
	if !ok {
		t.Fatalf("/mcp/ops-playbook 200 content=%v, want text/markdown; charset=utf-8", mediaTypeKeys(playbook))
	}
	text, isString := markdown.Example.(string)
	if !isString || !strings.HasPrefix(text, "#") || !strings.Contains(text, "手册") {
		t.Errorf("/mcp/ops-playbook example=%v, want markdown text starting with #", markdown.Example)
	}

	// Then 两个 admin-tls 端点同时声明 multipart 与 application/json
	for _, operation := range []struct {
		path   string
		method string
	}{{"/admin-tls", "put"}, {"/admin-tls/inspect", "post"}} {
		content := document.Paths[operation.path][operation.method].RequestBody.Content
		if _, ok := content["multipart/form-data"]; !ok {
			t.Errorf("%s %s request content=%v, want multipart/form-data", operation.method, operation.path, mediaTypeKeys(content))
		}
		jsonEntry, ok := content["application/json"]
		if !ok {
			t.Errorf("%s %s request content=%v, want application/json variant (MCP 通道)", operation.method, operation.path, mediaTypeKeys(content))
			continue
		}
		if _, isMap := jsonEntry.Example.(map[string]any); !isMap {
			t.Errorf("%s %s JSON example=%v, want object", operation.method, operation.path, jsonEntry.Example)
		}
	}
}

func TestCreateUser_returnsConflict_whenUsernameAlreadyExists(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "duplicate", "admin", true)

	// When
	response := serveUserMutation(h, http.MethodPost, "/users", `{"username":"duplicate","password":"Secret1!","role":"user"}`, 1, h.CreateUser)

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

func suppressBrandingSyncSideEffects(t *testing.T, dataDir string) {
	t.Helper()
	brandingSyncMu.Lock()
	brandingSyncDataDir = dataDir
	brandingSyncLast = time.Now()
	brandingSyncFingerprint = statBrandingFile(dataDir).fingerprint()
	brandingSyncMu.Unlock()
	t.Cleanup(resetBrandingSyncGateForTest)
}

func TestGetBranding_returnsDefaults_withoutWritingMissingFile(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	h := NewHandlers(Dependencies{Config: &config.Config{DataDir: dataDir, Version: "test"}})
	suppressBrandingSyncSideEffects(t, dataDir)
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

func TestGetBranding_fileVersion_overridesBuildVersion(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	custom := `{"app_name":"Lazy Balancer","footer_text":"x","version":"9.9.9-custom"}`
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(custom), 0o644); err != nil {
		t.Fatalf("write branding: %v", err)
	}
	suppressBrandingSyncSideEffects(t, dataDir)
	h := NewHandlers(Dependencies{Config: &config.Config{DataDir: dataDir, Version: "2.0.7"}})
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodGet, "/branding", nil)

	// When
	h.GetBranding(context)

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":"9.9.9-custom"`) {
		t.Fatalf("file version must win over build version: status=%d body=%q", response.Code, response.Body.String())
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

// 规则更新的成功响应在 ACME 改域分支携带 data.warnings（旧证书已弃用的可用性
// 披露）。导入/还原链路的同类机器可读披露已登记进契约，规则链路必须有同等待遇
// ——否则按 OpenAPI 解析的外部集成/脚本拿不到该字段（契约漂移）。
func TestAPIDocRoutes_ruleUpdateDocumentsWarningsDisclosure(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}
	route := routes["PUT /rules/:caddy_id"]
	if !strings.Contains(route.Response, "warnings") {
		t.Fatalf("PUT /rules/:caddy_id response sample missing data.warnings: %s", route.Response)
	}
	for _, fragment := range []string{"warnings", "ACME", "域名"} {
		if !strings.Contains(route.Description+route.Response, fragment) {
			t.Fatalf("PUT /rules/:caddy_id 契约缺少 warnings 触发条件说明（%s）: response=%s description=%s",
				fragment, route.Response, route.Description)
		}
	}
}

// ++:OIDC 公开契约登记、lbbak 导出形态、
// validate 128MB 上限与 settings/oidc 重试契约的文档漂移绊线。
func TestBuildOpenAPIYAML_documents_oidc_public_lbbak_and_retry_contracts(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string `yaml:"security"`
			Parameters []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
			RequestBody struct {
				Content map[string]map[string]any `yaml:"content"`
			} `yaml:"requestBody"`
			Responses map[string]struct {
				Content map[string]map[string]any `yaml:"content"`
			} `yaml:"responses"`
			Description string `yaml:"description"`
		} `yaml:"paths"`
	}
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}

	// 三条公开 OIDC 路由(登录页探测/授权跳转/回调)不得误标 bearerAuth。
	for _, operation := range []struct {
		path   string
		method string
	}{{"/auth/oidc/status", "get"}, {"/auth/oidc/login", "get"}, {"/auth/oidc/callback", "get"}} {
		security := document.Paths[operation.path][operation.method].Security
		if security == nil || len(security) != 0 {
			t.Errorf("C1: %s %s security=%v, want explicit empty security (public)", operation.method, operation.path, security)
		}
	}

	// ③:导出恒为 lbbak tar.gz(application/gzip),sections query 可选分类;
	// 描述不得再宣称「下载 JSON 备份文件」。
	export := document.Paths["/config/export"]["get"]
	if _, exists := export.Responses["200"].Content["application/gzip"]; !exists {
		t.Errorf("C2: /config/export 200 content=%v, want application/gzip (lbbak tar.gz)", export.Responses["200"].Content)
	}
	foundSections := false
	for _, parameter := range export.Parameters {
		if parameter.In == "query" && parameter.Name == "sections" {
			foundSections = true
		}
	}
	if !foundSections {
		t.Errorf("C2: /config/export parameters=%+v, want sections query parameter", export.Parameters)
	}
	if strings.Contains(export.Description, "JSON 备份文件") || !strings.Contains(export.Description, "lbbak") {
		t.Errorf("C2: /config/export description=%q, want lbbak tar.gz form", export.Description)
	}

	// validate 上限与错误码按 128MB 实现口径(maxConfigImportBytes=128<<20)。
	validate := routesEntry(t, "POST /config/import/validate")
	if !strings.Contains(validate.Description, "128MB") || !containsRouteError(validate.Errors, "413") {
		t.Errorf("C2: validate description=%q errors=%v, want 128MB limit text and 413 error", validate.Description, validate.Errors)
	}
	for _, routeError := range validate.Errors {
		if strings.Contains(routeError, "16") {
			t.Errorf("C2: validate error %q retains stale 16 MiB limit", routeError)
		}
	}
	// import 端点描述须覆盖二进制 lbbak 形态(tar.gz 而非仅 JSON)。
	imp := routesEntry(t, "POST /config/import")
	if !strings.Contains(imp.Description, "lbbak") {
		t.Errorf("C2: /config/import description=%q, want binary lbbak form documented", imp.Description)
	}

	// settings/oidc 三键重试契约(PUT/DELETE 幂等可重试,POST test 读探测可重试)。
	for _, operation := range []struct {
		path   string
		method string
	}{
		{"/settings/oidc", "put"},
		{"/settings/oidc", "delete"},
		{"/settings/oidc/test", "post"},
	} {
		description := document.Paths[operation.path][operation.method].Description
		// 幂等 PUT/DELETE 与读探测 POST 不得落入「不可安全重试」族
		//(通用兜底文案「不可安全重试：重复调用可能创建新资源…」含子串
		//「安全重试」,故以排除不可重试族为契约)。
		if strings.Contains(description, "不可安全重试") || strings.Contains(description, "不可盲目安全重试") {
			t.Errorf("C7: %s %s description=%q, want retryable contract", operation.method, operation.path, description)
		}
		if !strings.Contains(description, "重试") {
			t.Errorf("C7: %s %s description=%q lacks retry contract", operation.method, operation.path, description)
		}
	}
	// 回调是浏览器整页导航：成功与失败同为 302（错误经 URL fragment 携带），
	// 文档不得登记 4xx/5xx——按规格生成的客户端会去等 JSON 错误体；唯一
	// 例外是挂在该路由上的限流 429。
	callback := routesEntry(t, "GET /auth/oidc/callback")
	if !strings.Contains(callback.Description, "302") || !strings.Contains(callback.Description, "fragment") {
		t.Errorf("C7: callback description=%q, want 302 + URL fragment error contract", callback.Description)
	}
	for _, routeError := range callback.Errors {
		status, _, _ := strings.Cut(routeError, " ")
		if status != "429" {
			t.Errorf("C7: callback errors=%v, want only 429（其余失败形态均为 302 fragment）", callback.Errors)
			break
		}
	}
	oidcUpdate := routesEntry(t, "PUT /settings/oidc")
	if !strings.Contains(oidcUpdate.Request, "display_name") {
		t.Errorf("C7: PUT /settings/oidc request=%q, want display_name example field", oidcUpdate.Request)
	}
}

func TestAPIDocs_oidcSettingsAndProbeExamplesMatchImplementation(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	decodeData := func(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var envelope struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode response: %v body=%s", err, response.Body.String())
		}
		if envelope.Code != 0 || envelope.Data == nil {
			t.Fatalf("response envelope=%s, want code=0 and object data", response.Body.String())
		}
		return envelope.Data
	}

	settingsResponse := httptest.NewRecorder()
	router.ServeHTTP(settingsResponse, httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil))
	if settingsResponse.Code != http.StatusOK {
		t.Fatalf("GET settings status=%d body=%s", settingsResponse.Code, settingsResponse.Body.String())
	}
	settings := decodeData(t, settingsResponse)
	assertKeySetsEqual(t, "GET /settings/oidc", mapKeysOf(docResponseExample(t, "GET /settings/oidc")), mapKeysOf(settings))
	for _, key := range []string{"allowed_email_domains", "allowed_groups"} {
		values, ok := settings[key].([]any)
		if !ok || len(values) != 0 {
			t.Errorf("未配置白名单 %s=%#v, want 稳定空数组", key, settings[key])
		}
	}

	probeRoute := routesEntry(t, "POST /settings/oidc/test")
	var documentedRequest map[string]any
	if err := json.Unmarshal([]byte(probeRoute.Request), &documentedRequest); err != nil {
		t.Fatalf("decode documented probe request: %v", err)
	}
	assertKeySetsEqual(t, "POST /settings/oidc/test request", mapKeysOf(documentedRequest), mapKeysOf(map[string]any{
		"issuer": true, "client_id": true, "client_secret": true,
	}))
	probeBody := `{"issuer":"` + idp.issuer + `","client_id":"test-client","client_secret":"super-secret-123"}`
	probeResponse := httptest.NewRecorder()
	router.ServeHTTP(probeResponse, httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(probeBody)))
	if probeResponse.Code != http.StatusOK {
		t.Fatalf("probe success status=%d body=%s", probeResponse.Code, probeResponse.Body.String())
	}
	probe := decodeData(t, probeResponse)
	if probe["ok"] != true || probe["credentials_checked"] != true {
		t.Fatalf("probe success data=%#v", probe)
	}
	assertKeySetsEqual(t, "POST /settings/oidc/test success", mapKeysOf(docResponseExample(t, "POST /settings/oidc/test")), mapKeysOf(probe))

	failureResponse := httptest.NewRecorder()
	router.ServeHTTP(failureResponse, httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(`{"issuer":"http://127.0.0.1:1"}`)))
	if failureResponse.Code != http.StatusOK {
		t.Fatalf("probe failure status=%d body=%s, want HTTP 200 contract", failureResponse.Code, failureResponse.Body.String())
	}
	failure := decodeData(t, failureResponse)
	assertKeySetsEqual(t, "POST /settings/oidc/test failure", mapKeysOf(failure), mapKeysOf(map[string]any{"ok": true, "error": true}))
	if failure["ok"] != false || failure["error"] == "" {
		t.Fatalf("probe failure data=%#v, want ok=false and non-empty error", failure)
	}
	for _, want := range []string{"HTTP 200", "ok=false", "error"} {
		if !strings.Contains(probeRoute.Description, want) {
			t.Errorf("探测描述缺少失败契约 %q: %q", want, probeRoute.Description)
		}
	}
}

func routesEntry(t *testing.T, key string) apiDocRoute {
	t.Helper()
	for _, route := range apiDocRoutes {
		if route.Method+" "+route.Path == key {
			return route
		}
	}
	t.Fatalf("route %s missing from apiDocRoutes", key)
	return apiDocRoute{}
}

// 任务 ID 是 "threat"/"cert-job:5" 等字符串——OpenAPI
// 对 /system/tasks/{id} 族六个端点的路径参数必须保留 type: string（与其余
// 数字 :id 路由的 integer 判定分流）；MCP 侧同参数一直正确标 string，两侧
// 此前自相矛盾。
func TestBuildOpenAPIYAML_tasksPathParametersStayString(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name   string `yaml:"name"`
				In     string `yaml:"in"`
				Schema struct {
					Type string `yaml:"type"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}

	// When
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, operation := range []struct{ path, method string }{
		{"/system/tasks/{id}/logs", "get"},
		{"/system/tasks/{id}/history", "get"},
		{"/system/tasks/{id}/trigger", "post"},
		{"/system/tasks/{id}/toggle", "post"},
		{"/system/tasks/{id}/control", "post"},
		{"/system/tasks/{id}/cancel", "post"},
	} {
		parameters := document.Paths[operation.path][operation.method].Parameters
		// trigger 额外携带 ?force（cert-job 行冷却 429 的越权通道，查询参数）；
		// 本钉测关注的是 :id 保持 string（任务 ID 如 "threat"、"cert-job:5"），
		// 因此按名定位 id 参数而非断言参数个数。
		idIndex := -1
		for i := range parameters {
			if parameters[i].Name == "id" {
				idIndex = i
				break
			}
		}
		if idIndex < 0 || parameters[idIndex].In != "path" {
			t.Fatalf("%s %s parameters=%+v", operation.method, operation.path, parameters)
		}
		if parameters[idIndex].Schema.Type != "string" {
			t.Errorf("%s %s id schema type=%q, want string (task IDs such as \"threat\" or \"cert-job:5\" are strings)", operation.method, operation.path, parameters[idIndex].Schema.Type)
		}
	}
	// 回归形状：数字 :id 路由不受 tasks 分流影响，保持 integer。
	if parameters := document.Paths["/users/{id}"]["put"].Parameters; len(parameters) != 1 || parameters[0].Schema.Type != "integer" {
		t.Fatalf("PUT /users/{id} parameters=%+v, want id integer", parameters)
	}
}

// 威胁大屏文档响应示例键集必须与实现一致——
// rollup 改造（top_rules/attack_type_share/recent_rate/rollup_* 披露）后文档滞后。
// 钉测直接调用真实 handler 取响应键集，与 apiDocRoutes 示例双向比对。
func TestAPIDocs_threatScreenExampleKeysMatchImplementation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}

	var docExample map[string]any
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Path == "/security/overview/threat-screen" {
			if err := json.Unmarshal([]byte(route.Response), &docExample); err != nil {
				t.Fatalf("parse doc example: %v", err)
			}
		}
	}
	if docExample == nil {
		t.Fatal("apiDocRoutes missing GET /security/overview/threat-screen entry")
	}

	for key := range impl.Data {
		if _, ok := docExample[key]; !ok {
			t.Errorf("实现响应键 %q 未在文档示例中", key)
		}
	}
	for key := range docExample {
		if _, ok := impl.Data[key]; !ok {
			t.Errorf("文档示例键 %q 实现未返回", key)
		}
	}
}

// 攻击光流与正常光流的空洞披露必须同形（gap/gap_skipped）：文档示例缺这两个
// 字段时，自建大屏/告警脚本无从区分「攻击减少」与「环形缓冲溢出丢样」。
func TestAPIDocs_attackFlowExampleKeysMatchImplementation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/overview/threat-screen/attack-flow", (&Handlers{}).GetThreatScreenAttackFlow)
	recorder := getRequest(t, router, "/security/overview/threat-screen/attack-flow")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}

	var docExample map[string]any
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Path == "/security/overview/threat-screen/attack-flow" {
			if err := json.Unmarshal([]byte(route.Response), &docExample); err != nil {
				t.Fatalf("parse doc example: %v", err)
			}
		}
	}
	if docExample == nil {
		t.Fatal("apiDocRoutes missing GET /security/overview/threat-screen/attack-flow entry")
	}
	for key := range impl.Data {
		if _, ok := docExample[key]; !ok {
			t.Errorf("实现响应键 %q 未在文档示例中", key)
		}
	}
	for key := range docExample {
		if _, ok := impl.Data[key]; !ok {
			t.Errorf("文档示例键 %q 实现未返回", key)
		}
	}
}

// OpenAPI 总述的敏感材料可见性必须与实现同口径——
// TLS 私钥（rules.go）与 DNS 凭证（certificates.go）对非管理员
// 与只读 API Key 一律掩码，总述不得再声称「对所有已登录用户可读」。
func TestBuildOpenAPIYAML_descriptionMatchesCredentialMasking(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document struct {
		Info struct {
			Description string `yaml:"description"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	description := document.Info.Description
	if strings.Contains(description, "TLS 私钥、DNS 凭证及其他配置数据对所有已登录用户可读") {
		t.Fatalf("general description retains stale readable-by-all claim: %q", description)
	}
	for _, fragment := range []string{"TLS 私钥与 DNS 凭证仅对管理员", "掩码", "TLSKeySet"} {
		if !strings.Contains(description, fragment) {
			t.Errorf("general description missing masking contract %q: %q", fragment, description)
		}
	}
}

// GET /certificates/jobs 的文档示例曾写成裸数组，
// documentedResponse 会把它包成 data:[...]，与实现的 data.list/total/page/
// page_size/status_counts 对象分叉——按文档生成 SDK/脚本的消费方解析必失败。
// 钉测直接调用真实 handler 取 data 顶层键集，与 apiDocRoutes 示例双向比对。
func TestAPIDocs_certJobListExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/certificates/jobs", h.ListCertJobs)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/certificates/jobs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}

	var docExample map[string]any
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Path == "/certificates/jobs" {
			if err := json.Unmarshal([]byte(route.Response), &docExample); err != nil {
				t.Fatalf("文档示例必须是 data 对象的 JSON（裸数组会与实现 data.list 分叉）: %v", err)
			}
		}
	}
	if docExample == nil {
		t.Fatal("apiDocRoutes missing GET /certificates/jobs entry")
	}
	for key := range impl.Data {
		if _, ok := docExample[key]; !ok {
			t.Errorf("实现响应键 %q 未在文档示例中", key)
		}
	}
	for key := range docExample {
		if _, ok := impl.Data[key]; !ok {
			t.Errorf("文档示例键 %q 实现未返回", key)
		}
	}
}

// 写操作 428 生成门：mfaStepUpGuard 覆盖的全部 JWT 写路由（writeMethods +
// 敏感导出 GET，豁免机制本体 verify-step/logout、非 JWT 认证面、只读语义写
// 路由——判定与 middleware/services 同一事实源）必须在错误表登记 428。
// 此前 428 靠手工登记，系统性漏网（规则写族/安全写族等均未登记）。
func TestAPIDocRoutes_writeEndpointsDocumentMFAStepUp(t *testing.T) {
	writeMethods := map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}
	// 与写操作同敏感级的导出 GET：名单从 middleware 单源派生（
	// apiKeyReadOnlyGuard 与 mfaStepUpGuard 共用同一事实源）。
	sensitiveExportGets := sensitiveExportGetRoutesForDocs(t, false)
	// step-up 机制本体与登出豁免（DecideMFAStepUp 短路，428 不可达）。
	stepUpExempt := map[string]bool{"POST /auth/logout": true, "POST /auth/mfa/verify-step": true}
	checked := 0
	for _, route := range apiDocRoutes {
		key := route.Method + " " + route.Path
		if !writeMethods[route.Method] && !sensitiveExportGets[key] {
			continue
		}
		// 非 JWT 认证面（公开/集群机器/MCP 专用头）无 step-up 语义——
		// 按 security 枚举判定，新增未知 security 值不会被静默跳过。
		if apiDocRouteUsesNonJWTAuth(route) {
			continue
		}
		if stepUpExempt[key] {
			continue
		}
		// 只读语义写路由（批量查询/测试/预览/采集租约）与只读 Key 同一事实源豁免。
		if services.IsReadOnlyWriteRoute(route.Method, "/api/v1"+route.Path) {
			continue
		}
		checked++
		if !containsRouteError(route.Errors, "428") {
			t.Errorf("%s errors=%v, want 428 mfa_step_up_required（mfaStepUpGuard 覆盖的 JWT 写操作）", key, route.Errors)
		}
	}
	if checked == 0 {
		t.Fatal("no write routes checked——428 生成门比对形态失效")
	}
}

// MFA 写端点的两个跨切错误：配置导入窗口 409（users 表在全量替换清单内，
// 窗口内写入会被静默覆盖）与 OIDC 用户 403（OIDC 身份由 IdP 承担，不支持
// 本地 MFA 操作）——五个端点同门（mfa.go rejectWriteDuringImport /
// rejectOIDCUserMFAOperation）。
func TestAPIDocRoutes_mfaWriteEndpointsDocumentImportWindowAndOIDC(t *testing.T) {
	for _, key := range []string{
		"POST /auth/mfa/setup",
		"POST /auth/mfa/activate",
		"POST /auth/mfa/disable",
		"POST /auth/mfa/recovery-codes",
		"POST /users/:id/mfa/reset",
	} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "409") {
			t.Errorf("%s errors=%v, want 409（配置导入窗口拒绝 MFA 写）", key, route.Errors)
		}
	}
	for _, key := range []string{
		"POST /auth/mfa/setup",
		"POST /auth/mfa/activate",
		"POST /auth/mfa/disable",
		"POST /auth/mfa/recovery-codes",
	} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "403") {
			t.Errorf("%s errors=%v, want 403（OIDC 用户不支持本地 MFA）", key, route.Errors)
		}
	}
	// 管理端重置已有 403 admin_required（同码去重）；OIDC 目标拒绝须进描述。
	if !strings.Contains(routesEntry(t, "POST /users/:id/mfa/reset").Description, "OIDC") {
		t.Errorf("POST /users/:id/mfa/reset description lacks OIDC 目标拒绝说明")
	}
	// 恢复码重生成没有凭据校验的 401，但鉴权与处理之间用户被并发删除时
	// handler 仍返回 401（users 行 ErrNoRows）——文档不得宣称「无 401 路径」。
	recovery := routesEntry(t, "POST /auth/mfa/recovery-codes")
	if !containsRouteError(recovery.Errors, "401") {
		t.Errorf("POST /auth/mfa/recovery-codes errors=%v, want 401（并发删除用户时 handler 返回 401）", recovery.Errors)
	}
	if strings.Contains(recovery.Description, "无 401 路径") {
		t.Error("POST /auth/mfa/recovery-codes description 宣称「无 401 路径」，与 ErrNoRows→401 的实现矛盾")
	}
}

// 分页/时间参数校验 400：安全事件与证书任务列表对非法 page/page_size 与
// 无效/倒置时间区间返回 400（非静默忽略），错误表必须登记。
func TestAPIDocRoutes_paginatedReadsDocumentValidation400(t *testing.T) {
	for _, key := range []string{"GET /security/events", "GET /certificates/jobs"} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "400") {
			t.Errorf("%s errors=%v, want 400（非法分页/时间参数显式拒绝）", key, route.Errors)
		}
	}
}

// 契约表绊线①：apiDocContracts 每个键必须命中 apiDocRoutes——字符串键松
// 耦合下错拼/删除残留会静默回落默认契约（bearerAuth/200/JSON），已实证
// 漂移到机器接口误标。
func TestAPIDocContracts_keysExistInRoutes(t *testing.T) {
	routeKeys := make(map[string]bool, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routeKeys[route.Method+" "+route.Path] = true
	}
	for key := range apiDocContracts {
		if !routeKeys[key] {
			t.Errorf("apiDocContracts 键 %q 不在 apiDocRoutes——错拼或路由删除残留", key)
		}
	}
}

// GET 不得产出 requestBody：查询参数一律经契约表 queryParameters 登记为
// parameters(in: query)。此前三条大屏 GET 把查询串放进 Request 字段，
// 被生成器输出成带 JSON 示例的 requestBody——SDK 按 body 构参恒不生效。
func TestAPIDocRoutes_getRequestsDeclareQueryNotBody(t *testing.T) {
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Request != "" {
			t.Errorf("GET %s 的 Request 字段非空（%q）——GET 查询参数必须走 queryParameters，Request 仅用于 body 方法", route.Path, route.Request)
		}
	}
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody map[string]any `yaml:"requestBody"`
			Parameters  []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for path, operations := range document.Paths {
		if get, ok := operations["get"]; ok && get.RequestBody != nil {
			t.Errorf("GET %s 生成了 requestBody——GET 不得有请求体", path)
		}
	}
	// 游标/窗口参数逐个登记为 query 参数。
	wantQuery := map[string][]string{
		"/security/overview/threat-screen":             {"hours"},
		"/security/events/feed":                        {"since_id", "limit"},
		"/security/events/toast-summary":               {"since_id", "limit", "baseline"},
		"/security/overview/threat-screen/attack-flow": {"since", "limit"},
		"/security/overview/threat-screen/events":      {"since", "limit"},
		"/security/events/count":                       {"ip", "days"},
	}
	for path, names := range wantQuery {
		get, ok := document.Paths[path]["get"]
		if !ok {
			t.Errorf("OpenAPI missing GET %s", path)
			continue
		}
		got := make(map[string]bool, len(get.Parameters))
		for _, parameter := range get.Parameters {
			if parameter.In == "query" {
				got[parameter.Name] = true
			}
		}
		for _, name := range names {
			if !got[name] {
				t.Errorf("GET %s 缺 query 参数 %q（现有 %v）", path, name, got)
			}
		}
	}
}

// 成功状态码契约：异步受理 202 与浏览器跳转 302 不得输出成默认 200
// （生成客户端把 202/302 当非成功处理，备份触发/OIDC 登录集成断裂）。
func TestBuildOpenAPIYAML_documentsNon200SuccessStatuses(t *testing.T) {
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]any `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	want := map[string]string{
		"/auto-backup/run post":   "202",
		"/auth/oidc/login get":    "302",
		"/auth/oidc/callback get": "302",
	}
	for operation, status := range want {
		path, method, _ := strings.Cut(operation, " ")
		responses := document.Paths[path][method].Responses
		if _, ok := responses[status]; !ok {
			t.Errorf("%s %s responses=%v, want 成功状态码 %s", method, path, responseKeys(responses), status)
		}
	}
}

func responseKeys(responses map[string]any) []string {
	keys := make([]string, 0, len(responses))
	for key := range responses {
		keys = append(keys, key)
	}
	return keys
}

// MFA 首次绑定无需请求体（未启用 MFA 时空 body 合法）——requestBody 必须
// 标 required:false，否则 codegen 客户端会发无意义 {} 或拒绝调用。
func TestBuildOpenAPIYAML_mfaSetupBodyOptional(t *testing.T) {
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Required bool `yaml:"required"`
			} `yaml:"requestBody"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	setup, ok := document.Paths["/auth/mfa/setup"]["post"]
	if !ok {
		t.Fatal("OpenAPI missing POST /auth/mfa/setup")
	}
	if setup.RequestBody.Required {
		t.Error("POST /auth/mfa/setup requestBody.required=true, want false（首次绑定无需请求体）")
	}
}

// policy_type=mixed 是存量兼容形态：显式提交与跨阶段内容推断均被 400 拒绝，
// 创建/更新描述不得宣称可显式提交 mixed。
func TestAPIDocRoutes_policyTypeMixedDocumentationMatchesRejection(t *testing.T) {
	for _, key := range []string{"POST /security/policies", "PUT /security/policies/:id"} {
		description := routesEntry(t, key).Description
		if strings.Contains(description, "显式 mixed 须") {
			t.Errorf("%s description 仍宣称显式 mixed 可提交: %q", key, description)
		}
		if !strings.Contains(description, "mixed") || !strings.Contains(description, "拒绝") {
			t.Errorf("%s description 须说明 mixed 显式提交/跨阶段推断被拒绝: %q", key, description)
		}
	}
}

// system=true 内置名单分两类：威胁情报名单只读（写路径 400）、自动封禁预置
// 名单可增删处置（含解封语义）——两处描述必须同时表达两类语义，不得互斥表述。
func TestAPIDocRoutes_systemIPListSemanticsConsistent(t *testing.T) {
	for _, key := range []string{"GET /security/ip-lists", "GET /security/ip-lists/:id"} {
		description := routesEntry(t, key).Description
		if !strings.Contains(description, "威胁") || !strings.Contains(description, "自动封禁") {
			t.Errorf("%s description 须同时说明两类 system=1 名单语义: %q", key, description)
		}
		if strings.Contains(description, "内置只读名单") || strings.Contains(description, "内置名单只读（写路径一律 400）") {
			t.Errorf("%s description 仍把所有 system=1 名单表述为只读: %q", key, description)
		}
	}
}

// —— 响应示例键对账（扩面：原仅威胁大屏与证书任务两个端点）——

// jsonTagKeySet 反射收集结构体的 JSON 键集（跳过 "-"，递归匿名内嵌）。
// 返回 (全部键, 非 omitempty 键)——omitempty 键允许文档示例有而实时响应无。
func jsonTagKeySet(t *testing.T, sample any) (all, required map[string]bool) {
	t.Helper()
	all, required = make(map[string]bool), make(map[string]bool)
	valueType := reflect.TypeOf(sample)
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		t.Fatalf("sample %T is not a struct", sample)
	}
	for i := range valueType.NumField() {
		field := valueType.Field(i)
		if field.Anonymous {
			subAll, subRequired := jsonTagKeySet(t, reflect.New(field.Type).Elem().Interface())
			for key := range subAll {
				all[key] = true
			}
			for key := range subRequired {
				required[key] = true
			}
			continue
		}
		name, opts, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		all[name] = true
		if !strings.Contains(opts, "omitempty") {
			required[name] = true
		}
	}
	return all, required
}

func docResponseExample(t *testing.T, key string) map[string]any {
	t.Helper()
	route := routesEntry(t, key)
	var example map[string]any
	if err := json.Unmarshal([]byte(route.Response), &example); err != nil {
		t.Fatalf("%s 文档示例必须是 data 对象的 JSON: %v", key, err)
	}
	// 示例为完整信封（{"code":...,"data":{...}}）形态时解包到 data 载荷。
	if data, ok := example["data"].(map[string]any); ok {
		if _, hasCode := example["code"]; hasCode {
			return data
		}
	}
	return example
}

func assertKeySetsEqual(t *testing.T, context string, docKeys, implKeys map[string]bool) {
	t.Helper()
	for key := range implKeys {
		if !docKeys[key] {
			t.Errorf("%s：实现响应键 %q 未在文档示例中", context, key)
		}
	}
	for key := range docKeys {
		if !implKeys[key] {
			t.Errorf("%s：文档示例键 %q 实现未返回", context, key)
		}
	}
}

// assertStructKeysDocumented 校验文档示例键集落在 struct 全部键内、且覆盖
// 全部非 omitempty 键（omitempty 键空值不下发，示例可含可不含）。
func assertStructKeysDocumented(t *testing.T, context string, docKeys map[string]bool, sample any) {
	t.Helper()
	all, required := jsonTagKeySet(t, sample)
	for key := range required {
		if !docKeys[key] {
			t.Errorf("%s：实现响应键 %q 未在文档示例中", context, key)
		}
	}
	for key := range docKeys {
		if !all[key] {
			t.Errorf("%s：文档示例键 %q 实现结构无此字段", context, key)
		}
	}
}

func mapKeysOf(m map[string]any) map[string]bool {
	keys := make(map[string]bool, len(m))
	for key := range m {
		keys[key] = true
	}
	return keys
}

// 安全总览：包装结构 securityOverviewResponse（内嵌 models.SecurityOverview +
// raw_coverage_from/backfill_incomplete/includes_reserved/ingestion）——示例缺
// crs_available/update_status/attack_types_stage 等键会让消费者丢失覆盖可信度
// 与采集健康位。
func TestAPIDocs_securityOverviewExampleKeysMatchImplementation(t *testing.T) {
	description := operationDescription(routesEntry(t, "GET /security/overview"))
	if !strings.Contains(description, "includes_reserved 仅描述 today_blocked/today_detected") || !strings.Contains(description, "trend/top_ips/attack_types 恒含") {
		t.Fatalf("includes_reserved 文档必须限定今日两项并披露其他聚合恒含保留地址: %q", description)
	}
	example := docResponseExample(t, "GET /security/overview")
	assertStructKeysDocumented(t, "GET /security/overview", mapKeysOf(example), securityOverviewResponse{})

	nested := func(arrayKey string, sample any) {
		t.Helper()
		items, ok := example[arrayKey].([]any)
		if !ok || len(items) == 0 {
			t.Errorf("GET /security/overview 示例缺 %s 数组元素", arrayKey)
			return
		}
		item, ok := items[0].(map[string]any)
		if !ok {
			t.Errorf("GET /security/overview 示例 %s[0] 不是对象", arrayKey)
			return
		}
		assertStructKeysDocumented(t, "GET /security/overview "+arrayKey+"[]", mapKeysOf(item), sample)
	}
	nested("top_ips", models.SecurityTopIP{})
	nested("trend", models.SecurityTrendPoint{})
	nested("attack_types", models.SecurityAttackType{})
	nested("attack_types_stage", models.SecurityAttackType{})
	ingestion, ok := example["ingestion"].(map[string]any)
	if !ok {
		t.Fatalf("GET /security/overview 示例缺 ingestion 对象")
	}
	assertStructKeysDocumented(t, "GET /security/overview ingestion", mapKeysOf(ingestion), services.SecurityEventsIngestionHealthSnapshot())
}

// 安全事件列表：data 恒含 includes_reserved（口径披露）与 ingestion（采集
// 健康位，与总览同源）——示例缺键会丢关键字段。MetricsDB 未装配分支与成功
// 路径同键形状，直接取降级分支对账。
func TestAPIDocs_securityEventsExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	oldMetricsDB := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetricsDB })

	router := gin.New()
	router.GET("/security/events", h.ListSecurityEvents)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/events", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /security/events", mapKeysOf(docResponseExample(t, "GET /security/events")), mapKeysOf(impl.Data))
}

// Caddy 状态：statusData 七键（含 pid 与 background_apply_error）——示例缺
// pid/后台重载失败面会让巡检脚本误判进程态与配置收敛态。
func TestAPIDocs_caddyStatusExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/caddy/status", h.GetCaddyStatus)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/caddy/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /caddy/status", mapKeysOf(docResponseExample(t, "GET /caddy/status")), mapKeysOf(impl.Data))
}

// 集群状态：ClusterStatus 含 sync_users/sync_rules/sync_security 三开关与
// transport_insecure 明文链路标志——示例缺键会让外部监控漏掉同步范围与
// 明文传输常驻提示。
func TestAPIDocs_clusterStatusExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT OR IGNORE INTO global_config (id) VALUES (1)"); err != nil {
		t.Fatalf("seed global_config: %v", err)
	}
	router := gin.New()
	router.GET("/cluster/status", h.GetClusterStatus)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/cluster/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /cluster/status", mapKeysOf(docResponseExample(t, "GET /cluster/status")), mapKeysOf(impl.Data))
}

// 任务监控聚合：顶层含 tasks 与 cert_jobs_truncated；任务项键集以
// services.TaskInfo/TaskRunInfo 为准（omitempty 键允许示例有而实时响应
// 无——反射键集是全集上界）。
func TestAPIDocs_systemTasksExampleKeysMatchImplementation(t *testing.T) {
	example := docResponseExample(t, "GET /system/tasks")
	for _, key := range []string{"tasks", "cert_jobs_truncated"} {
		if _, ok := example[key]; !ok {
			t.Errorf("GET /system/tasks 示例缺顶层键 %q", key)
		}
	}
	items, ok := example["tasks"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("GET /system/tasks 示例缺 tasks 数组元素")
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("GET /system/tasks 示例 tasks[0] 不是对象")
	}
	taskAll, _ := jsonTagKeySet(t, services.TaskInfo{})
	for key := range mapKeysOf(item) {
		if !taskAll[key] {
			t.Errorf("GET /system/tasks 示例 tasks[] 键 %q 不在 TaskInfo", key)
		}
	}
	// 任务说明/运行节奏必须在示例中；started_at 仍属 TaskInfo 全集但仅
	// 常驻族有值（Scheduled 示例不得携带）。
	for _, key := range []string{"description", "cadence"} {
		if !taskAll[key] {
			t.Fatalf("TaskInfo 已无 %q 字段——本钉测需同步", key)
		}
		if _, ok := item[key]; !ok {
			t.Errorf("GET /system/tasks 示例 tasks[] 缺 %q", key)
		}
	}
	if !taskAll["started_at"] {
		t.Fatal("TaskInfo 已无 started_at 字段——本钉测需同步")
	}
	// 示例值必须与实现口径一致（键集测试拦不住值漂移）：
	// Scheduled 的 cadence 恒「定时排程」；threat 可取消（Cancelable=true）；
	// started_at 仅常驻族非空（Scheduled 示例不得携带）。
	if got, _ := item["cadence"].(string); got != "定时排程" {
		t.Errorf("GET /system/tasks 示例 cadence=%q, want 定时排程（Scheduled 实现口径）", got)
	}
	if got, ok := item["cancellable"].(bool); !ok || !got {
		t.Errorf("GET /system/tasks 示例 cancellable=%v, want true（threat 注册 Cancelable=true）", item["cancellable"])
	}
	if _, exists := item["started_at"]; exists {
		t.Error("GET /system/tasks 示例不得为 Scheduled 任务携带 started_at（仅常驻族非空）")
	}
	lastRun, ok := item["last_run"].(map[string]any)
	if !ok {
		t.Fatalf("GET /system/tasks 示例缺 last_run 对象")
	}
	runAll, _ := jsonTagKeySet(t, services.TaskRunInfo{})
	for key := range mapKeysOf(lastRun) {
		if !runAll[key] {
			t.Errorf("GET /system/tasks 示例 last_run 键 %q 不在 TaskRunInfo", key)
		}
	}
}

// 自动备份列表：doc 示例 backups[] 曾漏 app_version（实现恒下发、设置页
// 「版本号」列已消费）——对账同时锁顶层键与行视图键集，防再漂移。
func TestAPIDocs_autoBackupSettingsExampleKeysMatchImplementation(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, size_bytes, sections, trigger_type, message, app_version)
		VALUES ('lbbak-auto-20260920-030000.lbbak','success',1024,'["users"]','schedule','','v2.3.8-beta')`); err != nil {
		t.Fatalf("seed auto_backups row: %v", err)
	}
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	example := docResponseExample(t, "GET /settings/auto-backup")
	assertKeySetsEqual(t, "GET /settings/auto-backup", mapKeysOf(example), mapKeysOf(impl.Data))

	// 行视图双向对账（结构体全部键，含空 message 与 app_version）。
	docBackups, ok := example["backups"].([]any)
	if !ok || len(docBackups) == 0 {
		t.Fatalf("GET /settings/auto-backup 示例缺 backups 数组元素")
	}
	docRow, ok := docBackups[0].(map[string]any)
	if !ok {
		t.Fatalf("GET /settings/auto-backup 示例 backups[0] 不是对象")
	}
	implBackups, ok := impl.Data["backups"].([]any)
	if !ok || len(implBackups) == 0 {
		t.Fatalf("实现响应缺 backups 数组元素")
	}
	implRow, ok := implBackups[0].(map[string]any)
	if !ok {
		t.Fatalf("实现响应 backups[0] 不是对象")
	}
	assertKeySetsEqual(t, "GET /settings/auto-backup backups[]", mapKeysOf(docRow), mapKeysOf(implRow))
}

// 审计列表：total 5 秒缓存以 total_stale 披露来源——示例缺键会让按文档生成
// 的客户端拿不到该披露字段（面板已消费）。
func TestAPIDocs_auditLogsExampleKeysMatchImplementation(t *testing.T) {
	router := newAuditLogTestRouter(t, "")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /audit-logs", mapKeysOf(docResponseExample(t, "GET /audit-logs")), mapKeysOf(impl.Data))
}

// 废弃字段响应面收敛：upstreams.dynamic_dns（写侧恒 0 的废弃列）与全局
// dns_provider/dns_credentials（签发链不消费的遗留字段）不再随 API 响应
// 下发——消费者不得据恒假值做判定。全局 DB 列由启动迁移删除。
func TestDeprecatedFields_omittedFromAPIResponses(t *testing.T) {
	upstreamJSON, err := json.Marshal(models.Upstream{Host: "127.0.0.1", Port: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(upstreamJSON), "dynamic_dns") {
		t.Errorf("Upstream 零值仍下发废弃 dynamic_dns 键: %s", upstreamJSON)
	}
	configJSON, err := json.Marshal(models.GlobalConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dns_provider", "dns_credentials"} {
		if strings.Contains(string(configJSON), `"`+key+`"`) {
			t.Errorf("GlobalConfig 零值仍下发遗留键 %s: %s", key, configJSON)
		}
	}
}

// 403 生成门：business/admin 两组写路由对非管理员/从节点恒 403
// （readOnlyGuard），敏感导出 GET 同样；错误表必须登记 403（此前 6 条漏登，
// 同类端点有的登记有的不登记）。名单判据与 middleware 同源：
// services.IsReadOnlyWriteRoute 豁免只读语义写路由。
func TestAPIDocRoutes_nonAdminWriteEndpointsDocument403(t *testing.T) {
	writeMethods := map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}
	// 与写操作同敏感级的导出/敏感读取 GET：导出名单来自 middleware 单源，
	// 并派生 admin 组 canReadSensitiveSecrets handler（如 /caddy/config），
	// 对非管理员或只读 Key 恒 403。
	sensitiveExportGets := sensitiveExportGetRoutesForDocs(t, true)
	// 非管理员合法可达的写路由：认证自助（MFA/登出/个人资料/本人密钥）。
	// 公开与机器接口由 security 判据排除（无 JWT 角色语义）。
	selfService := map[string]bool{
		"POST /auth/logout":             true,
		"POST /auth/mfa/setup":          true,
		"POST /auth/mfa/activate":       true,
		"POST /auth/mfa/disable":        true,
		"POST /auth/mfa/recovery-codes": true,
		"POST /auth/mfa/verify-step":    true,
		"PATCH /users/me":               true,
		"POST /users/me/api-keys":       true,
		"PATCH /users/me/api-keys/:id":  true,
		"DELETE /users/me/api-keys/:id": true,
	}
	checked := 0
	for _, route := range apiDocRoutes {
		key := route.Method + " " + route.Path
		if !writeMethods[route.Method] && !sensitiveExportGets[key] {
			continue
		}
		if apiDocRouteUsesNonJWTAuth(route) || selfService[key] {
			continue
		}
		if services.IsReadOnlyWriteRoute(route.Method, "/api/v1"+route.Path) {
			continue
		}
		checked++
		if !containsRouteError(route.Errors, "403") {
			t.Errorf("%s errors=%v, want 403（非管理员/从节点恒 403）", key, route.Errors)
		}
	}
	if checked == 0 {
		t.Fatal("no write routes checked——403 生成门比对形态失效")
	}
}

// 策略列表过滤能力必须进契约：enabled 三态与 rule_caddy_id（IP 归属地弹窗）
// 是真实 query 参数，漏登记时生成 SDK/脚本发现不了。
func TestAPIDocRoutes_securityPoliciesDocumentFilterQueries(t *testing.T) {
	contract, ok := apiDocContracts["GET /security/policies"]
	if !ok {
		t.Fatal("apiDocContracts missing GET /security/policies")
	}
	names := map[string]bool{}
	for _, parameter := range contract.queryParameters {
		names[parameter.name] = true
	}
	for _, want := range []string{"enabled", "rule_caddy_id"} {
		if !names[want] {
			t.Errorf("GET /security/policies queryParameters=%v, want %q", names, want)
		}
	}
	if description := routesEntry(t, "GET /security/policies").Description; !strings.Contains(description, "enabled") || !strings.Contains(description, "rule_caddy_id") {
		t.Errorf("GET /security/policies description 未说明过滤参数: %q", description)
	}

	var document struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	got := map[string]bool{}
	for _, parameter := range document.Paths["/security/policies"]["get"].Parameters {
		if parameter.In == "query" {
			got[parameter.Name] = true
		}
	}
	for _, want := range []string{"enabled", "rule_caddy_id"} {
		if !got[want] {
			t.Errorf("OpenAPI GET /security/policies 缺 query 参数 %q（现有 %v）", want, got)
		}
	}
}

// 分页语义单一口径（非整数 400 / 越界钳到上限）必须与实现同文；深翻页显式
// 拒绝是审计日志端点的独立策略，同样必须写明。
func TestAPIDocRoutes_paginationSemanticsDocumented(t *testing.T) {
	for _, key := range []string{"GET /security/events", "GET /certificates/jobs", "GET /audit-logs"} {
		description := routesEntry(t, key).Description
		if !strings.Contains(description, "钳") {
			t.Errorf("%s description 未说明越界钳位语义: %q", key, description)
		}
		if !strings.Contains(description, "400") {
			t.Errorf("%s description 未说明非法分页参数 400: %q", key, description)
		}
	}
	if description := routesEntry(t, "GET /audit-logs").Description; !strings.Contains(description, "page>500") {
		t.Errorf("GET /audit-logs description 未说明深翻页 400 策略: %q", description)
	}
}

// 同码多形态不得丢弃后续语义：PUT /users/:id/status 的 400 同时是
// invalid_request 与 cannot_disable_self，生成规格必须合并两条描述。
func TestBuildOpenAPIYAML_mergesSameStatusErrorSemantics(t *testing.T) {
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Description string `yaml:"description"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	description := document.Paths["/users/{id}/status"]["put"].Responses["400"].Description
	if !strings.Contains(description, "invalid_request") || !strings.Contains(description, "cannot_disable_self") {
		t.Errorf("PUT /users/:id/status 400 description=%q, want 合并 invalid_request 与 cannot_disable_self", description)
	}
}

// docDataArray 取示例信封 data 数组的首元素（数组载荷端点）。
func docDataArray(t *testing.T, key string) map[string]any {
	t.Helper()
	route := routesEntry(t, key)
	var envelope struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(route.Response), &envelope); err != nil {
		t.Fatalf("%s 文档示例必须是 data 数组 JSON: %v", key, err)
	}
	if len(envelope.Data) == 0 {
		t.Fatalf("%s 文档示例 data 数组为空", key)
	}
	return envelope.Data[0]
}

// 决策相关响应键必须出现在文档示例（扩面：users/cluster nodes/策略族/规则库/
// 系统信息）——消费者（含 MCP Agent 生成的脚本）据此发现 MFA 状态、爬虫豁免、
// 缺库降级等能力面。
func TestAPIDocs_decisionKeyExamplesMatchImplementation(t *testing.T) {
	assertStructKeysDocumented(t, "GET /users", mapKeysOf(docDataArray(t, "GET /users")), models.UserResponse{})

	// 同一响应模型的全部产出端点共用一份示例（userResponseExample 单源）：
	// 只对列表做对账会让新增字段只进 1/4 示例，其余端点示例停留在旧形状，
	// 按 /users/me 示例生成的 SDK 会缺 is_setup_admin/mfa_enabled/auth_provider，
	// 按 PUT /users/:id 示例会以为响应无 body。
	for _, key := range []string{"GET /users/me", "PATCH /users/me", "PUT /users/:id"} {
		assertStructKeysDocumented(t, key, mapKeysOf(docResponseExample(t, key)), models.UserResponse{})
	}

	node := docDataArray(t, "GET /cluster/nodes")
	assertStructKeysDocumented(t, "GET /cluster/nodes", mapKeysOf(node), models.ClusterNodeView{})
	health, ok := node["health"].(map[string]any)
	if !ok {
		t.Fatalf("GET /cluster/nodes 示例缺 health 对象: %v", node)
	}
	assertStructKeysDocumented(t, "GET /cluster/nodes health", mapKeysOf(health), models.ClusterHealth{})

	assertStructKeysDocumented(t, "GET /security/policies", mapKeysOf(docDataArray(t, "GET /security/policies")), models.SecurityPolicySummary{})

	detail := docResponseExample(t, "GET /security/policies/:id")
	policy, ok := detail["policy"].(map[string]any)
	if !ok {
		t.Fatalf("GET /security/policies/:id 示例缺 policy 对象: %v", detail)
	}
	assertStructKeysDocumented(t, "GET /security/policies/:id policy", mapKeysOf(policy), securityPolicyDetail{})

	assertStructKeysDocumented(t, "GET /security/crs", mapKeysOf(docResponseExample(t, "GET /security/crs")), models.CRSInfo{})
	assertStructKeysDocumented(t, "GET /security/ip2region", mapKeysOf(docResponseExample(t, "GET /security/ip2region")), models.IP2RegionInfo{})
	assertStructKeysDocumented(t, "GET /system/info", mapKeysOf(docResponseExample(t, "GET /system/info")), models.SystemInfo{})
}

func TestAPIDocs_systemMetricsExampleKeysMatchImplementation(t *testing.T) {
	assertStructKeysDocumented(t, "GET /system/metrics", mapKeysOf(docResponseExample(t, "GET /system/metrics")), models.SystemMetrics{})
}

// 初始化管理员的三个保护类 400 是消费者必然遇到的可行动拒绝原因（降级/禁用/
// 删除），必须逐条登记——通用 invalid_request 掩盖后，SDK 会把 400 当实现缺陷
// 重试。文案与 handlers 的实现字面量对账（实现改词而文档未跟即红）。
func TestAPIDocs_setupAdminProtectionRejectionsDocumented(t *testing.T) {
	source, err := os.ReadFile("users.go")
	if err != nil {
		t.Fatalf("读 users.go: %v", err)
	}
	for _, want := range []struct {
		route    string
		message  string
		keywords []string
	}{
		{"PUT /users/:id", "初始管理员不可降级", []string{"不可降级"}},
		{"PUT /users/:id/status", "初始管理员不可禁用", []string{"不可禁用"}},
		{"DELETE /users/:id", "初始管理员不可删除", []string{"不可删除"}},
	} {
		if !strings.Contains(string(source), want.message) {
			t.Errorf("users.go 未出现保护文案 %q（实现与文档对账的单源已漂移）", want.message)
		}
		route := routesEntry(t, want.route)
		entry, ok := "", false
		for _, candidate := range route.Errors {
			if strings.HasPrefix(candidate, "400 ") && strings.Contains(candidate, "setup_admin_protected") {
				entry, ok = candidate, true
				break
			}
		}
		if !ok {
			t.Errorf("%s 未登记 400 setup_admin_protected（实现返回 %q）errors=%v", want.route, want.message, route.Errors)
			continue
		}
		for _, keyword := range want.keywords {
			if !strings.Contains(entry, keyword) && !strings.Contains(route.Description, keyword) {
				t.Errorf("%s 的 400 setup_admin_protected 未说明「%s」（errors=%q description=%q）", want.route, keyword, entry, route.Description)
			}
		}
	}
}

// 带分页查询的 GET 端点必须把 page/page_size 登记进 OpenAPI query 参数：
// 描述里写了分页而 contracts 未登记时，生成的 openapi.yaml 对该端点零
// parameters，SDK 只能拿到首页且无续页形参（/certificates 即此形态）。
func TestAPIDocContracts_paginatedGetRoutesDeclareQueryParameters(t *testing.T) {
	checked := 0
	for _, route := range apiDocRoutes {
		if route.Method != http.MethodGet || !strings.Contains(route.Description, "page_size") {
			continue
		}
		checked++
		names := map[string]bool{}
		for _, parameter := range apiDocContractFor(route).queryParameters {
			names[parameter.name] = true
		}
		for _, want := range []string{"page", "page_size"} {
			if !names[want] {
				t.Errorf("%s %s 描述声明分页但 OpenAPI 未登记 query 参数 %s（contracts 缺 %q 条目）",
					route.Method, route.Path, want, route.Method+" "+route.Path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("未扫到任何声明 page_size 的 GET 端点——派生基线失效，扫描口径需跟进")
	}
}

// summary/tags 必须可原样还原：裸拼自由文本会在含 ": "/"#" 等字符时破坏
// YAML 或静默截断（解析门只能保证「仍可解析」，不能保证语义未被改写）。
func TestBuildOpenAPIYAML_summaryAndTagRoundTrip(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document struct {
		Paths map[string]map[string]struct {
			Tags    []string `yaml:"tags"`
			Summary string   `yaml:"summary"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	checked := 0
	for _, route := range apiDocRoutes {
		path := apipath.ToOpenAPI(route.Path)
		op, ok := document.Paths[path][strings.ToLower(route.Method)]
		if !ok {
			t.Fatalf("missing operation %s %s", route.Method, path)
		}
		if op.Summary != route.Summary {
			t.Fatalf("%s %s summary=%q, want %q（自由文本被 YAML 改写）", route.Method, path, op.Summary, route.Summary)
		}
		if len(op.Tags) != 1 || op.Tags[0] != route.Tag {
			t.Fatalf("%s %s tags=%v, want [%q]", route.Method, path, op.Tags, route.Tag)
		}
		checked++
	}
	if checked != len(apiDocRoutes) {
		t.Fatalf("checked=%d routes=%d", checked, len(apiDocRoutes))
	}
}

// route.Errors 的描述与 JSON 示例 message 必须可原样还原：YAML 标量走引号
// 转义、示例 message 走 JSON 转义，未来新增含引号/井号/冒号的描述才不会被
// 解析门静默改写（只证明「仍可解析」不足以守住语义）。
func TestBuildOpenAPIYAML_errorDescriptionRoundTrip(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Description string `yaml:"description"`
				Content     map[string]struct {
					// 示例既可能是 JSON 对象，也可能是纯文本/二进制说明
					// （TXT/lbbak/302 指引），不能强约束为 map。
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	checked := 0
	for _, route := range apiDocRoutes {
		// 与发射链同源：导入窗口 409 是派生注入的，期望值也必须包含派生结果。
		route = withDerivedImportWindowError(route)
		if len(route.Errors) == 0 {
			continue
		}
		path := apipath.ToOpenAPI(route.Path)
		operation, ok := document.Paths[path][strings.ToLower(route.Method)]
		if !ok {
			t.Fatalf("missing operation %s %s", route.Method, path)
		}
		var order []string
		descriptions := map[string][]string{}
		for _, entry := range route.Errors {
			parts := strings.SplitN(entry, " ", 2)
			if _, seen := descriptions[parts[0]]; !seen {
				order = append(order, parts[0])
			}
			description := "错误"
			if len(parts) == 2 {
				description = parts[1]
			}
			descriptions[parts[0]] = append(descriptions[parts[0]], description)
		}
		for _, status := range order {
			want := strings.Join(descriptions[status], " / ")
			response, ok := operation.Responses[status]
			if !ok {
				t.Fatalf("%s %s missing response %s", route.Method, path, status)
			}
			if response.Description != want {
				t.Fatalf("%s %s %s description=%q, want %q（错误描述被 YAML 改写）", route.Method, path, status, response.Description, want)
			}
			example := response.Content["application/json"].Example
			// 部分错误响应示例是纯文本（TXT/lbbak/302 说明），没有 message 键；
			// 只有结构化 JSON 示例才校验 message 与描述一致。
			if envelope, ok := example.(map[string]any); ok {
				message, _ := envelope["message"].(string)
				if message != want {
					t.Fatalf("%s %s %s example message=%q, want %q（JSON 示例转义不一致）", route.Method, path, status, message, want)
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("未校验任何错误响应")
	}
}

// 降级语义必须文档化：partial 覆盖 display_name 富化失败；next_run_at 未启用
// 时为 null（客户端不得按恒时间串解析）。
func TestAPIDocRoutes_degradedSemanticsDocumented(t *testing.T) {
	audit := routesEntry(t, "GET /audit-logs").Description
	for _, want := range []string{"display_name", "partial"} {
		if !strings.Contains(audit, want) {
			t.Errorf("GET /audit-logs description 未说明 %q 的降级语义: %q", want, audit)
		}
	}
	backup := routesEntry(t, "GET /settings/auto-backup").Description
	if !strings.Contains(backup, "next_run_at") || !strings.Contains(backup, "null") {
		t.Errorf("GET /settings/auto-backup description 未说明 next_run_at 可能为 null: %q", backup)
	}
}

// 自动备份时间字段：文档示例为 UTC 墙钟串（2006-01-02 15:04:05）——实现必须
// 同形（显式格式化，不依赖驱动把 DATETIME 隐式转 RFC3339）。按示例写解析器的
// 脚本才能一次解析成功，也不会把 UTC 当本地时间再转一次。
func TestAPIDocs_autoBackupTimeFieldsMatchDocumentedFormat(t *testing.T) {
	layout := "2006-01-02 15:04:05"
	const want = "2026-09-20 03:00:00"
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, size_bytes, sections, trigger_type, message, app_version)
		VALUES ('lbbak-auto-20260920-030000.lbbak','` + want + `','success',1024,'["users"]','schedule','','v2.3.8-beta')`); err != nil {
		t.Fatalf("seed auto_backups row: %v", err)
	}
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var impl struct {
		Data struct {
			LastSuccessAt string `json:"last_success_at"`
			Backups       []struct {
				CreatedAt string `json:"created_at"`
			} `json:"backups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	if impl.Data.LastSuccessAt != want {
		t.Errorf("last_success_at=%q, want %q（UTC 墙钟串）", impl.Data.LastSuccessAt, want)
	}
	if len(impl.Data.Backups) != 1 || impl.Data.Backups[0].CreatedAt != want {
		t.Errorf("backups[0].created_at=%v, want %q（UTC 墙钟串）", impl.Data.Backups, want)
	}

	example := docResponseExample(t, "GET /settings/auto-backup")
	docBackups, ok := example["backups"].([]any)
	if !ok || len(docBackups) == 0 {
		t.Fatalf("GET /settings/auto-backup 示例缺 backups 数组元素")
	}
	docRow, ok := docBackups[0].(map[string]any)
	if !ok {
		t.Fatalf("GET /settings/auto-backup 示例 backups[0] 不是对象")
	}
	docCreated, _ := docRow["created_at"].(string)
	docLastSuccess, _ := example["last_success_at"].(string)
	for _, sample := range []string{docCreated, docLastSuccess} {
		if _, err := time.Parse(layout, sample); err != nil {
			t.Errorf("文档示例时间 %q 不能按实现格式 %q 解析: %v", sample, layout, err)
		}
	}
}

// 自动备份族与 admin 配置族的 500 登记门：实现与既有钉测都证明这些端点会
// 返回 500（DB 故障/节点角色查询失败），错误表缺 500 会让按规格生成的客户端
// 把可诊断故障当未知错误处理。
func TestAPIDocRoutes_autoBackupDocumentsReachable500(t *testing.T) {
	for _, key := range []string{
		"GET /settings/auto-backup",
		"PUT /settings/auto-backup",
		"POST /auto-backup/run",
		"DELETE /auto-backup/:id",
		"GET /auto-backup/:id/download",
		"PUT /admin-tls",
	} {
		if route := routesEntry(t, key); !containsRouteError(route.Errors, "500") {
			t.Errorf("%s errors=%v, want 500（DB/节点角色查询失败可达）", key, route.Errors)
		}
	}
}

// admin-tls 解析响应的决策键必须全部出现在文档示例：expired 是服务端现成的
// 过期判定，示例缺键会让按示例建模的消费方只能用 days_left<0 反推（与向零
// 截断语义耦合）。
func TestAPIDocs_adminTLSCertInfoExampleMatchesImplementation(t *testing.T) {
	assertStructKeysDocumented(t, "POST /admin-tls/inspect", mapKeysOf(docResponseExample(t, "POST /admin-tls/inspect")), adminTLSCertInfo{})
}

// day 字段契约：实现要求恒必填（daily 也校验 1-28），文档必须显式说明——
// 否则脚本客户端按「daily 不需要 day」省略会被 400「缺少必填字段」拒绝。
func TestAPIDocs_autoBackupDayFieldContractDocumented(t *testing.T) {
	description := routesEntry(t, "PUT /settings/auto-backup").Description
	for _, want := range []string{"day 恒必填", "daily 忽略取值"} {
		if !strings.Contains(description, want) {
			t.Errorf("PUT /settings/auto-backup description 缺 %q: %q", want, description)
		}
	}
}

// MFA 登录验码的并发形态：同一挑战已有一笔请求在验码时返回 409（不是重放
// 信号，对方失败会归还挑战），文档必须登记，避免客户端把它当致命错误丢弃。
func TestAPIDocs_mfaVerifyDocumentsConcurrent409(t *testing.T) {
	if !containsRouteError(routesEntry(t, "POST /auth/mfa/verify").Errors, "409") {
		t.Fatal("POST /auth/mfa/verify 未登记 409（并发验码形态）")
	}
}

// 鉴权表对 API Key 写能力的承诺必须与只读 Key 写豁免清单同源
// （services.IsReadOnlyWriteRoute）：非管理员用户创建的 Key 被强制
// read_only=true，且 /users/me 与 /users/me/api-keys 不在豁免清单里——自助写
// 只对登录会话放行。文档若把它们写成「Key 自助写除外」，按文档编排的脚本会
// 100% 收 403，并掩盖「Key 恒只读」这一更简单的事实。
//
// 反方向同样要钉：豁免清单里的只读语义写方法（解析证书/批量任务查询/规则
// 证书信息/大屏采集租约/预览/导入校验/OIDC 探测）对只读 Key 真实放行，
// 文档写成「写方法一律 403」会把可用的只读自动化判成必失败。
func TestAPIDocs_readOnlyKeyClaimMatchesWriteWhitelist(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "docs", "api.zh-CN.md"))
	if err != nil {
		t.Fatalf("读 docs/api.zh-CN.md: %v", err)
	}
	var row string
	for _, line := range strings.Split(string(source), "\n") {
		if strings.HasPrefix(line, "| API Key |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("docs/api.zh-CN.md 缺 API Key 鉴权行")
	}

	// 派生侧前提：自助写路径确实不在只读 Key 写豁免清单内。
	for _, probe := range []struct{ method, path string }{
		{http.MethodPatch, "/api/v1/users/me"},
		{http.MethodPost, "/api/v1/users/me/api-keys"},
	} {
		if services.IsReadOnlyWriteRoute(probe.method, probe.path) {
			t.Fatalf("前提变化：%s %s 已进只读 Key 写豁免清单——文档可恢复「Key 自助写」口径",
				probe.method, probe.path)
		}
	}

	// 豁免清单不含自助写路径 ⇒ 文档不得把它们写成 Key 的写例外。
	if strings.Contains(row, "自助写除外") {
		t.Errorf("API Key 行仍宣称「自助写除外」，但只读 Key 写豁免清单不含 /users/me 系列: %s", row)
	}
	for _, want := range []string{"恒为只读", "登录会话"} {
		if !strings.Contains(row, want) {
			t.Errorf("API Key 行缺 %q（须说明 Key 无写例外、自助写走登录会话）: %s", want, row)
		}
	}

	// 派生侧前提：豁免清单同时含只读语义写方法（解析证书/批量查询证书任务/
	// 规则证书信息/大屏采集租约/预览/导入校验/OIDC 探测）——它们对只读 Key
	// 放行，文档写成「写方法一律 403」会把可用的只读自动化判死。
	readOnlySemanticProbes := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/certificates/parse"},
		{http.MethodPost, "/api/v1/certificates/jobs/current"},
		{http.MethodPost, "/api/v1/rules/cert-info"},
		{http.MethodPost, "/api/v1/config/preview"},
		{http.MethodPost, "/api/v1/config/import/validate"},
		{http.MethodPost, "/api/v1/settings/oidc/test"},
		{http.MethodPost, "/api/v1/security/overview/threat-screen/collector"},
		{http.MethodDelete, "/api/v1/security/overview/threat-screen/collector"},
	}
	exempt := 0
	for _, probe := range readOnlySemanticProbes {
		if services.IsReadOnlyWriteRoute(probe.method, probe.path) {
			exempt++
		}
	}
	if exempt == 0 {
		t.Fatal("前提变化：只读语义写豁免清单为空——文档才可恢复「写方法一律 403」口径")
	}
	// 豁免面存在 ⇒ 文档必须交代只读语义 POST 例外，且不得留无限定的写 403 承诺。
	if !strings.Contains(row, "只读语义") {
		t.Errorf("API Key 行未交代只读语义 POST 例外（豁免清单有 %d 条写方法对只读 Key 放行）: %s", exempt, row)
	}
	for _, forbidden := range []string{"写方法一律 403", "所有写方法均 403", "写方法一律403"} {
		if strings.Contains(row, forbidden) {
			t.Errorf("API Key 行仍宣称「%s」，但只读语义 POST 按豁免清单放行: %s", forbidden, row)
		}
	}
	// 只读语义 POST 不等于只读 Key 可写：管理写操作仍必须写明 403。
	if !strings.Contains(row, "管理写操作一律 403") {
		t.Errorf("API Key 行须明确管理写操作仍为 403（只读语义 POST 是唯一写方法例外）: %s", row)
	}
}

// 证书任务列表与详情是同一投影（certJobListItem）：两处各自手写示例会让
// not_after/days_remaining/certificate_status/retry_cooldown_seconds 等
// 必下发字段只在其中一侧可见——按列表示例生成 SDK 会漏掉冷却三态，
// 按详情示例会漏掉到期与颁发者。
func TestAPIDocs_certJobExamplesMatchImplementation(t *testing.T) {
	route := routesEntry(t, "GET /certificates/jobs")
	var listEnvelope struct {
		List []map[string]any `json:"list"`
	}
	if err := json.Unmarshal([]byte(route.Response), &listEnvelope); err != nil {
		t.Fatalf("GET /certificates/jobs 示例必须是 data 对象 JSON: %v", err)
	}
	if len(listEnvelope.List) == 0 {
		t.Fatal("GET /certificates/jobs 示例缺 list 元素")
	}
	assertStructKeysDocumented(t, "GET /certificates/jobs list[0]", mapKeysOf(listEnvelope.List[0]), certJobListItem{})
	assertStructKeysDocumented(t, "GET /certificates/jobs/:id", mapKeysOf(docResponseExample(t, "GET /certificates/jobs/:id")), certJobListItem{})

	// 冷却三态是消费契约（0/正数/null），两个端点的描述都必须完整说明，
	// 否则调用方只能从 429 反推可重试性。
	for _, key := range []string{"GET /certificates/jobs", "GET /certificates/jobs/:id"} {
		description := routesEntry(t, key).Description
		for _, want := range []string{"retry_cooldown_seconds", "0=现在即可重试", "正数=还需等待的秒数", "null=永久不可重试"} {
			if !strings.Contains(description, want) {
				t.Errorf("%s 描述缺少冷却契约 %q: %q", key, want, description)
			}
		}
	}
}

// GET /certificates 的响应恒返回服务端实际生效的 page/page_size（被钳位时
// 调用方据此得知真实页位置）——示例缺这两个键会让生成的 SDK 无法续页。
// 直接调用真实 handler 取 data 顶层键集，与文档示例双向对账。
func TestAPIDocs_certificateListExampleMatchesImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/certificates", h.ListCertificates)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /certificates", mapKeysOf(docResponseExample(t, "GET /certificates")), mapKeysOf(impl.Data))
}

// 四个登录族响应的 user 是完整 models.UserResponse（同 userResponseExample
// 单源）——写成占位 {} 会让按示例建模的客户端发现不到 mfa_enabled/
// auth_provider/is_setup_admin 等决策字段。
func TestAPIDocs_loginFamilyUserExampleMatchesImplementation(t *testing.T) {
	for _, key := range []string{"POST /auth/login", "POST /auth/ticket-login", "POST /auth/mfa/verify", "POST /auth/mfa/verify-step"} {
		example := docResponseExample(t, key)
		user, ok := example["user"].(map[string]any)
		if !ok || len(user) == 0 {
			t.Errorf("%s 示例 user 必须是完整对象（占位 {} 会隐藏决策字段）: %v", key, example["user"])
			continue
		}
		assertStructKeysDocumented(t, key+" user", mapKeysOf(user), models.UserResponse{})
	}
}

// API Key 管理列表与自助列表实际返回同一完整投影
// （APIKeyWithUserResponse）——两处示例各自缺不同字段会让 SDK 模型二选一
// 地丢字段。
func TestAPIDocs_apiKeyExamplesMatchImplementation(t *testing.T) {
	for _, key := range []string{"GET /api-keys", "GET /users/me/api-keys"} {
		assertStructKeysDocumented(t, key, mapKeysOf(docDataArray(t, key)), models.APIKeyWithUserResponse{})
	}
}

// 证书任务页码上限的文档必须与 handler 实参同值：契约表与路由描述曾按
// 1000000 写，而实现是 maxCertJobPage=1000——按文档构参的 SDK 深翻页会
// 拿到被钳制后的另一页却不自知。上限从 ListCertJobs 的
// parsePaginationParam 实参派生，改实现而不改文档即红。
func TestAPIDocContract_certJobsPageLimitMatchesHandlerCap(t *testing.T) {
	source, err := os.ReadFile("certjobs.go")
	if err != nil {
		t.Fatalf("read certjobs.go: %v", err)
	}
	body := string(source)
	match := regexp.MustCompile(`parsePaginationParam\(c, "page", [^,]+, ([A-Za-z0-9_]+)\)`).FindStringSubmatch(body)
	if match == nil {
		t.Fatal("ListCertJobs 未找到 page 分页上限实参（解析基线失效）")
	}
	want, err := resolvePaginationCap(body, match[1])
	if err != nil {
		t.Fatal(err)
	}

	for _, parameter := range apiDocContractFor(apiDocRoute{Method: http.MethodGet, Path: "/certificates/jobs"}).queryParameters {
		if parameter.name != "page" {
			continue
		}
		// 不能只用 strings.Contains("1-1000")：「1-1000000」是它的超串，文档
		// 写回 1000000 也会命中。必须取出区间右端整数字再比数值。
		rangeMatch := regexp.MustCompile(`1-([0-9]+)`).FindStringSubmatch(parameter.description)
		if rangeMatch == nil {
			t.Fatalf("GET /certificates/jobs 的 page 契约描述=%q 未声明 1-<上限> 区间", parameter.description)
		}
		if got, err := strconv.Atoi(rangeMatch[1]); err != nil || got != want {
			t.Errorf("GET /certificates/jobs 的 page 契约上限=%q, want %d（handler 实参）", rangeMatch[1], want)
		}
	}
	description := routesEntry(t, "GET /certificates/jobs").Description
	capMatch := regexp.MustCompile(`page≤([0-9]+)`).FindStringSubmatch(description)
	if capMatch == nil {
		t.Fatalf("GET /certificates/jobs 描述=%q 未声明 page≤<上限>", description)
	}
	if got, err := strconv.Atoi(capMatch[1]); err != nil || got != want {
		t.Errorf("GET /certificates/jobs 描述上限=%q, want %d（handler 实参）", capMatch[1], want)
	}
}

// resolvePaginationCap 把分页上限实参解析成数值：字面量直接取值，命名常量
// 从同一文件的 const 声明解析（值域同源，避免文档侧另抄一份数字）。
func resolvePaginationCap(source, raw string) (int, error) {
	cleaned := strings.ReplaceAll(raw, "_", "")
	if value, err := strconv.Atoi(cleaned); err == nil {
		return value, nil
	}
	decl := regexp.MustCompile(`(?m)^const ` + regexp.QuoteMeta(raw) + ` = ([0-9_]+)$`).FindStringSubmatch(source)
	if decl == nil {
		return 0, fmt.Errorf("无法在 certjobs.go 解析常量 %s 的值", raw)
	}
	value, err := strconv.Atoi(strings.ReplaceAll(decl[1], "_", ""))
	if err != nil {
		return 0, fmt.Errorf("常量 %s 的值 %q 非法: %w", raw, decl[1], err)
	}
	return value, nil
}

// redeployed 同名不同类型（定向=boolean、批量=integer 计数）是既有运行时
// 契约，文档必须分别说明：只写布尔会让按 {"all":true} 批量调用的一方按
// boolean 建模而反序列化失败。两处运行时字面量从 certificates.go 派生，
// 文档或实现任一侧漂移即红。
func TestAPIDocs_issueCertificateRedeployedDualTypeDocumented(t *testing.T) {
	source, err := os.ReadFile("certificates.go")
	if err != nil {
		t.Fatalf("read certificates.go: %v", err)
	}
	body := string(source)
	if !strings.Contains(body, `"redeployed": true`) {
		t.Error("certificates.go 未出现定向形态的布尔字面量 \"redeployed\": true（派生基线已漂移）")
	}
	if !strings.Contains(body, `"redeployed":         redeployed`) {
		t.Error("certificates.go 未出现批量形态的整数计数器 \"redeployed\": redeployed（派生基线已漂移）")
	}
	description := routesEntry(t, "POST /certificates/issue").Description
	if !strings.Contains(description, "布尔") || !strings.Contains(description, "整数") {
		t.Errorf("POST /certificates/issue 描述未分别说明 redeployed 的布尔与整数形态: %q", description)
	}
	if !strings.Contains(description, `"redeployed":true`) || !strings.Contains(description, `"redeployed":0`) {
		t.Errorf("POST /certificates/issue 描述未给出两种响应示例: %q", description)
	}
}

// 文档占位符门：路由示例一旦写成 {...} 之类「看起来像 JSON 但不是合法 JSON」
// 的占位符，生成器会把它当纯文本走 strconv.Quote → 200 响应示例变成一条
// 字符串（按规格 codegen 的消费方把响应体建模为 string），请求侧则解析成无
// 意义的 flow map。示例要么是合法 JSON，要么是明确登记的说明文本（纯文本
// 表单/二进制下载形态由 TestAPIDocs_nonJSONResponsesDeclareExplicitMediaType
// 的 rawResponse 判据覆盖）。
func TestAPIDocRoutes_examplesAreValidJSONWhenJSONShaped(t *testing.T) {
	jsonShaped := func(example string) bool {
		trimmed := strings.TrimSpace(example)
		return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	}
	checked := 0
	for _, route := range apiDocRoutes {
		key := route.Method + " " + route.Path
		if request := strings.TrimSpace(route.Request); jsonShaped(request) {
			checked++
			if !json.Valid([]byte(request)) {
				t.Errorf("%s 请求示例不是合法 JSON（占位符会退化成字符串/flow map）: %s", key, request)
			}
		}
		if response := strings.TrimSpace(route.Response); jsonShaped(response) {
			checked++
			if !json.Valid([]byte(response)) {
				t.Errorf("%s 响应示例不是合法 JSON（占位符会让 200 示例退化成字符串）: %s", key, response)
			}
		}
	}
	if checked == 0 {
		t.Fatal("没有 JSON 形态示例被检查——路由示例表形态失效")
	}

	// 生成侧实证：三个「逃生口」端点的示例必须是结构化载荷，而不是字符串。
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, key := range []string{"GET /caddy/config", "GET /rules/:caddy_id/caddy-config"} {
		method, path := splitRouteKey(t, key)
		operation := document.Paths[apipath.ToOpenAPI(path)][strings.ToLower(method)]
		entry, ok := operation.Responses["200"].Content["application/json"]
		if !ok {
			t.Fatalf("%s 200 未声明 application/json", key)
		}
		if _, isString := entry.Example.(string); isString {
			t.Errorf("%s 200 示例被生成为字符串（占位符形态），want 结构化 JSON: %v", key, entry.Example)
		}
	}
}

// 安全事件计数端点的 ip 在 handler 侧缺参即 400（GetIPEventCount），
// OpenAPI 却把全部 query 参数一律写成 required=false——按规格生成的客户端
// 会把「缺 ip」当合法调用并在运行期吃 400。必填标记必须与 handler 的拒参
// 行为一致，且只标真正必填的那一项。
func TestBuildOpenAPIYAML_marksSecurityEventCountIPRequired(t *testing.T) {
	var document struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name     string `yaml:"name"`
				In       string `yaml:"in"`
				Required bool   `yaml:"required"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	required := func(path string) map[string]bool {
		got := map[string]bool{}
		for _, parameter := range document.Paths[path]["get"].Parameters {
			if parameter.In == "query" {
				got[parameter.Name] = parameter.Required
			}
		}
		return got
	}
	count := required("/security/events/count")
	if !count["ip"] {
		t.Fatalf("/security/events/count 的 ip 必须标 required=true（handler 缺参 400），实际 %v", count)
	}
	if count["days"] {
		t.Fatalf("/security/events/count 的 days 必须保持可选，实际 %v", count)
	}
	// 回归形状：其余端点的 query 参数仍全部可选（不得连带放大）。
	for _, path := range []string{"/audit-logs", "/security/events", "/metrics/history"} {
		for name, isRequired := range required(path) {
			if isRequired {
				t.Fatalf("%s 的 query 参数 %q 被标为必填（该端点缺参不报错）", path, name)
			}
		}
	}
}

// 证书凭据示例键形必须通过对应 provider 的 BuildCredentialsJSON
// 校验——历史示例 {"id","token"} 是早已废弃的键形，照示例调用必 400
// 「请选择认证方式」。现行 UI 形态：dnspod=auth_mode+app_id+app_token，
// aliyun=access_key_id+access_key_secret（文档必须披露，否则用户只能猜第二
// 提供商的键形）。
func TestAPIDocs_dnsCredentialExamplesPassProviderValidation(t *testing.T) {
	for _, key := range []string{"POST /certificate-configs", "POST /certificate-configs/test"} {
		route := routesEntry(t, key)
		var payload struct {
			DNSProvider    string            `json:"dns_provider"`
			DNSCredentials map[string]string `json:"dns_credentials"`
		}
		if err := json.Unmarshal([]byte(route.Request), &payload); err != nil {
			t.Fatalf("%s 示例请求体不是合法 JSON: %v", key, err)
		}
		if payload.DNSProvider == "" || len(payload.DNSCredentials) == 0 {
			t.Fatalf("%s 示例缺 dns_provider/dns_credentials", key)
		}
		provider, ok := dnsproviders.Get(payload.DNSProvider)
		if !ok {
			t.Fatalf("%s 示例 dns_provider %q 无对应提供商实现", key, payload.DNSProvider)
		}
		if _, err := provider.BuildCredentialsJSON(payload.DNSCredentials); err != nil {
			t.Errorf("%s 示例凭据未通过 BuildCredentialsJSON 校验（照示例调用必 400）: %v", key, err)
		}
		disclosed := route.Request + route.Description
		for _, want := range []string{"access_key_id", "access_key_secret"} {
			if !strings.Contains(disclosed, want) {
				t.Errorf("%s 文档未披露 aliyun 凭据键形 %q", key, want)
			}
		}
	}
}

// 规则日志两端点此前写「规则不存在…返回空内容」，与实现 404 矛盾。
// 描述必须区分「规则不存在 404」与「未启用日志空内容」，Errors 登记 404
// （log-stream 另有非法 offset 400）。
func TestAPIDocRoutes_ruleLogNotFoundSemanticsDocumented(t *testing.T) {
	for _, key := range []string{"GET /rules/:caddy_id/logs", "GET /rules/:caddy_id/log-stream"} {
		route := routesEntry(t, key)
		if !strings.Contains(route.Description, "规则不存在返回 404") || !strings.Contains(route.Description, "未启用日志") {
			t.Errorf("%s description 未区分「规则不存在 404」与「未启用日志空内容」: %q", key, route.Description)
		}
		if !containsRouteError(route.Errors, "404") {
			t.Errorf("%s errors 缺 404 not_found: %v", key, route.Errors)
		}
	}
	if !containsRouteError(routesEntry(t, "GET /rules/:caddy_id/log-stream").Errors, "400") {
		t.Errorf("GET /rules/:caddy_id/log-stream errors 缺 400 invalid_offset: %v", routesEntry(t, "GET /rules/:caddy_id/log-stream").Errors)
	}
}

// 监控/日志/任务族可达 4xx/5xx 逐条对照 handler 实现登记——
// 缺码会让按规格生成的客户端把可诊断故障当未知错误处理。
func TestAPIDocRoutes_monitoringLogTaskFamiliesDocumentReachableErrors(t *testing.T) {
	cases := []struct {
		key    string
		status string
	}{
		{"GET /config/health", "502"},
		{"GET /metrics/rule/:caddy_id", "500"},
		{"GET /metrics/rule/:caddy_id", "502"},
		{"GET /metrics/history", "500"},
		{"GET /rules/:caddy_id/metrics-history", "500"},
		{"GET /metrics/realtime", "500"},
		{"GET /metrics/connections", "500"},
		{"GET /caddy/metrics", "502"},
		{"GET /caddy/host-metrics", "502"},
		{"GET /system/logs", "500"},
		{"GET /caddy/logs", "400"},
		{"GET /caddy/logs", "500"},
		{"GET /system/tasks/:id/logs", "500"},
		{"GET /certificates/jobs/:id/logs", "400"},
		{"GET /certificates/jobs/:id/logs", "500"},
	}
	for _, tc := range cases {
		if !containsRouteError(routesEntry(t, tc.key).Errors, tc.status) {
			t.Errorf("%s errors 缺 %s（实现可达）", tc.key, tc.status)
		}
	}
}

// metrics 族响应示例键集对照真实响应结构补齐。
// get_metrics_overview 的 MCP 工具文案承诺「累计请求/字节/延迟分位数」——
// 字节与延迟键缺席会让按示例建模的客户端读不到承诺字段。
func TestAPIDocs_metricsOverviewExampleKeysMatchImplementation(t *testing.T) {
	assertStructKeysDocumented(t, "GET /metrics/overview", mapKeysOf(docResponseExample(t, "GET /metrics/overview")), models.MetricsOverview{})
}

// /metrics/history 行 = handler MetricRow：timestamp + requests_total +
// status_2xx/3xx/4xx/5xx + bytes_in/out（8 键，RFC3339 UTC 时间戳）。
func TestAPIDocs_metricsHistoryExampleKeysMatchImplementation(t *testing.T) {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(routesEntry(t, "GET /metrics/history").Response), &rows); err != nil {
		t.Fatalf("GET /metrics/history 示例必须是 data 数组 JSON: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("GET /metrics/history 示例缺数组元素")
	}
	want := map[string]bool{
		"timestamp":      true,
		"requests_total": true,
		"status_2xx":     true,
		"status_3xx":     true,
		"status_4xx":     true,
		"status_5xx":     true,
		"bytes_in":       true,
		"bytes_out":      true,
	}
	assertKeySetsEqual(t, "GET /metrics/history rows[]", mapKeysOf(rows[0]), want)
}

// /metrics/rule/:caddy_id = emptyRuleMetrics 8 键 + blocked（HTTP/TCP 两形态
// 恒补，TCP 恒 0）。
func TestAPIDocs_ruleMetricsExampleKeysMatchImplementation(t *testing.T) {
	want := mapKeysOf(emptyRuleMetrics())
	want["blocked"] = true
	assertKeySetsEqual(t, "GET /metrics/rule/:caddy_id", mapKeysOf(docResponseExample(t, "GET /metrics/rule/:caddy_id")), want)
}

// /config/health = map[server]map[upstream]*UpstreamHealthDetail（services）。
func TestAPIDocs_upstreamHealthExampleKeysMatchImplementation(t *testing.T) {
	example := docResponseExample(t, "GET /config/health")
	if len(example) == 0 {
		t.Fatal("GET /config/health 示例缺 server 层")
	}
	for serverKey, upstreamsAny := range example {
		upstreams, ok := upstreamsAny.(map[string]any)
		if !ok || len(upstreams) == 0 {
			t.Fatalf("GET /config/health 示例 server %q 缺上游对象", serverKey)
		}
		for upstreamKey, detailAny := range upstreams {
			detail, ok := detailAny.(map[string]any)
			if !ok {
				t.Fatalf("GET /config/health 示例上游 %q 不是对象", upstreamKey)
			}
			assertStructKeysDocumented(t, "GET /config/health "+upstreamKey, mapKeysOf(detail), services.UpstreamHealthDetail{})
		}
	}
}

// /metrics/connections 示例缺 syn_sent（ConnectionStats 11 键恒下发）。
func TestAPIDocs_connectionStatsExampleKeysMatchImplementation(t *testing.T) {
	assertStructKeysDocumented(t, "GET /metrics/connections", mapKeysOf(docResponseExample(t, "GET /metrics/connections")), models.ConnectionStats{})
}
