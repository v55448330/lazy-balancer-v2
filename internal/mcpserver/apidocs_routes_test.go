package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"

	"lazy-balancer-v2/internal/apipath"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/mcpserver"
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
		want[route.Method+" "+apipath.ToOpenAPI(path)] = struct{}{}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	request.Header.Set("Authorization", "Bearer "+apiDocTestToken(t))
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

// /openapi.yaml 与 /docs 此前置于公开块（匿名 200），
// 完整 API 目录（路径/载荷示例/错误码）可被未认证方枚举。本测试钉住新契约：
// 规格匿名 401、携带已认证 token 200；/docs 仅 HTML 壳（匿名 200 text/html，
// 本体内 Swagger 以 localStorage.token 注入 Authorization 头取规格，壳里不得
// 内联/转发规格本体）。
func TestOpenAPISpec_endpointsRequireAuthentication(t *testing.T) {
	router := newAPIDocTestRouter(t)

	anonymous := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	anonymousResponse := httptest.NewRecorder()
	router.ServeHTTP(anonymousResponse, anonymous)
	if anonymousResponse.Code != http.StatusUnauthorized {
		t.Fatalf("匿名取规格 status=%d, want 401", anonymousResponse.Code)
	}

	// /docs 公开但只是壳：匿名 200 text/html，响应体不得含规格本体。
	docs := httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil)
	docsResponse := httptest.NewRecorder()
	router.ServeHTTP(docsResponse, docs)
	if docsResponse.Code != http.StatusOK {
		t.Fatalf("匿名取 /docs status=%d, want 200（壳公开）", docsResponse.Code)
	}
	if contentType := docsResponse.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("/docs Content-Type=%q, want text/html", contentType)
	}
	docsBody := docsResponse.Body.String()
	if !strings.Contains(docsBody, "/api/v1/openapi.yaml") {
		t.Fatal("/docs 壳未引用已鉴权的规格端点（壳应让浏览器带令牌取规格）")
	}
	for _, leaked := range []string{"openapi: 3", `"paths":`} {
		if strings.Contains(docsBody, leaked) {
			t.Fatalf("/docs 匿名响应体内嵌了规格本体（%q）——完整 API 目录对匿名方泄露", leaked)
		}
	}

	authed := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	authed.Header.Set("Authorization", "Bearer "+apiDocTestToken(t))
	authedResponse := httptest.NewRecorder()
	router.ServeHTTP(authedResponse, authed)
	if authedResponse.Code != http.StatusOK {
		t.Fatalf("携带 token 取规格 status=%d body=%q, want 200", authedResponse.Code, authedResponse.Body.String())
	}
	if !strings.Contains(authedResponse.Body.String(), "openapi:") {
		t.Fatalf("规格响应体不含 openapi 文档头: %q", authedResponse.Body.String()[:min(80, authedResponse.Body.Len())])
	}
}

const apiDocTestJWTSecret = "test-secret"

// apiDocTestToken 铸造与 newAPIDocTestRouter 内测试用户（id=41）匹配的 HS256 令牌。
func apiDocTestToken(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id": float64(41), "username": "apidocs-user", "pwd_ver": float64(0),
		"jti": "apidocs-test", "exp": time.Now().Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(apiDocTestJWTSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func newAPIDocTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
		mcpserver.RestoreDBForTest(oldDB, oldMetricsDB, oldAuditDB)
	})
	// 已认证请求所需的用户行（jwtAuth 校验 pwd_ver 与 users.password_version 一致）
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (41,'apidocs-user','hash','user',1,0)"); err != nil {
		t.Fatalf("seed auth user: %v", err)
	}
	cfg := &config.Config{
		Port: 8000, StaticDir: t.TempDir(), CaddyAdminURL: "http://127.0.0.1:1",
		CaddyMetricsURL: "http://127.0.0.1:1/metrics", MetricsInterval: 60,
		NodeName: "apidocs-test", JWTSecret: apiDocTestJWTSecret,
	}
	caddy := services.NewCaddyService(cfg.CaddyAdminURL)
	handler := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddy, MetricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 60),
		SyncService: services.NewSyncService(db.DB, cfg, caddy), ClusterService: services.NewClusterService(db.DB, ""),
		CAProviderService: services.NewCAProviderService(),
	})
	return middleware.SetupRouter(handler, cfg)
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

// 集群机器接口绊线：文档声明的认证方式必须与 SetupRouter 注册真实认证链一致。
// 行为面——有效 JWT 打机器接口恒 401（证明不在 bearerAuth 链上）；文档面——
// 生成规格的 security scheme 与期望逐一相等，且全文档中带 clusterToken/
// registrationSecret 的操作必须落在本表（反向防误标）。
func TestClusterMachineEndpoints_documentMachineTokenScheme(t *testing.T) {
	router := newAPIDocTestRouter(t)
	// 与 SetupRouter 公开块注册的机器认证链一一对应。
	machineSchemes := map[string]string{
		"GET /cluster/register/:id/status":   "registrationSecret",
		"GET /cluster/sync/snapshot":         "clusterToken",
		"GET /cluster/sync/waf-files":        "clusterToken",
		"POST /cluster/registration/confirm": "clusterToken",
		"POST /cluster/nodes/report":         "clusterToken",
		// 集群集中汇聚（2026-11-22）：从节点事件/统计上报机器接口。
		"POST /cluster/events/report":     "clusterToken",
		"POST /cluster/node-stats/report": "clusterToken",
	}

	// 行为面：有效 JWT（bearerAuth 凭证）对机器接口恒 401。
	token := apiDocTestToken(t)
	for key := range machineSchemes {
		method, path, _ := strings.Cut(key, " ")
		url := strings.ReplaceAll(path, ":id", "1")
		var request *http.Request
		if method == http.MethodPost {
			request = httptest.NewRequest(method, "/api/v1"+url, strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
		} else {
			request = httptest.NewRequest(method, "/api/v1"+url, nil)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s 携有效 JWT status=%d, want 401（机器接口不在 bearerAuth 链上）", key, response.Code)
		}
	}

	// 文档面：生成的 OpenAPI security 与期望 scheme 相等。
	request := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("取规格 status=%d", response.Code)
	}
	var document struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `yaml:"security"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	covered := make(map[string]bool, len(machineSchemes))
	for path, operations := range document.Paths {
		for method, operation := range operations {
			for _, requirement := range operation.Security {
				for scheme := range requirement {
					if scheme != "clusterToken" && scheme != "registrationSecret" {
						continue
					}
					key := strings.ToUpper(method) + " " + apipath.ToGin(path)
					want, ok := machineSchemes[key]
					if !ok {
						t.Errorf("%s %s 文档标注 %s，但它不是已登记的集群机器接口（误标或漏登记）", method, path, scheme)
						continue
					}
					if scheme != want {
						t.Errorf("%s 文档 security=%s, want %s", key, scheme, want)
					}
					covered[key] = true
				}
			}
		}
	}
	for key, scheme := range machineSchemes {
		if !covered[key] {
			t.Errorf("%s 未在生成规格中标注 %s——契约表缺键会静默回落 bearerAuth", key, scheme)
		}
	}
}
