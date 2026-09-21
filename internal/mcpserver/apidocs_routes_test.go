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

// 第 48 轮审计 R48-API-1：/openapi.yaml 与 /docs 此前置于公开块（匿名 200），
// 完整 API 目录（路径/载荷示例/错误码）可被未认证方枚举。本测试钉住新契约：
// 规格匿名 401、携带已认证 token 200；/docs 仅 HTML 壳（本体内 Swagger 以
// localStorage.token 注入 Authorization 头取规格）。
func TestOpenAPISpec_endpointsRequireAuthentication(t *testing.T) {
	router := newAPIDocTestRouter(t)

	anonymous := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	anonymousResponse := httptest.NewRecorder()
	router.ServeHTTP(anonymousResponse, anonymous)
	if anonymousResponse.Code != http.StatusUnauthorized {
		t.Fatalf("匿名取规格 status=%d, want 401", anonymousResponse.Code)
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
		services.StopAuditCleanup()
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
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
		SyncService: services.NewSyncService(db.DB, cfg, caddy), ClusterService: services.NewClusterService(db.DB, nil, ""),
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
