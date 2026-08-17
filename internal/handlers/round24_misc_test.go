package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// Round 24 C-N3：validateCaddyConfigBeforeSave 构造的临时校验配置必须携带上游
// MaxConnections（渲染为 reverse_proxy upstream 的 max_requests），否则“校验通过的
// 配置”与实际落库后生成的配置不一致（校验≠将生成）。
func TestValidateCaddyConfigBeforeSave_forwardsUpstreamMaxConnections(t *testing.T) {
	tests := []struct {
		name        string
		dynamicDNS  bool
		wantContain string
	}{
		{name: "static upstream renders max_requests", wantContain: `"max_requests":100`},
		// DynamicDNS 为规则级开关，已随 SingleRuleConfig.DynamicDNS 透传；动态上游
		// 分支渲染为 dynamic_upstreams（A 记录源），不含 max_requests。
		{name: "dynamic dns upstream renders dynamic_upstreams", dynamicDNS: true, wantContain: `"dynamic_upstreams"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			initializeRuleFeatureTestDB(t)
			var validatedBody string
			fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/config/":
					_, _ = response.Write([]byte(`{"apps":{"http":{"servers":{"http_8080":{"routes":[]}}}}}`))
				case request.Method == http.MethodPost && request.URL.Path == "/load":
					body, err := io.ReadAll(request.Body)
					if err != nil {
						response.WriteHeader(http.StatusInternalServerError)
						return
					}
					validatedBody = string(body)
					_, _ = response.Write([]byte(`{}`))
				default:
					_, _ = response.Write([]byte(`{}`))
				}
			}))
			t.Cleanup(fakeCaddy.Close)
			handler := &Handlers{
				cfg:          &config.Config{CaddyAdminURL: fakeCaddy.URL},
				caddyService: services.NewCaddyService(fakeCaddy.URL),
			}
			req := models.CreateRuleRequest{
				Name: "max-conn", Protocol: "http", Domain: "maxconn.example.test", ListenPort: 8080,
				Strategy: "weighted_round_robin", DynamicDNS: test.dynamicDNS, DnsFamily: "ipv4",
				Upstreams: []models.Upstream{{Host: "upstream.example.test", Port: 9000, Weight: 1, Enabled: true, MaxConnections: 100}},
			}

			// When
			err := handler.validateCaddyConfigBeforeSave(req, createRuleFeatures(req), "round24", "http_8080")

			// Then
			if err != nil {
				t.Fatalf("validateCaddyConfigBeforeSave() error = %v", err)
			}
			if !strings.Contains(validatedBody, test.wantContain) {
				t.Fatalf("validated config missing %s: %s", test.wantContain, validatedBody)
			}
		})
	}
}

// Round 24 C-N5：路径规则上游的主机格式必须与主上游走同样的 isValidHost 校验，
// 防止非法主机名进入生成的 Caddy 配置。
func TestValidateRuleFeatures_rejects_invalid_path_upstream_host(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		wantError string
	}{
		// R25：Docker Compose 服务名允许下划线，isValidHost 已放行 '_'（详见 round25_low_test.go）
		{name: "docker underscore service accepted", address: "bad_host.example.test", wantError: ""},
		{name: "leading hyphen label rejected", address: "-bad.example.test", wantError: "主机"},
		{name: "space in host rejected", address: "bad host.example.test", wantError: "主机"},
		{name: "valid domain accepted", address: "good.example.test", wantError: ""},
		{name: "valid ip accepted", address: "127.0.0.1", wantError: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			input := ruleFeatureInput{
				CustomRoutesEnabled: true,
				PathRules: []models.PathRule{{
					MatchType: "prefix", Path: "/api/",
					Upstreams: []models.PathRuleUpstream{{Address: test.address, Port: 9100, Weight: 1}},
				}},
			}

			// When
			err := validateRuleFeatures(input)

			// Then
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateRuleFeatures() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

// Round 24 D-LOW：CreateUserRequest 用户名长度约束与初始化管理员（min=3,max=50）对齐。
func TestCreateUser_rejectsShortUsername(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/users", handler.CreateUser)
	request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"username":"ab","password":"secret123","role":"user"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("create short-username status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='ab'").Scan(&count); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("short username user created, want rejected before insert")
	}
}

// Round 24 D-LOW：管理员重置密码过短时，错误文案应指向密码长度而非「请求格式错误」。
func TestResetUserPassword_shortPasswordMessage(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	seedUserAuditTest(t, 9, "target", "user", true)
	gin.SetMode(gin.TestMode)
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodPost, "/users/9/reset-password", strings.NewReader(`{"new_password":"123"}`))
	context.Request.Header.Set("Content-Type", "application/json")
	context.Params = gin.Params{{Key: "id", Value: "9"}}

	// When
	handler.ResetUserPassword(context)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "密码至少 6 位") {
		t.Fatalf("reset short password status=%d body=%s, want 400 with 密码至少 6 位", response.Code, response.Body.String())
	}
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=9").Scan(&hash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if hash != "hash" {
		t.Fatalf("short password overwrote hash, want original")
	}
}
