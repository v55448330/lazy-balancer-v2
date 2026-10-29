package middleware

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/db"
)

// 认证/身份/凭据类响应体带会话令牌、MFA 秘密或一次性明文凭据：被浏览器回退
// 缓存或中间反代留存后回放给另一个使用者即凭据泄露。这些路由必须逐条声明
// Cache-Control: no-store，而未携带凭据的业务响应不得被顺手降级（no-store
// 会连带禁用浏览器缓存，业务列表因此每次都重新取数）。
type noStoreRouteCase struct {
	name         string
	method       string
	path         string
	registration string
	body         string
	withToken    bool
	wantStatus   []int
}

func TestAuthenticationResponsesAreNotStored(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	token, spareToken := seedNoStoreAuthUser(t)

	cases := []noStoreRouteCase{
		{name: "login", method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"nobody","password":"x"}`},
		{name: "ticket login", method: http.MethodPost, path: "/api/v1/auth/ticket-login", body: `{"ticket":"bogus"}`},
		{name: "mfa verify", method: http.MethodPost, path: "/api/v1/auth/mfa/verify", body: `{"username":"nobody","code":"000000"}`},
		{name: "setup", method: http.MethodPost, path: "/api/v1/auth/setup", body: `{}`},
		{name: "oidc login", method: http.MethodGet, path: "/api/v1/auth/oidc/login"},
		{name: "oidc callback", method: http.MethodGet, path: "/api/v1/auth/oidc/callback?code=bogus&state=bogus"},
		{name: "current user", method: http.MethodGet, path: "/api/v1/users/me", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "self update", method: http.MethodPatch, path: "/api/v1/users/me", body: `{}`, withToken: true},
		{name: "user update", method: http.MethodPut, path: "/api/v1/users/999999", registration: "/api/v1/users/:id", body: `{}`, withToken: true},
		{name: "user reset password", method: http.MethodPost, path: "/api/v1/users/999999/reset-password", registration: "/api/v1/users/:id/reset-password", body: `{}`, withToken: true},
		{name: "mfa status", method: http.MethodGet, path: "/api/v1/auth/mfa/status", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "mfa setup", method: http.MethodPost, path: "/api/v1/auth/mfa/setup", body: `{}`, withToken: true},
		{name: "mfa activate", method: http.MethodPost, path: "/api/v1/auth/mfa/activate", body: `{}`, withToken: true},
		{name: "mfa disable", method: http.MethodPost, path: "/api/v1/auth/mfa/disable", body: `{}`, withToken: true},
		{name: "mfa recovery codes", method: http.MethodPost, path: "/api/v1/auth/mfa/recovery-codes", body: `{}`, withToken: true},
		{name: "mfa verify step", method: http.MethodPost, path: "/api/v1/auth/mfa/verify-step", body: `{}`, withToken: true},
		{name: "self api key list", method: http.MethodGet, path: "/api/v1/users/me/api-keys", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "self api key create", method: http.MethodPost, path: "/api/v1/users/me/api-keys", body: `{}`, withToken: true},
		{name: "api key list", method: http.MethodGet, path: "/api/v1/api-keys", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "api key create", method: http.MethodPost, path: "/api/v1/api-keys", body: `{}`, withToken: true},
		{name: "admin mfa reset", method: http.MethodPost, path: "/api/v1/users/999999/mfa/reset", registration: "/api/v1/users/:id/mfa/reset", body: `{}`, withToken: true},
		{name: "rule list contains private keys", method: http.MethodGet, path: "/api/v1/rules", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "rule detail contains private keys", method: http.MethodGet, path: "/api/v1/rules/missing", registration: "/api/v1/rules/:caddy_id", withToken: true},
		{name: "certificate configs contain credentials", method: http.MethodGet, path: "/api/v1/certificate-configs", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "ca provider list contains credentials", method: http.MethodGet, path: "/api/v1/ca-providers", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "ca provider detail contains credentials", method: http.MethodGet, path: "/api/v1/ca-providers/999999", registration: "/api/v1/ca-providers/:id", withToken: true},
		// 一次性机器凭据：register-tokens 回一次性注册令牌明文、login-ticket 回
		// 一次性 HMAC 票据明文，两者被缓存即等于把凭据交给下一个使用者。
		// 机器侧两条（registration status / sync snapshot）已挂 no-store，
		// 一并纳入对账矩阵（AST 对账不再按 /cluster/ 前缀整体豁免）。
		// 注意：必须排在 logout 之前——logout 用例会撤销本矩阵共用的 token。
		{name: "cluster register token", method: http.MethodPost, path: "/api/v1/cluster/register-tokens", body: `{}`, withToken: true},
		{name: "cluster login ticket", method: http.MethodPost, path: "/api/v1/cluster/nodes/999999/login-ticket", registration: "/api/v1/cluster/nodes/:id/login-ticket", body: `{}`, withToken: true},
		{name: "cluster registration status", method: http.MethodGet, path: "/api/v1/cluster/register/999999/status", registration: "/api/v1/cluster/register/:id/status", withToken: true},
		{name: "cluster sync snapshot", method: http.MethodGet, path: "/api/v1/cluster/sync/snapshot", withToken: true},
		{name: "logout", method: http.MethodPost, path: "/api/v1/auth/logout", withToken: true, wantStatus: []int{http.StatusOK}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if tc.withToken {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			router.ServeHTTP(recorder, request)

			// 先确认请求真的走到了目标 handler（认证层拒绝不会设置该头，
			// 只断言头会放过「路由都没命中」的假绿）。
			if len(tc.wantStatus) > 0 && !containsStatus(tc.wantStatus, recorder.Code) {
				t.Fatalf("status=%d body=%q, want one of %v", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q body=%q, want no-store", got, recorder.Body.String())
			}
		})
	}

	assertNoStoreRouteCoverage(t, cases)

	// 不含凭据的业务响应：不得被顺手降级。
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/dns-providers", nil)
	// 上面的 logout 用例已撤销 token，这里必须用未撤销的第二枚（同一用户
	// 不同令牌串=不同撤销指纹）。
	request.Header.Set("Authorization", "Bearer "+spareToken)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dns-providers status=%d body=%q, want 200", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("非凭据响应 Cache-Control=%q, want 空", got)
	}
}

func assertNoStoreRouteCoverage(t *testing.T, cases []noStoreRouteCase) {
	t.Helper()
	expected := make(map[string]bool, len(cases))
	for _, tc := range cases {
		path, _, _ := strings.Cut(tc.path, "?")
		if tc.registration != "" {
			path = tc.registration
		}
		expected[tc.method+" "+path] = true
	}
	source, err := os.ReadFile("middleware.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "middleware.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return true
		}
		pathLiteral, ok := call.Args[0].(*ast.BasicLit)
		if !ok || pathLiteral.Kind != token.STRING {
			return true
		}
		path, err := strconv.Unquote(pathLiteral.Value)
		// 不再按 /cluster/ 前缀整体跳过：机器凭据类响应同样是一次性明文，
		// 「集群路由默认免检」会让新增的 noStoreResponse 挂载无声逃过对账。
		// 未在测试矩阵声明却挂了 no-store 的路由一律报错（下方 actual 反向
		// 对账），新增者必须把它连同断言一起加进 cases。
		if err != nil {
			return true
		}
		for _, arg := range call.Args[1:] {
			ast.Inspect(arg, func(argNode ast.Node) bool {
				middlewareCall, ok := argNode.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := middlewareCall.Fun.(*ast.Ident); ok && ident.Name == "noStoreResponse" {
					actual[selector.Sel.Name+" /api/v1"+path] = true
				}
				return true
			})
		}
		return true
	})
	for route := range expected {
		if !actual[route] {
			t.Errorf("%s 测试声明了 no-store 契约，但路由未挂载", route)
		}
	}
	for route := range actual {
		if !expected[route] {
			t.Errorf("%s 挂载了 noStoreResponse，但敏感响应测试矩阵未覆盖", route)
		}
	}
}

// seedNoStoreAuthUser 建一个已启用管理员并签发两枚与之匹配的 JWT（jwtAuth 会
// 回库校验用户名/密码版本，故必须落在同一个 db 里）。第二枚供登出撤销后仍需要
// 身份的非认证用例使用——撤销按令牌串哈希记账，两枚互不影响。
func seedNoStoreAuthUser(t *testing.T) (string, string) {
	t.Helper()
	const userID = 43
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version)
		VALUES (?,?,?,?,1,0)`, userID, "no-store-user", "hash", "admin"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sign := func(expiry time.Duration) string {
		claims := jwt.MapClaims{
			"user_id":  userID,
			"username": "no-store-user",
			"pwd_ver":  0,
			"exp":      time.Now().Add(expiry).Unix(),
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret"))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return token
	}
	return sign(time.Hour), sign(2 * time.Hour)
}

func containsStatus(candidates []int, got int) bool {
	for _, code := range candidates {
		if code == got {
			return true
		}
	}
	return false
}
