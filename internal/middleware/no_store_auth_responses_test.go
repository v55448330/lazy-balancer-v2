package middleware

import (
	"net/http"
	"net/http/httptest"
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
func TestAuthenticationResponsesAreNotStored(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	token, spareToken := seedNoStoreAuthUser(t)

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		withToken  bool
		wantStatus []int
	}{
		{name: "login", method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"nobody","password":"x"}`},
		{name: "ticket login", method: http.MethodPost, path: "/api/v1/auth/ticket-login", body: `{"ticket":"bogus"}`},
		{name: "mfa verify", method: http.MethodPost, path: "/api/v1/auth/mfa/verify", body: `{"username":"nobody","code":"000000"}`},
		{name: "current user", method: http.MethodGet, path: "/api/v1/users/me", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "self update", method: http.MethodPatch, path: "/api/v1/users/me", body: `{}`, withToken: true},
		{name: "mfa status", method: http.MethodGet, path: "/api/v1/auth/mfa/status", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "self api key list", method: http.MethodGet, path: "/api/v1/users/me/api-keys", withToken: true, wantStatus: []int{http.StatusOK}},
		{name: "api key list", method: http.MethodGet, path: "/api/v1/api-keys", withToken: true, wantStatus: []int{http.StatusOK}},
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

	// 非认证响应：不得带 no-store。
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	// 上面的 logout 用例已撤销 token，这里必须用未撤销的第二枚（同一用户
	// 不同令牌串=不同撤销指纹）。
	request.Header.Set("Authorization", "Bearer "+spareToken)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rules status=%d body=%q, want 200", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("非认证响应 Cache-Control=%q, want 空", got)
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
