package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resetLoginRateBuckets(t *testing.T) {
	t.Helper()
	loginRateBuckets.Lock()
	loginRateBuckets.entries = make(map[string]*loginRateBucket)
	loginRateBuckets.Unlock()
	t.Cleanup(func() {
		loginRateBuckets.Lock()
		loginRateBuckets.entries = make(map[string]*loginRateBucket)
		loginRateBuckets.Unlock()
	})
}

// Round 24 D-LOW：/auth/setup 与登录共用 IP 限流（10 次/分钟），
// 防止初始化接口被暴力尝试创建管理员。
func TestSetupRouter_authSetupRoutesRateLimited(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	resetLoginRateBuckets(t)
	body := `{"username":"adminuser","password":"adminpass123"}`

	// When：连续 11 次创建管理员请求
	var last *httptest.ResponseRecorder
	for i := 0; i < 11; i++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		last = httptest.NewRecorder()
		router.ServeHTTP(last, request)
	}

	// Then：第 11 次被限流拦截
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "登录尝试过于频繁") {
		t.Fatalf("11th setup status=%d body=%s, want 429 rate limited", last.Code, last.Body.String())
	}

	// And：同 IP 的 GET /auth/setup 也受同一限流桶约束
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/setup", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("setup status check status=%d body=%s, want 429 rate limited", response.Code, response.Body.String())
	}
}
