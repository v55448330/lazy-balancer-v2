package middleware

// logout 属自助语义路径——当前路由不在
// readOnlyGuard 链上(行为已正确),白名单收录为防御性对齐:未来若把
// /auth/logout 挪入 business 组,非管理员登出不因守卫误拒。
//
// 三守卫（apiKeyReadOnlyGuard / mfaStepUpGuard 的 DecideMFAStepUp /
// readOnlyGuard）对 logout 口径一致：放行到 handler，由其返回统一 404。
// 只读 API Key 此前被本守卫拦成 403（与 JWT/从节点不一致）。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIsSelfServicePath_includesLogout(t *testing.T) {
	if !isSelfServicePath("/api/v1/auth/logout") {
		t.Fatal("logout must be whitelisted as self-service (defense-in-depth)")
	}
	for _, p := range []string{"/api/v1/users/me", "/api/v1/users/me/api-keys", "/api/v1/users/me/api-keys/3", "/api/v1/auth/mfa/setup"} {
		if !isSelfServicePath(p) {
			t.Fatalf("existing self-service path %s must stay whitelisted", p)
		}
	}
	if isSelfServicePath("/api/v1/rules") {
		t.Fatal("non self-service path must not be whitelisted")
	}
}

// Given 只读/可写两种 API Key 身份。
// When POST /api/v1/auth/logout。
// Then 都落到 handler（统一 404「无会话令牌可吊销」），守卫不截断；
// 同守卫对其他写路由的 403 语义不变。
func TestAPIKeyReadOnlyGuard_allowsLogoutToHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, readOnly := range []bool{true, false} {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("auth_type", "api_key")
			c.Set("api_key_read_only", readOnly)
			c.Next()
		})
		router.Use(apiKeyReadOnlyGuard())
		handlerReached := false
		router.POST("/api/v1/auth/logout", func(c *gin.Context) {
			handlerReached = true
			c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "无会话令牌可吊销"})
		})
		router.POST("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil))
		if !handlerReached || recorder.Code != http.StatusNotFound {
			t.Fatalf("read_only=%v logout status=%d body=%s, want handler 404（守卫放行）", readOnly, recorder.Code, recorder.Body.String())
		}

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))
		want := http.StatusNoContent
		if readOnly {
			want = http.StatusForbidden
		}
		if recorder.Code != want {
			t.Fatalf("read_only=%v 写路由 status=%d, want %d（放行面不得扩大到其他写路由）", readOnly, recorder.Code, want)
		}
	}
}
