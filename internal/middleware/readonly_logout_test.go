package middleware

// C403-1(第 40 轮分歧裁定后补):logout 属自助语义路径——当前路由不在
// readOnlyGuard 链上(行为已正确),白名单收录为防御性对齐:未来若把
// /auth/logout 挪入 business 组,非管理员登出不因守卫误拒。
import "testing"

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
