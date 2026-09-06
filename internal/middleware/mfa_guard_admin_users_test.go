package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	jwt "github.com/golang-jwt/jwt/v5"
)

// S-1（2026-09-05 裁定）：管理员经 PUT /users/:id 与 POST /users/:id/reset-password
// 重置任意用户（含本人）密码属重置操作、不验当前密码；唯一要求是 MFA 写保护
// （mfa_write_guard）开启且操作者已启用 MFA 时须 MFA 验证码。两端点均为写方法、
// 不在 readOnlyWriteRoutes/守卫豁免清单内，由 v1 级 mfaStepUpGuard 覆盖——
// 本测试以真实 JWT 穿完整认证链钉住该契约：无 mfa_ts → 428；验码后的新 JWT → 200。
func TestMFAStepUpGuard_protectsAdminUserPasswordEndpoints(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const jwtSecret = "test-secret"

	// Given：启用 MFA 的管理员（id=101）、普通目标用户（id=102）、写守卫开启
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version,mfa_enabled)
		VALUES (101,'pw-admin','x','admin',1,0,1), (102,'pw-target','x','user',1,0,0)`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatalf("enable write guard: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	mintToken := func(mfaTs int64) string {
		t.Helper()
		claims := jwt.MapClaims{
			"user_id": float64(101), "username": "pw-admin", "pwd_ver": float64(0),
			"jti": fmt.Sprintf("pwj%d", time.Now().UnixNano()), "exp": time.Now().Add(time.Hour).Unix(),
		}
		if mfaTs > 0 {
			claims["mfa_ts"] = float64(mfaTs)
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return token
	}
	do := func(method, path, token, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	tokenUnverified := mintToken(0)
	tokenVerified := mintToken(time.Now().Unix())

	// When/Then 1：守卫开启 + MFA 管理员 + 无 mfa_ts → 两个密码端点均 428
	if code := do(http.MethodPut, "/api/v1/users/102", tokenUnverified, `{"display_name":"Guard"}`); code != http.StatusPreconditionRequired {
		t.Fatalf("PUT /users/:id without mfa_ts: got %d, want 428（管理员重置密码须 MFA 验证）", code)
	}
	if code := do(http.MethodPost, "/api/v1/users/102/reset-password", tokenUnverified, `{"new_password":"fresh-pass-1"}`); code != http.StatusPreconditionRequired {
		t.Fatalf("POST /users/:id/reset-password without mfa_ts: got %d, want 428（管理员重置密码须 MFA 验证）", code)
	}

	// When/Then 2：验码后的新 JWT（mfa_ts 新鲜）→ 直通 handler → 200
	if code := do(http.MethodPut, "/api/v1/users/102", tokenVerified, `{"display_name":"Guard"}`); code != http.StatusOK {
		t.Fatalf("PUT /users/:id with fresh mfa_ts: got %d, want 200", code)
	}
	if code := do(http.MethodPost, "/api/v1/users/102/reset-password", tokenVerified, `{"new_password":"fresh-pass-1"}`); code != http.StatusOK {
		t.Fatalf("POST /users/:id/reset-password with fresh mfa_ts: got %d, want 200", code)
	}
}
