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
// 不在 readOnlyWriteRoutes/守卫豁免清单内，由 admin 组级 mfaStepUpGuard 覆盖（U7c-68-01
// 自 v1 级下沉）——本测试以真实 JWT 穿完整认证链钉住该契约：无 mfa_ts → 428；验码后的新 JWT → 200。
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

// U7c-68-01（第 68 轮审计）：admin 组端点的拒绝次序——非管理员（含 MFA 启用
// 且 mfa_ts 过期者）打 admin 组端点必须先见 adminOnly 的 403 真因，而非
// mfaStepUpGuard 的 428（此前守卫挂在 v1 级、先于组级 adminOnly 执行，用户
// 输码重试后才见「需要管理员权限」——与 U7c-3 从节点 403 先于 428 同型）。
// 修复=链序：mfaStepUpGuard 从 v1 级下沉至 admin/business 两组级，admin 组内
// adminOnly 先于 step-up。
func TestMFAStepUpGuard_adminOnly403BeforeStepUp428(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const jwtSecret = "test-secret"

	// Given：启用 MFA 的普通用户（非 admin）、写守卫开启
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version,mfa_enabled)
		VALUES (201,'order-user','x','user',1,0,1)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatalf("enable write guard: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	claims := jwt.MapClaims{
		"user_id": float64(201), "username": "order-user", "pwd_ver": float64(0),
		"jti": fmt.Sprintf("orderj%d", time.Now().UnixNano()), "exp": time.Now().Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	// When：非管理员打 admin 组写端点（无 mfa_ts——428 条件同样成立）
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"x","password":"fresh-pass-1"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Then：403 admin_required（角色真因先于 step-up）
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin POST /users: got %d, want 403（adminOnly 真因不得被 428 遮蔽）", rec.Code)
	}
}

// SYSMW-U2（第 69 轮 P3）：business 组守卫次序对称 U7c-68-01——非管理员打
// business 组管理写端点须先见 readOnlyGuard 的 403 角色真因，而非
// mfaStepUpGuard 的 428（旧次序 step-up 在前：用户验码重试后才见
// 「非管理员用户只读」，与 admin 组已修的误导链同型）。
func TestMFAStepUpGuard_businessWrite403BeforeStepUp428(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const jwtSecret = "test-secret"

	// Given：启用 MFA 的普通用户（非 admin）、写守卫开启、主节点（库默认）
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version,mfa_enabled)
		VALUES (301,'biz-order-user','x','user',1,0,1)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatalf("enable write guard: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	mint := func(mfaTs int64) string {
		t.Helper()
		claims := jwt.MapClaims{
			"user_id": float64(301), "username": "biz-order-user", "pwd_ver": float64(0),
			"jti": fmt.Sprintf("bizorderj%d", time.Now().UnixNano()), "exp": time.Now().Add(time.Hour).Unix(),
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

	// When/Then 1（目标形状）：无 mfa_ts（428 条件同样成立）打 business 管理写
	// 端点 → 403 角色真因必须先于 step-up（旧次序此处为 428）
	if code := do(http.MethodPost, "/api/v1/rules", mint(0), `{}`); code != http.StatusForbidden {
		t.Fatalf("non-admin POST /rules without mfa_ts: got %d, want 403（角色真因不得被 428 遮蔽）", code)
	}
	// When/Then 2（回归形状）：验码后（mfa_ts 新鲜）仍 403——角色是终态真因，
	// 与 step-up 窗口无关（新旧次序同为 403）。
	if code := do(http.MethodPost, "/api/v1/rules", mint(time.Now().Unix()), `{}`); code != http.StatusForbidden {
		t.Fatalf("non-admin POST /rules with fresh mfa_ts: got %d, want 403", code)
	}
	// When/Then 3（回归形状）：自助写次序不变——readOnlyGuard 自助放行后照常
	// 进 step-up，陈旧 mfa_ts 仍 428（新旧次序同为 428）。
	if code := do(http.MethodPatch, "/api/v1/users/me", mint(0), `{"display_name":"X"}`); code != http.StatusPreconditionRequired {
		t.Fatalf("self-service PATCH /users/me without mfa_ts: got %d, want 428（自助路径 step-up 不变）", code)
	}
}
