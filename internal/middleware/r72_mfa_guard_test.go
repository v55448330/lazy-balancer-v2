package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	jwt "github.com/golang-jwt/jwt/v5"
)

// R72 B-1 回归绊线：mfaStepUpGuard 的 428 行为——此前 auth_type 从未被 jwtAuth
// 设置 + GetString 读 float64 user_id 双缺陷使守卫整体死代码（单测全绿掩盖）。
// 本测试让真实 JWT 穿过完整认证链。
func TestMFAStepUpGuard_endToEnd(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	// 与 newMiddlewareTestRouterAtPort 相同的 JWT secret。
	const jwtSecret = "test-secret"

	seedUser := func(mfaEnabled bool, mfaTs int64) string {
		t.Helper()
		username := fmt.Sprintf("g%d%v", time.Now().UnixNano(), mfaEnabled)
		res, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled,password_version) VALUES (?,?,'admin',1,0)", username, "x")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		_ = username
		if mfaEnabled {
			if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1 WHERE id=?", id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })
		claims := jwt.MapClaims{
			"user_id": float64(id), "username": username, "pwd_ver": float64(0),
			"jti": fmt.Sprintf("j%d", time.Now().UnixNano()), "exp": time.Now().Add(time.Hour).Unix(),
		}
		if mfaTs > 0 {
			claims["mfa_ts"] = float64(mfaTs)
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	post := func(path, token string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	// R72 十六次：/config/preview 已是只读语义 POST（被豁免），写探针改用 PUT /config。
	put := func(path, token string) int {
		req := httptest.NewRequest(http.MethodPut, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	// Case 1：MFA 用户 + 无 mfa_ts + 真实写路由（PUT /config）→ 428
	tokenOld := seedUser(true, 0)
	if code := put("/api/v1/config", tokenOld); code != http.StatusPreconditionRequired {
		t.Fatalf("MFA user without mfa_ts: got %d, want 428（守卫生效证明）", code)
	}

	// Case 2：verify-step 豁免 → 不是 428（401 也行——证明未被守卫拦截）
	if code := post("/api/v1/auth/mfa/verify-step", tokenOld); code == http.StatusPreconditionRequired {
		t.Fatal("verify-step must be exempt from step-up guard（C-I-1 自锁）")
	}

	// Case 3：非 MFA 用户 → 直通到后续中间件（非 428）
	tokenPlain := seedUser(false, 0)
	if code := put("/api/v1/config", tokenPlain); code == http.StatusPreconditionRequired {
		t.Fatal("non-MFA user must not be challenged")
	}

	// Case 4：MFA 用户 + 新鲜 mfa_ts → 非 428
	tokenFresh := seedUser(true, time.Now().Unix())
	if code := put("/api/v1/config", tokenFresh); code == http.StatusPreconditionRequired {
		t.Fatal("fresh mfa_ts must pass")
	}

	// Case 5（R72 十六次）：只读语义 POST（readOnlyWriteRoutes：批量证书状态
	// 查询/测试/预览）即使 mfa_ts 过期也不弹码——用户打开规则列表页不该被要求验证。
	if code := post("/api/v1/rules/cert-info", tokenOld); code == http.StatusPreconditionRequired {
		t.Fatal("read-semantics POST (cert-info) must be exempt from step-up（打开列表页不弹码）")
	}
}
