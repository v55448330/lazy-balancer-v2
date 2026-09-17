package middleware

// R39-5(第 39 轮审计):mfaStepUpGuard 对 OIDC 会话(auth_method=oidc)必须在
// MFA 状态查询前显式短路——当前实现依赖「OIDC 行 mfa_enabled 恒 0」的跨文件
// 不变量,任何把 mfa_enabled 写上 OIDC 行的新路径都会让 OIDC 用户落入本地
// step-up 428 链(verify-step 因 mfa_secret='' 必败→写操作全锁)。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestMFAStepUpGuard_oidcMethodShortCircuit(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const jwtSecret = "test-secret"

	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	seedToken := func(mfaEnabled bool, authMethod string) string {
		t.Helper()
		username := fmt.Sprintf("oidcg%d", time.Now().UnixNano())
		res, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled,password_version,auth_provider) VALUES (?,?,'admin',1,0,?)", username, "x", authMethod)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		if mfaEnabled {
			if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1 WHERE id=?", id); err != nil {
				t.Fatal(err)
			}
		}
		claims := jwt.MapClaims{
			"user_id": float64(id), "username": username, "pwd_ver": float64(0),
			"auth_method": authMethod,
			"jti":         fmt.Sprintf("j%d", time.Now().UnixNano()), "exp": time.Now().Add(time.Hour).Unix(),
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	put := func(token string) int {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/config", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	// Given/When:OIDC 会话 + 行上 mfa_enabled 被置位(不变量破坏形状)+ 无 mfa_ts
	// Then:不得 428(auth_method 短路;进 handler 后任意非 428 结果均可)
	if code := put(seedToken(true, "oidc")); code == http.StatusPreconditionRequired {
		t.Fatal("oidc session must short-circuit step-up guard even if mfa_enabled row drifts, got 428")
	}

	// 回归形状:本地 MFA 用户无 mfa_ts 仍须 428(守卫本体不被削弱)
	if code := put(seedToken(true, "local")); code != http.StatusPreconditionRequired {
		t.Fatalf("local mfa user without mfa_ts must stay 428, got %d", code)
	}
}
