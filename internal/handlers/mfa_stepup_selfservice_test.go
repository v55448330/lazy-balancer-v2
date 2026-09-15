package handlers

// SYS37-1(第 37 轮审计,P2):MFA 自助写端点(禁用/重绑确认)在 mfa_write_guard
// 开启时的 428 流程结构性必 401——守卫/verify-step 已消费 TOTP 时间片,前端
// 自动重试带同码,handler 无条件再验 → 同片重放拒绝。R73(MFAResetByAdmin)
// 已裁定同形为 bug 并以 mfa_stepup_verified 标记修复,本测试钉住自助两端点
// 的同款标记优先行为(机器身份无标记→本层验码保持)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/db"
)

// mfaSelfServiceRouter 模拟 JWT 用户(user_id=1)经守卫后的自助端点;
// guardMarker=true 时注入 mfa_stepup_verified(生产由 mfaStepUpGuard 放行路径置)。
func mfaSelfServiceRouter(h *Handlers, guardMarker bool) *gin.Engine {
	router := gin.New()
	wrap := func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "operator")
			c.Set("auth_type", "jwt")
			if guardMarker {
				c.Set("mfa_stepup_verified", true)
			}
			handler(c)
		}
	}
	router.POST("/auth/mfa/disable", wrap(h.MFADisable))
	router.POST("/auth/mfa/setup", wrap(h.MFASetup))
	return router
}

func postMfaSelfService(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// 场景 1(SYS37-1 主形):守卫验码放行后(标记在),禁用不带码必须成功——
// 修复前:401 验证码错误(同片互斥)。
func TestMFADisable_guardMarker_skipsCodeCheck(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true) // operator(id=1)启用 MFA
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouter(h, true)

	rec := postMfaSelfService(router, "/auth/mfa/disable", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable with guard marker=(%d,%s), want 200——守卫已验码,本层同片互斥必败", rec.Code, rec.Body.String())
	}
	// 且 MFA 确已禁用
	var enabled int
	if err := db.DB.QueryRow("SELECT mfa_enabled FROM users WHERE id=1").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("mfa_enabled=%d, want 0(禁用应生效)", enabled)
	}
}

// 场景 2(回归):无标记(守卫关/机器身份)时本层验码保持——空码 401。
func TestMFADisable_noMarker_stillRequiresCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, false)
	router := mfaSelfServiceRouter(h, false)

	rec := postMfaSelfService(router, "/auth/mfa/disable", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disable without marker=(%d), want 401(本层验码保持)", rec.Code)
	}
	var enabled int
	if err := db.DB.QueryRow("SELECT mfa_enabled FROM users WHERE id=1").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatalf("mfa_enabled=%d, want 1(未验码不得禁用)", enabled)
	}
}

// 场景 3(SYS37-1 同形同 handler):重绑确认(MFASetup 的 mfaEnabled 分支)
// 在标记路径不验码——返回新密钥候选(200),修复前 401。
func TestMFASetup_rebindGuardMarker_skipsCodeCheck(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouter(h, true)

	rec := postMfaSelfService(router, "/auth/mfa/setup", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup rebind with guard marker=(%d,%s), want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("setup rebind should return new secret candidate, got %s", rec.Body.String())
	}
}

// 场景 4(回归):重绑无标记空码 401(本层验码保持)。
func TestMFASetup_rebindNoMarker_stillRequiresCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, false)
	router := mfaSelfServiceRouter(h, false)

	rec := postMfaSelfService(router, "/auth/mfa/setup", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("setup rebind without marker=(%d), want 401", rec.Code)
	}
}
