package handlers

// MFA 自助写端点（setup/activate/disable/recovery-codes/verify-step）仅接受
// JWT 会话身份：可写 API Key 是机器身份，不得经「JWT 会话即确认」的自助通道
// 免验码首绑 MFA、重生成恢复码或换发会话 JWT（管理员登录 DoS + 第二因子获取）。
// 与「管理员重置对 API Key 仍验码」的口径对齐——机器身份没有会话确认语义。
// 拒绝必须留审计（认证拒绝/用户认证），且不得产生任何 MFA 状态变更。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// mfaMachineIdentityRouter 模拟可写 API Key（admin 属主）经认证链后的自助
// 端点上下文：auth_type=api_key，其余键与 jwtAuth/apiKeyAuth 注入同形。
func mfaMachineIdentityRouter(h *Handlers) *gin.Engine {
	router := gin.New()
	for _, r := range []struct {
		path    string
		handler gin.HandlerFunc
	}{
		{"/auth/mfa/setup", h.MFASetup},
		{"/auth/mfa/activate", h.MFAActivate},
		{"/auth/mfa/disable", h.MFADisable},
		{"/auth/mfa/recovery-codes", h.MFARecoveryCodes},
		{"/auth/mfa/verify-step", h.MFAVerifyStep},
	} {
		path, handler := r.path, r.handler
		router.POST(path, func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "operator")
			c.Set("role", "admin")
			c.Set("auth_type", "api_key")
			c.Set("api_key_id", 7)
			c.Set("api_key_name", "automation-key")
			handler(c)
		})
	}
	return router
}

func postMfaMachineIdentity(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// 五个自助端点对可写 Key 身份一律 403 + 审计留痕，且零状态变更。
// 修复前：setup 对未启用 MFA 的属主 200 下发 secret（首绑无验码门）、
// recovery-codes 200 下发新恢复码、verify-step 凭有效码换发 JWT——
// 机器身份拿到了「会话即确认」通道的人类第二因子能力。
func TestMFASelfServiceEndpoints_rejectWritableAPIKeyIdentity(t *testing.T) {
	cases := []struct {
		name string
		path string
		// enabled=true 种已启用 MFA 的属主（disable/recovery-codes/verify-step
		// 需要启用态才能走到状态变更）；false 种未启用属主（setup 首绑形态）。
		enabled bool
		body    func(secret string) string
	}{
		{
			name: "setup 首绑不得下发密钥", path: "/auth/mfa/setup", enabled: false,
			body: func(string) string { return `{}` },
		},
		{
			name: "setup 重绑不得轮换 pending", path: "/auth/mfa/setup", enabled: true,
			body: func(string) string { return `{}` },
		},
		{
			name: "activate 不得启用", path: "/auth/mfa/activate", enabled: false,
			body: func(string) string { return `{"code":"123456"}` },
		},
		{
			name: "disable 不得禁用", path: "/auth/mfa/disable", enabled: true,
			body: func(secret string) string { return fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)) },
		},
		{
			name: "recovery-codes 不得重生成", path: "/auth/mfa/recovery-codes", enabled: true,
			body: func(string) string { return `{}` },
		},
		{
			name: "verify-step 不得换发 JWT", path: "/auth/mfa/verify-step", enabled: true,
			body: func(secret string) string { return fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given：admin 属主 + 可写 Key 身份上下文
			h := newBackupTestHandlers(t)
			var secret string
			if tc.enabled {
				secret = seedMfaGateUser(t)
			} else {
				seedMfaSetupUser(t)
			}
			var beforeEnabled int
			var beforeSecret, beforePending, beforeCodes string
			if err := db.DB.QueryRow(`SELECT COALESCE(mfa_enabled,0), COALESCE(mfa_secret,''), COALESCE(mfa_pending_secret,''), COALESCE(mfa_recovery_codes,'') FROM users WHERE id=1`).
				Scan(&beforeEnabled, &beforeSecret, &beforePending, &beforeCodes); err != nil {
				t.Fatalf("read before state: %v", err)
			}
			router := mfaMachineIdentityRouter(h)

			// When
			rec := postMfaMachineIdentity(router, tc.path, tc.body(secret))

			// Then：403 + 认证拒绝审计（含 Key 归因），零状态变更
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s, want 403（机器身份不得走自助 MFA 通道）", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "recovery_codes") || strings.Contains(rec.Body.String(), "otpauth") {
				t.Fatalf("拒绝响应泄露第二因子材料: %s", rec.Body.String())
			}
			if got := countAuditRows(t, "认证拒绝", "用户认证"); got != 1 {
				t.Fatalf("认证拒绝审计=%d 条, want 1（机器身份拒绝必须留痕）", got)
			}
			if detail := latestAuditDetail(t, "认证拒绝", "用户认证"); !strings.Contains(detail, "API密钥 7（automation-key）") {
				t.Fatalf("审计 detail=%q, want 含 Key 归因（API密钥 7）", detail)
			}
			var afterEnabled int
			var afterSecret, afterPending, afterCodes string
			if err := db.DB.QueryRow(`SELECT COALESCE(mfa_enabled,0), COALESCE(mfa_secret,''), COALESCE(mfa_pending_secret,''), COALESCE(mfa_recovery_codes,'') FROM users WHERE id=1`).
				Scan(&afterEnabled, &afterSecret, &afterPending, &afterCodes); err != nil {
				t.Fatalf("read after state: %v", err)
			}
			if afterEnabled != beforeEnabled || afterSecret != beforeSecret || afterPending != beforePending || afterCodes != beforeCodes {
				t.Fatalf("机器身份请求改变了 MFA 状态: enabled %d→%d secret变=%v pending变=%v codes变=%v",
					beforeEnabled, afterEnabled, afterSecret != beforeSecret, afterPending != beforePending, afterCodes != beforeCodes)
			}
		})
	}
}

// JWT 会话回归：同一组端点对 auth_type=jwt 的既有行为不变（首绑 setup 200
// 下发 secret；已启用用户的 recovery-codes 200 重生成）。门只拦机器身份。
func TestMFASelfServiceEndpoints_jwtSessionStillAllowed(t *testing.T) {
	t.Run("首绑 setup", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedMfaSetupUser(t)
		router := gin.New()
		router.POST("/auth/mfa/setup", func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "operator")
			c.Set("auth_type", "jwt")
			h.MFASetup(c)
		})
		rec := postMfaMachineIdentity(router, "/auth/mfa/setup", `{}`)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "otpauth") {
			t.Fatalf("JWT 首绑 setup status=%d body=%s, want 200+secret", rec.Code, rec.Body.String())
		}
	})
	t.Run("恢复码重生成", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedMfaGateUser(t)
		router := gin.New()
		router.POST("/auth/mfa/recovery-codes", func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "operator")
			c.Set("auth_type", "jwt")
			h.MFARecoveryCodes(c)
		})
		rec := postMfaMachineIdentity(router, "/auth/mfa/recovery-codes", `{}`)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "recovery_codes") {
			t.Fatalf("JWT recovery-codes status=%d body=%s, want 200+恢复码", rec.Code, rec.Body.String())
		}
	})
}
