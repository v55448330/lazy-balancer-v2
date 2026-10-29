package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// 现行语义（2026-09 用户二次裁定，66b35ce0 移除端点硬门后）：登录后的
// MFA 验证失败（verify-step 及全部登录后验码入口）只提示 401、不计数不锁定
// ——全系统唯一锁定在登录阶段（密码+验证码同计 5 次/10 分钟，受「登录失败
// 锁定」开关控制）。仍生效的硬闸仅剩登录阶段两处：单挑战连续失败 10 次作废
// 挑战、pending 绑定连续失败 5 次作废待激活密钥。

// seedMfaVerifyStepUser 种 id=1 且已启用 MFA 的操作者，返回其 TOTP secret。
func seedMfaVerifyStepUser(t *testing.T) string {
	t.Helper()
	// 登录后验码限流为进程内内存态——播种即清，防跨用例残留误中 429。
	services.MFAResetVerifyAttemptsForTest()
	t.Cleanup(services.MFAResetVerifyAttemptsForTest)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator','x','admin',1)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	secret, _, err := services.MFAGenerateSecret("operator")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=1", secret); err != nil {
		t.Fatalf("enable mfa: %v", err)
	}
	return secret
}

// mfaVerifyStepRouter 模拟 JWT 中间件上下文（auth_type 可注入——硬门对机器身份同样生效）。
func mfaVerifyStepRouter(h *Handlers, authType string) *gin.Engine {
	router := gin.New()
	router.POST("/auth/mfa/verify-step", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", authType)
		h.MFAVerifyStep(c)
	})
	return router
}

func postMfaVerifyStep(router *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify-step", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// wrongMfaCode 取一个在当前 ±1 窗内确定无效的 6 位码（排除真实码，确定性）。
func wrongMfaCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	valid := map[string]bool{}
	for _, drift := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		code, err := totp.GenerateCodeCustom(secret, now.Add(drift), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			t.Fatalf("generate totp: %v", err)
		}
		valid[code] = true
	}
	for _, candidate := range []string{"000000", "000001", "000002", "000003"} {
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatal("无法构造确定无效的验证码")
	return ""
}

// 用户裁决：除登录与重置 MFA 外，全部 MFA 入口（含 verify-step）仅接受
// 6 位动态验证码——恢复码属一次性应急登录凭证，不得作为操作授权凭证（导入
// 配置等写守卫链经此端点）。RED：当前实现接受恢复码，本测试断言拒绝。
func TestMFAVerifyStep_rejectsRecoveryCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	_ = seedMfaVerifyStepUser(t)
	codes, err := services.MFARegenerateRecoveryCodes(1)
	if err != nil || len(codes) == 0 {
		t.Fatalf("seed recovery codes: %v n=%d", err, len(codes))
	}
	router := mfaVerifyStepRouter(h, "jwt")

	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, codes[0]))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("verify-step with recovery code: status=%d body=%s, want 401（仅接受动态验证码）", rec.Code, rec.Body.String())
	}

	// 拒绝不得消费恢复码：随后经 MFAVerifyCode（登录口径）仍应成功。
	ok, verr := services.MFAVerifyCode(1, codes[0], time.Now())
	if !ok {
		t.Fatalf("recovery code must remain consumable via login path after TOTP-only rejection: ok=%v err=%v", ok, verr)
	}
}

// step-up 验码通过后的用户重读，DB 错误此前与
// 「用户不存在/禁用」同报 401 用户不可用——DB 故障被降级成认证拒绝。
// 拆分：读失败 500；行缺失/禁用保持 401。
func TestMFAVerifyStep_userReloadFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	secret := seedMfaVerifyStepUser(t)
	if _, err := db.DB.Exec("ALTER TABLE users RENAME COLUMN password_version TO password_version_unreadable"); err != nil {
		t.Fatalf("break password_version column: %v", err)
	}
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	router := mfaVerifyStepRouter(h, "jwt")
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（DB 故障不得报 401 用户不可用）", rec.Code, rec.Body.String())
	}
}

// ErrMFANotEnabled 业务态分支（并发禁用/重置后验码）必须留痕「MFA 未启用」——
// 与登录步（MFAVerifyLogin）同口径；此前该分支零审计，安全可观测面缺失。
func TestMFAVerifyStep_notEnabledWritesAudit(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator','x','admin',1)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := mfaVerifyStepRouter(h, "jwt")

	rec := postMfaVerifyStep(router, `{"code":"123456"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（MFA 未启用业务态）", rec.Code, rec.Body.String())
	}
	var events int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%MFA 未启用%'`).Scan(&events); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if events != 1 {
		t.Fatalf("not-enabled rejection audit events=%d, want 1（与登录步同口径留痕）", events)
	}
}

// verify-step 重读用户必须带 auth_provider（此前 SELECT 漏列 →
// 所有 step-up 响应 auth_provider=""，存量 OIDC 行丢 auth_method 声明）。
func TestMFAVerifyStep_preservesAuthProvider(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.JWTSecret = "test-secret"
	secret := seedMfaVerifyStepUser(t)
	if _, err := db.DB.Exec("UPDATE users SET auth_provider='oidc' WHERE id=1"); err != nil {
		t.Fatalf("set auth provider: %v", err)
	}
	router := mfaVerifyStepRouter(h, "jwt")
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload models.LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if payload.User.AuthProvider != "oidc" {
		t.Fatalf("auth_provider=%q, want oidc（verify-step 重读用户漏列）", payload.User.AuthProvider)
	}
	if !strings.Contains(payload.Token, ".") {
		t.Fatalf("token=%q 不是 JWT", payload.Token)
	}
}

func TestMFAVerifyStep_preservesCurrentSessionAuthMethod(t *testing.T) {
	for _, tc := range []struct {
		name          string
		currentMethod string
		wantMethod    any
	}{
		{name: "local password session on imported mixed row", currentMethod: "", wantMethod: nil},
		{name: "legitimate OIDC session", currentMethod: "oidc", wantMethod: "oidc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			h.cfg.JWTSecret = "test-secret"
			secret := seedMfaVerifyStepUser(t)
			if _, err := db.DB.Exec("UPDATE users SET auth_provider='oidc' WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.POST("/auth/mfa/verify-step", func(c *gin.Context) {
				c.Set("user_id", 1)
				c.Set("username", "operator")
				c.Set("auth_type", "jwt")
				if tc.currentMethod != "" {
					c.Set("auth_method", tc.currentMethod)
				}
				h.MFAVerifyStep(c)
			})
			recorder := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
			}
			var payload models.LoginResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			parsed, err := jwt.Parse(payload.Token, func(token *jwt.Token) (any, error) { return []byte("test-secret"), nil })
			if err != nil || !parsed.Valid {
				t.Fatalf("parse step-up token: %v", err)
			}
			claims := parsed.Claims.(jwt.MapClaims)
			if got := claims["auth_method"]; got != tc.wantMethod {
				t.Fatalf("auth_method=%v, want %v (current session method %q)", got, tc.wantMethod, tc.currentMethod)
			}
		})
	}
}
