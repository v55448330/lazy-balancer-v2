package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// 现行语义（2026-09 用户二次裁定，66b35ce0 移除 R74 端点硬门后）：登录后的
// MFA 验证失败（verify-step 及全部登录后验码入口）只提示 401、不计数不锁定
// ——全系统唯一锁定在登录阶段（密码+验证码同计 5 次/10 分钟，受「登录失败
// 锁定」开关控制）。仍生效的硬闸仅剩登录阶段两处：单挑战连续失败 10 次作废
// 挑战（B-I-4）、pending 绑定连续失败 5 次作废待激活密钥（A-F-2）。

// seedMfaVerifyStepUser 种 id=1 且已启用 MFA 的操作者，返回其 TOTP secret。
func seedMfaVerifyStepUser(t *testing.T) string {
	t.Helper()
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

// N+10 用户裁决：除登录与重置 MFA 外，全部 MFA 入口（含 verify-step）仅接受
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
