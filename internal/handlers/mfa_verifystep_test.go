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

// R74（审计 B3 I-5）verify-step 端点级硬失败上限：mfa_lockout_enabled 关（默认）
// 时 verify-step 无任何硬门——每次 401 仅自增 mfa_failed_attempts 而无效果，
// 路由也不在 loginRateLimit 内，被劫持会话可在线爆破 TOTP（10^6 空间 ±1 窗，
// 高速率下小时级可行），成功即得带 mfa_ts 的新 JWT（守卫写放行 60 秒）。
// 硬门与登录 challenge 10 次（B-I-4）/激活 pending 5 次（A-F-2）同族：
// 连续失败 ≥10 → 10 分钟冷却，一律 429「连续失败过多，请 10 分钟后重试」
//（冷却窗内登录 MFA 同样冻结，旧文案「请重新登录后再试」有误导）。

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

// 场景 1（爆破收敛）：连续 10 次错误码各得 401；第 11 次起硬门触发 → 429。
// 修复前：第 11 次仍是 401（无硬门），本断言失败。
func TestMFAVerifyStep_hardCap_429AfterTenFailures(t *testing.T) {
	// Given 启用 MFA 的操作者 + JWT 上下文（mfa_lockout_enabled 默认关）
	h := newBackupTestHandlers(t)
	secret := seedMfaVerifyStepUser(t)
	router := mfaVerifyStepRouter(h, "jwt")
	wrong := wrongMfaCode(t, secret, time.Now())

	// When 连续 10 次错误码
	for i := 1; i <= 10; i++ {
		rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":"%s"}`, wrong))
		// Then 各 401（既有失败语义不变）
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body.String())
		}
	}

	// When 第 11 次——计数已达 10，硬门应触发
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":"%s"}`, wrong))

	// Then 429 + 请 10 分钟后重试（冷却生效，不再验码）
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 11: status=%d body=%s, want 429（端点级硬失败上限应触发）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "连续失败过多，请 10 分钟后重试") {
		t.Fatalf("attempt 11: body=%s, want 包含「连续失败过多，请 10 分钟后重试」", rec.Body.String())
	}

	// Then 冷却期内第 12 次仍 429（不回落到验码路径）
	rec = postMfaVerifyStep(router, fmt.Sprintf(`{"code":"%s"}`, wrong))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 12 (cooldown): status=%d body=%s, want 429（冷却期内应持续拒绝）", rec.Code, rec.Body.String())
	}
}

// 场景 2（恢复路径）：硬门触发后冷却过期（SQL 把 mfa_locked_until 拨到过去），
// 凭有效码 → 200 且失败计数清零——正常用户不被永久锁死。
func TestMFAVerifyStep_hardCap_recoversAfterCooldownWithValidCode(t *testing.T) {
	// Given 硬门已触发（10 次失败 + 第 11 次 429）
	h := newBackupTestHandlers(t)
	secret := seedMfaVerifyStepUser(t)
	router := mfaVerifyStepRouter(h, "jwt")
	wrong := wrongMfaCode(t, secret, time.Now())
	for i := 1; i <= 10; i++ {
		if rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":"%s"}`, wrong)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i, rec.Code)
		}
	}
	if rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":"%s"}`, wrong)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("cap fire: status=%d, want 429", rec.Code)
	}

	// When 冷却过期（拨回过去）+ 有效码（失败不推进 lastStep，当前片码必有效）
	if _, err := db.DB.Exec("UPDATE users SET mfa_locked_until=? WHERE id=1",
		time.Now().Add(-time.Minute).UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("expire cooldown: %v", err)
	}
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatalf("generate valid totp: %v", err)
	}
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":"%s"}`, code))

	// Then 200 + 失败计数清零
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery with valid code: status=%d body=%s, want 200（冷却过期后有效码应放行）", rec.Code, rec.Body.String())
	}
	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_failed_attempts,0) FROM users WHERE id=1").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("mfa_failed_attempts=%d, want 0（成功后计数应清零）", attempts)
	}
}
