package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// step-up 接缝端到端钉：守卫验码置标记 → handler 免码消费的完整链路——
// 全程穿真实路由（jwtAuth → business 组 mfaStepUpGuard → handler），标记由
// 守卫放行路径自置，测试不自行注入 mfa_stepup_verified。
// 链路：旧 JWT（无 mfa_ts）→ verify-step 验码 → 新 JWT（新鲜 mfa_ts）→
// disable 空码体 → 守卫宽限窗置标记放行 → handler 见标记跳过本层验码 → 200。
// 无此接缝时 handler 对空码必 401。
// totpPeriod 是 TOTP 时间片长度（与校验器 services.MFAVerifyTOTPCode 的周期一致）。
const totpPeriod = 30 * time.Second

// totpCodeForStep 生成「at 所在时间片」的 TOTP 码。码只由片起点决定——片内
// 任意时刻（含片尾最后一毫秒）生成的码相同——因此不读第二遍时钟，也不做
// 真实等待。「片尾生成、请求跨片到达」由校验器的 ±1 片容差兜住，无需在片尾
// 睡到下一片；该容差由 TestMFAStepUpSeam_totpCodeSurvivesStepBoundary 以注入
// 时刻钉住，容差被收窄时在那里点名报红，而不是在这里靠睡眠掩盖。
func totpCodeForStep(secret string, at time.Time) (string, error) {
	// 按 30 秒取整；Unix 纪元是 30 秒的整数倍，取整结果与 TOTP 计数器
	// floor(unix/30) 的片起点对齐。
	stepStart := at.Truncate(totpPeriod)
	return totp.GenerateCodeCustom(secret, stepStart, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

func TestMFAStepUpSeam_guardMarkerFlowDisablesWithoutCode(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const jwtSecret = "test-secret" // 与 newMiddlewareTestRouterAtPort 相同

	// Given：启用 MFA 的用户（真实 TOTP 密钥）+ 守卫开启。
	res, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled,password_version) VALUES ('seam-op','x','admin',1,0)")
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := res.LastInsertId()
	secret, _, err := services.MFAGenerateSecret("seam-op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=?", secret, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	issueJWT := func(mfaTs int64) string {
		claims := jwt.MapClaims{
			"user_id": float64(userID), "username": "seam-op", "pwd_ver": float64(0),
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
	do := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	oldToken := issueJWT(0)

	// 对照：无 mfa_ts 直接 disable → 守卫 428（接缝前置条件成立）。
	if rec := do(http.MethodPost, "/api/v1/auth/mfa/disable", `{}`, oldToken); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stale-token disable: status=%d body=%s, want 428", rec.Code, rec.Body.String())
	}

	// When①：verify-step 验码 → 新 JWT 携新鲜 mfa_ts。
	// 码只取决于生成时刻所在的时间片；校验器带 ±1 片容差，「片尾生成、请求跨片
	// 到达」照样通过——无需为避让边界而真实睡眠（边界契约见文末用例）。
	code, err := totpCodeForStep(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := do(http.MethodPost, "/api/v1/auth/mfa/verify-step", fmt.Sprintf(`{"code":%q}`, code), oldToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-step: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil || loginResp.Token == "" {
		t.Fatalf("verify-step response must carry token: err=%v body=%s", err, rec.Body.String())
	}

	// When②：携新 JWT 空码 disable——守卫宽限窗置标记，handler 免码消费。
	// （不经测试注入 mfa_stepup_verified；无标记时本路径恒 401。）
	rec = do(http.MethodPost, "/api/v1/auth/mfa/disable", `{}`, loginResp.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable with fresh step-up JWT and empty code: status=%d body=%s, want 200（守卫标记须贯通 handler）", rec.Code, rec.Body.String())
	}

	// Then：MFA 确已禁用（handler 真实执行，非守卫旁路假象）。
	var enabled int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("mfa_enabled=%d, want 0（disable 未真实执行）", enabled)
	}
}

// 时间片边界契约：verify-step 用的校验器（services.MFAVerifyTOTPCode）带 ±1 片
// 容差——片尾生成的码，请求落到下一片仍须通过。上面的端到端用例据此不再为
// 避让边界而真实睡眠；容差一旦被收窄，这里立即红并点名，而不是让端到端用例
// 在「恰好在片尾生成」的偶发时刻假红。到达时刻全部注入，零墙钟等待。
func TestMFAStepUpSeam_totpCodeSurvivesStepBoundary(t *testing.T) {
	newMiddlewareTestRouter(t)
	res, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled,password_version) VALUES ('seam-boundary','x','admin',1,0)")
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := res.LastInsertId()
	secret, _, err := services.MFAGenerateSecret("seam-boundary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=?`, secret, userID); err != nil {
		t.Fatal(err)
	}
	// 每个断言独立持有干净的重放状态：校验成功会推进 mfa_last_timestep，
	// 同一片的码第二次提交将被重放防护拒绝——那不是本用例要测的东西。
	resetReplay := func() {
		t.Helper()
		if _, err := db.DB.Exec(`UPDATE users SET mfa_last_timestep=0 WHERE id=?`, userID); err != nil {
			t.Fatal(err)
		}
	}
	// 固定时间轴：片起点按 30 秒对齐。
	stepStart := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	endOfStep := stepStart.Add(totpPeriod - 10*time.Millisecond)

	for _, tc := range []struct {
		name     string
		arriveAt time.Time
	}{
		{name: "同片到达", arriveAt: endOfStep.Add(5 * time.Millisecond)},
		{name: "跨片到达", arriveAt: stepStart.Add(totpPeriod + 500*time.Millisecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetReplay()
			code, err := totpCodeForStep(secret, endOfStep)
			if err != nil {
				t.Fatal(err)
			}
			if ok, verr := services.MFAVerifyTOTPCode(int(userID), code, tc.arriveAt); !ok || verr != nil {
				t.Fatalf("片尾生成的码在片起点 +%v 到达被拒: ok=%v err=%v（±1 片容差被收窄？）", tc.arriveAt.Sub(stepStart), ok, verr)
			}
		})
	}

	// 反向对照：容差是 ±1 片而非无界——落后两片到达的码必须拒绝（排除
	// 「任何码都通过」的假绿）。重放状态已复位，拒绝只能来自容差窗本身。
	resetReplay()
	stale, err := totpCodeForStep(secret, stepStart)
	if err != nil {
		t.Fatal(err)
	}
	if ok, verr := services.MFAVerifyTOTPCode(int(userID), stale, stepStart.Add(3*totpPeriod-10*time.Millisecond)); ok || verr != nil {
		t.Fatalf("落后两片到达的码不得通过: ok=%v err=%v", ok, verr)
	}
}
