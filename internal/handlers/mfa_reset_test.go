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

// R73：管理员重置 MFA 的双层验证死锁——重置端点自带验码（handlers/mfa.go 第一层）
// 与 mfaStepUpGuard（第二层）在同一 TOTP 时间片内互斥：守卫验码（verify-step）消费
// 时间片后，第一层重放保护必然拒绝同片码 → 401 → 踢出登录 → 连续失败触发 10 分钟
// 锁定。用户裁决语义：守卫开 → 直接使用守卫验码（第一层豁免，含登录 60 秒内场景）；
// 守卫关 → 第一层正常验码（重放保护照旧）。

func mfaResetCurrentCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	return code
}

// seedMfaResetUsers 种操作者（id=1，可带 MFA）与目标用户（id=2，启用 MFA 待重置）。
func seedMfaResetUsers(t *testing.T, operatorMfa bool) (operatorSecret string) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator','x','admin',1),(2,'target','x','viewer',1)"); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if operatorMfa {
		secret, _, err := services.MFAGenerateSecret("operator")
		if err != nil {
			t.Fatalf("generate secret: %v", err)
		}
		if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=1", secret); err != nil {
			t.Fatalf("enable operator mfa: %v", err)
		}
		operatorSecret = secret
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret='TARGETSECRET' WHERE id=2"); err != nil {
		t.Fatalf("enable target mfa: %v", err)
	}
	return operatorSecret
}

// authType 模拟中间件设置的认证类型（R73 补正：第一层豁免只对被 mfaStepUpGuard
// 真正验过码的 jwt 路径生效；api_key/MCP 机器身份由场景 5 覆盖）。
func mfaResetRouter(h *Handlers, authType string) *gin.Engine {
	router := gin.New()
	router.POST("/users/:id/mfa/reset", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", authType)
		h.MFAResetByAdmin(c)
	})
	return router
}

func setMfaWriteGuard(t *testing.T, on bool) {
	t.Helper()
	v := 0
	if on {
		v = 1
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=? WHERE id=1", v); err != nil {
		t.Fatalf("set mfa_write_guard: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })
}

func postMfaReset(router *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/users/2/mfa/reset", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// 场景 1（用户报的 bug）：守卫开启时，第一层必须豁免——守卫已用 verify-step/登录
// 消费的时间片完成验码，再要求一次同片码在重放保护下结构性必败。
func TestMFAResetByAdmin_guardOn_skipsOperatorCodeCheck(t *testing.T) {
	// Given 守卫开 + 操作者启用 MFA + 目标用户启用 MFA；请求体不带 code
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaResetRouter(h, "jwt")

	// When
	rec := postMfaReset(router, `{}`)

	// Then 第一层豁免 → 200 且目标 MFA 被清除（修复前：401 验证码错误）
	if rec.Code != http.StatusOK {
		t.Fatalf("guard on: status=%d body=%s, want 200（守卫验码已足够，第一层应豁免）", rec.Code, rec.Body.String())
	}
	var targetMfa int
	if err := db.DB.QueryRow("SELECT mfa_enabled FROM users WHERE id=2").Scan(&targetMfa); err != nil {
		t.Fatal(err)
	}
	if targetMfa != 0 {
		t.Fatalf("target mfa_enabled=%d, want 0（重置应生效）", targetMfa)
	}
}

// 场景 2：守卫关闭时第一层照常验码——无码 401、有效码 200。
func TestMFAResetByAdmin_guardOff_requiresOperatorCode(t *testing.T) {
	// Given 守卫关 + 操作者启用 MFA
	h := newBackupTestHandlers(t)
	secret := seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, false)
	router := mfaResetRouter(h, "jwt")

	// When 无码
	rec := postMfaReset(router, `{}`)
	// Then 401
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("guard off without code: status=%d, want 401", rec.Code)
	}

	// When 有效码
	rec = postMfaReset(router, fmt.Sprintf(`{"code":"%s"}`, mfaResetCurrentCode(t, secret, time.Now())))
	// Then 200
	if rec.Code != http.StatusOK {
		t.Fatalf("guard off with valid code: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

// 场景 3：守卫关闭时重放保护照旧——同一时间片码第二次使用必须 401。
func TestMFAResetByAdmin_guardOff_replayStillRejected(t *testing.T) {
	// Given 守卫关 + 操作者启用 MFA
	h := newBackupTestHandlers(t)
	secret := seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, false)
	router := mfaResetRouter(h, "jwt")
	code := mfaResetCurrentCode(t, secret, time.Now())

	// When 第一次用码（成功）后立刻重用同片码
	if rec := postMfaReset(router, fmt.Sprintf(`{"code":"%s"}`, code)); rec.Code != http.StatusOK {
		t.Fatalf("first use: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	rec := postMfaReset(router, fmt.Sprintf(`{"code":"%s"}`, code))

	// Then 重放拒绝
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay same timestep: status=%d, want 401（重放保护不因修复而松动）", rec.Code)
	}
}

// 场景 4：操作者未启用 MFA 时无需验码（既有行为不变）。
func TestMFAResetByAdmin_operatorWithoutMfa_noCodeRequired(t *testing.T) {
	// Given 操作者无 MFA（守卫开——即使守卫开启，无 MFA 用户本就不在守卫适用范围）
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, false)
	setMfaWriteGuard(t, true)
	router := mfaResetRouter(h, "jwt")

	// When
	rec := postMfaReset(router, `{}`)

	// Then
	if rec.Code != http.StatusOK {
		t.Fatalf("operator without mfa: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

// 场景 5（审计 IMPORTANT-3，用户裁决）：mfaStepUpGuard 按设计豁免
// auth_type != "jwt" 的机器身份（API Key/MCP）——守卫对这类请求从不验码，
// 故「守卫已验码」的豁免理由不成立，第一层必须照常要求操作者 TOTP 码；
// R72 二次防劫持语义对机器身份同样保持。豁免仅适用于守卫真正验过码的
// JWT 路径（场景 1/4）。
func TestMFAResetByAdmin_guardOn_apiKeyStillRequiresCode(t *testing.T) {
	// Given 守卫开 + 操作者启用 MFA + 请求为 api_key 机器身份
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaResetRouter(h, "api_key")

	// When 无码
	rec := postMfaReset(router, `{}`)

	// Then 第一层不豁免 → 401（修复前：守卫开的豁免误及机器身份 → 200 免码重置）
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("guard on + api_key without code: status=%d body=%s, want 401（守卫不验机器身份的码，第一层不得豁免）", rec.Code, rec.Body.String())
	}
}
