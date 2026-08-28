package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// B5 I-A：MFADisable 与 MFASetup 重新绑定路径是仅剩的两个无端点级失败上限、
// 无失败审计的 MFAVerifyCode 消费点（默认 mfa_lockout_enabled=0 时
// mfaRecordFailure 只计数不锁定，被劫持会话可在线爆破 TOTP 后一键拆/换
// 第二因子）。修复：复用 R74 verify-step 硬门机制（users.mfa_failed_attempts
// 共享计数 + 10 次/10 分钟冷却 429），并对 disable 的 401 路径补「认证拒绝」
// 审计（对齐 MFAResetByAdmin）。

const gateTestPassword = "Gate-Passw0rd!"

// seedMfaGateUser 种 id=1 已启用 MFA + 真实 bcrypt 密码的操作者，返回 TOTP secret。
func seedMfaGateUser(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator',?,'admin',1)", string(hash)); err != nil {
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

// mfaSetupTestRouter / mfaDisableTestRouter 模拟 JWT 中间件上下文。
func mfaSetupTestRouter(h *Handlers) *gin.Engine {
	router := gin.New()
	router.POST("/auth/mfa/setup", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFASetup(c)
	})
	return router
}

func mfaDisableTestRouter(h *Handlers) *gin.Engine {
	router := gin.New()
	router.POST("/auth/mfa/disable", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFADisable(c)
	})
	return router
}

// 场景 1（disable 爆破收敛）：连续 10 次错误码各得 401；第 11 次起硬门触发 → 429
// 「连续失败过多，请 10 分钟后重试」，冷却期内持续 429。修复前：第 11 次仍 401（无门）。
func TestMFADisable_hardCap_429AfterTenFailures(t *testing.T) {
	// Given 启用 MFA + 已知密码的操作者（mfa_lockout_enabled 默认关）
	h := newBackupTestHandlers(t)
	secret := seedMfaGateUser(t, gateTestPassword)
	router := mfaDisableTestRouter(h)
	wrong := wrongMfaCode(t, secret, time.Now())

	// When 连续 10 次错误码（密码正确，仅码错）
	for i := 1; i <= 10; i++ {
		rec := postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))
		// Then 各 401（既有失败语义不变）
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body.String())
		}
	}

	// When 第 11 次——计数已达 10，硬门应触发
	rec := postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))

	// Then 429 + 请 10 分钟后重试（冷却生效，不再验码）
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 11: status=%d body=%s, want 429（端点级硬失败上限应触发）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "连续失败过多，请 10 分钟后重试") {
		t.Fatalf("attempt 11: body=%s, want 包含「连续失败过多，请 10 分钟后重试」", rec.Body.String())
	}

	// Then 冷却期内第 12 次仍 429（不回落到验码路径）
	rec = postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 12 (cooldown): status=%d body=%s, want 429（冷却期内应持续拒绝）", rec.Code, rec.Body.String())
	}
}

// 场景 2（setup 重新绑定爆破收敛）：同一硬门作用于重新绑定确认段。
// 修复前：第 11 次仍 401（无门）。
func TestMFASetup_reenableHardCap_429AfterTenFailures(t *testing.T) {
	// Given 启用 MFA + 已知密码的操作者
	h := newBackupTestHandlers(t)
	secret := seedMfaGateUser(t, gateTestPassword)
	router := mfaSetupTestRouter(h)
	wrong := wrongMfaCode(t, secret, time.Now())

	// When 连续 10 次错误码
	for i := 1; i <= 10; i++ {
		rec := postRaw(router, "/auth/mfa/setup", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))
		// Then 各 401
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body.String())
		}
	}

	// When 第 11 次
	rec := postRaw(router, "/auth/mfa/setup", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))

	// Then 429 + 请 10 分钟后重试
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 11: status=%d body=%s, want 429（端点级硬失败上限应触发）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "连续失败过多，请 10 分钟后重试") {
		t.Fatalf("attempt 11: body=%s, want 包含「连续失败过多，请 10 分钟后重试」", rec.Body.String())
	}

	// Then 冷却期内第 12 次仍 429
	rec = postRaw(router, "/auth/mfa/setup", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 12 (cooldown): status=%d body=%s, want 429（冷却期内应持续拒绝）", rec.Code, rec.Body.String())
	}
}

// 场景 3（恢复路径）：硬门触发后冷却过期（SQL 把 mfa_locked_until 拨到过去），
// 凭有效码 + 密码 → 200 且失败计数清零——正常用户不被永久锁死。
func TestMFADisable_hardCap_recoversAfterCooldownWithValidCode(t *testing.T) {
	// Given 硬门已触发（10 次失败 + 第 11 次 429）
	h := newBackupTestHandlers(t)
	secret := seedMfaGateUser(t, gateTestPassword)
	router := mfaDisableTestRouter(h)
	wrong := wrongMfaCode(t, secret, time.Now())
	for i := 1; i <= 10; i++ {
		if rec := postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i, rec.Code)
		}
	}
	if rec := postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("cap fire: status=%d, want 429", rec.Code)
	}

	// When 冷却过期（拨回过去）+ 有效码（失败不推进 lastStep，当前片码必有效）
	if _, err := db.DB.Exec("UPDATE users SET mfa_locked_until=? WHERE id=1",
		time.Now().Add(-time.Minute).UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("expire cooldown: %v", err)
	}
	rec := postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, mfaResetCurrentCode(t, secret, time.Now())))

	// Then 200（MFA 已禁用）+ 失败计数清零
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

// 场景 4（失败审计）：disable 验码 401 路径写「认证拒绝」审计行（含操作者身份），
// 对齐 MFAResetByAdmin 前置验码失败的留痕语义。修复前：无审计行。
func TestMFADisable_verifyFailure_writesAuditRow(t *testing.T) {
	// Given 启用 MFA + 已知密码的操作者
	h := newBackupTestHandlers(t)
	secret := seedMfaGateUser(t, gateTestPassword)
	router := mfaDisableTestRouter(h)
	wrong := wrongMfaCode(t, secret, time.Now())

	// When 一次错误码（密码正确）
	rec := postRaw(router, "/auth/mfa/disable", fmt.Sprintf(`{"password":%q,"code":%q}`, gateTestPassword, wrong))

	// Then 401 + 审计行存在（username=operator, action=认证拒绝, detail 含禁用 MFA 前验证失败）
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	var cnt int
	if err := db.AuditDB.QueryRow(
		"SELECT COUNT(*) FROM audit_log WHERE username='operator' AND action='认证拒绝' AND detail LIKE '%禁用 MFA 前验证失败%'").Scan(&cnt); err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if cnt < 1 {
		t.Fatalf("audit rows=%d, want >=1（disable 验码失败应写「认证拒绝」审计）", cnt)
	}
}
