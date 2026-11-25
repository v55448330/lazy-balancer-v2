package handlers

// 拆除/重绑 MFA 的守卫免码窗收窄钉测：标记 + 守卫验码年龄 ≤15s 才豁免本层
// 验码；年龄超窗或年龄键缺失一律回落本层验码（空码 401、有效码 200）。
// 通用 60s 宽限窗对其余写操作不变；登录后验码另有 per-user 滑动窗仅限流门
// （60 秒 5 次失败 → 429，成功清零，不锁定）。

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// mfaSelfServiceRouterWithAge 同 mfaSelfServiceRouter，但守卫标记年龄可注入
// （secondsAgo<0 表示只置布尔标记、不置年龄键——模拟旧守卫/缺键注入）。
func mfaSelfServiceRouterWithAge(h *Handlers, secondsAgo int64) *gin.Engine {
	router := gin.New()
	wrap := func(handler gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "operator")
			c.Set("auth_type", "jwt")
			c.Set("mfa_stepup_verified", true)
			if secondsAgo >= 0 {
				c.Set("mfa_stepup_seconds_ago", secondsAgo)
			}
			handler(c)
		}
	}
	router.POST("/auth/mfa/disable", wrap(h.MFADisable))
	router.POST("/auth/mfa/setup", wrap(h.MFASetup))
	return router
}

// 场景 1：标记年龄超窗（20s）时禁用必须回落本层验码——空码 401，有效码 200。
func TestMFADisable_staleGuardMarker_requiresCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	secret := seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouterWithAge(h, 20)

	rec := postMfaSelfService(router, "/auth/mfa/disable", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale marker disable without code: status=%d body=%s, want 401（超窗不免验）", rec.Code, rec.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow("SELECT mfa_enabled FROM users WHERE id=1").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatalf("mfa_enabled=%d, want 1（未验码不得禁用）", enabled)
	}

	code := currentTOTPCode(t, secret)
	rec = postMfaSelfService(router, "/auth/mfa/disable", fmt.Sprintf(`{"code":%q}`, code))
	if rec.Code != http.StatusOK {
		t.Fatalf("stale marker disable with valid code: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

// 场景 2：年龄键缺失（只置布尔标记）不免验——fail-safe 回落本层验码。
func TestMFADisable_markerWithoutAgeKey_requiresCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouterWithAge(h, -1)

	rec := postMfaSelfService(router, "/auth/mfa/disable", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("marker without age key: status=%d body=%s, want 401（年龄不可判定不免验）", rec.Code, rec.Body.String())
	}
}

// 场景 3：窄窗内（5s）标记豁免保持——拆除操作紧跟守卫验码时免本层验码。
func TestMFADisable_freshGuardMarker_skipsCodeCheck(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouterWithAge(h, 5)

	rec := postMfaSelfService(router, "/auth/mfa/disable", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh marker disable: status=%d body=%s, want 200（窄窗内免验）", rec.Code, rec.Body.String())
	}
}

// 场景 4：重绑确认（setup 的 mfaEnabled 分支）同口径——超窗标记空码 401。
func TestMFASetup_rebindStaleGuardMarker_requiresCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouterWithAge(h, 20)

	rec := postMfaSelfService(router, "/auth/mfa/setup", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale marker rebind without code: status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
}

// 场景 5：管理员重置第一层同口径——超窗标记空码 401。
func TestMFAResetByAdmin_staleGuardMarker_requiresCode(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := gin.New()
	router.POST("/users/:id/mfa/reset", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		c.Set("mfa_stepup_verified", true)
		c.Set("mfa_stepup_seconds_ago", int64(20))
		h.MFAResetByAdmin(c)
	})

	rec := postMfaReset(router, `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale marker admin reset without code: status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
}

// 登录后验码仅限流门钉测（verify-step 为代表入口）：60 秒滑动窗内失败 5 次
// 后第 6 次 429；中途验码成功清零计数；429 不触碰 login_* 锁定列。
func TestMFAVerifyStep_rateLimitOnlyNoLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.JWTSecret = "test-secret"
	secret := seedMfaVerifyStepUser(t)
	router := mfaVerifyStepRouter(h, "jwt")

	wrong := wrongMfaCode(t, secret, time.Now())
	for i := 1; i <= 4; i++ {
		if rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, wrong)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body.String())
		}
	}
	// 验码成功清零限流计数——后续失败重新计窗。
	if rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret))); rec.Code != http.StatusOK {
		t.Fatalf("valid code: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	for i := 1; i <= 5; i++ {
		if rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, wrongMfaCode(t, secret, time.Now()))); rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-clear attempt %d: status=%d, want 401（成功已清零计数）", i, rec.Code)
		}
	}
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, wrongMfaCode(t, secret, time.Now())))
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "验证码尝试过于频繁") {
		t.Fatalf("6th failure in window: status=%d body=%s, want 429 限流文案", rec.Code, rec.Body.String())
	}
	// 限流不落 login_* 列（仅限流不锁定）。
	var loginAttempts int
	if err := db.DB.QueryRow("SELECT COALESCE(login_failed_attempts,0) FROM users WHERE id=1").Scan(&loginAttempts); err != nil {
		t.Fatal(err)
	}
	if loginAttempts != 0 {
		t.Fatalf("login_failed_attempts=%d, want 0（登录后验码限流不计数不锁定）", loginAttempts)
	}
}

// 429 限流在验码之前——触发限流后即使持有效码也 429（窗口滑动前不再消耗
// 验码路径）；审计留痕「验码尝试过于频繁」。
func TestMFAVerifyStep_rateLimitPrecedesVerification(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.JWTSecret = "test-secret"
	secret := seedMfaVerifyStepUser(t)
	router := mfaVerifyStepRouter(h, "jwt")

	for i := 1; i <= 5; i++ {
		postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, wrongMfaCode(t, secret, time.Now())))
	}
	rec := postMfaVerifyStep(router, fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("valid code while limited: status=%d body=%s, want 429（限流先于验码）", rec.Code, rec.Body.String())
	}
	var events int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%验码尝试过于频繁%'`).Scan(&events); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if events == 0 {
		t.Fatal("限流拒绝未留审计（429 拒绝是可观测面）")
	}
}

// installMFAAuditTestDB 安装审计库与最小 audit_log 表（MFA 登录步故障分支
// 留痕断言用）。
func installMFAAuditTestDB(t *testing.T) {
	t.Helper()
	old := db.AuditDB
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50), action VARCHAR(50), resource VARCHAR(50),
		detail TEXT, detail_key TEXT, detail_params TEXT, ip_address VARCHAR(50), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	db.AuditDB = auditDB
	t.Cleanup(func() {
		db.AuditDB = old
		_ = auditDB.Close()
	})
}

// 登录后验码的 5/60s 限流门覆盖全部四个入口：重绑确认（MFASetup）与管理员
// 重置（MFAResetByAdmin）的 429 分支与 verify-step/disable 同口径，且不触碰
// login_* 锁定列。
func TestMFASetup_rebindRateLimitedReturns429(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, true)
	router := mfaSelfServiceRouterWithAge(h, -1) // 无窄窗年龄键 → 不免验，落到限流门

	for i := 0; i < mfaRateLimitFailures; i++ {
		services.MFARecordVerifyAttemptFailure(1, time.Now())
	}
	rec := postMfaSelfService(router, "/auth/mfa/setup", `{}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("重绑确认限流: status=%d body=%s, want 429", rec.Code, rec.Body.String())
	}
	var attempts int
	var locked sql.NullString
	if err := db.DB.QueryRow("SELECT COALESCE(login_failed_attempts,0), login_locked_until FROM users WHERE id=1").Scan(&attempts, &locked); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || locked.Valid {
		t.Fatalf("login_failed_attempts=%d locked=%v, want 0/NULL（限流不锁定）", attempts, locked)
	}
}

// mfaRateLimitFailures 与 services.mfaVerifyAttemptLimit 同值（跨包不可见；
// 播种次数需达到上限以触发 429）。
const mfaRateLimitFailures = 5

func TestMFAResetByAdmin_rateLimitedReturns429(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	setMfaWriteGuard(t, false) // 守卫关 → 第一层验码执行 → 限流门生效
	router := mfaResetRouter(h, "jwt")

	for i := 0; i < mfaRateLimitFailures; i++ {
		services.MFARecordVerifyAttemptFailure(1, time.Now())
	}
	rec := postMfaReset(router, `{}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("管理员重置限流: status=%d body=%s, want 429", rec.Code, rec.Body.String())
	}
	var targetMfa int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=2").Scan(&targetMfa); err != nil {
		t.Fatal(err)
	}
	if targetMfa != 1 {
		t.Fatalf("target mfa_enabled=%d, want 1（限流不得重置目标用户）", targetMfa)
	}
}

// 15s 窄窗边界：≤15s 免本层验码、16s 回落验码（严格边界钉测）。
func TestMfaDestructiveStepUpWindow_boundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		secs int64
		want bool
	}{{15, true}, {16, false}} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("mfa_stepup_verified", true)
		c.Set("mfa_stepup_seconds_ago", tc.secs)
		if got := mfaStepUpVerifiedForDestructiveOp(c); got != tc.want {
			t.Fatalf("seconds_ago=%d exempt=%v, want %v", tc.secs, got, tc.want)
		}
	}
}

// MFAVerifyLogin 的基础设施故障分支必须留痕（与 Login 同型 internal_error
// 口径）：挑战查询失败。
func TestMFAVerifyLogin_challengeQueryFailureIsAudited(t *testing.T) {
	setupAuthTestDB(t)
	installMFAAuditTestDB(t)
	if _, err := db.DB.Exec("DROP TABLE mfa_challenges"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"mfa_token":"tok","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='认证拒绝' AND resource='用户认证' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(detail, "挑战查询失败") {
		t.Fatalf("audit detail=%q, want 挑战查询失败留痕", detail)
	}
}

// 锁定开关读取失败分支（global_config 不可读）同样必须留痕。
func TestMFAVerifyLogin_lockSwitchReadFailureIsAudited(t *testing.T) {
	setupAuthTestDB(t)
	installMFAAuditTestDB(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator','x','admin',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO mfa_challenges (token,user_id,expires_at,password_version) VALUES ('tok',1,datetime('now','+5 minutes'),0)"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"mfa_token":"tok","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（锁定开关读失败 fail-closed）", rec.Code, rec.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='认证拒绝' AND resource='用户认证' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(detail, "锁定开关读取失败") {
		t.Fatalf("audit detail=%q, want 锁定开关读取失败留痕", detail)
	}
}

// 认证后的 MFA 写端点遵循「请求体大小」配置项（此前固定 64KiB，配置对
// 这些端点静默失效）。100KB 请求体在 1MB 配置下必须放行到业务层。
func TestMFASetup_usesConfiguredBodyLimit(t *testing.T) {
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, request_body_max_size_mb INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO global_config (id, request_body_max_size_mb) VALUES (1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator','x','admin',1)"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	router := gin.New()
	router.POST("/auth/mfa/setup", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFASetup(c)
	})

	body := `{"pad":"` + strings.Repeat("a", 100<<10) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("100KB 请求体在 1MB 配置下被 413 拒绝（仍使用固定 64KiB 上限）: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（配置上限内的合法请求体）", rec.Code, rec.Body.String())
	}
}
