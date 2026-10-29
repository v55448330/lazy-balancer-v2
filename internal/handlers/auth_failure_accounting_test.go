package handlers

// 失败记账的可观测性：登录计数与 MFA 挑战计数/归还的写失败不改变认证响应
// （失败仍是失败），但必须留痕——静默吞错会让「账户锁定」「挑战作废」两项
// 防护无声失效。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestLogin_failureAccountingWriteErrorIsLogged(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN);
		INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// 注入写失败：任何对 users 的 UPDATE 都失败（计数与锁定都不落库）。
	if _, err := database.Exec(`CREATE TRIGGER break_user_update BEFORE UPDATE ON users
		BEGIN SELECT RAISE(FAIL, 'write blocked'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	buf := captureLog(t)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"root","password":"WrongPass1!"}`)))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401（记账失败不得改变认证响应）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "登录失败计数写入失败") {
		t.Fatalf("captured log=%q, want 记账失败留痕", buf.String())
	}
}

func TestMFAVerifyLogin_challengeAccountingWriteErrorIsLogged(t *testing.T) {
	secret, _ := seedMFAChallengeLoginFixture(t, "acct-tok", 0)
	if _, err := db.DB.Exec(`UPDATE global_config SET mfa_lockout_enabled=1 WHERE id=1`); err != nil {
		t.Fatalf("enable lockout: %v", err)
	}
	// 只拦「挑战失败计数」（attempts 递增），不影响挑战消费/归还判定。
	if _, err := db.DB.Exec(`CREATE TRIGGER break_challenge_attempts BEFORE UPDATE ON mfa_challenges
		WHEN NEW.attempts IS NOT OLD.attempts BEGIN SELECT RAISE(FAIL, 'attempt write blocked'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	buf := captureLog(t)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	rec := postMFAVerify(t, router, "acct-tok", wrongTOTPCode(t, secret))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "MFA 挑战失败计数写入失败") {
		t.Fatalf("captured log=%q, want 挑战计数失败留痕", buf.String())
	}
}

func TestMFAVerifyLogin_challengeRestoreWriteErrorIsLogged(t *testing.T) {
	secret, _ := seedMFAChallengeLoginFixture(t, "restore-tok", 0)
	// 只拦归还（consumed 1→0），验码失败路径的计数写入保持可用。
	if _, err := db.DB.Exec(`CREATE TRIGGER break_challenge_restore BEFORE UPDATE ON mfa_challenges
		WHEN NEW.consumed = 0 BEGIN SELECT RAISE(FAIL, 'restore write blocked'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	buf := captureLog(t)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	rec := postMFAVerify(t, router, "restore-tok", wrongTOTPCode(t, secret))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "MFA 挑战归还失败") {
		t.Fatalf("captured log=%q, want 挑战归还失败留痕", buf.String())
	}
}

// wrongTOTPCode 生成一个必然与当前时间片有效码不同的 6 位码。
func wrongTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	valid := currentTOTPCode(t, secret)
	if valid != "000000" {
		return "000000"
	}
	return "000001"
}

func TestLogout_revocationWriteFailureWritesAuditAndLog(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_logout_revocation BEFORE INSERT ON revoked_jti
		BEGIN SELECT RAISE(FAIL, 'revocation write blocked'); END`); err != nil {
		t.Fatalf("install revocation failure trigger: %v", err)
	}
	logs := captureLog(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	ctx.Set("auth_type", "jwt")
	ctx.Set("username", "operator")
	ctx.Set("token_revocation_hash", "sha256:logout-failure")
	ctx.Set("token_expires_at", time.Now().Add(time.Hour))

	// When 吊销记录写库失败。
	h.Logout(ctx)

	// Then 500 不变，但失败同时进入运行日志与操作审计。
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(logs.String(), "登出") || !strings.Contains(logs.String(), "失败") {
		t.Fatalf("logout failure log=%q, want revocation failure detail", logs.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='登出' AND resource='用户认证' AND detail LIKE '%失败%'`).Scan(&count); err != nil {
		t.Fatalf("query logout audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("logout failure audit rows=%d, want 1", count)
	}
}
