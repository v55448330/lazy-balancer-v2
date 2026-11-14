package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 签发失败（随机源异常/密钥未装配）不得推进 last_login：账号活动证据必须
// 与审计口径一致，不能出现「最后登录时间已更新 + 审计记登录失败」。
func TestLogin_signingFailureDoesNotAdvanceLastLogin(t *testing.T) {
	withIsolatedGlobal(t)
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,mfa_enabled) VALUES ('root',?,'admin',1,0)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	oldReader := jwtJTIReader
	jwtJTIReader = func([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }
	t.Cleanup(func() { jwtJTIReader = oldReader })

	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", h.Login)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var lastLogin any
	if err := database.QueryRow(`SELECT last_login FROM users WHERE username='root'`).Scan(&lastLogin); err != nil {
		t.Fatalf("read last_login: %v", err)
	}
	if lastLogin != nil {
		t.Fatalf("签发失败后 last_login=%v, want NULL（失败分支不得推进最后登录时间）", lastLogin)
	}
}

// MFA 挑战签发失败（基础设施故障）必须留痕：否则「密码正确却拿不到挑战」
// 在登录审计里完全不可见。
func TestLogin_mfaChallengeIssueFailureIsAudited(t *testing.T) {
	database := setupAuthTestDB(t)
	installMFAAuditTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,mfa_enabled) VALUES ('root',?,'admin',1,1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := database.Exec(`DROP TABLE mfa_challenges`); err != nil {
		t.Fatalf("drop mfa_challenges: %v", err)
	}

	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", h.Login)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var action, resource, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, resource, detail FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action, &resource, &detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if action != "登录失败" || resource != "用户认证" {
		t.Fatalf("audit action=%q resource=%q, want 登录失败/用户认证", action, resource)
	}
	if !strings.Contains(detail, services.AuditResultPart("internal_error")) {
		t.Fatalf("audit detail=%q, want 含 %q", detail, services.AuditResultPart("internal_error"))
	}
}
