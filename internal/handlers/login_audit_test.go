package handlers

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

func setupLoginAuditDB(t *testing.T) {
	t.Helper()
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE IF NOT EXISTS global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled INTEGER); INSERT OR REPLACE INTO global_config (id, mfa_lockout_enabled) VALUES (1, 1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	oldAudit := db.AuditDB
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	t.Cleanup(func() { db.AuditDB = oldAudit })
}

// 登录成功审计详情含完整用户标识「用户 N（username）」,非裸数字 ID(2026-09-11 裁定)。
func TestLogin_successAuditDetailContainsUsername(t *testing.T) {
	setupLoginAuditDB(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	createdAt := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,created_at) VALUES ('zhang',?,'admin',1,?)`, string(hash), createdAt); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"zhang","password":"secret123"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='登录成功' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(detail, "（zhang）") {
		t.Errorf("login success detail=%q, want contains username marker （zhang）", detail)
	}
}

// 登录失败(账户锁定)审计详情同样含完整用户标识。
func TestLogin_lockedAuditDetailContainsUsername(t *testing.T) {
	setupLoginAuditDB(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	createdAt := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,created_at) VALUES ('zhang',?,'admin',1,?)`, string(hash), createdAt); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE users SET login_locked_until=datetime('now','+10 minutes') WHERE username='zhang'`); err != nil {
		t.Fatalf("lock: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"zhang","password":"wrong"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE detail LIKE '%已锁定%' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(detail, "（zhang）") {
		t.Errorf("locked detail=%q, want contains username marker （zhang）", detail)
	}
}
