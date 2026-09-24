package handlers

// 第 49 轮 F49-P5-19③：登录锁定的 429 文案必须按 login_locked_until 派生剩余
// 分钟——修复前硬编码「请 10 分钟后重试」：与 loginLockCooldown 漂移，且锁定
// 中途重试时剩余时长早已不足 10 分钟。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
)

func TestLogin_lockedMessageReflectsRemainingMinutes(t *testing.T) {
	// Given：开启「登录失败锁定」+ 锁定中的账户（剩余约 3.5 分钟）
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled INTEGER);
		INSERT INTO global_config VALUES (1, 1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	lockedUntil := time.Now().UTC().Add(3*time.Minute + 30*time.Second).Format("2006-01-02 15:04:05")
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,login_locked_until) VALUES ('locked',?,'admin',1,?)`, string(hash), lockedUntil); err != nil {
		t.Fatalf("seed locked user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", h.Login)

	// When
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"locked","password":"whatever"}`)))

	// Then：429 且文案为剩余分钟（3.5min 向上取整=4），非硬编码 10
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s, want 429", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "请 4 分钟后重试") {
		t.Fatalf("body=%s, want 「请 4 分钟后重试」（按 login_locked_until 派生）", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "10 分钟") {
		t.Fatalf("body=%s, 不得为硬编码「10 分钟」", recorder.Body.String())
	}
}
