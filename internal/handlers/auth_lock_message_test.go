package handlers

// 登录锁定的 429 文案必须按 login_locked_until 派生剩余
// 分钟——修复前硬编码「请 10 分钟后重试」：与 loginLockCooldown 漂移，且锁定
// 中途重试时剩余时长早已不足 10 分钟。

import (
	"encoding/json"
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
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
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

// 锁定时间的带外形态（导入/手工修库写入的 RFC3339）必须按时间值解析——
// 字符串比较对「'T' > ' '」恒判已锁定且文案恒兜底全长；统一多格式解析后
// 判定与剩余分钟均正确。
func TestLogin_lockedMessageParsesRFC3339LockedUntil(t *testing.T) {
	// Given：开启「登录失败锁定」+ RFC3339 形态锁定值（剩余约 3.5 分钟）
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled INTEGER);
		INSERT INTO global_config VALUES (1, 1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	lockedUntil := time.Now().UTC().Add(3*time.Minute + 30*time.Second).Format(time.RFC3339)
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

	// Then：429 且文案按 RFC3339 值派生剩余分钟（向上取整=4），非兜底 10
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s, want 429（RFC3339 锁值须判锁定）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "请 4 分钟后重试") {
		t.Fatalf("body=%s, want 「请 4 分钟后重试」（RFC3339 解析派生，非兜底全长）", recorder.Body.String())
	}
}

// 已过期的锁定值按时间值比较判未锁——同日边界不再因字符串字典序误判。
func TestLogin_expiredLockSameDayBoundaryNotLocked(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled INTEGER);
		INSERT INTO global_config VALUES (1, 1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// 锁定值已过期 1 分钟（UTC 同日或跨日均按时间值判定）
	expired := time.Now().UTC().Add(-time.Minute).Format("2006-01-02 15:04:05")
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,login_locked_until) VALUES ('unlocked',?,'admin',1,?)`, string(hash), expired); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", h.Login)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"unlocked","password":"Secret123!"}`)))
	// 「不是 429」也会被 401（密码/用户异常）或 500（解析失败 500 分支）满足——
	// 必须断言登录真的成功并签发 JWT，否则过期锁被误判为锁定时仍会假绿。
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（过期锁值不得拦登录，也不得报内部错误）", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse login response: %v body=%s", err, recorder.Body.String())
	}
	if body.Token == "" {
		t.Fatalf("body=%s, want 非空 token（过期锁值用户必须正常登录）", recorder.Body.String())
	}
}

// 锁定时间解析覆盖全部已知带外形态（毫秒/带时区偏移/RFC3339Nano）——
// 任何一种解析失败都会让账户落入「解析失败 → 永久锁定」且提示 10 分钟。
func TestParseLoginLockedUntil_acceptsOffNominalLayouts(t *testing.T) {
	base := time.Date(2026, 10, 23, 12, 34, 56, 123456789, time.UTC)
	truncated := base.Truncate(time.Second)
	cases := []struct {
		raw  string
		want time.Time
	}{
		{base.Format("2006-01-02 15:04:05"), truncated},
		{base.Format("2006-01-02 15:04:05.999999999"), base},
		{base.Format("2006-01-02 15:04:05Z07:00"), truncated},
		{base.Format(time.RFC3339), truncated},
		{base.Format(time.RFC3339Nano), base},
	}
	for _, tc := range cases {
		got, ok := parseLoginLockedUntil(tc.raw)
		if !ok {
			t.Fatalf("parseLoginLockedUntil(%q) 失败（会落入永久锁定）", tc.raw)
		}
		if !got.Equal(tc.want) {
			t.Fatalf("parseLoginLockedUntil(%q)=%v, want %v", tc.raw, got, tc.want)
		}
	}
	if _, ok := parseLoginLockedUntil("not-a-timestamp"); ok {
		t.Fatal("非法形态必须返回 !ok（调用方保持 fail-closed）")
	}
}
