package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// D5-S5（N+11 轮）：Login 的 ErrNoRows 分支不跑 bcrypt 即返 401，与「用户存在
// 但密码错」路径存在 ~bcrypt 量级（数十毫秒）的时序差 → 用户名枚举侧信道。
// 修复：不存在用户也对包级固定 dummy 哈希（init 生成一次，DefaultCost 与真实
// 哈希同档）跑一次注定失败的比较后再返回同形 401。
// 本测试锚定行为不变量：两条 401 路径状态码与响应体逐字节一致。
// 时序断言豁免：毫秒级时序差断言受调度/负载抖动支配，跨机器必然 flaky，
// 不作为回归门——缓解措施为上述等时比较本身（见 auth.go）。
func TestLogin_unknownUserAndWrongPassword_returnIdentical401(t *testing.T) {
	// Given 存在用户 root（真实 bcrypt 哈希，DefaultCost 与生产一致）
	database := setupAuthTestDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		return rec
	}

	// When 用户名不存在 vs 用户名存在但密码错
	recUnknown := post(`{"username":"no-such-user","password":"whatever"}`)
	recWrong := post(`{"username":"root","password":"wrong-password"}`)

	// Then 两者 401 且响应体逐字节一致（不泄露用户名存在性）
	if recUnknown.Code != http.StatusUnauthorized || recWrong.Code != http.StatusUnauthorized {
		t.Fatalf("status unknown=%d wrong=%d, want both 401", recUnknown.Code, recWrong.Code)
	}
	if recUnknown.Body.String() != recWrong.Body.String() {
		t.Fatalf("401 响应体不一致（用户名枚举面）：unknown=%s wrong=%s", recUnknown.Body.String(), recWrong.Body.String())
	}
}

// M7（用户已批准契约）：登录账户级锁定——5 次密码失败锁 10 分钟（429），锁定
// 期间即使密码正确同样 429（且先跑一次真实 bcrypt 等时占位，不泄露锁定账户的
// 密码正误）；置锁同语句清零计数（锁满不再累计）。
func TestLogin_locksAccountAfterFiveFailures(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		return rec
	}

	// When 连续 5 次错误密码
	for i := 1; i <= 5; i++ {
		if rec := post(`{"username":"root","password":"wrong-password"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body.String())
		}
	}

	// Then 第 6 次（即使密码正确）→ 429 账户已锁定
	rec := post(`{"username":"root","password":"secret123"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 6 (correct password while locked): status=%d body=%s, want 429", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "账户已锁定") {
		t.Fatalf("attempt 6: body=%s, want 账户已锁定文案", rec.Body.String())
	}
	// Then 置锁同语句已清零计数（锁定窗内不再累计）
	var attempts int
	var lockedUntil sql.NullString
	if err := database.QueryRow("SELECT login_failed_attempts, login_locked_until FROM users WHERE username='root'").Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || !lockedUntil.Valid || lockedUntil.String == "" {
		t.Fatalf("login_failed_attempts=%d login_locked_until=%v, want 0 + 已置锁", attempts, lockedUntil)
	}
}

// M7：成功登录清零失败计数——4 次失败后正确登录不触发锁定，计数归零。
func TestLogin_successClearsLockoutCounter(t *testing.T) {
	// Given 4 次失败（再错一次即锁定）
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		return rec
	}
	for i := 1; i <= 4; i++ {
		if rec := post(`{"username":"root","password":"wrong-password"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d body=%s, want 401", i, rec.Code, rec.Body.String())
		}
	}

	// When 正确密码
	rec := post(`{"username":"root","password":"secret123"}`)

	// Then 200 + 计数清零
	if rec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s, want 200（4 次失败后正确登录不应锁定）", rec.Code, rec.Body.String())
	}
	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(login_failed_attempts,0) FROM users WHERE username='root'").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("login_failed_attempts=%d, want 0（成功登录应清零）", attempts)
	}
}

// 2026-09 用户裁定：登录失败锁定受「登录失败锁定」开关控制——开关关闭时
// 连续失败只计数不锁定，第 6 次仍按密码正误返回（无 429）。
func TestLogin_lockoutDisabledBySwitch(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,0)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	post := func(body string) int {
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		return rec.Code
	}
	for i := 1; i <= 6; i++ {
		if code := post(`{"username":"root","password":"wrong-password"}`); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401（开关关闭不锁定）", i, code)
		}
	}
	if code := post(`{"username":"root","password":"secret123"}`); code != http.StatusOK {
		t.Fatalf("correct password after 6 failures: status=%d, want 200（开关关闭无锁定）", code)
	}
	var attempts int
	var lockedUntil sql.NullString
	if err := database.QueryRow("SELECT login_failed_attempts, login_locked_until FROM users WHERE username='root'").Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || lockedUntil.Valid {
		t.Fatalf("attempts=%d locked=%v, want 0 + 未置锁（成功清零、全程无锁）", attempts, lockedUntil)
	}
}
