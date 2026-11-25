package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// Login 的 ErrNoRows 分支不跑 bcrypt 即返 401，与「用户存在
// 但密码错」路径存在 ~bcrypt 量级（数十毫秒）的时序差 → 用户名枚举侧信道。
// 修复：不存在用户也对包级固定 dummy 哈希（init 生成一次，DefaultCost 与真实
// 哈希同档）跑一次注定失败的比较后再返回同形 401。
// 本测试锚定行为不变量：两条 401 路径状态码与响应体逐字节一致。
// 时序断言豁免：毫秒级时序差断言受调度/负载抖动支配，跨机器必然 flaky，
// 不作为回归门——缓解措施为上述等时比较本身（见 auth.go）。
func TestLogin_unknownUserAndWrongPassword_returnIdentical401(t *testing.T) {
	// Given 存在用户 root（真实 bcrypt 哈希，DefaultCost 与生产一致）
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.DefaultCost)
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

// （用户已批准契约）：登录账户级锁定——5 次密码失败锁 10 分钟（429），锁定
// 期间即使密码正确同样 429（且先跑一次真实 bcrypt 等时占位，不泄露锁定账户的
// 密码正误）；置锁同语句清零计数（锁满不再累计）。
func TestLogin_locksAccountAfterFiveFailures(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
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
	rec := post(`{"username":"root","password":"Secret123!"}`)
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

// 成功登录清零失败计数——4 次失败后正确登录不触发锁定，计数归零。
func TestLogin_successClearsLockoutCounter(t *testing.T) {
	// Given 4 次失败（再错一次即锁定）
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
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
	rec := post(`{"username":"root","password":"Secret123!"}`)

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

func TestLogin_resetFailureIsLoggedWithoutRevokingJWT(t *testing.T) {
	seed := func(t *testing.T, failReset bool) (*Handlers, *gin.Engine, *sql.DB) {
		t.Helper()
		database := setupAuthTestDB(t)
		if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
			t.Fatalf("create global config: %v", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,login_failed_attempts) VALUES ('root',?,'admin',1,4)`, string(hash)); err != nil {
			t.Fatal(err)
		}
		if failReset {
			if _, err := database.Exec(`CREATE TRIGGER fail_login_reset
				BEFORE UPDATE OF login_failed_attempts, login_locked_until ON users
				BEGIN SELECT RAISE(FAIL, 'login reset blocked'); END`); err != nil {
				t.Fatalf("create reset fault trigger: %v", err)
			}
		}
		h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
		router := gin.New()
		router.POST("/auth/login", h.Login)
		return h, router, database
	}
	post := func(router *gin.Engine) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("success clears counter without warning", func(t *testing.T) {
		_, router, database := seed(t, false)
		var logs strings.Builder
		oldWriter := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(oldWriter) })
		response := post(router)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"token"`) {
			t.Fatalf("status=%d body=%s, want successful login", response.Code, response.Body.String())
		}
		var attempts int
		if err := database.QueryRow(`SELECT login_failed_attempts FROM users WHERE username='root'`).Scan(&attempts); err != nil {
			t.Fatal(err)
		}
		if attempts != 0 {
			t.Fatalf("login_failed_attempts=%d, want 0", attempts)
		}
		if strings.Contains(logs.String(), "登录成功清零登录失败计数与锁定失败") {
			t.Fatalf("healthy reset must not warn, logs=%q", logs.String())
		}
	})

	t.Run("reset failure logs and preserves verified login", func(t *testing.T) {
		_, router, database := seed(t, true)
		var logs strings.Builder
		oldWriter := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(oldWriter) })
		response := post(router)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"token"`) {
			t.Fatalf("verified login status=%d body=%s, want 200 with token", response.Code, response.Body.String())
		}
		var attempts int
		if err := database.QueryRow(`SELECT login_failed_attempts FROM users WHERE username='root'`).Scan(&attempts); err != nil {
			t.Fatal(err)
		}
		if attempts != 4 {
			t.Fatalf("fault injection expected old attempts=4, got %d", attempts)
		}
		if !strings.Contains(logs.String(), "登录成功清零登录失败计数与锁定失败") || !strings.Contains(logs.String(), "login reset blocked") {
			t.Fatalf("missing reset failure warning, logs=%q", logs.String())
		}
	})
}

// 2026-09 用户裁定：登录失败锁定受「登录失败锁定」开关控制——开关关闭时
// 连续失败只计数不锁定，第 6 次仍按密码正误返回（无 429）。
func TestLogin_lockoutDisabledBySwitch(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,0)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
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
	if code := post(`{"username":"root","password":"Secret123!"}`); code != http.StatusOK {
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

// 未认证登录请求的 username/password 此前无长度上限
// （guardAuthJSONBody 只限 64KiB 整体）——失败登录把 ~64KiB 用户名原文写入
// audit_log，分布式绕开 10/min/IP 限流即可放大审计库。登录侧补齐与
// users 列宽（50）/bcrypt 上限（72）对齐的 binding max，超限在写库/审计前拒绝。
func TestLogin_rejectsOverlongCredentials(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	oldAuditDB := db.AuditDB
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100), detail TEXT, detail_key TEXT, detail_params TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	db.AuditDB = auditDB
	t.Cleanup(func() {
		auditDB.Close()
		db.AuditDB = oldAuditDB
	})

	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	post := func(username, password string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"username": username, "password": password})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		return rec
	}
	long := strings.Repeat("u", 300)

	// 超长用户名与超长密码都必须在 binding 层 400（未落认证查询/审计原文）。
	if rec := post(long, "Secret123!"); rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong username status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if rec := post("root", strings.Repeat("p", 300)); rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong password status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	// 边界回归：50 字符用户名与 72 字符密码不因新上限被误拒（进入认证查询后
	// 按 401 返回，而不是 400）。
	if rec := post(strings.Repeat("u", 50), strings.Repeat("p", 72)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("boundary-length credentials status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	// 审计放大回归：无任何审计行携带超长用户名。
	var maxLen int
	if err := auditDB.QueryRow(`SELECT COALESCE(MAX(LENGTH(username)),0) FROM audit_log`).Scan(&maxLen); err != nil {
		t.Fatal(err)
	}
	if maxLen > 50 {
		t.Fatalf("audit_log 出现超长用户名（len=%d），未认证请求可放大审计库", maxLen)
	}
}

// 等时缓解的结构性回归钉（不做毫秒级时序断言——CI 抖动必然 flaky）：
// ① dummy 哈希与生产哈希同档（DefaultCost、60 字节）；
// ② 「用户名不存在」路径确实执行了一次 dummy 比较，且比较对象就是该 dummy 哈希。
// 删掉比较语句、改用 MinCost 或走格式错误快路径都会使本用例变红。
func TestLogin_unknownUserRunsDummyBcryptComparison(t *testing.T) {
	withIsolatedGlobal(t)
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,0)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	if cost, err := bcrypt.Cost(loginDummyBcryptHash); err != nil || cost != bcrypt.DefaultCost {
		t.Fatalf("dummy bcrypt cost=%v err=%v, want DefaultCost（降成本即恢复时序侧信道）", cost, err)
	}
	if len(loginDummyBcryptHash) != 60 {
		t.Fatalf("dummy hash 长度=%d, want 60（bcrypt 标准形态；格式错误会走快路径）", len(loginDummyBcryptHash))
	}

	oldCompare := loginDummyCompare
	calls := 0
	var comparedHash string
	var comparedPassword string
	loginDummyCompare = func(hashedPassword, password []byte) error {
		calls++
		comparedHash = string(hashedPassword)
		comparedPassword = string(password)
		return bcrypt.ErrMismatchedHashAndPassword
	}
	t.Cleanup(func() { loginDummyCompare = oldCompare })

	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"no-such-user","password":"whatever"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("未知用户名路径的 dummy 比较次数=%d, want 1（缺比较即恢复用户名枚举时序差）", calls)
	}
	if comparedHash != string(loginDummyBcryptHash) {
		t.Fatalf("未知用户名路径未使用 dummy 哈希（比较对象=%q）", comparedHash)
	}
	if comparedPassword != "whatever" {
		t.Fatalf("dummy 比较的密码=%q, want 请求密码（比较必须真实消耗 bcrypt 时间）", comparedPassword)
	}
}
