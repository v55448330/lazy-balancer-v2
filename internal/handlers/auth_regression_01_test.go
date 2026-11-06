package handlers

//   自助改密 current_password 不再被新密码策略 max=24 提前拦截；
//   MFA 挑战绑定签发时 password_version，改密吊销在册挑战；
//   自助改密复用 passwordResetColumns（清失败计数与锁定）；
//   锁定开关读取失败 fail-closed（500，不消费挑战）；
//   MFA 验证存储错误不按「验证码错误」计数；
//   OIDC 重复登录刷新 IdP 侧显示名；
//   OIDC state 封顶改为原子预留（并发不越界）；
//   JIT 用户名并发竞态有限重试（不同 subject 同名不失败）；
//   OIDC 配置测试区分空 body 与畸形 body。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	sqlitedriver "github.com/glebarez/go-sqlite"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// ensureMFATestSchema 给 setupAuthTestDB 的最小 users 表补 MFA 列与挑战表
// （挑战表列形状与 migrations 后的生产形态一致，含 password_version）。
// 单源：此前四个测试
// 文件各自内联一份 DDL（auth_setup/auth_login_provider/auth_regression/
// mfa_verifylogin_challenge），列集合漂移（如 password_version）时
// 四处不同步 → 单文件测试假绿/假红。重复调用安全（duplicate column 容忍、
// 挑战表 IF NOT EXISTS）。
func ensureMFATestSchema(t *testing.T, database *sql.DB) {
	t.Helper()
	for _, col := range []string{
		"mfa_secret TEXT DEFAULT ''",
		"mfa_pending_secret TEXT DEFAULT ''",
		"mfa_pending_fails INTEGER DEFAULT 0",
		"mfa_recovery_codes TEXT DEFAULT '[]'",
		"mfa_last_timestep INTEGER DEFAULT 0",
	} {
		if _, err := database.Exec("ALTER TABLE users ADD COLUMN " + col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			t.Fatalf("add mfa column %s: %v", col, err)
		}
	}
	if _, err := database.Exec(`CREATE TABLE IF NOT EXISTS mfa_challenges (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			consumed BOOLEAN DEFAULT 0,
			attempts INTEGER DEFAULT 0,
			password_version INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		t.Fatalf("create mfa_challenges: %v", err)
	}
}

// 旧策略下设置的 25-72 字符密码仍可登录，就必须可以自助改密——
// current_password 的 max=24 绑定会把确认输入在 bcrypt 比较前拦成 400。
func TestUpdateCurrentUser_acceptsLegacyLongCurrentPassword(t *testing.T) {
	database := setupAuthTestDB(t)
	const legacyPassword = "legacy-password-0123456789-abc" // 30 字符，旧策略存量
	hash, err := bcrypt.GenerateFromPassword([]byte(legacyPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version) VALUES (1,'alice',?,'user','Alice',1,3)`, string(hash)); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/users/me",
		strings.NewReader(`{"password":"NewPass123!","current_password":"`+legacyPassword+`"}`))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(recorder)
	context.Request = request
	context.Set("user_id", 1)
	(&Handlers{}).UpdateCurrentUser(context)

	if recorder.Code != http.StatusOK {
		t.Fatalf("legacy 30-char current_password must be accepted, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var newHash string
	if err := database.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&newHash); err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(newHash), []byte("NewPass123!")) != nil {
		t.Fatal("new policy-compliant password must be stored")
	}
}

// 自助改密与管理员重置同语义——清空登录失败计数与锁定。
func TestUpdateCurrentUser_clearsStaleLoginLock(t *testing.T) {
	database := setupAuthTestDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("OldPass123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version,login_failed_attempts,login_locked_until)
		VALUES (1,'alice',?,'user','Alice',1,1,4,datetime('now','+5 minutes'))`, string(hash)); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/users/me",
		strings.NewReader(`{"password":"NewPass123!","current_password":"OldPass123!"}`))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(recorder)
	context.Request = request
	context.Set("user_id", 1)
	(&Handlers{}).UpdateCurrentUser(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var attempts int
	var locked sql.NullString
	if err := database.QueryRow("SELECT login_failed_attempts, login_locked_until FROM users WHERE id=1").Scan(&attempts, &locked); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || locked.Valid {
		t.Fatalf("self-service password change must clear login lock, got attempts=%d locked=%v", attempts, locked)
	}
}

// 挑战绑定签发时的密码版本；密码已变更的挑战必须 401 并删除，
// 不得以新 pwd_ver 完成第二因素登录。
func TestMFAVerifyLogin_rejectsChallengeIssuedForOlderPassword(t *testing.T) {
	secret, userID := seedMFAChallengeLoginFixture(t, "stale-ver-tok", 0)
	if _, err := db.DB.Exec("UPDATE users SET password_version=2 WHERE id=?", userID); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	recorder := postMFAVerify(t, router, "stale-ver-tok", currentTOTPCode(t, secret))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("challenge issued before password change must be rejected, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var remaining int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM mfa_challenges WHERE token='stale-ver-tok'").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("stale challenge must be deleted, remaining=%d", remaining)
	}
}

// 三条改密路径（自助/管理员更新/管理员重置）都必须吊销在册 MFA 挑战。
func TestPasswordUpdateRevokesMFALoginChallenges(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		serve  func(*Handlers, *gin.Context)
		token  string
	}{
		{
			name: "current user", method: http.MethodPatch, path: "/users/me",
			body:  `{"password":"second-password","current_password":"first-password"}`,
			serve: func(h *Handlers, c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) },
			token: "self-change-tok",
		},
		{
			name: "administrator update", method: http.MethodPut, path: "/users/1",
			body:  `{"password":"second-password"}`,
			serve: func(h *Handlers, c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: "1"}}; h.UpdateUser(c) },
			token: "admin-update-tok",
		},
		{
			name: "administrator reset", method: http.MethodPost, path: "/users/1/reset-password",
			body: `{"new_password":"second-password"}`,
			serve: func(h *Handlers, c *gin.Context) {
				c.Params = gin.Params{{Key: "id", Value: "1"}}
				h.ResetUserPassword(c)
			},
			token: "admin-reset-tok",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			database := setupAuthTestDB(t)
			ensureMFATestSchema(t, database)
			hash, err := bcrypt.GenerateFromPassword([]byte("first-password"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version) VALUES (1,'alice',?,'admin','Alice',1,4)`, string(hash)); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed) VALUES (?,1,datetime('now','+5 minutes'),0)`, tt.token); err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			context, _ := gin.CreateTestContext(recorder)
			context.Request = request
			tt.serve(&Handlers{}, context)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}

			var remaining int
			if err := database.QueryRow("SELECT COUNT(*) FROM mfa_challenges WHERE user_id=1").Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			if remaining != 0 {
				t.Fatalf("password change must revoke pending MFA challenges, remaining=%d", remaining)
			}
		})
	}
}

// 锁定开关读取失败必须 （500 且不消费挑战），
// 不得静默按「未锁定 + 开关关闭」放行。
func TestMFAVerifyLogin_lockoutConfigReadFailureFailsClosed(t *testing.T) {
	secret, _ := seedMFAChallengeLoginFixture(t, "cfg-fail-tok", 0)
	if _, err := db.DB.Exec("DROP TABLE global_config"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	recorder := postMFAVerify(t, router, "cfg-fail-tok", currentTOTPCode(t, secret))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("lockout config read failure must fail closed with 500, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var consumed int
	if err := db.DB.QueryRow("SELECT consumed FROM mfa_challenges WHERE token='cfg-fail-tok'").Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Fatalf("challenge must not be consumed on infrastructure failure, consumed=%d", consumed)
	}
}

// 验证码存储错误（恢复码 JSON 损坏/写库失败）是基础设施错误，
// 必须 500 且不消耗挑战、不累加挑战/账户失败计数。
func TestMFAVerifyLogin_storageErrorDoesNotCountAsCredentialFailure(t *testing.T) {
	_, userID := seedMFAChallengeLoginFixture(t, "store-err-tok", 0)
	if _, err := db.DB.Exec("UPDATE users SET mfa_recovery_codes='not-json' WHERE id=?", userID); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// 16 字符 = 恢复码通道；存储 JSON 损坏 → 三态中的「存储错误」。
	recorder := postMFAVerify(t, router, "store-err-tok", "ABCDEFGHIJKLMNOP")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("storage error must surface as 500, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var consumed, attempts, failed int
	if err := db.DB.QueryRow(`SELECT ch.consumed, ch.attempts, u.login_failed_attempts
		FROM mfa_challenges ch JOIN users u ON u.id=ch.user_id WHERE ch.token='store-err-tok'`).Scan(&consumed, &attempts, &failed); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 || attempts != 0 || failed != 0 {
		t.Fatalf("infrastructure error must not burn credentials or count failures: consumed=%d attempts=%d failed=%d", consumed, attempts, failed)
	}
}

// 重复登录刷新 IdP 侧显示名（本地 username/role 不受影响）。
func TestOIDCCallback_refreshesDisplayNameFromIdP(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	oidcLoginAndGetClaims(t, router)
	var display, username, role string
	if err := db.DB.QueryRow("SELECT COALESCE(display_name,''), username, role FROM users WHERE auth_provider='oidc'").Scan(&display, &username, &role); err != nil {
		t.Fatal(err)
	}
	if display != "oidcalice" {
		t.Fatalf("first login display_name=%q, want preferred_username fallback", display)
	}

	idp.claimName.Store("Alice Renamed")
	oidcLoginAndGetClaims(t, router)
	if err := db.DB.QueryRow("SELECT COALESCE(display_name,''), username, role FROM users WHERE auth_provider='oidc'").Scan(&display, &username, &role); err != nil {
		t.Fatal(err)
	}
	if display != "Alice Renamed" {
		t.Fatalf("repeat login must refresh display_name from IdP, got %q", display)
	}
	if username != "oidcalice" || role != "user" {
		t.Fatalf("username/role must stay local, got username=%q role=%q", username, role)
	}
	var rows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc'").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("repeat login must reuse the identity row, rows=%d", rows)
	}
}

// state 封顶是检查+预留原子操作——并发未认证登录不得越过上限。
func TestOIDCLogin_stateReservationAtomicUnderConcurrency(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	oidcStates.Range(func(k, _ any) bool { oidcStates.Delete(k); return true })
	oidcStateCount.Store(0)
	old := oidcStateMaxEntries
	oidcStateMaxEntries = 1
	t.Cleanup(func() {
		oidcStateMaxEntries = old
		oidcStates.Range(func(k, _ any) bool { oidcStates.Delete(k); return true })
		oidcStateCount.Store(0)
	})

	const workers = 16
	var accepted int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
			location := recorder.Header().Get("Location")
			if recorder.Code == http.StatusFound && !strings.Contains(location, "#/login?oidc_error=") {
				atomic.AddInt32(&accepted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("concurrent logins must admit exactly one state: accepted=%d max=1", accepted)
	}
	if got := oidcStateCount.Load(); got > 1 || int(got) != int(accepted) {
		t.Fatalf("state counter inconsistent: count=%d accepted=%d max=1", got, accepted)
	}
}

type oidcUsernameQueryConnector struct {
	dsn     string
	inner   driver.Driver
	queries *atomic.Int64
}

func (c oidcUsernameQueryConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &oidcUsernameQueryConn{Conn: conn, queries: c.queries}, nil
}

func (c oidcUsernameQueryConnector) Driver() driver.Driver { return c.inner }

type oidcUsernameQueryConn struct {
	driver.Conn
	queries *atomic.Int64
}

func (c *oidcUsernameQueryConn) Prepare(query string) (driver.Stmt, error) {
	if strings.Contains(query, "FROM users WHERE username") {
		c.queries.Add(1)
	}
	return c.Conn.Prepare(query)
}

func TestOIDCCandidateUsername_boundedQueriesForCollisionShapes(t *testing.T) {
	// Given 一个真实 SQLite users 表；driver 只统计候选用户名 SELECT，INSERT
	// 夹具不计入。目标性能契约：无冲突 1 次查询，任意数量既有冲突最多 2 次。
	setup := func(t *testing.T) (*sql.DB, *atomic.Int64) {
		t.Helper()
		var queries atomic.Int64
		connector := oidcUsernameQueryConnector{dsn: t.TempDir() + "/users.db", inner: &sqlitedriver.Driver{}, queries: &queries}
		database := sql.OpenDB(connector)
		if _, err := database.Exec(`CREATE TABLE users (username VARCHAR(50) UNIQUE NOT NULL)`); err != nil {
			t.Fatalf("create users table: %v", err)
		}
		oldDB := db.DB
		db.DB = database
		db.SetDB(database)
		t.Cleanup(func() {
			_ = database.Close()
			db.DB = oldDB
			db.SetDB(oldDB)
		})
		return database, &queries
	}
	seed := func(t *testing.T, database *sql.DB, names ...string) {
		t.Helper()
		for _, name := range names {
			if _, err := database.Exec(`INSERT INTO users (username) VALUES (?)`, name); err != nil {
				t.Fatalf("seed username %q: %v", name, err)
			}
		}
	}
	candidateWithSuffix := func(base string, index int) string {
		suffix := fmt.Sprintf("-%d", index)
		runes := []rune(base)
		budget := 50 - len(suffix)
		if budget < 0 {
			budget = 0
		}
		if len(runes) > budget {
			return string(runes[:budget]) + suffix
		}
		return base + suffix
	}

	t.Run("many collisions", func(t *testing.T) {
		database, queries := setup(t)
		names := []string{"alice"}
		for i := 2; i <= 40; i++ {
			names = append(names, fmt.Sprintf("alice-%d", i))
		}
		seed(t, database, names...)
		candidate, err := oidcCandidateUsername("alice")
		if err != nil || candidate != "alice-41" {
			t.Fatalf("candidate=%q err=%v, want alice-41", candidate, err)
		}
		if got := queries.Load(); got != 2 {
			t.Fatalf("collision SELECT count=%d, want bounded 2 (old linear scan would be 41)", got)
		}
	})

	t.Run("no collision regression", func(t *testing.T) {
		_, queries := setup(t)
		candidate, err := oidcCandidateUsername("fresh")
		if err != nil || candidate != "fresh" {
			t.Fatalf("candidate=%q err=%v, want fresh", candidate, err)
		}
		if got := queries.Load(); got != 1 {
			t.Fatalf("free-name SELECT count=%d, want 1", got)
		}
	})

	t.Run("LIKE metacharacters are literals", func(t *testing.T) {
		database, queries := setup(t)
		base := `a_%\`
		seed(t, database, base, base+"-2")
		candidate, err := oidcCandidateUsername(base)
		if err != nil || candidate != base+"-3" {
			t.Fatalf("candidate=%q err=%v, want %q", candidate, err, base+"-3")
		}
		if got := queries.Load(); got != 2 {
			t.Fatalf("metacharacter collision SELECT count=%d, want 2", got)
		}
	})

	t.Run("rune truncation across suffix widths", func(t *testing.T) {
		database, queries := setup(t)
		base := strings.Repeat("界", 50)
		names := []string{base}
		for i := 2; i <= 10; i++ {
			names = append(names, candidateWithSuffix(base, i))
		}
		seed(t, database, names...)
		want := candidateWithSuffix(base, 11)
		candidate, err := oidcCandidateUsername(base)
		if err != nil || candidate != want {
			t.Fatalf("candidate=%q err=%v, want %q", candidate, err, want)
		}
		if got := queries.Load(); got != 2 {
			t.Fatalf("truncated collision SELECT count=%d, want 2", got)
		}
	})
}

// 不同 subject 并发首登撞同一候选用户名时，唯一冲突后重算候选名
// 有限重试——不得把瞬时竞态升级为登录失败；重试上限内仍冲突才失败。
func TestCreateOIDCUserWithRetry_survivesUsernameRace(t *testing.T) {
	idp := newMockIdP(t)
	setupOIDCTest(t, idp) // 仅需真实 DB schema

	oldHook := oidcJITInsertAttemptHook
	t.Cleanup(func() { oidcJITInsertAttemptHook = oldHook })

	// 第一次 INSERT 前模拟「并发者已抢占 alice」：hook 落库对端身份行并返回
	// 唯一冲突错误；重试时批量候选查询能看到对端行 → 选 alice-2 成功。
	oidcJITInsertAttemptHook = func(attempt int) error {
		if attempt != 1 {
			return nil
		}
		if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,display_name,is_enabled,auth_provider,oidc_subject,oidc_issuer)
			VALUES ('alice','','user','Competitor',1,'oidc','other-sub',?)`, idp.issuer); err != nil {
			return err
		}
		return errors.New("UNIQUE constraint failed: users.username")
	}
	ident, created, err := createOIDCUserWithRetry(context.Background(), idp.issuer, "sub-race-1", "alice", "Alice")
	if err != nil {
		t.Fatalf("username collision must be retried instead of failing login: %v", err)
	}
	if !created || ident.username != "alice-2" || ident.id == 0 {
		t.Fatalf("retry must create alice-2, got created=%v ident=%+v", created, ident)
	}

	// 目标形状：同名 base 已占用 → 后缀去重。
	ident2, created2, err := createOIDCUserWithRetry(context.Background(), idp.issuer, "sub-race-2", "alice", "Alice 2")
	if err != nil {
		t.Fatalf("second subject with same base must get suffix: %v", err)
	}
	if !created2 || ident2.username != "alice-3" {
		t.Fatalf("want alice-3, got created=%v ident=%+v", created2, ident2)
	}

	// 退化形状：持续冲突必须在有限次数后报错（有界重试，不无限循环）。
	oidcJITInsertAttemptHook = func(int) error {
		return errors.New("UNIQUE constraint failed: users.username")
	}
	if _, _, err := createOIDCUserWithRetry(context.Background(), idp.issuer, "sub-race-3", "carol", "Carol"); err == nil {
		t.Fatal("persistent username collision must fail after bounded retries")
	}
}

// 畸形请求体必须 400；真正的空 body 才回退「测试已保存配置」。
func TestOIDCSettingsTest_distinguishesMalformedFromEmptyBody(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	post := func(body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		return recorder
	}

	if recorder := post(`{"issuer":`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON must be 400, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := post(""); recorder.Code != http.StatusOK {
		t.Fatalf("empty body must fall back to saved config, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
