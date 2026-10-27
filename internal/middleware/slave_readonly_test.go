package middleware

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"golang.org/x/crypto/bcrypt"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
)

func TestJWTLogout_revokes_only_current_token(t *testing.T) {
	cfg := &config.Config{JWTSecret: "logout-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin',?,'admin',1)", string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := handlers.NewHandlers(handlers.Dependencies{Config: cfg})
	login := func() string {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
		request.Header.Set("Content-Type", "application/json")
		context, _ := gin.CreateTestContext(response)
		context.Request = request
		h.Login(context)
		if response.Code != http.StatusOK {
			t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode login: %v", err)
		}
		return body.Token
	}
	firstToken := login()
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.POST("/logout", h.Logout)
	router.GET("/protected", noContent)
	request := func(method, path, token string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(response, req)
		return response
	}
	if response := request(http.MethodPost, "/logout", firstToken); response.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request(http.MethodGet, "/protected", firstToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out token status=%d, want 401", response.Code)
	}
	if response := request(http.MethodGet, "/protected", login()); response.Code != http.StatusNoContent {
		t.Fatalf("new token status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestJWTLogout_revokes_legacy_token_without_jti(t *testing.T) {
	// Given
	cfg := &config.Config{JWTSecret: "legacy-logout-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (2,'legacy-logout','hash','user',1,0)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sign := func(session string) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": 2, "username": "legacy-logout", "exp": time.Now().Add(time.Hour).Unix(), "pwd_ver": 0, "session": session,
		})
		signed, err := token.SignedString([]byte(cfg.JWTSecret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return signed
	}
	loggedOutToken := sign("logged-out")
	otherToken := sign("other")
	h := handlers.NewHandlers(handlers.Dependencies{Config: cfg})
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.POST("/logout", h.Logout)
	router.GET("/protected", noContent)
	request := func(method, path, token string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(response, req)
		return response
	}

	// When
	logout := request(http.MethodPost, "/logout", loggedOutToken)
	afterLogout := request(http.MethodGet, "/protected", loggedOutToken)
	otherSession := request(http.MethodGet, "/protected", otherToken)

	// Then
	if logout.Code != http.StatusOK || afterLogout.Code != http.StatusUnauthorized || otherSession.Code != http.StatusNoContent {
		t.Fatalf("logout=%d revoked=%d other=%d body=%q", logout.Code, afterLogout.Code, otherSession.Code, afterLogout.Body.String())
	}
	var passwordVersion int64
	if err := db.DB.QueryRow("SELECT password_version FROM users WHERE id=2").Scan(&passwordVersion); err != nil {
		t.Fatal(err)
	}
	if passwordVersion != 0 {
		t.Fatalf("password_version=%d, logout must not revoke all sessions", passwordVersion)
	}
}

func TestJWTLogout_revocation_usesUTCTextAcrossNegativeTimezoneQueryAndCleanup(t *testing.T) {
	// Given
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	originalLocal := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = originalLocal })
	cfg := &config.Config{JWTSecret: "timezone-logout-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (3,'timezone-logout','hash','user',1,0)"); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 3, "username": "timezone-logout", "exp": expiresAt, "pwd_ver": 0, "jti": "timezone-jti",
	})
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	h := handlers.NewHandlers(handlers.Dependencies{Config: cfg})
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.POST("/logout", h.Logout)
	router.GET("/protected", noContent)
	request := func(method, path string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		router.ServeHTTP(response, req)
		return response
	}

	// When
	logout := request(http.MethodPost, "/logout")
	revoked := request(http.MethodGet, "/protected")
	var stored string
	if err := db.DB.QueryRow("SELECT expires_at FROM revoked_jti").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM revoked_jti WHERE expires_at > ?", time.Now().UTC().Format("2006-01-02T15:04:05Z")).Scan(&active); err != nil {
		t.Fatal(err)
	}
	// 驱动生产清理实现（db.CleanupExpiredRevokedJTI）而非在测试里复刻
	// DELETE——真实 SQL 与时间格式由此被覆盖。
	if _, err := db.DB.Exec("INSERT INTO revoked_jti (jti_hash, expires_at) VALUES ('stale-jti','2000-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	cleanupErr := db.CleanupExpiredRevokedJTI(db.DB)
	var remaining int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM revoked_jti").Scan(&remaining); err != nil {
		t.Fatal(err)
	}

	// Then
	if logout.Code != http.StatusOK || revoked.Code != http.StatusUnauthorized {
		t.Fatalf("logout=%d revoked=%d", logout.Code, revoked.Code)
	}
	// 过期行被清理、未过期的登出行保留（UTC 文本比较格式与生产一致）。
	if !strings.HasSuffix(stored, "Z") || active != 1 || cleanupErr != nil || remaining != 1 {
		t.Fatalf("stored=%q active=%d cleanup=%v remaining=%d, want stale removed and active kept", stored, active, cleanupErr, remaining)
	}
}

// 401 消息按失败类别分语义——过期（自然态，重登可解）与
// 签名无效/格式损坏（凭证问题）不得同发「登录状态已过期」；状态码均保持 401。
// API Key 认证无会话令牌概念——登出应返回 404（无会话令牌
// 可吊销，对齐 DELETE 重复调用 404 的幂等契约），而非旧代码的恒 500（context
// 缺少 JWT 吊销哈希落穿错误分支）。
func TestAPIKeyLogout_returnsNotFoundInsteadOf500(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_api-logout-test"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (40,'api-logout','x','admin',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled) VALUES ('api-logout',?,?,40,1)", hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("API-key logout status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "无会话令牌") {
		t.Fatalf("API-key logout body must explain no session token, body=%s", rec.Body.String())
	}
}

func TestJWTAuth_splitsExpiredVsInvalidMessages(t *testing.T) {
	cfg := &config.Config{JWTSecret: "split-message-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	hit := func(token string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/protected", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(response, request)
		return response
	}
	expired := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 1, "username": "u", "exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
	expiredToken, err := expired.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	if response := hit(expiredToken); response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "登录状态已过期") {
		t.Fatalf("expired token status=%d body=%s, want 401 登录状态已过期", response.Code, response.Body.String())
	}
	if response := hit("aaa.bbb.ccc"); response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "登录凭证无效") {
		t.Fatalf("malformed token status=%d body=%s, want 401 登录凭证无效", response.Code, response.Body.String())
	}
}

func TestJWTAuth_rejects_username_mismatch_for_same_user_id(t *testing.T) {
	// Given
	cfg := &config.Config{JWTSecret: "username-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// db.Close() 会把 AuditDB/MetricsDB 一并关闭并置 nil——收尾必须走
		// 单源 helper，否则本用例之后包级句柄恒为 nil（后续直读 db.AuditDB 的
		// 用例只在「先经 Initialize」时侥幸绿，-shuffle 下会 nil 解引用）。
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (12,'current-name','hash','admin',1,0)"); err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 12, "username": "imported-name", "exp": time.Now().Add(time.Hour).Unix(), "pwd_ver": 0,
	})
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+signed)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

func TestJWTAuth_rejects_first_token_after_two_same_second_password_changes(t *testing.T) {
	cfg := &config.Config{JWTSecret: "password-version-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	ensurePasswordVersionColumn(t)
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	hash, err := bcrypt.GenerateFromPassword([]byte("initial-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.DB.Exec(`
		INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (7,'admin',?,'admin',1,0);
		CREATE TRIGGER fixed_password_change_time AFTER UPDATE OF password_hash ON users
		BEGIN UPDATE users SET password_changed_at='2026-07-30 12:00:00' WHERE id=NEW.id; END;
	`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := handlers.NewHandlers(handlers.Dependencies{})
	update := func(current, next string) int64 {
		response := httptest.NewRecorder()
		// （契约）：本人改密须携带 current_password 过共享确认门。
		request := httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"password":"`+next+`","current_password":"`+current+`"}`))
		request.Header.Set("Content-Type", "application/json")
		context, _ := gin.CreateTestContext(response)
		context.Request = request
		context.Set("user_id", 7)
		h.UpdateCurrentUser(context)
		if response.Code != http.StatusOK {
			t.Fatalf("password update status=%d body=%q", response.Code, response.Body.String())
		}
		var version int64
		var changedAt string
		if err := db.DB.QueryRow("SELECT password_version,password_changed_at FROM users WHERE id=7").Scan(&version, &changedAt); err != nil {
			t.Fatalf("read password state: %v", err)
		}
		if changedAt != "2026-07-30T12:00:00Z" && changedAt != "2026-07-30 12:00:00" {
			t.Fatalf("password_changed_at=%q, want fixed same-second value", changedAt)
		}
		return version
	}
	firstVersion := update("initial-secret", "first-password")
	secondVersion := update("first-password", "second-password")
	if firstVersion != 1 || secondVersion != 2 {
		t.Fatalf("password versions=(%d,%d), want (1,2)", firstVersion, secondVersion)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	sign := func(passwordVersion int64) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": 7, "username": "admin", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "pwd_ver": passwordVersion,
		})
		signed, err := token.SignedString([]byte(cfg.JWTSecret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return signed
	}
	request := func(token string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(response, req)
		return response
	}

	if response := request(sign(firstVersion)); response.Code != http.StatusUnauthorized {
		t.Fatalf("first token status=%d, want 401", response.Code)
	}
	if response := request(sign(secondVersion)); response.Code != http.StatusNoContent {
		t.Fatalf("second token status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestResetUserPassword_revokes_target_users_existing_token(t *testing.T) {
	cfg := &config.Config{JWTSecret: "reset-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	ensurePasswordVersionColumn(t)
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (9,'target','hash','user',1,0)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sign := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": 9, "username": "target", "exp": time.Now().Add(time.Hour).Unix(), "pwd_ver": 0,
		})
		signed, err := token.SignedString([]byte(cfg.JWTSecret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return signed
	}
	oldToken := sign()
	h := handlers.NewHandlers(handlers.Dependencies{})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users/9/reset-password", strings.NewReader(`{"new_password":"reset-password"}`))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(response)
	context.Request = request
	context.Params = gin.Params{{Key: "id", Value: "9"}}
	h.ResetUserPassword(context)
	if response.Code != http.StatusOK {
		t.Fatalf("reset status=%d body=%q", response.Code, response.Body.String())
	}

	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	authRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	authRequest.Header.Set("Authorization", "Bearer "+oldToken)
	authResponse := httptest.NewRecorder()
	router.ServeHTTP(authResponse, authRequest)
	if authResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old target token status=%d, want 401", authResponse.Code)
	}
}

func TestJWTAuth_allows_legacy_token_only_for_password_version_zero(t *testing.T) {
	cfg := &config.Config{JWTSecret: "legacy-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	ensurePasswordVersionColumn(t)
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (8,'legacy','hash','user',1,0)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 8, "username": "legacy", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+signed)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("legacy token status=%d body=%q", response.Code, response.Body.String())
	}
}

// ensurePasswordVersionColumn 钉夹具契约：users.password_version 在场。
// 现行架构 db.Initialize 建库即含该列
// （v2.1.8 迁移内联），原 ALTER 补列分支不可达已删——列缺席即夹具错误，
// 直接失败暴露而非静默修补。
func ensurePasswordVersionColumn(t *testing.T) {
	t.Helper()
	var version int
	if err := db.DB.QueryRow("SELECT password_version FROM users LIMIT 1").Scan(&version); err != nil && err != sql.ErrNoRows {
		t.Fatalf("users.password_version missing: %v", err)
	}
}

func newReadOnlyGuardTestRouter(t *testing.T, isMaster bool, role string) *gin.Engine {
	t.Helper()
	database, err := sql.Open("sqlite", t.TempDir()+"/readonly.db")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1, ?)", isMaster); err != nil {
		t.Fatalf("seed database: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	if role != "" {
		router.Use(func(c *gin.Context) {
			c.Set("role", role)
			c.Next()
		})
	}
	router.Use(readOnlyGuard(database))
	router.GET("/api/v1/mcp/tools", noContent)
	router.POST("/api/v1/rules", noContent)
	router.POST("/api/v1/users", noContent)
	router.PATCH("/api/v1/users/me", noContent)
	router.POST("/api/v1/users/me/api-keys", noContent)
	router.PATCH("/api/v1/users/me/api-keys/:id", noContent)
	router.DELETE("/api/v1/users/me/api-keys/:id", noContent)
	router.POST("/api/v1/cluster/nodes/report", noContent)
	router.POST("/api/v1/auth/login", noContent)
	router.POST("/api/v1/rules/cert-info", noContent)
	router.POST("/api/v1/config/preview", noContent)
	router.POST("/api/v1/certificates/jobs/current", noContent)
	router.POST("/api/v1/certificate-configs/test", noContent)
	router.POST("/api/v1/certificate-configs/:id/test", noContent)
	router.POST("/api/v1/ca-providers/:id/test", noContent)
	router.POST("/api/v1/future-write", noContent)
	return router
}

func noContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

func TestReadOnlyGuard_blocks_non_admin_business_write(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, true, "user")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if !strings.Contains(response.Body.String(), "非管理员用户只读") {
		t.Fatalf("body = %q, want non-admin read-only message", response.Body.String())
	}
}

func TestReadOnlyGuard_nullIsMasterDoesNot500(t *testing.T) {
	// Given
	database, err := sql.Open("sqlite", t.TempDir()+"/null-master.db")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1, NULL)"); err != nil {
		t.Fatalf("seed database: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("role", "admin")
		c.Next()
	})
	router.Use(readOnlyGuard(database))
	router.POST("/api/v1/rules", noContent)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body = %s, want 204 (NULL is_master 须按 schema 默认 TRUE 处理)", response.Code, response.Body.String())
	}
}

func TestReadOnlyGuard_allows_slave_mcp_tool_registry(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, false, "user")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil))

	// Then
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestReadOnlyGuard_blocks_non_admin_jwt_after_authentication(t *testing.T) {
	// Given
	database, err := sql.Open("sqlite", t.TempDir()+"/jwt-readonly.db")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1, 1)"); err != nil {
		t.Fatalf("seed database: %v", err)
	}
	cfg := &config.Config{JWTSecret: "test-secret"}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	ensurePasswordVersionColumn(t)
	// 三句柄一律经单源恢复（只还原 db.DB 会把已关闭/已删目录的
	// MetricsDB/AuditDB 留给后续用例，-shuffle 下表现为随机假红）。
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, is_enabled) VALUES (7, 'viewer', 'x', 'user', 1)"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 7, "username": "viewer", "role": "user", "exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg), readOnlyGuard(database))
	router.POST("/api/v1/rules", noContent)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	request.Header.Set("Authorization", "Bearer "+signed)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "非管理员用户只读") {
		t.Fatalf("status = %d body = %q, want non-admin 403", response.Code, response.Body.String())
	}
}

func TestReadOnlyGuard_does_not_whitelist_admin_users_route(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, true, "user")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/users", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestReadOnlyGuard_allows_non_admin_profile_update(t *testing.T) {
	// Given：主节点非管理员可修改自己的密码和显示名
	router := newReadOnlyGuardTestRouter(t, true, "user")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", nil))

	// Then
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestReadOnlyGuard_blocks_slave_profile_update(t *testing.T) {
	// Given：从节点全站只读，个人资料修改同样拒绝
	router := newReadOnlyGuardTestRouter(t, false, "admin")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestReadOnlyGuard_allows_non_admin_self_managed_api_keys(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, true, "user")

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", nil),
		httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/1", nil),
		httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/api-keys/1", nil),
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status = %d, want 204", request.Method, request.URL.Path, response.Code)
		}
	}
}

func TestReadOnlyGuard_allows_admin_business_write(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, true, "admin")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestReadOnlyGuard_preserves_slave_write_rejection(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, false, "admin")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if !strings.Contains(response.Body.String(), "从节点只读，请在主节点操作") {
		t.Fatalf("body = %q, want slave read-only message", response.Body.String())
	}
}

func TestReadOnlyGuard_allows_unauthenticated_machine_and_login_routes(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, false, "")

	// When
	machine := httptest.NewRecorder()
	router.ServeHTTP(machine, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/report", nil))
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))

	// Then
	if machine.Code != http.StatusNoContent || login.Code != http.StatusNoContent {
		t.Fatalf("machine status = %d, login status = %d, want both 204", machine.Code, login.Code)
	}
}

func TestReadOnlyGuard_allows_slave_readonly_post_routes(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, false, "admin")

	// When
	certInfo := httptest.NewRecorder()
	router.ServeHTTP(certInfo, httptest.NewRequest(http.MethodPost, "/api/v1/rules/cert-info", nil))
	preview := httptest.NewRecorder()
	router.ServeHTTP(preview, httptest.NewRequest(http.MethodPost, "/api/v1/config/preview", nil))

	// Then
	if certInfo.Code != http.StatusNoContent || preview.Code != http.StatusNoContent {
		t.Fatalf("cert-info status = %d, preview status = %d, want both 204", certInfo.Code, preview.Code)
	}
}

func TestReadOnlyGuard_writeRouteClassificationIsIndependentFromAuditPolicy(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, false, "admin")
	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{name: "non-whitelisted write route", path: "/api/v1/rules", wantStatus: http.StatusForbidden},
		{name: "whitelisted read-only POST", path: "/api/v1/certificates/jobs/current", wantStatus: http.StatusNoContent},
		{name: "audit-skip route outside whitelist", path: "/api/v1/future-write", wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, test.path, nil))

			// Then
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

// 从节点 MCP 写工具的保护是「loopback 转发重入目标写路由 → readOnlyGuard
// 403」，中间件级形态由 TestReadOnlyGuard_preserves_slave_write_rejection 覆盖，
// 端到端形态（真实 listener + 完整 router + 管理员 mcp Key）见
// TestMCPEndpoint_slaveWriteToolRejectedByInnerReadOnlyGuard（mcp_test.go）。
// 不再单列「名实不符」的转发目标用例：它只发普通 POST /rules、JSON-RPC body
// 是死数据，与上述两例重复，却让人误以为 MCP 从端写保护有独立回归钉。

// 证书配置「测试」两条路由已移出只读白名单
// ——它们会经 dnsproviders.Validate 真实 Present+CleanUp DNS TXT 记录（非纯读
// 探测），从节点与只读 API Key 不得触发。CA 提供商
// 测试同步移出——ZeroSSL 缺 EAB 时会真实写 ca_providers.credentials。
func TestReadOnlyGuard_slaveCannotRunCertificateConfigTests(t *testing.T) {
	router := newReadOnlyGuardTestRouter(t, false, "admin")

	for _, path := range []string{
		"/api/v1/certificate-configs/test",
		"/api/v1/certificate-configs/1/test",
		"/api/v1/ca-providers/1/test",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d, want 403（从节点不得触发真实写入的测试端点）", path, response.Code)
		}
	}
}

func TestReadOnlyGuard_adminCanRunCertificateConfigTests(t *testing.T) {
	router := newReadOnlyGuardTestRouter(t, true, "admin")
	for _, path := range []string{"/api/v1/certificate-configs/test", "/api/v1/certificate-configs/1/test"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s status=%d, want 204（admin 正常）", path, response.Code)
		}
	}
}

// 只读 API Key（同一 readOnlyWriteRoutes 事实源）同样不得触发证书配置测试，
// 也不得触发 ZeroSSL 缺 EAB 时会写库的 CA 提供商测试。
func TestAPIKeyReadOnlyGuard_blocksCertificateConfigTests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", true)
		c.Next()
	})
	router.Use(apiKeyReadOnlyGuard())
	router.POST("/api/v1/certificate-configs/test", noContent)
	router.POST("/api/v1/certificate-configs/:id/test", noContent)
	router.POST("/api/v1/ca-providers/:id/test", noContent)

	for _, path := range []string{
		"/api/v1/certificate-configs/test",
		"/api/v1/certificate-configs/1/test",
		"/api/v1/ca-providers/1/test",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d, want 403（只读 Key 不得触发真实写探测）", path, response.Code)
		}
	}
}
