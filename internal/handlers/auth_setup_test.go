package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func setupAuthTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	db.SetDB(database)
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldDB)
		database.Close()
	})
	_, err = database.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		display_name VARCHAR(100),
		is_enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME,
		password_changed_at DATETIME,
		password_version INTEGER NOT NULL DEFAULT 0,
		auth_provider TEXT NOT NULL DEFAULT 'local',
		mfa_enabled BOOLEAN DEFAULT 0,
		-- 登录锁定列（与生产迁移后形状一致）。api_keys 表为认证链路相关查询
		-- 的建表依赖保留——改密吊销 Key 语义已删（2026-09 裁定）：改密不再
		-- 产生任何 api_keys DELETE，API Key 无密码门、改密不吊销。
		login_failed_attempts INTEGER NOT NULL DEFAULT 0,
		login_locked_until TEXT,
		-- break-glass 管理入口标记（保护判定读本列，常量仅作缺省）。
		is_setup_admin INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		created_by INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatal(err)
	}
	// MFA 列与挑战表统一由 ensureMFATestSchema 创建（此前内联副本
	// 导致四份 DDL 漂移）。挑战表随生产 schema 常备（三条改密路径
	// 在同一事务内吊销挑战，缺表会让改密 500）。
	ensureMFATestSchema(t, database)
	return database
}

func TestLogin_returns_created_at_and_new_last_login_as_nullable_values(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	createdAt := "2026-07-29 01:02:03"
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,display_name,is_enabled,created_at) VALUES ('root',?,'admin',NULL,1,?)`, string(hash), createdAt); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	before := time.Now().Add(-time.Second)

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		User struct {
			DisplayName *string    `json:"display_name"`
			CreatedAt   time.Time  `json:"created_at"`
			LastLogin   *time.Time `json:"last_login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if body.User.DisplayName != nil || body.User.CreatedAt.IsZero() || body.User.LastLogin == nil || body.User.LastLogin.Before(before) {
		t.Fatalf("login user=%+v, want null display name and current timestamps", body.User)
	}
}

// master 登录写点 last_login 绑定平面串（2026-10-11 时间戳统一裁定）：
// 写侧不再直绑 time.Time（驱动默认带时区后缀）。glebarez 驱动对 DATETIME
// 列有亲和归一——读回恒 RFC3339（探针实证），存储形态由驱动决定；本钉
// 断言读回是合法时间戳且与登录时刻一致（写侧收口的可观测面），不钉存储
// 字节形态（驱动行为不可从写侧收口，如实披露见 touchLastLogin 注释）。
func TestLogin_lastLoginStoredFlatFormat(t *testing.T) {
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
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	before := time.Now().UTC().Add(-2 * time.Second)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	var stored string
	if err := database.QueryRow(`SELECT last_login FROM users WHERE username='root'`).Scan(&stored); err != nil {
		t.Fatalf("read last_login: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339, stored)
	if err != nil {
		t.Fatalf("last_login=%q 非合法时间戳: %v", stored, err)
	}
	if parsed.Before(before) || parsed.After(time.Now().UTC().Add(2*time.Second)) {
		t.Fatalf("last_login=%q 与登录时刻不一致", stored)
	}
}

func TestLogin_signs_password_version_claim(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,password_changed_at,password_version) VALUES ('root',?,'admin',1,datetime('now'),7)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
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
		t.Fatalf("decode login response: %v", err)
	}
	token, err := jwt.Parse(body.Token, func(*jwt.Token) (any, error) { return []byte("test-secret"), nil })
	if err != nil {
		t.Fatalf("parse login token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["pwd_ver"] != float64(7) {
		t.Fatalf("pwd_ver=%v, want 7", claims["pwd_ver"])
	}
}

func TestLogin_clamps_excessive_jwt_expiration(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,999999,1)`); err != nil {
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
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
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
		t.Fatalf("decode login response: %v", err)
	}
	token, err := jwt.Parse(body.Token, func(*jwt.Token) (any, error) { return []byte("test-secret"), nil })
	if err != nil {
		t.Fatalf("parse login token: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if duration := int64(claims["exp"].(float64) - claims["iat"].(float64)); duration != int64((20 * time.Minute).Seconds()) {
		t.Fatalf("token lifetime=%d seconds, want 1200", duration)
	}
}

// 登录成功后的 last_login 记账写失败不得撤销已签发的会话：审计与活动证据
// 的单源顺序是「签发 → 登录成功审计 → last_login 尽力更新」。旧密码路径在
// 记账失败时 500 并丢弃令牌，而 OIDC 回调路径 warn 放行——两条路径口径分叉，
// 取证时「最后活动时间」与审计可信度不一致。本用例与 OIDC 侧
// TestOIDCCallback_lastLoginWriteFailureLoggedButLoginSucceeds 对称。
func TestLogin_last_login_failure_keeps_session_and_logs(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1); CREATE TRIGGER fail_last_login BEFORE UPDATE OF last_login ON users BEGIN SELECT RAISE(ABORT,'last login failed'); END`, string(hash)); err != nil {
		t.Fatalf("seed user and trigger: %v", err)
	}
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	// 审计落点：夹具库不含 audit_log，单独给一个最小审计库（与本用例的
	// 「审计口径」断言配对）。
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT, action TEXT, resource TEXT, detail TEXT, ip_address TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	oldAuditDB := db.AuditDB
	db.AuditDB = auditDB
	t.Cleanup(func() {
		db.AuditDB = oldAuditDB
		_ = auditDB.Close()
	})
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then ① 登录仍成功并返回 token（记账失败不是授权前提）
	if response.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s, want 200（last_login 记账失败不得撤销已签发会话）", response.Code, response.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if body.Token == "" {
		t.Fatal("登录响应必须携带 token")
	}
	// Then ② 审计口径与 OIDC 路径一致：记「登录成功」而非「登录失败」
	var successAudits, failAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='登录成功'`).Scan(&successAudits); err != nil {
		t.Fatalf("count success audits: %v", err)
	}
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='登录失败'`).Scan(&failAudits); err != nil {
		t.Fatalf("count failure audits: %v", err)
	}
	if successAudits != 1 || failAudits != 0 {
		t.Fatalf("audits success=%d failure=%d, want 1/0（记账失败不得把登录记成失败）", successAudits, failAudits)
	}
	// Then ③ 必须留痕（连续失败首条升级 error 级）
	if !strings.Contains(logBuf.String(), "last_login") {
		t.Fatalf("last_login 写失败必须留痕, captured log=%q", logBuf.String())
	}
}

func TestSetupAdmin_first_run_flow(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.GET("/auth/setup", h.GetSetupStatus)
	router.POST("/auth/setup", h.SetupAdmin)
	router.POST("/auth/login", h.Login)

	// When / Then: empty users -> needs_setup true
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/setup", nil)
	router.ServeHTTP(response, request)
	var statusBody struct {
		Data struct {
			NeedsSetup bool `json:"needs_setup"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &statusBody); err != nil || !statusBody.Data.NeedsSetup {
		t.Fatalf("empty db needs_setup=%v body=%s", statusBody.Data.NeedsSetup, response.Body.String())
	}

	// When: create first admin
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"root","password":"Secret123!","display_name":"管理员"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("setup status=%d body=%s", response.Code, response.Body.String())
	}

	// When: setup again -> forbidden
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"other","password":"Secret123!"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("second setup status=%d body=%s", response.Code, response.Body.String())
	}

	// When: login with created admin
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("login after setup status=%d body=%s", response.Code, response.Body.String())
	}
}
