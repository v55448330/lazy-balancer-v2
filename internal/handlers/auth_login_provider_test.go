package handlers

// 密码登录与 MFA 挑战两步的登录响应必须携带 auth_provider
// ('local'/'oidc')——前端据此隐藏本地显示名/密码编辑；OIDC 的 auth_method
// 会话声明只由真实 OIDC 回调、集群票据与既有 OIDC 会话 step-up 保留。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
)

func TestLogin_responseCarriesAuthProvider(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User struct {
			AuthProvider string `json:"auth_provider"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User.AuthProvider != "local" {
		t.Fatalf("local login must carry auth_provider=local, got %q", resp.User.AuthProvider)
	}
}

// 角色读取失败时 node_mode 必须三态化 unknown（与 /system/info 同口径）：
// 回落 master 会绕开前端 fail-closed 只读分支，把 DB 故障窗口呈现成可写主节点。
func TestLogin_nodeModeTriState(t *testing.T) {
	cases := []struct {
		name      string
		roleQuery string
		want      string
	}{
		{
			name:      "unreadableRole",
			roleQuery: `CREATE TABLE global_config (id INTEGER PRIMARY KEY, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,20,1)`,
			want:      "unknown",
		},
		{
			name:      "slaveNode",
			roleQuery: `CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,0,20,1)`,
			want:      "slave",
		},
		{
			name:      "masterNode",
			roleQuery: `CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`,
			want:      "master",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := setupAuthTestDB(t)
			if _, err := database.Exec(tc.roleQuery); err != nil {
				t.Fatalf("seed global config: %v", err)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
				t.Fatal(err)
			}
			h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
			router := gin.New()
			router.POST("/auth/login", h.Login)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`)))
			if rec.Code != http.StatusOK {
				t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
			}
			var resp struct {
				NodeMode string `json:"node_mode"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.NodeMode != tc.want {
				t.Fatalf("node_mode=%q, want %q", resp.NodeMode, tc.want)
			}
		})
	}
}

func TestMFAVerifyLogin_responseCarriesAuthProvider(t *testing.T) {
	database := setupAuthTestDB(t) // 已含 MFA 列/挑战表（ensureMFATestSchema 单源）
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled INTEGER NOT NULL DEFAULT 0);
		INSERT INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "LazyBalancer", AccountName: "mfa-user",
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,mfa_enabled,mfa_secret) VALUES ('mfa-root',?,'admin',1,1,?)`, string(hash), key.Secret()); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed) VALUES ('challenge-tok', (SELECT id FROM users WHERE username='mfa-root'), datetime('now','+5 minutes'), 0)`); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	code, err := totp.GenerateCodeCustom(key.Secret(), time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"mfa_token":"challenge-tok","code":"`+code+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa verify: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User struct {
			AuthProvider string `json:"auth_provider"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User.AuthProvider != "local" {
		t.Fatalf("mfa verify must carry auth_provider=local, got %q", resp.User.AuthProvider)
	}
}

func TestPasswordLogin_importedOIDCRowUsesLocalSessionClaims(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN);
		INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// Given 仅导入/旧库可产生的混合行：provider=oidc 但持有可用本地密码。
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,auth_provider)
		VALUES ('legacy-oidc',?,'admin',1,'oidc')`, string(hash)); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"legacy-oidc","password":"Secret123!"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Token string `json:"token"`
		User  struct {
			AuthProvider string `json:"auth_provider"`
		} `json:"user"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.User.AuthProvider != "oidc" {
		t.Fatalf("display auth_provider=%q, want oidc preserved", response.User.AuthProvider)
	}
	parsed, err := jwt.Parse(response.Token, func(token *jwt.Token) (any, error) { return []byte("test-secret"), nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("parse session token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected session claims type")
	}
	// Then 本次认证实际使用本地密码，不得借行内 provider 写入 OIDC 会话短路声明。
	if method, exists := claims["auth_method"]; exists {
		t.Fatalf("password session auth_method=%v, want claim absent", method)
	}
}
