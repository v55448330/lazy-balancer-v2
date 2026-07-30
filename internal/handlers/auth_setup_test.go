package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		password_version INTEGER NOT NULL DEFAULT 0
	)`)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func TestLogin_returns_created_at_and_new_last_login_as_nullable_values(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER); INSERT INTO global_config VALUES (1,1,20)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
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
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"secret123"}`))
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

func TestLogin_signs_password_version_claim(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER); INSERT INTO global_config VALUES (1,1,20)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,password_changed_at,password_version) VALUES ('root',?,'admin',1,datetime('now'),7)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"secret123"}`))
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

func TestLogin_returns_error_when_last_login_update_fails(t *testing.T) {
	// Given
	database := setupAuthTestDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1); CREATE TRIGGER fail_last_login BEFORE UPDATE OF last_login ON users BEGIN SELECT RAISE(ABORT,'last login failed'); END`, string(hash)); err != nil {
		t.Fatalf("seed user and trigger: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"secret123"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("login status=%d body=%s, want 500", response.Code, response.Body.String())
	}
}

func TestSetupAdmin_first_run_flow(t *testing.T) {
	// Given
	setupAuthTestDB(t)
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
	request = httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"root","password":"secret123","display_name":"管理员"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("setup status=%d body=%s", response.Code, response.Body.String())
	}

	// When: setup again -> forbidden
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"other","password":"secret123"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("second setup status=%d body=%s", response.Code, response.Body.String())
	}

	// When: login with created admin
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"secret123"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("login after setup status=%d body=%s", response.Code, response.Body.String())
	}
}
