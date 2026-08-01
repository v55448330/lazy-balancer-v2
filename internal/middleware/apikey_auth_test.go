package middleware

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestAPIKeyAuthBindsOwningUser(t *testing.T) {
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
		id INTEGER PRIMARY KEY, username VARCHAR(50), role VARCHAR(20), is_enabled BOOLEAN DEFAULT TRUE
	);
	CREATE TABLE api_keys (
		id INTEGER PRIMARY KEY, name VARCHAR(100), key_hash VARCHAR(255), key_prefix VARCHAR(20),
		created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN DEFAULT TRUE,
		mcp_enabled INTEGER DEFAULT 0, read_only INTEGER DEFAULT 0, mcp_ip_whitelist TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO users VALUES (7, 'alice', 'user', 1);`)
	if err != nil {
		t.Fatal(err)
	}
	plain := "lb_sk_test-secret"
	hash := sha256.Sum256([]byte(plain))
	_, err = database.Exec("INSERT INTO api_keys VALUES (9, 'ci', ?, 'lb_sk_test-s', 7, NULL, NULL, 1, 0, 0, '', CURRENT_TIMESTAMP)", hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(apiKeyAuth(&config.Config{}))
	router.GET("/probe", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":      c.GetInt("user_id"),
			"username":     c.GetString("username"),
			"role":         c.GetString("role"),
			"auth_type":    c.GetString("auth_type"),
			"api_key_id":   c.GetInt("api_key_id"),
			"api_key_name": c.GetString("api_key_name"),
		})
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var pendingLastUsed sql.NullTime
	if err := database.QueryRow("SELECT last_used FROM api_keys WHERE id=9").Scan(&pendingLastUsed); err != nil {
		t.Fatal(err)
	}
	if pendingLastUsed.Valid {
		t.Fatal("last_used was written synchronously during authentication")
	}
	if err := db.FlushAPIKeyLastUsed(); err != nil {
		t.Fatal(err)
	}
	var lastUsed sql.NullTime
	if err := database.QueryRow("SELECT last_used FROM api_keys WHERE id=9").Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Valid || time.Since(lastUsed.Time) > time.Minute {
		t.Fatalf("last_used not updated: %#v", lastUsed)
	}
}

func TestJWTAuthQueriesAuthenticationStateOnce(t *testing.T) {
	// Given
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
		_ = database.Close()
	})
	if _, err := database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, is_enabled BOOLEAN, password_version INTEGER NOT NULL DEFAULT 0);
		CREATE TABLE revoked_jti (jti_hash TEXT PRIMARY KEY, expires_at DATETIME NOT NULL);
		INSERT INTO users VALUES (7,'alice','user',1,0);`); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(7), "username": "alice", "pwd_ver": float64(0), "jti": "one-query",
	}).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	oldQuery := jwtAuthenticationQuery
	queryCount := 0
	jwtAuthenticationQuery = func(query string, args ...any) *sql.Row {
		queryCount++
		return database.QueryRow(query, args...)
	}
	t.Cleanup(func() { jwtAuthenticationQuery = oldQuery })
	router := gin.New()
	router.Use(jwtAuth(cfg))
	router.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if queryCount != 1 {
		t.Fatalf("authentication queries=%d, want 1", queryCount)
	}
}

func TestAPIKeyAuthAppliesIPWhitelistToRESTRequests(t *testing.T) {
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
	if _, err := database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, is_enabled BOOLEAN);
		CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name TEXT, key_hash TEXT, key_prefix TEXT, created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN, mcp_enabled BOOLEAN, read_only BOOLEAN, mcp_ip_whitelist TEXT);
		INSERT INTO users VALUES (1,'rest-user','user',1);`); err != nil {
		t.Fatal(err)
	}
	plain := "lb_sk_rest-whitelist-secret"
	hash := sha256.Sum256([]byte(plain))
	if _, err := database.Exec(`INSERT INTO api_keys VALUES (1,'rest',?,?,1,NULL,NULL,1,0,0,'["192.0.2.0/24"]')`, hex.EncodeToString(hash[:]), plain[:12]); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(apiKeyAuth(&config.Config{}))
	router.GET("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-API-Key", plain)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	if denied := request("198.51.100.8:1234"); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "来源 IP 不在白名单") {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}
	if allowed := request("192.0.2.8:1234"); allowed.Code != http.StatusOK {
		t.Fatalf("allowed status=%d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestJWTAuthAllowsValidJWTWithInvalidAPIKeyHeader(t *testing.T) {
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
	if _, err := database.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY, username VARCHAR(50), role VARCHAR(20), is_enabled BOOLEAN DEFAULT TRUE,
		password_version INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE api_keys (
		id INTEGER PRIMARY KEY, name VARCHAR(100), key_hash VARCHAR(255), key_prefix VARCHAR(20),
		created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN DEFAULT TRUE,
		mcp_enabled INTEGER DEFAULT 0, read_only INTEGER DEFAULT 0, mcp_ip_whitelist TEXT DEFAULT ''
	);
	CREATE TABLE revoked_jti (jti_hash TEXT PRIMARY KEY, expires_at DATETIME NOT NULL);
	INSERT INTO users VALUES (7, 'alice', 'user', 1, 0);`); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(7), "username": "alice", "pwd_ver": float64(0),
	}).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(apiKeyAuth(cfg), jwtAuth(cfg))
	router.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-API-Key", "invalid")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func TestAPIKeyAuthRejectsDisabledKey(t *testing.T) {
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
	_, err = database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(50), role VARCHAR(20), is_enabled BOOLEAN DEFAULT TRUE);
	CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name VARCHAR(100), key_hash VARCHAR(255), key_prefix VARCHAR(20), created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN DEFAULT TRUE, mcp_enabled INTEGER DEFAULT 0, read_only INTEGER DEFAULT 0, mcp_ip_whitelist TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	INSERT INTO users VALUES (7, 'alice', 'user', 1);`)
	if err != nil {
		t.Fatal(err)
	}
	plain := "lb_sk_disabled-secret"
	hash := sha256.Sum256([]byte(plain))
	_, err = database.Exec("INSERT INTO api_keys VALUES (10, 'disabled', ?, 'lb_sk_disabl', 7, NULL, NULL, 0, 0, 0, '', CURRENT_TIMESTAMP)", hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(apiKeyAuth(&config.Config{}))
	router.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}
