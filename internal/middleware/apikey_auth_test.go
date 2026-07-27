package middleware

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

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
		created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN DEFAULT TRUE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO users VALUES (7, 'alice', 'user', 1);`)
	if err != nil {
		t.Fatal(err)
	}
	plain := "lb_sk_test-secret"
	hash := sha256.Sum256([]byte(plain))
	_, err = database.Exec("INSERT INTO api_keys VALUES (9, 'ci', ?, 'lb_sk_test-s', 7, NULL, NULL, 1, CURRENT_TIMESTAMP)", hex.EncodeToString(hash[:]))
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
	var lastUsed sql.NullTime
	if err := database.QueryRow("SELECT last_used FROM api_keys WHERE id=9").Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Valid || time.Since(lastUsed.Time) > time.Minute {
		t.Fatalf("last_used not updated: %#v", lastUsed)
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
	CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name VARCHAR(100), key_hash VARCHAR(255), key_prefix VARCHAR(20), created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN DEFAULT TRUE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	INSERT INTO users VALUES (7, 'alice', 'user', 1);`)
	if err != nil {
		t.Fatal(err)
	}
	plain := "lb_sk_disabled-secret"
	hash := sha256.Sum256([]byte(plain))
	_, err = database.Exec("INSERT INTO api_keys VALUES (10, 'disabled', ?, 'lb_sk_disabl', 7, NULL, NULL, 0, CURRENT_TIMESTAMP)", hex.EncodeToString(hash[:]))
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
