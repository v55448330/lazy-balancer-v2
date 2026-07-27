package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

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
		last_login DATETIME
	)`)
	if err != nil {
		t.Fatal(err)
	}
	return database
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
