package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func setupAPIKeyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldAuditDB := db.DB, db.AuditDB
	database, err := sql.Open("sqlite", t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	db.SetDB(database)
	db.AuditDB = auditDB
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldDB)
		db.AuditDB = oldAuditDB
		database.Close()
		auditDB.Close()
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
	);
	CREATE TABLE api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		key_hash VARCHAR(255) NOT NULL,
		key_prefix VARCHAR(20) NOT NULL,
		created_by INTEGER NOT NULL,
		last_used DATETIME,
		expires_at DATETIME,
		is_enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO users (id, username, password_hash, role) VALUES (1, 'alice', 'x', 'user'), (2, 'bob', 'x', 'user');
	INSERT INTO api_keys (id, name, key_hash, key_prefix, created_by, is_enabled) VALUES (10, 'alice-key', 'h1', 'prefix1', 1, 1), (20, 'bob-key', 'h2', 'prefix2', 2, 1);`)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func TestListCurrentUserAPIKeysOnlyOwn(t *testing.T) {
	setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/api-keys", nil)
	ctx.Set("user_id", 1)

	h := &Handlers{}
	h.ListCurrentUserAPIKeys(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Data []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].ID != 10 {
		t.Fatalf("unexpected keys: %#v", body.Data)
	}
}

func TestDeleteCurrentUserAPIKeyRejectsOtherUsersKey(t *testing.T) {
	setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/api-keys/20", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "20"}}
	ctx.Set("user_id", 1)

	h := &Handlers{}
	h.DeleteCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestCreateCurrentUserAPIKeyReturnsPlaintextOnce(t *testing.T) {
	setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"ci"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)

	h := &Handlers{}
	h.CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	var body struct {
		Data struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Data.Key, "lb_sk_") {
		t.Fatalf("key prefix invalid: %q", body.Data.Key)
	}
}
