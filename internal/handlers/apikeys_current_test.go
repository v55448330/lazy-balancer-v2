package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

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
		last_login DATETIME,
		mfa_failed_attempts INTEGER DEFAULT 0,
		mfa_locked_until DATETIME
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
		mcp_enabled INTEGER DEFAULT 0,
		read_only INTEGER DEFAULT 0,
		mcp_ip_whitelist TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO users (id, username, password_hash, role) VALUES (1, 'alice', 'x', 'user'), (2, 'bob', 'x', 'user');
	INSERT INTO api_keys (id, name, key_hash, key_prefix, created_by, is_enabled) VALUES (10, 'alice-key', 'h1', 'prefix1', 1, 1), (20, 'bob-key', 'h2', 'prefix2', 2, 1);`)
	if err != nil {
		t.Fatal(err)
	}
	// M6（契约）：特权 Key 创建走共享密码确认门——user 1 配真实 bcrypt 哈希。
	hash, err := bcrypt.GenerateFromPassword([]byte("alice-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE users SET password_hash=? WHERE id=1", string(hash)); err != nil {
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
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].ID != 10 || body.Data[0].Username != "alice" {
		t.Fatalf("unexpected keys: %#v", body.Data)
	}
}

func TestListAPIKeysIncludesUsernameOwnership(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)

	(&Handlers{}).ListAPIKeys(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data []struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 2 || body.Data[0].ID != 10 || body.Data[0].Username != "alice" || body.Data[1].ID != 20 || body.Data[1].Username != "bob" {
		t.Fatalf("unexpected key ownership: %#v", body.Data)
	}
}

func TestCertJobEndpointsSerializeNullableTimes(t *testing.T) {
	h := newBackupTestHandlers(t)
	validTime := time.Date(2026, time.July, 30, 12, 34, 56, 0, time.UTC)
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, expires_at, created_at, updated_at, ca_available_after)
		VALUES ('lb_valid', 'valid.example', 'issued', ?, ?, ?, ?),
		       ('lb_null', 'null.example', 'queued', NULL, ?, NULL, NULL)`, validTime, validTime, validTime, validTime, validTime)
	if err != nil {
		t.Fatalf("seed certificate jobs: %v", err)
	}
	nullID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	validID := nullID - 1

	t.Run("list", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/cert-jobs", nil)
		h.ListCertJobs(ctx)

		body := recorder.Body.String()
		if recorder.Code != http.StatusOK || !strings.Contains(body, `"expires_at":"2026-07-30T12:34:56Z"`) || !strings.Contains(body, `"updated_at":"2026-07-30T12:34:56Z"`) || !strings.Contains(body, `"ca_available_after":"2026-07-30T12:34:56Z"`) || !strings.Contains(body, `"expires_at":null`) || !strings.Contains(body, `"updated_at":null`) || !strings.Contains(body, `"ca_available_after":null`) {
			t.Fatalf("status=%d body=%s", recorder.Code, body)
		}
		if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
			t.Fatalf("response leaked sql.NullTime representation: %s", body)
		}
	})

	for _, tt := range []struct {
		name string
		id   int64
		want []string
	}{
		{name: "valid", id: validID, want: []string{`"expires_at":"2026-07-30T12:34:56Z"`, `"ca_available_after":"2026-07-30T12:34:56Z"`}},
		{name: "null", id: nullID, want: []string{`"expires_at":null`, `"ca_available_after":null`}},
	} {
		t.Run("detail "+tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/cert-jobs/"+strconv.FormatInt(tt.id, 10), nil)
			ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatInt(tt.id, 10)}}
			h.GetCertJob(ctx)

			body := recorder.Body.String()
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, body)
			}
			for _, want := range tt.want {
				if !strings.Contains(body, want) {
					t.Fatalf("body=%s, want %s", body, want)
				}
			}
			if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
				t.Fatalf("response leaked sql.NullTime representation: %s", body)
			}
		})
	}
}

func TestCertificateConfigEndpointsHandleNullDNSCredentials(t *testing.T) {
	h := newBackupTestHandlers(t)
	result, err := db.DB.Exec("INSERT INTO certificate_configs (name, dns_provider, dns_credentials, enabled) VALUES ('legacy', 'dnspod', NULL, 1)")
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}

	t.Run("list", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/certificate-configs", nil)
		h.ListCertificateConfigs(ctx)

		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"dns_credentials":""`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("test", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/certificate-configs/"+strconv.FormatInt(id, 10)+"/test", strings.NewReader(`{"domain":"example.com"}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatInt(id, 10)}}
		h.TestCertificateConfig(ctx)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want credential validation error instead of 404", recorder.Code, recorder.Body.String())
		}
	})
}

func TestRegisterClusterNodeRejectsInvalidAddressAndPort(t *testing.T) {
	h := newBackupTestHandlers(t)
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid IP", body: `{"token":"token","name":"node","ip_address":"not-an-ip","port":8000}`},
		{name: "negative port", body: `{"token":"token","name":"node","ip_address":"127.0.0.1","port":-1}`},
		{name: "port too large", body: `{"token":"token","name":"node","ip_address":"127.0.0.1","port":65536}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(tt.body))
			ctx.Request.Header.Set("Content-Type", "application/json")
			h.RegisterClusterNode(ctx)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestListCurrentUserAPIKeys_serializes_nullable_times_as_strings_or_null(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec("UPDATE api_keys SET last_used=?, expires_at=? WHERE id=10", time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC), nil); err != nil {
		t.Fatalf("seed API key times: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/api-keys", nil)
	ctx.Set("user_id", 1)

	// When
	(&Handlers{}).ListCurrentUserAPIKeys(ctx)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"last_used":"2026-07-30T01:02:03Z"`) || !strings.Contains(body, `"expires_at":null`) {
		t.Fatalf("unexpected nullable time JSON: %s", body)
	}
	if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
		t.Fatalf("response leaked sql.NullTime representation: %s", body)
	}
}

func TestListAPIKeys_serializes_nullable_times_as_strings_or_null(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec("UPDATE api_keys SET expires_at=? WHERE id=20", time.Date(2026, time.August, 1, 2, 3, 4, 0, time.UTC)); err != nil {
		t.Fatalf("seed API key expiry: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)

	// When
	(&Handlers{}).ListAPIKeys(ctx)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"expires_at":"2026-08-01T02:03:04Z"`) || !strings.Contains(body, `"last_used":null`) {
		t.Fatalf("unexpected nullable time JSON: %s", body)
	}
	if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
		t.Fatalf("response leaked sql.NullTime representation: %s", body)
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

func TestDeleteCurrentUserAPIKey_returns_not_found_when_row_disappears_before_delete(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec(`CREATE TRIGGER delete_key_before_outer_delete BEFORE DELETE ON api_keys
		WHEN OLD.id=10 BEGIN DELETE FROM api_keys WHERE id=OLD.id; SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create delete race trigger: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/api-keys/10", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)

	// When
	(&Handlers{}).DeleteCurrentUserAPIKey(ctx)

	// Then
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateAPIKeyStatus_returns_not_found_when_row_disappears_before_update(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec(`CREATE TRIGGER delete_key_before_status_update BEFORE UPDATE ON api_keys
		WHEN OLD.id=10 BEGIN DELETE FROM api_keys WHERE id=OLD.id; SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create update race trigger: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/api-keys/10/status", strings.NewReader(`{"is_enabled":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}

	// When
	(&Handlers{}).UpdateAPIKeyStatus(ctx)

	// Then
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
}

func TestCreateCurrentUserAPIKeyReturnsPlaintextOnce(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"ci"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

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
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE name='ci'").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if !readOnly {
		t.Fatal("non-admin API key was not forced to read-only")
	}
}

func TestUpdateCurrentUserAPIKeyRejectsDisablingReadOnly(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10", strings.NewReader(`{"read_only":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "普通用户密钥必须为只读") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateCurrentUserAPIKeyForcesLegacyKeyReadOnly(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10", strings.NewReader(`{"mcp_enabled":true}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE id=10").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if !readOnly {
		t.Fatal("legacy non-admin API key remained writable")
	}
}

func TestAdminAPIKeyReadOnlySettingIsUnchanged(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	// M6（契约）：可写 Key 属特权 Key，须真实密码种子并携带 password 过共享确认门
	hash, err := bcrypt.GenerateFromPassword([]byte("admin-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec("UPDATE users SET password_hash=? WHERE id=1", string(hash)); err != nil {
		t.Fatalf("seed admin hash: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"name":"admin-write","read_only":false,"password":"admin-secret"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")

	(&Handlers{}).CreateAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE name='admin-write'").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if readOnly {
		t.Fatal("admin API key read_only=false was overridden")
	}
}

func TestAdminCanDisableReadOnlyOnOwnAPIKey(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec("UPDATE api_keys SET read_only=1 WHERE id=10"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10", strings.NewReader(`{"read_only":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")

	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE id=10").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if readOnly {
		t.Fatal("admin could not disable read_only on own API key")
	}
}

func TestCreateCurrentUserAPIKeyNormalizesMCPWhitelist(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	// M6（契约）：mcp_enabled Key 属特权 Key，须携带密码过共享确认门。
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"mcp","mcp_enabled":true,"read_only":true,"mcp_ip_whitelist":["192.168.1.5","2001:db8::1"],"password":"alice-secret"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)

	(&Handlers{}).CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var mcpEnabled, readOnly bool
	var whitelist string
	if err := database.QueryRow("SELECT mcp_enabled,read_only,mcp_ip_whitelist FROM api_keys WHERE name='mcp'").Scan(&mcpEnabled, &readOnly, &whitelist); err != nil {
		t.Fatal(err)
	}
	if !mcpEnabled || !readOnly || whitelist != `["192.168.1.5/32","2001:db8::1/128"]` {
		t.Fatalf("mcp_enabled=%v read_only=%v whitelist=%q", mcpEnabled, readOnly, whitelist)
	}
}

func TestUpdateAPIKeyRejectsInvalidMCPWhitelist(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/api-keys/10/status", strings.NewReader(`{"mcp_ip_whitelist":["invalid"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}

	(&Handlers{}).UpdateAPIKeyStatus(ctx)

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "MCP IP 白名单无效") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
