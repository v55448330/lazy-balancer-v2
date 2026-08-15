package handlers

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestUserPasswordEndpoints_reject_passwords_shorter_than_six_characters(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: `{"username":"short-create","password":"12345","role":"user"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: `{"password":"12345"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/password", body: `{"new_password":"12345"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/password", h.ResetUserPassword) }},
		{name: "update current user", method: http.MethodPut, path: "/me", body: `{"password":"12345"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.PUT("/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'existing','old-hash','admin','Before')"); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			router := gin.New()
			test.mount(router, h)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			var passwordHash string
			if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
				t.Fatalf("read password hash: %v", err)
			}
			if passwordHash != "old-hash" {
				t.Fatalf("password hash=%q, want unchanged", passwordHash)
			}
		})
	}
}

func TestUpdateCurrentUser_rolls_back_display_name_when_password_update_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'current','old-hash','admin','Before')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("CREATE TRIGGER fail_current_password BEFORE UPDATE OF password_hash ON users BEGIN SELECT RAISE(ABORT,'password update failed'); END"); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	router := gin.New()
	router.PUT("/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
	request := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(`{"display_name":"After","password":"secret1"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var displayName, passwordHash string
	if err := db.DB.QueryRow("SELECT display_name,password_hash FROM users WHERE id=1").Scan(&displayName, &passwordHash); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if displayName != "Before" || passwordHash != "old-hash" {
		t.Fatalf("user=(%q,%q), want original state", displayName, passwordHash)
	}
}

func TestUserMutationEndpoints_validate_ID_and_return_not_found(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		mount      func(*gin.Engine, *Handlers)
		wantStatus int
	}{
		{name: "toggle invalid id", path: "/users/not-a-number/status", body: `{"is_enabled":false}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id/status", h.ToggleUserStatus) }, wantStatus: http.StatusBadRequest},
		{name: "toggle missing user", path: "/users/999/status", body: `{"is_enabled":false}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id/status", h.ToggleUserStatus) }, wantStatus: http.StatusNotFound},
		{name: "reset invalid id", path: "/users/not-a-number/password", body: `{"new_password":"secret1"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id/password", h.ResetUserPassword) }, wantStatus: http.StatusBadRequest},
		{name: "reset missing user", path: "/users/999/password", body: `{"new_password":"secret1"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id/password", h.ResetUserPassword) }, wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec("ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 0"); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
				t.Fatalf("ensure password_version column: %v", err)
			}
			router := gin.New()
			test.mount(router, h)
			request := httptest.NewRequest(http.MethodPut, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
		})
	}
}

func TestListCurrentUserAPIKeys_returns_error_when_row_scan_fails(t *testing.T) {
	// Given
	setupAPIKeyTestDB(t)
	if _, err := db.DB.Exec("UPDATE api_keys SET created_at='not-a-time' WHERE id=10"); err != nil {
		t.Fatalf("corrupt API key row: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api-keys", nil)
	ctx.Set("user_id", 1)

	// When
	(&Handlers{}).ListCurrentUserAPIKeys(ctx)

	// Then
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}

func TestConfigImportEndpoints_reject_bodies_larger_than_16MiB(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		mount func(*gin.Engine, *Handlers)
	}{
		{name: "validate", path: "/validate", mount: func(r *gin.Engine, h *Handlers) { r.POST("/validate", h.ValidateConfigImport) }},
		{name: "v1 import", path: "/v1", mount: func(r *gin.Engine, h *Handlers) { r.POST("/v1", h.ImportV1Config) }},
		{name: "v2 import", path: "/v2", mount: func(r *gin.Engine, h *Handlers) { r.POST("/v2", h.ImportConfigBackup) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			router := gin.New()
			test.mount(router, h)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(strings.Repeat("x", (16<<20)+1)))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d body=%s, want 413", response.Code, response.Body.String())
			}
		})
	}
}

func TestRestoreRuleSnapshot_succeeds_with_detached_compensation_context(t *testing.T) {
	// Given
	_ = newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_ctx','before','http',8080)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	ruleRow, err := dumpRowByKey(context.Background(), "lb_rules", "caddy_id", "lb_ctx")
	if err != nil {
		t.Fatalf("snapshot rule: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET name='after' WHERE caddy_id='lb_ctx'"); err != nil {
		t.Fatalf("mutate rule: %v", err)
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	compensationCtx, cancelCompensation := compensationContext(requestCtx)
	defer cancelCompensation()

	// When
	err = restoreRuleSnapshot(compensationCtx, "lb_ctx", ruleRow, nil, nil)

	// Then
	if err != nil {
		t.Fatalf("restore with canceled request context: %v", err)
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_ctx'").Scan(&name); err != nil {
		t.Fatalf("read restored rule: %v", err)
	}
	if name != "before" {
		t.Fatalf("restored name=%q, want before", name)
	}
}

func TestUpdateRule_stops_before_database_commit_when_route_snapshot_fails(t *testing.T) {
	// Given
	initializeRuleFeatureTestDB(t)
	seedAuditRule(t, "lb_snapshot_fail", "before", "snapshot.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_snapshot_fail")
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			http.Error(w, "snapshot failed", http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	h := &Handlers{cfg: cfg, caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.PUT("/rules/:caddy_id", h.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_snapshot_fail", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_snapshot_fail'").Scan(&name); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if name != "before" {
		t.Fatalf("rule name=%q, want unchanged", name)
	}
}

func TestUpdateRule_restores_database_when_request_is_canceled_before_compensation(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_cancel_restore", 0, true)
	harness.blockOnRoutePost = 2
	seedAuditRule(t, "lb_cancel_restore", "before", "cancel-restore.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_cancel_restore")
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	firstRequest := httptest.NewRequest(http.MethodPut, "/rules/lb_cancel_restore", strings.NewReader(`{"name":"committed"}`))
	firstRequest.Header.Set("Content-Type", "application/json")
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("prime update status=%d body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	secondRequest := httptest.NewRequest(http.MethodPut, "/rules/lb_cancel_restore", strings.NewReader(`{"name":"must-rollback"}`)).WithContext(requestCtx)
	secondRequest.Header.Set("Content-Type", "application/json")
	secondResponse := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(secondResponse, secondRequest)
		close(done)
	}()
	<-harness.firstRouteEntered

	// When
	cancelRequest()
	harness.release()
	<-done

	// Then
	if secondResponse.Code == http.StatusOK {
		t.Fatalf("canceled update unexpectedly succeeded: %s", secondResponse.Body.String())
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_cancel_restore'").Scan(&name); err != nil {
		t.Fatalf("read restored rule: %v", err)
	}
	if name != "committed" {
		t.Fatalf("restored name=%q, want committed", name)
	}
}

func TestPutCaddyConfig_uses_service_load_and_preserves_database_when_Caddy_rejects(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("UPDATE global_config SET caddy_config='old-config' WHERE id=1"); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	var mu sync.Mutex
	currentConfig := `{"old":true}`
	loads := 0
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			mu.Lock()
			body := currentConfig
			mu.Unlock()
			_, _ = w.Write([]byte(body))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			loads++
			if loads == 1 {
				mu.Unlock()
				http.Error(w, "rejected", http.StatusBadRequest)
				return
			}
			currentConfig = string(body)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	h.caddyService = services.NewCaddyService(fakeCaddy.URL)
	router := gin.New()
	router.PUT("/caddy", h.PutCaddyConfig)
	request := httptest.NewRequest(http.MethodPut, "/caddy", strings.NewReader(`{"content":"{\"new\":true}"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT caddy_config FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read stored config: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if stored != "old-config" || currentConfig != `{"old":true}` || loads != 2 {
		t.Fatalf("stored=%q runtime=%s loads=%d, want DB and runtime restored", stored, currentConfig, loads)
	}
}

func TestUpdateConfig_restores_Caddy_when_commit_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("PRAGMA foreign_keys=ON; CREATE TABLE commit_parent(id INTEGER PRIMARY KEY); CREATE TABLE commit_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_config_commit AFTER UPDATE ON global_config BEGIN INSERT INTO commit_guard(parent_id) VALUES (999); END"); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}
	var mu sync.Mutex
	currentConfig := `{"old":true}`
	loads := 0
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			mu.Lock()
			body := currentConfig
			mu.Unlock()
			_, _ = w.Write([]byte(body))
		case r.Method == http.MethodPost && r.URL.Path == "/load" && r.URL.Query().Get("validate") == "true":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			loads++
			currentConfig = string(body)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	h.cfg = &config.Config{CaddyAdminURL: fakeCaddy.URL}
	h.caddyService = services.NewCaddyService(fakeCaddy.URL)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"dns_credentials":"new-id,new-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if loads != 2 || currentConfig != `{"old":true}` {
		t.Fatalf("Caddy loads=%d runtime=%s, want apply plus old snapshot restore", loads, currentConfig)
	}
}

func TestScanAPIKeys_returns_rows_iteration_error(t *testing.T) {
	// Given
	database, err := sql.Open("sqlite", t.TempDir()+"/rows.db")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE keys(id INTEGER); INSERT INTO keys VALUES (1)"); err != nil {
		t.Fatalf("seed database: %v", err)
	}
	rows, err := database.Query("SELECT id FROM keys")
	if err != nil {
		t.Fatalf("query rows: %v", err)
	}
	defer rows.Close()

	// When
	_, err = scanAPIKeys(rows)

	// Then
	if err == nil {
		t.Fatal("scanAPIKeys error=nil, want scan error")
	}
}
