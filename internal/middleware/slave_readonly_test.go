package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

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
	router.POST("/api/v1/rules", noContent)
	router.POST("/api/v1/users", noContent)
	router.PATCH("/api/v1/users/me", noContent)
	router.POST("/api/v1/users/me/api-keys", noContent)
	router.POST("/api/v1/cluster/nodes/report", noContent)
	router.POST("/api/v1/auth/login", noContent)
	router.POST("/api/v1/rules/cert-info", noContent)
	router.POST("/api/v1/config/preview", noContent)
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
	oldDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() { db.DB = oldDB })
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
	router.Use(jwtAuth(cfg), readOnlyGuard(database))
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

func TestReadOnlyGuard_blocks_slave_profile_update(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, true, "user")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestReadOnlyGuard_blocks_slave_api_key_creation(t *testing.T) {
	// Given
	router := newReadOnlyGuardTestRouter(t, true, "user")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", nil))

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
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
