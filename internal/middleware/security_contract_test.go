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

func TestJWTAuth_rejects_token_without_expiration(t *testing.T) {
	// Given
	cfg, token := newJWTContractFixture(t, jwt.SigningMethodHS256, false)
	router := gin.New()
	router.Use(jwtAuth(cfg))
	router.GET("/protected", noContent)
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

func TestJWTAuth_rejects_non_HS256_HMAC_algorithms(t *testing.T) {
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		t.Run(method.Alg(), func(t *testing.T) {
			// Given
			cfg, token := newJWTContractFixture(t, method, true)
			router := gin.New()
			router.Use(jwtAuth(cfg))
			router.GET("/protected", noContent)
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
			}
		})
	}
}

func TestAdminOnly_records_rate_limited_security_event_without_credential(t *testing.T) {
	// Given
	const credential = "admin-jwt-plaintext"
	recorded := captureAuthenticationSecurityAudits(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("role", "user")
		c.Next()
	}, adminOnly())
	router.POST("/admin", noContent)

	// When
	serveRepeatedDeniedRequests(router, http.MethodPost, "/admin", "Authorization", "Bearer "+credential)

	// Then
	assertSingleSecurityAudit(t, *recorded, "admin_required", credential)
}

func TestAPIKeyReadOnlyGuard_records_rate_limited_security_event_without_credential(t *testing.T) {
	// Given
	const credential = "lb_sk_read-only-plaintext"
	recorded := captureAuthenticationSecurityAudits(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", true)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.POST("/write", noContent)

	// When
	serveRepeatedDeniedRequests(router, http.MethodPost, "/write", "X-API-Key", credential)

	// Then
	assertSingleSecurityAudit(t, *recorded, "api_key_read_only", credential)
}

func TestReadOnlyGuard_records_rate_limited_security_event_without_credential(t *testing.T) {
	// Given
	const credential = "slave-jwt-plaintext"
	recorded := captureAuthenticationSecurityAudits(t)
	database, err := sql.Open("sqlite", t.TempDir()+"/readonly-audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1, 0)"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(readOnlyGuard(database))
	router.POST("/api/v1/rules", noContent)

	// When
	serveRepeatedDeniedRequests(router, http.MethodPost, "/api/v1/rules", "Authorization", "Bearer "+credential)

	// Then
	assertSingleSecurityAudit(t, *recorded, "slave_write_denied", credential)
}

func newJWTContractFixture(t *testing.T, method jwt.SigningMethod, includeExpiration bool) (*config.Config, string) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (41,'contract-user','hash','user',1,0)"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "contract-secret"}
	claims := jwt.MapClaims{"user_id": 41, "username": "contract-user", "pwd_ver": 0}
	if includeExpiration {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	token, err := jwt.NewWithClaims(method, claims).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, token
}

func captureAuthenticationSecurityAudits(t *testing.T) *[]string {
	t.Helper()
	oldRecorder := recordAuthenticationSecurityAudit
	securityAuditLimiter.reset()
	recorded := make([]string, 0, 1)
	recordAuthenticationSecurityAudit = func(username, action, resource, detail, ipAddress string) {
		recorded = append(recorded, strings.Join([]string{username, action, resource, detail, ipAddress}, " "))
	}
	t.Cleanup(func() {
		recordAuthenticationSecurityAudit = oldRecorder
		securityAuditLimiter.reset()
	})
	return &recorded
}

func serveRepeatedDeniedRequests(router *gin.Engine, method, path, header, credential string) {
	for range 2 {
		request := httptest.NewRequest(method, path, nil)
		request.RemoteAddr = "198.51.100.77:1234"
		request.Header.Set(header, credential)
		router.ServeHTTP(httptest.NewRecorder(), request)
	}
}

func assertSingleSecurityAudit(t *testing.T, recorded []string, reason, credential string) {
	t.Helper()
	if len(recorded) != 1 {
		t.Fatalf("security audit events=%d, want 1: %q", len(recorded), recorded)
	}
	if !strings.Contains(recorded[0], "原因类别："+reason) {
		t.Fatalf("security audit=%q, want reason %q", recorded[0], reason)
	}
	if strings.Contains(recorded[0], credential) {
		t.Fatalf("security audit leaked credential: %q", recorded[0])
	}
}
