package middleware

import (
	"database/sql"
	"fmt"
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

// SYSMW-U1（第 69 轮 P3）：认证审计限流器容量硬上限——PERF43-3 的 1024 清扫阈值
// 只清 >=2min 陈旧键，洪水期（唯一 reason+path+ip 键高速涌入）全部键新鲜、清扫
// 零效果，map 曾无界增长（对照 loginRateBuckets 1024 硬拒建桶的真上限）。修复=
// 清扫后仍达硬上限（4096）则丢弃新键：不进 map 也不记审计（审计丢失可接受，
// 内存必须有界），与 loginRateBuckets「超限本轮放行不添桶」同族。
func TestAuthenticationAuditLimiter_floodHardCap(t *testing.T) {
	// Given：4096 个新鲜唯一键灌满（同分钟窗写入——清扫对新鲜键零效果）
	securityAuditLimiter.reset()
	t.Cleanup(securityAuditLimiter.reset)
	now := time.Now()
	for i := 0; i < 4096; i++ {
		if !securityAuditLimiter.allow(fmt.Sprintf("flood-%d", i), now) {
			t.Fatalf("key %d within hard cap must be admitted", i)
		}
	}

	// When：第 4097 个新键（洪水形状）
	if securityAuditLimiter.allow("flood-overflow", now) {
		t.Fatal("硬上限已满，新键必须丢弃（不记 map 不记审计）")
	}

	// Then：map 规模封顶 4096
	securityAuditLimiter.mu.Lock()
	size := len(securityAuditLimiter.events)
	securityAuditLimiter.mu.Unlock()
	if size != 4096 {
		t.Fatalf("events size=%d, want hard cap 4096（洪水期内存必须有界）", size)
	}

	// And 回归形状：既有键超 1min 窗刷新不占新键额——照常放行记审计；
	// 61s 后清扫仍零效果（<2min），新键依旧拒。
	later := now.Add(61 * time.Second)
	if !securityAuditLimiter.allow("flood-0", later) {
		t.Fatal("既有键超窗刷新不得受容量上限影响")
	}
	if securityAuditLimiter.allow("flood-overflow-2", later) {
		t.Fatal("容量已满时新键仍须丢弃")
	}
	securityAuditLimiter.mu.Lock()
	size = len(securityAuditLimiter.events)
	securityAuditLimiter.mu.Unlock()
	if size != 4096 {
		t.Fatalf("events size after refresh=%d, want 4096（既有键刷新不扩容）", size)
	}
}
