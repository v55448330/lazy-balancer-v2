package middleware

import (
	"database/sql"
	"lazy-balancer-v2/internal/services"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 集群机器凭据的枚举尝试必须留安全审计痕迹——此前
// clusterTokenAuth/registrationAuth 只返回 401，审计日志零线索（进程重启后
// 内存限流桶也清零，取证完全缺失）。
func TestClusterAuthMiddlewares_recordAuthRejectionAudit(t *testing.T) {
	database, _ := newClusterAuthContractDatabase(t)
	oldRecorder := recordAuthenticationSecurityAudit
	var recorded []string
	recordAuthenticationSecurityAudit = func(_ string, _ string, _ string, detail services.AuditDetail, _ string) {
		recorded = append(recorded, detail.Text())
	}
	t.Cleanup(func() { recordAuthenticationSecurityAudit = oldRecorder })
	securityAuditLimiter.reset()
	t.Cleanup(securityAuditLimiter.reset)

	t.Run("cluster token", func(t *testing.T) {
		router := newClusterAuthContractRouter(database)
		request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
		request.Header.Set("X-Cluster-Token", "definitely-not-the-token")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want 401", response.Code)
		}
		if len(recorded) != 1 || !strings.Contains(recorded[0], "cluster_token_invalid") {
			t.Fatalf("recorded=%v, want 含 cluster_token_invalid", recorded)
		}
	})

	t.Run("registration secret", func(t *testing.T) {
		recorded = nil
		registrationDB, regErr := sql.Open("sqlite", t.TempDir()+"/registration-audit.db")
		if regErr != nil {
			t.Fatal(regErr)
		}
		t.Cleanup(func() { _ = registrationDB.Close() })
		if _, execErr := registrationDB.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, registration_secret TEXT, registration_secret_expires_at DATETIME, is_approved INTEGER DEFAULT 0, cluster_token_hash TEXT);
			INSERT INTO nodes (id, registration_secret, registration_secret_expires_at) VALUES (7, 'abc', datetime('now','+1 hour'))`); execErr != nil {
			t.Fatal(execErr)
		}
		router := gin.New()
		router.GET("/cluster/register/:id/status", registrationAuth(registrationDB), func(c *gin.Context) { c.Status(http.StatusOK) })
		request := httptest.NewRequest(http.MethodGet, "/cluster/register/7/status", nil)
		request.Header.Set("X-Registration-Secret", "wrong-secret")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want 401", response.Code)
		}
		if len(recorded) != 1 || !strings.Contains(recorded[0], "registration_secret_invalid") {
			t.Fatalf("recorded=%v, want 含 registration_secret_invalid", recorded)
		}
	})
}

// API Key 认证必须区分「Key 无效」与基础设施故障——
// DB 故障时返回 401「API 密钥无效」会诱导全站客户端重登且日志零线索。
func TestAPIKeyAuth_mapsInfrastructureFailureTo500(t *testing.T) {
	database := newIsolatedTestDB(t)
	if _, err := database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, is_enabled BOOLEAN);
	CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name TEXT, key_hash TEXT, key_prefix TEXT, created_by INTEGER,
		last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN, mcp_enabled INTEGER, api_enabled INTEGER DEFAULT 1, read_only INTEGER,
		api_read_only INTEGER DEFAULT 0, mcp_read_only INTEGER DEFAULT 0, mcp_ip_whitelist TEXT, created_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(apiKeyAuth(db.DB))
	router.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Header.Set("X-API-Key", "lb_sk_wellformed-but-db-down")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（DB 故障不得折叠成 401 密钥无效）", response.Code, response.Body.String())
	}
}
