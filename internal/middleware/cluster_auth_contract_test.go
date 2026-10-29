package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func TestClusterTokenAuth_rejects_raw_authorization_token(t *testing.T) {
	// Given
	database, token := newClusterAuthContractDatabase(t)
	router := newClusterAuthContractRouter(database)
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.Header.Set("Authorization", token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

func TestClusterTokenAuth_rejects_empty_bearer_token(t *testing.T) {
	// Given
	database, _ := newClusterAuthContractDatabase(t)
	router := newClusterAuthContractRouter(database)
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.Header.Set("Authorization", "Bearer ")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

func TestClusterTokenAuth_stores_normalized_bearer_token_in_context(t *testing.T) {
	// Given
	database, token := newClusterAuthContractDatabase(t)
	router := newClusterAuthContractRouter(database)
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK || response.Body.String() != token {
		t.Fatalf("status=%d body=%q, want authenticated context token", response.Code, response.Body.String())
	}
}

func newClusterAuthContractDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	database, err := sql.Open("sqlite", t.TempDir()+"/cluster-auth.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE nodes (id INTEGER PRIMARY KEY, cluster_token_hash TEXT, is_approved BOOLEAN)"); err != nil {
		t.Fatal(err)
	}
	const token = "cluster-contract-token"
	hash := sha256.Sum256([]byte(token))
	if _, err := database.Exec("INSERT INTO nodes VALUES (7, ?, 1)", hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	return database, token
}

func newClusterAuthContractRouter(database *sql.DB) *gin.Engine {
	router := gin.New()
	router.Use(clusterTokenAuth(database))
	router.GET("/cluster", func(c *gin.Context) {
		c.String(http.StatusOK, c.GetString("cluster_token"))
	})
	return router
}

func TestClusterAuthMiddlewares_mapDatabaseFailuresTo500(t *testing.T) {
	t.Run("cluster token", func(t *testing.T) {
		// Given：非空有效形态凭证 + 已关闭数据库（基础设施故障而非凭证无效）。
		database, token := newClusterAuthContractDatabase(t)
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		router := newClusterAuthContractRouter(database)
		request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
		request.Header.Set("X-Cluster-Token", token)
		response := httptest.NewRecorder()

		// When
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500 for database failure", response.Code, response.Body.String())
		}
	})
	t.Run("registration secret", func(t *testing.T) {
		database, err := sql.Open("sqlite", t.TempDir()+"/registration-auth-failure.db")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = database.Close() })
		if _, err := database.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, registration_secret TEXT, registration_secret_expires_at DATETIME)`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		router := gin.New()
		router.GET("/cluster/register/:id/status", registrationAuth(database), func(c *gin.Context) { c.Status(http.StatusOK) })
		request := httptest.NewRequest(http.MethodGet, "/cluster/register/7/status", nil)
		request.Header.Set("X-Registration-Secret", "non-empty-secret")
		response := httptest.NewRecorder()

		// When
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500 for database failure", response.Code, response.Body.String())
		}
	})
}

// AuthenticateRegistrationSecret 哈希比对改常量时间
// (镜像 services/cluster.go RegistrationStatus 的形态)——防御一致性
// 改写,无行为差异。本测试为基线钉(非 RED):钉住改写前后契约不变——
// 有效注册密钥通过;错误/空密钥、未知节点、过期密钥一律拒绝。
func TestAuthenticateRegistrationSecret_contract(t *testing.T) {
	// Given
	database, err := sql.Open("sqlite", t.TempDir()+"/registration-auth.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, registration_secret TEXT, registration_secret_expires_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	const secret = "registration-contract-secret"
	hash := sha256.Sum256([]byte(secret))
	if _, err := database.Exec(`INSERT INTO nodes (id, registration_secret, registration_secret_expires_at) VALUES (7, ?, datetime('now','+24 hours'))`, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// When / Then:有效密钥通过
	if err := services.AuthenticateRegistrationSecret(ctx, database, 7, secret); err != nil {
		t.Fatalf("valid registration secret rejected: %v", err)
	}
	// 错误密钥拒绝
	if err := services.AuthenticateRegistrationSecret(ctx, database, 7, "wrong-secret"); !errors.Is(err, services.ErrInvalidClusterAuth) {
		t.Fatalf("wrong secret err=%v, want ErrInvalidClusterAuth", err)
	}
	// 空密钥拒绝
	if err := services.AuthenticateRegistrationSecret(ctx, database, 7, ""); !errors.Is(err, services.ErrInvalidClusterAuth) {
		t.Fatalf("empty secret err=%v, want ErrInvalidClusterAuth", err)
	}
	// 未知节点拒绝
	if err := services.AuthenticateRegistrationSecret(ctx, database, 404, secret); !errors.Is(err, services.ErrInvalidClusterAuth) {
		t.Fatalf("unknown node err=%v, want ErrInvalidClusterAuth", err)
	}
	// 过期密钥拒绝
	if _, err := database.Exec(`UPDATE nodes SET registration_secret_expires_at=datetime('now','-1 minute') WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	if err := services.AuthenticateRegistrationSecret(ctx, database, 7, secret); !errors.Is(err, services.ErrInvalidClusterAuth) {
		t.Fatalf("expired secret err=%v, want ErrInvalidClusterAuth", err)
	}
}

// bearerToken 是 jwtAuth / clusterTokenAuth / registrationAuth / 凭据指纹的
// 单源解析：RFC 7235 §2.1 规定 auth-scheme 大小写不敏感——小写/大写方案的
// 手写客户端不得被拒；裸 token（无 scheme）与空令牌仍返回空串（调用方按
// 既有契约拒绝）。
func TestBearerToken_schemeIsCaseInsensitive(t *testing.T) {
	for _, test := range []struct {
		name   string
		header string
		want   string
	}{
		{"标准大写", "Bearer abc123", "abc123"},
		{"小写方案", "bearer abc123", "abc123"},
		{"全大写方案", "BEARER abc123", "abc123"},
		{"混合大小写", "BeArEr abc123", "abc123"},
		{"多空白分隔", "Bearer \t abc123", "abc123"},
		{"tab 分隔", "Bearer\tabc123", "abc123"},
		{"额外字段", "Bearer abc123 extra", ""},
		{"空令牌", "Bearer ", ""},
		{"只有方案无空格", "Bearer", ""},
		{"裸 token", "abc123", ""},
		{"空头", "", ""},
		{"其它方案", "Basic dXNlcjpwYXNz", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := bearerToken(test.header); got != test.want {
				t.Fatalf("bearerToken(%q)=%q, want %q", test.header, got, test.want)
			}
		})
	}
}
