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

// CL45-3(第 45 轮审计):AuthenticateRegistrationSecret 哈希比对改常量时间
// (镜像 services/cluster.go RegistrationStatus 的 CL41-5 形态)——防御一致性
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
