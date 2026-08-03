package middleware

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
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
