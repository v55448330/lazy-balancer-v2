package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthenticatedClusterToken_uses_bearer_token(t *testing.T) {
	// Given
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("GET", "/api/v1/cluster/sync/snapshot", nil)
	context.Request.Header.Set("Authorization", "Bearer bearer-token")

	// When
	token := authenticatedClusterToken(context)

	// Then
	if token != "bearer-token" {
		t.Fatalf("authenticated token=%q", token)
	}
}

func TestAuthenticatedClusterToken_prefers_middleware_context(t *testing.T) {
	// Given
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("GET", "/api/v1/cluster/sync/snapshot", nil)
	context.Request.Header.Set("X-Cluster-Token", "header-token")
	context.Set("cluster_token", "authenticated-token")

	// When
	token := authenticatedClusterToken(context)

	// Then
	if token != "authenticated-token" {
		t.Fatalf("authenticated token=%q", token)
	}
}
