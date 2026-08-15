package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedDetachedNode(t *testing.T, token string) int64 {
	t.Helper()
	hash := sha256.Sum256([]byte(token))
	result, err := db.DB.Exec(`INSERT INTO nodes (name, ip_address, is_approved, status, cluster_token_hash) VALUES ('slave-a','127.0.0.1',1,'online',?)`, hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatalf("seed node: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read node id: %v", err)
	}
	return id
}

func detachNodeExists(t *testing.T, id int64) bool {
	t.Helper()
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM nodes WHERE id=?", id).Scan(&count); err != nil {
		t.Fatalf("query node: %v", err)
	}
	return count == 1
}

func TestReportClusterNode_detachedDeletesNode(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	const token = "detach-token"
	nodeID := seedDetachedNode(t, token)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/report", strings.NewReader(`{"applied_version":0,"service_status":"ok","detached":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Cluster-Token", token)
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if detachNodeExists(t, nodeID) {
		t.Fatal("node still exists after detached report")
	}
}

func TestReportClusterNode_detachedInvalidTokenRejected(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	const token = "detach-token"
	nodeID := seedDetachedNode(t, token)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/report", strings.NewReader(`{"applied_version":0,"service_status":"ok","detached":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Cluster-Token", "wrong-token")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", response.Code, response.Body.String())
	}
	if !detachNodeExists(t, nodeID) {
		t.Fatal("node deleted despite invalid token")
	}
}
