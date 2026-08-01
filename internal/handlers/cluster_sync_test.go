package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
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

func TestPullClusterSnapshot_persists_manual_sync_failure(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0, master_url='', cluster_token='', last_sync_error='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	syncService := services.NewSyncService(db.DB, &config.Config{DataDir: t.TempDir()}, nil)
	h := &Handlers{syncService: syncService}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/v1/cluster/sync/pull", nil).WithContext(context.Background())
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = request

	// When
	h.PullClusterSnapshot(ginContext)

	// Then
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError || stored == "" {
		t.Fatalf("status=%d stored=%q body=%q", response.Code, stored, response.Body.String())
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
