package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestIsSynchronizedWrite_classifies_only_snapshot_content_mutations(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{"PUT", "/api/v1/config", true},
		{"POST", "/api/v1/config/preview", false},
		{"PUT", "/api/v1/caddy/config", true},
		{"POST", "/api/v1/rules", true},
		{"POST", "/api/v1/rules/cert-info", false},
		{"PATCH", "/api/v1/users/me", true},
		{"DELETE", "/api/v1/api-keys/:id", true},
		{"POST", "/api/v1/cluster/mode", false},
	}
	for _, test := range tests {
		if got := isSynchronizedWrite(test.method, test.path); got != test.want {
			t.Errorf("isSynchronizedWrite(%s %s)=%v, want %v", test.method, test.path, got, test.want)
		}
	}
}

func TestClusterVersionMiddleware_bumps_in_business_write_transaction(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	gin.SetMode(gin.TestMode)
	requestContext, cancel := context.WithCancel(context.Background())
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	router.POST("/api/v1/rules", func(c *gin.Context) {
		if _, err := database.ExecContext(c.Request.Context(), `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_version', 'version', 'http', 8080)`); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		cancel()
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil).WithContext(requestContext)
	recorder := httptest.NewRecorder()

	// When
	router.ServeHTTP(recorder, request)

	// Then
	var version int
	if err := database.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if recorder.Code != http.StatusNoContent || version != 1 {
		t.Fatalf("response=%d version=%d, want 204 and 1", recorder.Code, version)
	}
}

func TestClusterVersionMiddleware_rolls_back_business_write_when_version_bump_fails(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	if _, err := database.Exec(`CREATE TRIGGER reject_cluster_version BEFORE UPDATE OF cluster_version ON global_config
		BEGIN SELECT RAISE(ABORT, 'cluster version unavailable'); END`); err != nil {
		t.Fatalf("install failing bump trigger: %v", err)
	}
	router.POST("/api/v1/rules", func(c *gin.Context) {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_rollback', 'rollback', 'http', 8080)`); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"saved": true})
	})
	recorder := httptest.NewRecorder()

	// When
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("response status=%d body=%q, want 500", recorder.Code, recorder.Body.String())
	}
	var count, version int
	if err := database.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_rollback'").Scan(&count); err != nil {
		t.Fatalf("count rolled back rules: %v", err)
	}
	if err := database.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if count != 0 || version != 0 {
		t.Fatalf("rule count=%d version=%d, want both unchanged", count, version)
	}
}
