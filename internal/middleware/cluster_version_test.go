package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
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

func TestClusterVersionTriggers_bump_for_snapshot_insert_update_delete(t *testing.T) {
	tests := []struct {
		name   string
		seed   string
		insert string
		update string
		delete string
	}{
		{name: "lb_rules", insert: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_rule','rule','http',8080)`, update: `UPDATE lb_rules SET name='updated' WHERE caddy_id='matrix_rule'`, delete: `DELETE FROM lb_rules WHERE caddy_id='matrix_rule'`},
		{name: "upstreams", seed: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_parent','parent','http',8080)`, insert: `INSERT INTO upstreams (rule_id,host,port) VALUES ('matrix_parent','127.0.0.1',80)`, update: `UPDATE upstreams SET host='127.0.0.2' WHERE rule_id='matrix_parent'`, delete: `DELETE FROM upstreams WHERE rule_id='matrix_parent'`},
		{name: "path_rules", seed: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_parent','parent','http',8080)`, insert: `INSERT INTO path_rules (rule_id,path) VALUES ('matrix_parent','/old')`, update: `UPDATE path_rules SET path='/new' WHERE rule_id='matrix_parent'`, delete: `DELETE FROM path_rules WHERE rule_id='matrix_parent'`},
		{name: "users", insert: `INSERT INTO users (username,password_hash) VALUES ('matrix_user','hash')`, update: `UPDATE users SET display_name='updated' WHERE username='matrix_user'`, delete: `DELETE FROM users WHERE username='matrix_user'`},
		{name: "api_keys", seed: `INSERT INTO users (username,password_hash) VALUES ('matrix_owner','hash')`, insert: `INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('matrix_key','hash','prefix',1)`, update: `UPDATE api_keys SET name='updated' WHERE key_prefix='prefix'`, delete: `DELETE FROM api_keys WHERE key_prefix='prefix'`},
		{name: "cert_jobs", insert: `INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('matrix_rule','example.com','issued')`, update: `UPDATE cert_jobs SET cert_pem='certificate' WHERE rule_id='matrix_rule'`, delete: `DELETE FROM cert_jobs WHERE rule_id='matrix_rule'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			database := newClusterVersionTestDB(t)
			if test.seed != "" {
				if _, err := database.Exec(test.seed); err != nil {
					t.Fatalf("seed dependency: %v", err)
				}
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatalf("seed cluster version: %v", err)
			}
			if err := installClusterVersionTriggers(database); err != nil {
				t.Fatalf("install triggers: %v", err)
			}
			if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
				t.Fatalf("reset cluster version: %v", err)
			}

			operations := []struct {
				name      string
				statement string
				version   int
			}{
				{name: "insert", statement: test.insert, version: 1},
				{name: "update", statement: test.update, version: 2},
				{name: "delete", statement: test.delete, version: 3},
			}
			for _, operation := range operations {
				// When
				if _, err := database.Exec(operation.statement); err != nil {
					t.Fatalf("%s row: %v", operation.name, err)
				}

				// Then
				if got := clusterVersion(t, database); got != operation.version {
					t.Fatalf("version after %s=%d, want %d", operation.name, got, operation.version)
				}
			}
		})
	}
}

func TestClusterVersionTriggers_doNotBumpForAPIKeyLastUsed(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (username,password_hash) VALUES ('last_used_owner','hash')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('last_used','hash','prefix',1)`); err != nil {
		t.Fatalf("seed API key: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER cluster_version_api_keys_update AFTER UPDATE ON api_keys
		BEGIN UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1; END`); err != nil {
		t.Fatalf("install legacy trigger: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("replace triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatalf("seed cluster version: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}

	// When
	if _, err := database.Exec(`UPDATE api_keys SET last_used=CURRENT_TIMESTAMP WHERE key_prefix='prefix'`); err != nil {
		t.Fatalf("update last_used: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after last_used update=%d, want 0", got)
	}
}

func TestClusterVersionTriggers_doNotBumpForCertificateProgress(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain) VALUES ('progress_rule','example.com')`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatalf("seed cluster version: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}

	// When
	if _, err := database.Exec(`UPDATE cert_jobs SET status='processing', message='working', updated_at=CURRENT_TIMESTAMP WHERE rule_id='progress_rule'`); err != nil {
		t.Fatalf("update certificate progress: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after certificate progress update=%d, want 0", got)
	}
}

func TestClusterVersionTriggers_refreshCachedSnapshotWhenCertificateEntersAndLeavesIssued(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('status_rule','example.com','downloaded','certificate','key')`); err != nil {
		t.Fatalf("seed downloaded certificate: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	cluster := services.NewClusterService(database, nil)
	downloadedSnapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build downloaded snapshot: %v", err)
	}
	if len(downloadedSnapshot.Certs) != 0 {
		t.Fatalf("downloaded snapshot certificates=%d, want 0", len(downloadedSnapshot.Certs))
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='status_rule'"); err != nil {
		t.Fatalf("mark certificate issued: %v", err)
	}
	issuedSnapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build issued snapshot: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after issued=%d, want 1", got)
	}
	if len(issuedSnapshot.Certs) != 1 || issuedSnapshot.Certs[0].RuleID != "status_rule" {
		t.Fatalf("issued snapshot certificates=%+v, want status_rule", issuedSnapshot.Certs)
	}

	// When
	if _, err := database.Exec("UPDATE cert_jobs SET status='disabled' WHERE rule_id='status_rule'"); err != nil {
		t.Fatalf("disable certificate: %v", err)
	}
	disabledSnapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build disabled snapshot: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 2 {
		t.Fatalf("version after disabled=%d, want 2", got)
	}
	if len(disabledSnapshot.Certs) != 0 {
		t.Fatalf("disabled snapshot certificates=%+v, want none", disabledSnapshot.Certs)
	}
}

func TestClusterVersionTriggers_doNotBumpForGlobalSyncMetadata(t *testing.T) {
	// Given
	database := newClusterVersionTestDB(t)
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=100 WHERE id=1"); err != nil {
		t.Fatalf("seed cluster version: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}

	// When
	if _, err := database.Exec("UPDATE global_config SET last_sync=CURRENT_TIMESTAMP WHERE id=1"); err != nil {
		t.Fatalf("update sync metadata: %v", err)
	}

	// Then
	if got := clusterVersion(t, database); got != 0 {
		t.Fatalf("version after sync metadata update=%d, want 0", got)
	}
}

func newClusterVersionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	return database
}

func clusterVersion(t *testing.T, database *sql.DB) int {
	t.Helper()
	var version int
	if err := database.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	return version
}
