package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
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
		{"PUT", "/api/v1/cluster/settings", true},
		{"PUT", "/api/v1/admin-tls", true},
		{"POST", "/api/v1/admin-tls/inspect", false},
		{"POST", "/api/v1/config/import", true},
		{"POST", "/api/v1/config/import/v1", true},
		{"POST", "/api/v1/config/import/validate", false},
		{"POST", "/api/v1/certificates/issue", true},
		{"POST", "/api/v1/certificates/jobs/:id/retry", true},
		{"DELETE", "/api/v1/certificates/jobs/:id", true},
		{"POST", "/api/v1/certificates/jobs/current", false},
		{"POST", "/api/v1/certificates/parse", false},
		{"GET", "/api/v1/certificates/jobs/:id", false},
		{"PUT", "/api/v1/ca-providers/:id", true},
		{"POST", "/api/v1/ca-providers/:id/test", false},
		{"POST", "/api/v1/certificate-configs", true},
		{"PUT", "/api/v1/certificate-configs/:id", true},
		{"DELETE", "/api/v1/certificate-configs/:id", true},
		{"POST", "/api/v1/certificate-configs/test", false},
		{"POST", "/api/v1/certificate-configs/:id/test", false},
		{"POST", "/api/v1/security/policies", true},
		{"PUT", "/api/v1/security/policies/:id", true},
		{"DELETE", "/api/v1/security/policies/:id", true},
		{"POST", "/api/v1/security/policies/:id/bind", true},
		{"DELETE", "/api/v1/security/policies/:id/bind/:caddy_id", true},
		{"POST", "/api/v1/security/custom-rules", true},
		{"PUT", "/api/v1/security/custom-rules/:id", true},
		{"DELETE", "/api/v1/security/custom-rules/:id", true},
		{"POST", "/api/v1/security/block-pages", true},
		{"PUT", "/api/v1/security/block-pages/:id", true},
		{"DELETE", "/api/v1/security/block-pages/:id", true},
		{"PUT", "/api/v1/security/crs/auto-update", true},
		{"POST", "/api/v1/security/crs/update", true},
		{"GET", "/api/v1/security/policies", false},
		{"GET", "/api/v1/security/custom-rules", false},
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

// N+8 B5-S3：触发器安装失败时中间件必须按 {code,message} APIResponse 契约返回
// 500（此前是英文 gin.H{"error":...}，脱离 API 契约且未中文化）。
func TestClusterVersionMiddleware_rejects_with_api_response_when_trigger_install_fails(t *testing.T) {
	// Given：触发器安装失败（已关闭的连接让首次 Exec 报错）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	router.POST("/api/v1/rules", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	// When
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	// Then：500 + APIResponse 契约体
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("response status=%d body=%q, want 500", recorder.Code, recorder.Body.String())
	}
	var resp models.APIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal body %q: %v", recorder.Body.String(), err)
	}
	if resp.Code != 500 || resp.Message != "集群版本触发器不可用" {
		t.Fatalf("body={code:%d message:%q}, want {code:500 message:集群版本触发器不可用}", resp.Code, resp.Message)
	}
}

func TestClusterVersionTriggers_bump_for_snapshot_insert_update_delete(t *testing.T) {
	tests := []struct {
		name       string
		seed       string
		insert     string
		insertArgs []any
		update     string
		delete     string
	}{
		{name: "lb_rules", insert: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_rule','rule','http',8080)`, update: `UPDATE lb_rules SET name='updated' WHERE caddy_id='matrix_rule'`, delete: `DELETE FROM lb_rules WHERE caddy_id='matrix_rule'`},
		{name: "upstreams", seed: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_parent','parent','http',8080)`, insert: `INSERT INTO upstreams (rule_id,host,port) VALUES ('matrix_parent','127.0.0.1',80)`, update: `UPDATE upstreams SET host='127.0.0.2' WHERE rule_id='matrix_parent'`, delete: `DELETE FROM upstreams WHERE rule_id='matrix_parent'`},
		{name: "path_rules", seed: `INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('matrix_parent','parent','http',8080)`, insert: `INSERT INTO path_rules (rule_id,path) VALUES ('matrix_parent','/old')`, update: `UPDATE path_rules SET path='/new' WHERE rule_id='matrix_parent'`, delete: `DELETE FROM path_rules WHERE rule_id='matrix_parent'`},
		{name: "users", insert: `INSERT INTO users (username,password_hash) VALUES ('matrix_user','hash')`, update: `UPDATE users SET display_name='updated' WHERE username='matrix_user'`, delete: `DELETE FROM users WHERE username='matrix_user'`},
		{name: "api_keys", seed: `INSERT INTO users (username,password_hash) VALUES ('matrix_owner','hash')`, insert: `INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('matrix_key','hash','prefix',1)`, update: `UPDATE api_keys SET name='updated' WHERE key_prefix='prefix'`, delete: `DELETE FROM api_keys WHERE key_prefix='prefix'`},
		{name: "cert_jobs", insert: `INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('matrix_rule','example.com','failed',?,?,datetime('now','+30 days'))`, update: `UPDATE cert_jobs SET expires_at=datetime('now','+60 days') WHERE rule_id='matrix_rule'`, delete: `DELETE FROM cert_jobs WHERE rule_id='matrix_rule'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			database := newClusterVersionTestDB(t)
			if test.name == "cert_jobs" {
				certPEM, keyPEM := clusterVersionCertificatePair(t)
				test.insertArgs = []any{certPEM, keyPEM}
			}
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
				args      []any
				version   int
			}{
				{name: "insert", statement: test.insert, args: test.insertArgs, version: 1},
				{name: "update", statement: test.update, version: 2},
				{name: "delete", statement: test.delete, version: 3},
			}
			for _, operation := range operations {
				// When
				if _, err := database.Exec(operation.statement, operation.args...); err != nil {
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

func TestClusterVersionTriggers_bump_for_security_tables(t *testing.T) {
	tests := []struct {
		name   string
		insert string
		update string
		delete string
	}{
		{name: "security_policies",
			insert: `INSERT INTO security_policies (id,name,mode) VALUES (7,'matrix policy','blocking')`,
			update: `UPDATE security_policies SET ip_acl_mode='deny',ip_acl_list='["10.0.0.0/8"]' WHERE id=7`,
			delete: `DELETE FROM security_policies WHERE id=7`},
		{name: "security_policy_bindings",
			insert: `INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_matrix',7)`,
			update: `UPDATE security_policy_bindings SET policy_id=8 WHERE rule_caddy_id='lb_matrix'`,
			delete: `DELETE FROM security_policy_bindings WHERE rule_caddy_id='lb_matrix'`},
		{name: "security_custom_rules",
			insert: `INSERT INTO security_custom_rules (id,name,conditions) VALUES (7,'matrix rule','[]')`,
			update: `UPDATE security_custom_rules SET score=10 WHERE id=7`,
			delete: `DELETE FROM security_custom_rules WHERE id=7`},
		{name: "security_block_pages",
			insert: `INSERT INTO security_block_pages (id,name,content) VALUES (7,'matrix page','<html>blocked</html>')`,
			update: `UPDATE security_block_pages SET content='<html>v2</html>' WHERE id=7`,
			delete: `DELETE FROM security_block_pages WHERE id=7`},
		{name: "security_crs_version",
			insert: `INSERT INTO security_crs_version (id,version) VALUES (1,'v4.14.0')`,
			update: `UPDATE security_crs_version SET update_status='success',message='done' WHERE id=1`,
			delete: `DELETE FROM security_crs_version WHERE id=1`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			database := newClusterVersionTestDB(t)
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatalf("seed cluster version: %v", err)
			}
			if err := installClusterVersionTriggers(database); err != nil {
				t.Fatalf("install triggers: %v", err)
			}
			for _, operation := range []string{"insert", "update", "delete"} {
				triggerName := "cluster_version_" + test.name + "_" + operation
				var count int
				if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?", triggerName).Scan(&count); err != nil {
					t.Fatalf("query trigger %s: %v", triggerName, err)
				}
				if count != 1 {
					t.Fatalf("trigger %s missing from sqlite_master", triggerName)
				}
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

func TestClusterVersionTriggersBumpForAPIKeyRestrictions(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash) VALUES (1,'owner','hash'); INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by) VALUES (1,'key','hash','prefix',1)`); err != nil {
		t.Fatal(err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE api_keys SET mcp_enabled=1,read_only=1,mcp_ip_whitelist='["192.0.2.0/24"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after API key restriction update=%d, want 1", got)
	}
}

func TestClusterVersionTriggers_bumpForUserPasswordVersion(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,password_version) VALUES (1,'alice','hash',0)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec("UPDATE users SET password_version=1,password_changed_at=CURRENT_TIMESTAMP WHERE id=1"); err != nil {
		t.Fatalf("change password version: %v", err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("version after password change=%d, want 1", got)
	}
}

func TestClusterPasswordVersionSync_rejects_old_JWT(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (1,'alice','hash','admin',1,0)`); err != nil {
		t.Fatalf("seed slave user: %v", err)
	}
	const clusterToken = "cluster-token"
	snapshot := models.ClusterSnapshot{Version: 1, SchemaVersion: services.CurrentSnapshotSchema, MinReaderVersion: services.CurrentSnapshotSchema, Users: []models.ClusterUser{{ID: 1, Username: "alice", PasswordHash: "new-hash", Role: "admin", IsEnabled: true, PasswordVersion: 1}}, ACME: &models.ClusterACMEState{CAProviders: []models.CAProvider{}, CertificateConfigs: []models.CertificateConfig{}, DNSOwnership: json.RawMessage(`{"version":1,"records":[]}`)}}
	canonicalSnapshot := snapshot
	canonicalSnapshot.Fingerprint = ""
	canonicalSnapshot.Signature = ""
	canonicalSnapshot.CanonicalPayload = nil
	payload, err := json.Marshal(canonicalSnapshot)
	if err != nil {
		t.Fatalf("marshal canonical snapshot: %v", err)
	}
	fingerprint := sha256.Sum256(payload)
	snapshot.Fingerprint = hex.EncodeToString(fingerprint[:])
	snapshot.CanonicalPayload = payload
	mac := hmac.New(sha256.New, []byte(clusterToken))
	_, _ = mac.Write(payload)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": snapshot})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0,master_url=?,cluster_token=? WHERE id=1", master.URL, clusterToken); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	cfg := &config.Config{JWTSecret: "jwt-secret", CaddyAdminURL: caddy.URL}
	if _, err := services.NewSyncService(database, cfg, services.NewCaddyService(caddy.URL)).Pull(context.Background()); err != nil {
		t.Fatalf("sync changed password version: %v", err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": float64(1), "username": "alice", "pwd_ver": float64(0), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("sign old JWT: %v", err)
	}
	router := gin.New()
	router.Use(jwtAuth(cfg))
	router.GET("/protected", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old JWT status=%d body=%q, want 401", response.Code, response.Body.String())
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
	certPEM, keyPEM := clusterVersionCertificatePair(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed master: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, domain, enable_tls, tls_source, enabled) VALUES ('status_rule', 'status rule', 'http', 443, 'example.com', 1, 'acme_dns', 1)`); err != nil {
		t.Fatalf("seed enabled ACME rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('status_rule','example.com','downloaded',?,?,datetime('now','+60 days'))`, certPEM, keyPEM); err != nil {
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
	if len(downloadedSnapshot.Certs) != 1 || downloadedSnapshot.Certs[0].RuleID != "status_rule" {
		t.Fatalf("downloaded snapshot certificates=%+v, want status_rule", downloadedSnapshot.Certs)
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

func TestClusterVersionTriggers_bumpForTimestampOnlyUpdates(t *testing.T) {
	// R24：created_at/updated_at 属于快照 payload（cluster_snapshot.go 的 rules 与
	// ACME 证书候选节），时间戳单列更新也必须递增 cluster_version，否则指纹漂移。
	t.Run("lb_rules", func(t *testing.T) {
		database := newClusterVersionTestDB(t)
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('stamp_rule','rule','http',8080)`); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
		if err := installClusterVersionTriggers(database); err != nil {
			t.Fatalf("install triggers: %v", err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
			t.Fatalf("seed master: %v", err)
		}

		if _, err := database.Exec(`UPDATE lb_rules SET updated_at=datetime('now') WHERE caddy_id='stamp_rule'`); err != nil {
			t.Fatalf("update rule timestamp: %v", err)
		}
		if got := clusterVersion(t, database); got != 1 {
			t.Fatalf("version after rule updated_at=%d, want 1", got)
		}
	})

	t.Run("cert_jobs member", func(t *testing.T) {
		database := newClusterVersionTestDB(t)
		certPEM, keyPEM := clusterVersionCertificatePair(t)
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('stamp_cert','example.com','issued',?,?,datetime('now','+30 days'))`, certPEM, keyPEM); err != nil {
			t.Fatalf("seed issued job: %v", err)
		}
		if err := installClusterVersionTriggers(database); err != nil {
			t.Fatalf("install triggers: %v", err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
			t.Fatalf("seed master: %v", err)
		}

		if _, err := database.Exec(`UPDATE cert_jobs SET updated_at=datetime('now') WHERE rule_id='stamp_cert'`); err != nil {
			t.Fatalf("update job timestamp: %v", err)
		}
		if got := clusterVersion(t, database); got != 1 {
			t.Fatalf("version after member cert updated_at=%d, want 1", got)
		}
	})

	t.Run("cert_jobs non-member", func(t *testing.T) {
		database := newClusterVersionTestDB(t)
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('stamp_progress','example.com','processing')`); err != nil {
			t.Fatalf("seed progress job: %v", err)
		}
		if err := installClusterVersionTriggers(database); err != nil {
			t.Fatalf("install triggers: %v", err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1"); err != nil {
			t.Fatalf("seed master: %v", err)
		}

		if _, err := database.Exec(`UPDATE cert_jobs SET updated_at=datetime('now') WHERE rule_id='stamp_progress'`); err != nil {
			t.Fatalf("update job timestamp: %v", err)
		}
		if got := clusterVersion(t, database); got != 0 {
			t.Fatalf("version after non-member cert updated_at=%d, want 0", got)
		}
	})
}

func clusterVersionCertificatePair(t *testing.T) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	pair := server.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatalf("marshal test certificate key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
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
