package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateLbRulesPrimaryKey_preserves_upstream_connection_settings(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`
		CREATE TABLE lb_rules (
			id INTEGER PRIMARY KEY, name TEXT, description TEXT, protocol TEXT, domain TEXT, listen_port INTEGER,
			strategy TEXT, dynamic_dns BOOLEAN, enable_dns_server BOOLEAN, dns_server TEXT, dns_family TEXT,
			health_check_path TEXT, health_check_interval INTEGER, health_check_timeout INTEGER,
			health_check_unhealthy_threshold INTEGER, health_check_healthy_threshold INTEGER,
			enable_active_health_check BOOLEAN, tcp_health_check_port INTEGER, tcp_proxy_protocol BOOLEAN,
			tcp_try_duration INTEGER, tcp_try_interval INTEGER, request_body_max_size_mb INTEGER,
			upstream_keepalive_timeout INTEGER, server_tokens_hidden INTEGER, ip_acl_mode TEXT, ip_acl_list TEXT,
			custom_routes_enabled BOOLEAN, proxy_dial_timeout INTEGER, proxy_response_header_timeout INTEGER,
			proxy_read_timeout INTEGER, proxy_write_timeout INTEGER, proxy_stream_timeout INTEGER,
			host_header TEXT, enable_tls BOOLEAN, tls_cert TEXT, tls_key TEXT, tls_http_redirect BOOLEAN,
			tls_source TEXT, acme_config_id INTEGER, ca_provider_id INTEGER, enable_compress BOOLEAN,
			compress_types TEXT, enabled BOOLEAN, log_enabled BOOLEAN, created_by INTEGER, created_at DATETIME,
			updated_at DATETIME, updated_by INTEGER, caddy_id TEXT
		);
		CREATE TABLE upstreams (
			id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
			weight INTEGER, domain TEXT, dynamic_dns BOOLEAN, enabled BOOLEAN, protocol TEXT, host_header TEXT,
			dns_server TEXT, max_connections INTEGER, proxy_protocol TEXT
		);
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'tcp', 443, 'lb_preserve');
		INSERT INTO upstreams (id, rule_id, host, port, max_connections, proxy_protocol)
		VALUES (9, 7, '127.0.0.1', 8443, 37, 'v2');
	`); err != nil {
		t.Fatalf("seed legacy load-balancer schema: %v", err)
	}

	// When
	if err := migrateLbRulesPrimaryKey(); err != nil {
		t.Fatalf("migrate load-balancer primary key: %v", err)
	}

	// Then
	var maxConnections int
	var proxyProtocol string
	if err := database.QueryRow("SELECT max_connections, proxy_protocol FROM upstreams WHERE id=9").Scan(&maxConnections, &proxyProtocol); err != nil {
		t.Fatalf("read migrated upstream: %v", err)
	}
	if maxConnections != 37 || proxyProtocol != "v2" {
		t.Fatalf("connection settings=(%d, %q), want (37, %q)", maxConnections, proxyProtocol, "v2")
	}
}

func TestMigrateCertJobsStatusConstraint_rebuilds_incomplete_expanded_constraint(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	createLegacyCertJobs(t, database, "'queued'", "'queued','presenting_dns','disabled','waiting_order_ready'")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES
		('lb_1', 'disabled.example', 'disabled'),
		('lb_2', 'ready.example', 'waiting_order_ready')`); err != nil {
		t.Fatalf("seed certificate jobs: %v", err)
	}

	// When
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("migrate certificate job constraint: %v", err)
	}

	// Then
	if _, err := database.Exec("INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_3', 'valid.example', 'order_valid')"); err != nil {
		t.Fatalf("target constraint still rejects order_valid: %v", err)
	}
}

func TestMigrateCertJobsStatusConstraint_preserves_paused_and_acme_stage_statuses(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	createLegacyCertJobs(t, database, "'queued'", "'queued','disabled','waiting_order_ready'")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES
		('lb_1', 'disabled.example', 'disabled'),
		('lb_2', 'ready.example', 'waiting_order_ready')`); err != nil {
		t.Fatalf("seed certificate jobs: %v", err)
	}

	// When
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("migrate certificate job constraint: %v", err)
	}

	// Then
	rows, err := database.Query("SELECT status FROM cert_jobs ORDER BY id")
	if err != nil {
		t.Fatalf("query migrated statuses: %v", err)
	}
	defer rows.Close()
	want := []string{"disabled", "waiting_order_ready"}
	got := 0
	for index := 0; rows.Next(); index++ {
		got++
		var status string
		if err := rows.Scan(&status); err != nil {
			t.Fatalf("scan migrated status: %v", err)
		}
		if index >= len(want) || status != want[index] {
			t.Fatalf("status[%d]=%q, want %q", index, status, want[index])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated statuses: %v", err)
	}
	if got != len(want) {
		t.Fatalf("migrated rows=%d, want %d (migration must not drop rows)", got, len(want))
	}
}

func TestMigrateCertJobsStatusConstraint_repairs_incorrect_status_default(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	allStatuses := "'queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid'"
	createLegacyCertJobs(t, database, "'pending'", allStatuses)

	// When
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("migrate certificate job constraint: %v", err)
	}
	if _, err := database.Exec("INSERT INTO cert_jobs (rule_id, domain) VALUES ('lb_default', 'default.example')"); err != nil {
		t.Fatalf("insert certificate job using default: %v", err)
	}

	// Then
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_default'").Scan(&status); err != nil {
		t.Fatalf("read default status: %v", err)
	}
	if status != "queued" {
		t.Fatalf("default status=%q, want queued", status)
	}
}

func TestInitialize_returns_error_when_global_config_singleton_insert_fails(t *testing.T) {
	// Given
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY CHECK (id = 2), caddy_config TEXT)"); err != nil {
		t.Fatalf("create conflicting global config table: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	err = Initialize(dir)

	// Then
	if err == nil {
		t.Fatal("Initialize() error=nil, want singleton insert failure")
	}
	if !strings.Contains(err.Error(), "global config") {
		t.Fatalf("Initialize() error=%q, want global config context", err)
	}
}

func TestInitialize_adds_certificate_deployment_retry_columns(t *testing.T) {
	// Given
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	// Then
	var count int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('cert_jobs') WHERE name IN ('deployment_attempts','deployment_available_after')`).Scan(&count); err != nil {
		t.Fatalf("read certificate job columns: %v", err)
	}
	if count != 2 {
		t.Fatalf("deployment retry columns=%d, want 2", count)
	}
}

func openMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration.db")+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	oldDB := DB
	DB = database
	t.Cleanup(func() {
		_ = database.Close()
		DB = oldDB
	})
	return database
}

func createLegacyCertJobs(t *testing.T, database *sql.DB, defaultStatus, allowedStatuses string) {
	t.Helper()
	schema := fmt.Sprintf(`CREATE TABLE cert_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id TEXT NOT NULL,
		domain TEXT NOT NULL,
		status TEXT DEFAULT %s CHECK (status IN (%s)),
		message TEXT,
		expires_at DATETIME,
		cert_pem TEXT,
		key_pem TEXT,
		ca_provider_id INTEGER DEFAULT 0,
		renewal_attempts INTEGER DEFAULT 0,
		ca_available_after DATETIME,
		last_error_code TEXT,
		deployment_attempts INTEGER DEFAULT 0,
		deployment_available_after DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	)`, defaultStatus, allowedStatuses)
	if _, err := database.Exec(schema); err != nil {
		t.Fatalf("create legacy certificate jobs table: %v", err)
	}
}
