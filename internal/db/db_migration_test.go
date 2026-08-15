package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateTables_omits_dead_upstream_accessURL_column(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name='access_url'").Scan(&count); err != nil {
		t.Fatalf("query upstream schema: %v", err)
	}
	if count != 0 {
		t.Fatalf("upstreams.access_url count=%d, want 0", count)
	}
}

func TestRunMigrationsCreatesAuthenticationAndUpstreamIndexes(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then
	for _, index := range []string{"idx_api_keys_prefix_hash", "idx_upstreams_rule_enabled_id"} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count); err != nil {
			t.Fatalf("query index %s: %v", index, err)
		}
		if count != 1 {
			t.Fatalf("index %s count=%d, want 1", index, count)
		}
	}
}

func TestRunMigrationsDropsLegacyTLSCertificatesAndNodeSyncColumnsIdempotently(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE nodes ADD COLUMN sync_enabled BOOLEAN DEFAULT 1;
		ALTER TABLE nodes ADD COLUMN sync_scope TEXT DEFAULT 'all';
		INSERT INTO nodes (id,name,ip_address,port,status,sync_enabled,sync_scope) VALUES (7,'legacy-node','10.0.0.7',9000,'online',1,'all');
		CREATE TABLE tls_certificates (id INTEGER PRIMARY KEY, domain TEXT);`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then
	var tableCount, columnCount, port int
	var nodeName, status string
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tls_certificates'").Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name IN ('sync_enabled','sync_scope')").Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 0 || columnCount != 0 {
		t.Fatalf("legacy table=%d columns=%d, want 0/0", tableCount, columnCount)
	}
	if err := database.QueryRow("SELECT name,port,status FROM nodes WHERE id=7").Scan(&nodeName, &port, &status); err != nil {
		t.Fatal(err)
	}
	if nodeName != "legacy-node" || port != 9000 || status != "online" {
		t.Fatalf("migrated node=(%q,%d,%q)", nodeName, port, status)
	}
}

func TestRunMigrations_dropsDeadSecurityAndAdminTLSColumns(t *testing.T) {
	// Given a schema that still carries the dead status_code / admin TLS columns
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE security_custom_rules ADD COLUMN status_code INTEGER DEFAULT 403;
		ALTER TABLE security_block_pages ADD COLUMN status_code INTEGER DEFAULT 403;
		ALTER TABLE global_config ADD COLUMN admin_tls_acme_rule_id VARCHAR(50) DEFAULT '';
		ALTER TABLE global_config ADD COLUMN admin_tls_port INTEGER DEFAULT 8443;
		INSERT INTO security_custom_rules (id,name,description,conditions,action,score,status_code,enabled,updated_by) VALUES (1,'legacy rule','','[]','block',5,451,1,0);
		INSERT INTO security_block_pages (id,name,description,content,status_code,is_default,created_by,updated_by) VALUES (2,'legacy page','','<html>x</html>',499,0,0,0);`); err != nil {
		t.Fatalf("seed legacy dead columns: %v", err)
	}

	// When migrations run (twice, to prove idempotence)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then the dead columns are dropped while the rows survive
	for _, drop := range []struct{ table, column string }{
		{"security_custom_rules", "status_code"},
		{"security_block_pages", "status_code"},
		{"global_config", "admin_tls_acme_rule_id"},
		{"global_config", "admin_tls_port"},
	} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", drop.table, drop.column).Scan(&count); err != nil {
			t.Fatalf("query %s.%s: %v", drop.table, drop.column, err)
		}
		if count != 0 {
			t.Fatalf("%s.%s count=%d, want dropped", drop.table, drop.column, count)
		}
	}
	var ruleName, pageName string
	if err := database.QueryRow("SELECT name FROM security_custom_rules WHERE id=1").Scan(&ruleName); err != nil {
		t.Fatalf("read migrated custom rule: %v", err)
	}
	if err := database.QueryRow("SELECT name FROM security_block_pages WHERE id=2").Scan(&pageName); err != nil {
		t.Fatalf("read migrated block page: %v", err)
	}
	if ruleName != "legacy rule" || pageName != "legacy page" {
		t.Fatalf("rows lost after drop: rule=%q page=%q", ruleName, pageName)
	}
}

func TestRunMigrations_makes_users_isEnabled_notNull_and_backfills_null(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		display_name TEXT,
		is_enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME,
		password_changed_at DATETIME,
		password_version INTEGER NOT NULL DEFAULT 0
	);
	INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('legacy','hash','admin',NULL);`); err != nil {
		t.Fatalf("seed legacy users: %v", err)
	}

	// When
	if err := migrateUsersIsEnabledNotNull(); err != nil {
		t.Fatalf("migrate users.is_enabled: %v", err)
	}
	if err := migrateUsersIsEnabledNotNull(); err != nil {
		t.Fatalf("repeat users.is_enabled migration: %v", err)
	}

	// Then
	var notNull, enabled int
	if err := database.QueryRow("SELECT \"notnull\" FROM pragma_table_info('users') WHERE name='is_enabled'").Scan(&notNull); err != nil {
		t.Fatalf("read users.is_enabled schema: %v", err)
	}
	if err := database.QueryRow("SELECT is_enabled FROM users WHERE username='legacy'").Scan(&enabled); err != nil {
		t.Fatalf("read migrated user: %v", err)
	}
	if notNull != 1 || enabled != 1 {
		t.Fatalf("is_enabled notnull=%d value=%d, want 1/1", notNull, enabled)
	}
	if _, err := database.Exec("UPDATE users SET is_enabled=NULL WHERE username='legacy'"); err == nil {
		t.Fatal("users.is_enabled accepted NULL after migration")
	}
}

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
			upstream_keepalive_timeout INTEGER, server_tokens_hidden INTEGER,
			custom_routes_enabled BOOLEAN, proxy_dial_timeout INTEGER, proxy_response_header_timeout INTEGER,
			proxy_read_timeout INTEGER, proxy_write_timeout INTEGER, proxy_stream_timeout INTEGER,
			proxy_flush_interval INTEGER, proxy_stream_close_delay INTEGER,
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
	if err := database.QueryRow("SELECT max_connections FROM upstreams WHERE id=9").Scan(&maxConnections); err != nil {
		t.Fatalf("read migrated upstream: %v", err)
	}
	if maxConnections != 37 {
		t.Fatalf("max_connections=%d, want 37", maxConnections)
	}
	// Legacy dead columns are not carried into the rebuilt table.
	for _, column := range []string{"domain", "host_header", "dns_server", "proxy_protocol"} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name=?", column).Scan(&count); err != nil {
			t.Fatalf("check migrated upstreams.%s: %v", column, err)
		}
		if count != 0 {
			t.Fatalf("legacy column %s survived primary key migration", column)
		}
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

func TestMigrateCertJobsStatusConstraint_rebuilds_constraint_with_deprecated_status(t *testing.T) {
	database := openMigrationTestDB(t)
	allStatuses := "'queued', 'pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid','deprecated'"
	createLegacyCertJobs(t, database, "'queued'", allStatuses)
	if _, err := database.Exec("INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_old', 'old.example', 'deprecated')"); err != nil {
		t.Fatalf("seed deprecated certificate job status: %v", err)
	}

	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("migrate certificate job constraint: %v", err)
	}

	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_old'").Scan(&status); err != nil {
		t.Fatalf("read migrated certificate job status: %v", err)
	}
	if status != "queued" {
		t.Fatalf("migrated deprecated status=%q, want queued", status)
	}
	if _, err := database.Exec("INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_rejected', 'rejected.example', 'deprecated')"); err == nil {
		t.Fatal("deprecated status accepted after migration")
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

func TestMigrateCertJobsStatusConstraint_backfills_null_status_and_is_idempotent(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	allStatuses := "'queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid'"
	createLegacyCertJobs(t, database, "'queued'", allStatuses)
	if _, err := database.Exec("INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_null', 'null.example', NULL)"); err != nil {
		t.Fatalf("seed NULL certificate job status: %v", err)
	}

	// When
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("migrate certificate job status: %v", err)
	}
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("repeat certificate job status migration: %v", err)
	}

	// Then
	var notNull int
	var status string
	if err := database.QueryRow("SELECT \"notnull\" FROM pragma_table_info('cert_jobs') WHERE name='status'").Scan(&notNull); err != nil {
		t.Fatalf("read cert_jobs.status schema: %v", err)
	}
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_null'").Scan(&status); err != nil {
		t.Fatalf("read migrated certificate job status: %v", err)
	}
	if notNull != 1 || status != "queued" {
		t.Fatalf("cert_jobs.status notnull=%d value=%q, want 1/queued", notNull, status)
	}
	if _, err := database.Exec("UPDATE cert_jobs SET status=NULL WHERE rule_id='lb_null'"); err == nil {
		t.Fatal("cert_jobs.status accepted NULL after migration")
	}
}

func TestMigrateCertJobsStatusConstraint_rebuilds_after_startup_index_creation(t *testing.T) {
	database := openMigrationTestDB(t)
	createLegacyCertJobs(t, database, "'queued'", "'queued','disabled'")
	if _, err := database.Exec(`
		CREATE INDEX idx_cert_jobs_rule_domain ON cert_jobs(rule_id, domain);
		CREATE UNIQUE INDEX idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain);
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_index','index.example','queued');
	`); err != nil {
		t.Fatalf("seed startup index state: %v", err)
	}

	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("migrate certificate jobs after startup index creation: %v", err)
	}

	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_index'").Scan(&status); err != nil {
		t.Fatalf("read certificate job after rebuild: %v", err)
	}
	if status != "queued" {
		t.Fatalf("certificate job status=%q, want queued", status)
	}
}

func TestInitialize_upgrades_legacy_cert_jobs_before_creating_indexes(t *testing.T) {
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE cert_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, domain TEXT NOT NULL,
		status TEXT DEFAULT 'pending' CHECK (status IN ('pending','issued','failed')),
		message TEXT, expires_at DATETIME, cert_pem TEXT, key_pem TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME
	);
	INSERT INTO cert_jobs (rule_id,domain,status,message) VALUES
		('lb_duplicate','duplicate.example','failed','old'),
		('lb_duplicate','duplicate.example','issued','new');`); err != nil {
		t.Fatalf("seed legacy certificate jobs: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	for attempt := 1; attempt <= 2; attempt++ {
		if err := Initialize(dir); err != nil {
			t.Fatalf("initialize legacy database attempt %d: %v", attempt, err)
		}
		if attempt == 1 {
			if err := Close(); err != nil {
				t.Fatalf("close upgraded database: %v", err)
			}
		}
	}

	var count, keptID int
	var message string
	if err := DB.QueryRow("SELECT COUNT(*), MAX(id), MAX(message) FROM cert_jobs WHERE rule_id='lb_duplicate' AND domain='duplicate.example'").Scan(&count, &keptID, &message); err != nil {
		t.Fatalf("read deduplicated certificate job: %v", err)
	}
	if count != 1 || keptID != 2 || message != "new" {
		t.Fatalf("deduplicated job count=%d id=%d message=%q, want newest id=2", count, keptID, message)
	}
	var columns, indexes int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('cert_jobs') WHERE name='ca_available_after'").Scan(&columns); err != nil {
		t.Fatalf("read migrated certificate columns: %v", err)
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN
		('idx_cert_jobs_rule_domain_unique','idx_cert_jobs_status_ca_available','idx_cert_jobs_status_expires')`).Scan(&indexes); err != nil {
		t.Fatalf("read certificate indexes: %v", err)
	}
	if columns != 1 || indexes != 3 {
		t.Fatalf("migrated columns=%d indexes=%d, want 1 and 3", columns, indexes)
	}
}

func TestInitialize_canonicalizes_lb_rule_domain_after_caddy_id_backfill(t *testing.T) {
	// Given a legacy database whose lb_rules predate the caddy_id column
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`
		CREATE TABLE lb_rules (
			id INTEGER PRIMARY KEY, name TEXT, description TEXT, protocol TEXT, domain TEXT, listen_port INTEGER,
			strategy TEXT, dynamic_dns BOOLEAN, enable_dns_server BOOLEAN, dns_server TEXT, dns_family TEXT,
			health_check_path TEXT, health_check_interval INTEGER, health_check_timeout INTEGER,
			health_check_unhealthy_threshold INTEGER, health_check_healthy_threshold INTEGER,
			enable_active_health_check BOOLEAN, tcp_health_check_port INTEGER, tcp_proxy_protocol BOOLEAN,
			tcp_try_duration INTEGER, tcp_try_interval INTEGER, request_body_max_size_mb INTEGER,
			upstream_keepalive_timeout INTEGER, server_tokens_hidden INTEGER,
			custom_routes_enabled BOOLEAN, proxy_dial_timeout INTEGER, proxy_response_header_timeout INTEGER,
			proxy_read_timeout INTEGER, proxy_write_timeout INTEGER, proxy_stream_timeout INTEGER,
			proxy_flush_interval INTEGER, proxy_stream_close_delay INTEGER,
			host_header TEXT, enable_tls BOOLEAN, tls_cert TEXT, tls_key TEXT, tls_http_redirect BOOLEAN,
			tls_source TEXT, acme_config_id INTEGER, ca_provider_id INTEGER, enable_compress BOOLEAN,
			compress_types TEXT, enabled BOOLEAN, log_enabled BOOLEAN, created_by INTEGER, created_at DATETIME,
			updated_at DATETIME, updated_by INTEGER
		);
		INSERT INTO lb_rules (id, name, protocol, listen_port, domain) VALUES (7, 'legacy', 'http', 80, 'Example.COM.');`); err != nil {
		t.Fatalf("seed legacy lb_rules: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When the legacy database is upgraded and then restarted
	for attempt := 1; attempt <= 2; attempt++ {
		if err := Initialize(dir); err != nil {
			t.Fatalf("initialize legacy database attempt %d: %v", attempt, err)
		}
		if attempt == 1 {
			if err := Close(); err != nil {
				t.Fatalf("close upgraded database: %v", err)
			}
		}
	}

	// Then the domain is canonical on first boot and caddy_id is backfilled
	var domain, caddyID string
	if err := DB.QueryRow("SELECT domain, caddy_id FROM lb_rules WHERE id=7").Scan(&domain, &caddyID); err != nil {
		t.Fatalf("read migrated lb_rule: %v", err)
	}
	if domain != "example.com" {
		t.Fatalf("domain=%q, want canonical %q", domain, "example.com")
	}
	if caddyID == "" {
		t.Fatal("caddy_id is empty, want backfilled value")
	}
}

func TestInitialize_normalizes_out_of_range_jwt_expiration(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec("UPDATE global_config SET jwt_expire_minutes=999999 WHERE id=1"); err != nil {
		t.Fatalf("seed invalid JWT expiration: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close database before restart: %v", err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("reinitialize database: %v", err)
	}
	var expireMinutes int
	if err := DB.QueryRow("SELECT jwt_expire_minutes FROM global_config WHERE id=1").Scan(&expireMinutes); err != nil {
		t.Fatalf("read normalized JWT expiration: %v", err)
	}
	if expireMinutes != 20 {
		t.Fatalf("jwt_expire_minutes=%d, want 20", expireMinutes)
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

func TestInitialize_closesNewHandlesAndPreservesGlobalsWhenInitializationFails(t *testing.T) {
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
	mainSentinel, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open main sentinel: %v", err)
	}
	metricsSentinel, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open metrics sentinel: %v", err)
	}
	auditSentinel, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open audit sentinel: %v", err)
	}
	DB, MetricsDB, AuditDB = mainSentinel, metricsSentinel, auditSentinel
	oldOpenDatabase := openDatabase
	var openedMain *sql.DB
	openDatabase = func(driverName, dataSourceName string) (*sql.DB, error) {
		openedMain, err = sql.Open(driverName, dataSourceName)
		return openedMain, err
	}
	t.Cleanup(func() {
		openDatabase = oldOpenDatabase
		if DB != mainSentinel {
			_ = DB.Close()
		}
		if MetricsDB != metricsSentinel {
			_ = MetricsDB.Close()
		}
		if AuditDB != auditSentinel {
			_ = AuditDB.Close()
		}
		_ = mainSentinel.Close()
		_ = metricsSentinel.Close()
		_ = auditSentinel.Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	err = Initialize(dir)

	// Then
	if err == nil {
		t.Fatal("Initialize() error=nil, want initialization failure")
	}
	if DB != mainSentinel || MetricsDB != metricsSentinel || AuditDB != auditSentinel {
		t.Fatalf("database globals changed after failure: DB=%p MetricsDB=%p AuditDB=%p", DB, MetricsDB, AuditDB)
	}
	if pingErr := openedMain.Ping(); pingErr == nil {
		t.Fatal("new main database remains open after initialization failure")
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

func TestMigrateLegacyDNSCredentials_rollsBackAllRowsOnFailure(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE certificate_configs (
		id INTEGER PRIMARY KEY, dns_id TEXT, dns_key TEXT, dns_credentials TEXT
	);
	INSERT INTO certificate_configs VALUES (1, 'id-1', 'key-1', NULL), (2, 'id-2', 'key-2', NULL);
	CREATE TRIGGER fail_second_credential BEFORE UPDATE ON certificate_configs WHEN NEW.id = 2
	BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;`); err != nil {
		t.Fatalf("seed legacy certificate configs: %v", err)
	}

	err := migrateLegacyDNSCredentials()

	if err == nil || !strings.Contains(err.Error(), "injected migration failure") {
		t.Fatalf("migration error=%v, want injected failure", err)
	}
	var migrated int
	if err := database.QueryRow("SELECT COUNT(*) FROM certificate_configs WHERE dns_credentials IS NOT NULL").Scan(&migrated); err != nil {
		t.Fatalf("count migrated credentials: %v", err)
	}
	if migrated != 0 {
		t.Fatalf("migrated rows=%d, want transaction rollback", migrated)
	}
}

func TestInitialize_adds_security_policy_response_and_event_retention_columns(t *testing.T) {
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
