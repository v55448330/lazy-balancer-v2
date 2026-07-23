package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/glebarez/sqlite"
)

var (
	DB             *sql.DB
	currentDB      atomic.Value
	MetricsDB      *sql.DB
	AuditDB        *sql.DB
	BackgroundDBMu sync.Mutex
)

// SetDB registers the handle background goroutines should use; tests that
// swap DB directly should call this too so refresh loops follow.
func SetDB(d *sql.DB) {
	currentDB.Store(d)
}

// GetDB returns the handle registered via Initialize/SetDB, safe for
// concurrent background readers.
func GetDB() *sql.DB {
	if v, ok := currentDB.Load().(*sql.DB); ok {
		return v
	}
	return nil
}

func Initialize(dataDir string) error {
	// Create data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "lazy-balancer.db")

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=30000&_synchronous=NORMAL&_txlock=immediate")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	DB = db
	currentDB.Store(db)

	// Initialize metrics database
	if err := InitializeMetricsDB(dataDir); err != nil {
		return fmt.Errorf("failed to initialize metrics database: %w", err)
	}

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Ensure default config row exists
	var configCount int
	DB.QueryRow("SELECT COUNT(*) FROM global_config").Scan(&configCount)
	if configCount == 0 {
		DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')")
	}

	// Run migrations
	if err := runMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := InitializeAuditDB(dataDir); err != nil {
		return fmt.Errorf("failed to initialize audit database: %w", err)
	}

	log.Println("Database initialized successfully")
	return nil
}

func createTables() error {
	schema := `
	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		display_name VARCHAR(100),
		is_enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);

	-- Add display_name column if not exists (for existing databases)
	-- ALTER TABLE users ADD COLUMN display_name VARCHAR(100);

	-- API Keys table
	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		key_hash VARCHAR(255) NOT NULL,
		key_prefix VARCHAR(20) NOT NULL,
		created_by INTEGER NOT NULL,
		last_used DATETIME,
		expires_at DATETIME,
		is_enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (created_by) REFERENCES users(id)
	);

	-- LB Rules table (caddy_id is now the primary key)
	CREATE TABLE IF NOT EXISTS lb_rules (
		id INTEGER,
		name VARCHAR(100) NOT NULL,
		description VARCHAR(300),
		protocol VARCHAR(10) NOT NULL,
		domain VARCHAR(255),
		listen_port INTEGER NOT NULL,
		strategy VARCHAR(20) DEFAULT 'weighted_round_robin',
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enable_dns_server BOOLEAN DEFAULT FALSE,
		dns_server VARCHAR(255) DEFAULT '',
		dns_family VARCHAR(20) DEFAULT 'ipv4',
		health_check_path VARCHAR(255),
		health_check_interval INTEGER DEFAULT 10,
		health_check_timeout INTEGER DEFAULT 5,
		health_check_unhealthy_threshold INTEGER DEFAULT 3,
		health_check_healthy_threshold INTEGER DEFAULT 2,
		enable_active_health_check BOOLEAN DEFAULT FALSE,
		tcp_health_check_port INTEGER DEFAULT 0,
		tcp_try_duration INTEGER DEFAULT 0,
		tcp_try_interval INTEGER DEFAULT 250,
		request_body_max_size_mb INTEGER DEFAULT 0,
		upstream_keepalive_timeout INTEGER DEFAULT 0,
		server_tokens_hidden INTEGER DEFAULT 0,
		host_header VARCHAR(255),
		enable_tls BOOLEAN DEFAULT FALSE,
		tls_cert TEXT,
		tls_key TEXT,
		tls_http_redirect BOOLEAN DEFAULT FALSE,
		enable_compress BOOLEAN DEFAULT TRUE,
		compress_types VARCHAR(100) DEFAULT 'gzip',
		enabled BOOLEAN DEFAULT TRUE,
		log_enabled BOOLEAN DEFAULT 0,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		updated_by INTEGER,
		caddy_id VARCHAR(20) PRIMARY KEY
	);

	-- CA Providers table for ACME certificate issuance
	CREATE TABLE IF NOT EXISTS ca_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		provider VARCHAR(50) NOT NULL,
		directory_url VARCHAR(255) NOT NULL,
		credentials TEXT,
		max_concurrent INTEGER DEFAULT 1,
		min_interval_ms INTEGER DEFAULT 2000,
		enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Upstreams table (rule_id now references caddy_id)
	CREATE TABLE IF NOT EXISTS upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		domain VARCHAR(255),
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN DEFAULT TRUE,
		protocol VARCHAR(10) DEFAULT 'http',
		host_header VARCHAR(255),
		dns_server VARCHAR(255) DEFAULT '',
		max_connections INTEGER DEFAULT 0,
		proxy_protocol VARCHAR(10) DEFAULT '',
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	);

	-- TLS Certificates table for Let's Encrypt
	CREATE TABLE IF NOT EXISTS tls_certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain VARCHAR(255) UNIQUE NOT NULL,
		cert_pem TEXT NOT NULL,
		key_pem TEXT NOT NULL,
		issuer VARCHAR(50) DEFAULT 'self-signed',
		acme_email VARCHAR(255),
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);

	-- Certificate Configs table for ACME DNS providers
	CREATE TABLE IF NOT EXISTS certificate_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		dns_provider VARCHAR(50) DEFAULT 'dnspod',
		dns_credentials TEXT,
		enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);

	-- Certificate Jobs table for ACME issuance tracking
	CREATE TABLE IF NOT EXISTS cert_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		domain VARCHAR(255) NOT NULL,
		status VARCHAR(20) DEFAULT 'queued' CHECK (status IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid')),
		message TEXT,
		expires_at DATETIME,
		cert_pem TEXT,
		key_pem TEXT,
		ca_provider_id INTEGER DEFAULT 0,
		renewal_attempts INTEGER DEFAULT 0,
		ca_available_after DATETIME,
		last_error_code VARCHAR(20),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain ON cert_jobs(rule_id, domain);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain);

	-- Global Config table
	CREATE TABLE IF NOT EXISTS global_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		caddy_config TEXT DEFAULT '{}',
		dns_provider VARCHAR(50) DEFAULT 'dnspod',
		dns_credentials TEXT,
		acme_email VARCHAR(255),
		log_level VARCHAR(10) DEFAULT 'info',
		is_master BOOLEAN DEFAULT TRUE,
		master_url VARCHAR(255),
		sync_interval INTEGER DEFAULT 60,
		caddy_log_path VARCHAR(500) DEFAULT '/app/logs/caddy.log',
		caddy_log_level VARCHAR(10) DEFAULT 'info',
		caddy_log_size_mb INTEGER DEFAULT 100,
		request_body_max_size_mb INTEGER DEFAULT 0,
		http_read_timeout INTEGER DEFAULT 60,
		http_write_timeout INTEGER DEFAULT 60,
		http_idle_timeout INTEGER DEFAULT 120,
		upstream_keepalive_timeout INTEGER DEFAULT 60,
		server_tokens_hidden BOOLEAN DEFAULT FALSE,
		cert_expiry_days INTEGER DEFAULT 30,
		cert_renewal_days INTEGER DEFAULT 30,
		cert_job_log_size_mb INTEGER DEFAULT 10,
	runtime_log_size_mb INTEGER DEFAULT 100,
		access_log_json BOOLEAN DEFAULT TRUE,
		access_log_format TEXT DEFAULT '',
		audit_retention_months INTEGER DEFAULT 3,
		jwt_expire_minutes INTEGER DEFAULT 20,
		timezone VARCHAR(50) DEFAULT 'Asia/Shanghai',
		last_sync DATETIME,
		last_sync_error TEXT DEFAULT '',
		applied_version INTEGER DEFAULT 0,
		cluster_version INTEGER DEFAULT 0,
		sync_caddy_config BOOLEAN DEFAULT FALSE,
		cluster_token TEXT DEFAULT '',
		registration_id INTEGER DEFAULT 0,
		registration_secret TEXT DEFAULT '',
		sync_fingerprint TEXT DEFAULT '',
		updated_at DATETIME
	);

	-- Nodes table
	CREATE TABLE IF NOT EXISTS nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		mode VARCHAR(10) NOT NULL DEFAULT 'slave',
		ip_address VARCHAR(45) NOT NULL,
		port INTEGER DEFAULT 8000,
		master_id INTEGER,
		is_approved BOOLEAN DEFAULT FALSE,
		sync_enabled BOOLEAN DEFAULT TRUE,
		sync_interval INTEGER DEFAULT 60,
		sync_scope VARCHAR(50) DEFAULT 'all',
		status VARCHAR(20) DEFAULT 'offline',
		cluster_token_hash VARCHAR(64),
		registration_secret VARCHAR(64),
		cluster_token_delivered BOOLEAN DEFAULT FALSE,
		reported_version INTEGER DEFAULT 0,
		health_json TEXT,
		last_sync_at DATETIME,
		last_sync_error TEXT,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (master_id) REFERENCES nodes(id)
	);

	-- Create indexes
	CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
	CREATE INDEX IF NOT EXISTS idx_nodes_master ON nodes(master_id);

	CREATE TABLE IF NOT EXISTS cluster_register_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash VARCHAR(64) UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_cluster_register_tokens_hash ON cluster_register_tokens(token_hash);
	`

	_, err := DB.Exec(schema)
	return err
}

func runMigrations() error {
	var colCount int

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='display_name'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE users ADD COLUMN display_name VARCHAR(100)")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='is_enabled'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE users ADD COLUMN is_enabled BOOLEAN DEFAULT 1")
	}
	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name='is_enabled'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE api_keys ADD COLUMN is_enabled BOOLEAN DEFAULT 1")
	}

	// lb_rules new columns
	newLbColumns := map[string]string{
		"domain":                     "VARCHAR(255)",
		"tls_cert":                   "TEXT",
		"tls_key":                    "TEXT",
		"tls_http_redirect":          "BOOLEAN DEFAULT 0",
		"dynamic_dns":                "BOOLEAN DEFAULT 0",
		"enable_active_health_check": "BOOLEAN DEFAULT 0",
		"tls_source":                 "VARCHAR(20) DEFAULT 'manual'",
		"acme_config_id":             "INTEGER DEFAULT 0",
	}

	for col, dtype := range newLbColumns {
		DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name=?", col).Scan(&colCount)
		if colCount == 0 {
			DB.Exec("ALTER TABLE lb_rules ADD COLUMN " + col + " " + dtype)
		}
	}

	DB.Exec("UPDATE lb_rules SET strategy='weighted_round_robin' WHERE strategy='round_robin'")

	DB.Exec("DROP TABLE IF EXISTS config_versions")
	var accessLogCol int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='access_log_enabled'").Scan(&accessLogCol); err == nil && accessLogCol > 0 {
		DB.Exec("ALTER TABLE global_config DROP COLUMN access_log_enabled")
	}

	// ca_providers columns are created by createTables; here we only add columns to existing tables.
	newColumns := map[string]string{
		"lb_rules.ca_provider_id":              "INTEGER DEFAULT 0",
		"cert_jobs.ca_provider_id":             "INTEGER DEFAULT 0",
		"cert_jobs.renewal_attempts":           "INTEGER DEFAULT 0",
		"cert_jobs.ca_available_after":         "DATETIME",
		"cert_jobs.last_error_code":            "VARCHAR(20)",
		"global_config.default_ca_provider_id": "INTEGER DEFAULT 0",
		"global_config.cert_renewal_days":      "INTEGER DEFAULT 30",
		"global_config.cert_renewal_attempts":  "INTEGER DEFAULT 5",
		"global_config.cert_job_log_size_mb":   "INTEGER DEFAULT 10",
		"global_config.runtime_log_size_mb":    "INTEGER DEFAULT 100",
		"global_config.admin_tls_enabled":      "BOOLEAN DEFAULT 0",
		"global_config.admin_tls_mode":         "VARCHAR(20) DEFAULT 'selfsigned'",
		"global_config.admin_tls_cert":         "TEXT DEFAULT ''",
		"global_config.admin_tls_key":          "TEXT DEFAULT ''",
		"global_config.admin_tls_acme_rule_id": "VARCHAR(50) DEFAULT ''",
		"global_config.admin_tls_port":         "INTEGER DEFAULT 8443",
		"global_config.access_log_json":        "BOOLEAN DEFAULT TRUE",
		"global_config.access_log_format":      "TEXT DEFAULT ''",
		"global_config.audit_retention_months": "INTEGER DEFAULT 3",
		"global_config.jwt_expire_minutes":     "INTEGER DEFAULT 20",
		"global_config.timezone":               "VARCHAR(50) DEFAULT 'Asia/Shanghai'",
		"lb_rules.log_enabled":                 "BOOLEAN DEFAULT 0",
		"users.password_changed_at":            "DATETIME",
		"global_config.cluster_version":        "INTEGER DEFAULT 0",
		"global_config.sync_caddy_config":      "BOOLEAN DEFAULT 0",
		"global_config.cluster_token":          "TEXT DEFAULT ''",
		"global_config.registration_id":        "INTEGER DEFAULT 0",
		"global_config.registration_secret":    "TEXT DEFAULT ''",
		"global_config.applied_version":        "INTEGER DEFAULT 0",
		"global_config.last_sync_error":        "TEXT DEFAULT ''",
		"global_config.sync_fingerprint":       "TEXT DEFAULT ''",
		"nodes.cluster_token_hash":             "VARCHAR(64)",
		"nodes.registration_secret":            "VARCHAR(64)",
		"nodes.cluster_token_delivered":        "BOOLEAN DEFAULT 0",
		"nodes.reported_version":               "INTEGER DEFAULT 0",
		"nodes.health_json":                    "TEXT",
		"nodes.last_sync_at":                   "DATETIME",
		"nodes.last_sync_error":                "TEXT",
	}
	for col, dtype := range newColumns {
		parts := strings.Split(col, ".")
		if len(parts) != 2 {
			continue
		}
		table, name := parts[0], parts[1]
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, name).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check column %s.%s: %w", table, name, err)
		}
		if colCount == 0 {
			if _, err := DB.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + dtype); err != nil {
				return fmt.Errorf("failed to add column %s.%s: %w", table, name, err)
			}
		}
	}
	if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS cluster_register_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash VARCHAR(64) UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create cluster_register_tokens: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cluster_register_tokens_hash ON cluster_register_tokens(token_hash)"); err != nil {
		return fmt.Errorf("failed to index cluster_register_tokens: %w", err)
	}

	// Drop legacy cert_job_logs table — logs now stored in files under /app/logs/
	DB.Exec("DROP TABLE IF EXISTS cert_job_logs")

	// Set recommended defaults for timeout fields that are still 0
	DB.Exec("UPDATE global_config SET http_read_timeout=60 WHERE http_read_timeout=0")
	DB.Exec("UPDATE global_config SET http_write_timeout=60 WHERE http_write_timeout=0")
	DB.Exec("UPDATE global_config SET http_idle_timeout=120 WHERE http_idle_timeout=0")
	DB.Exec("UPDATE global_config SET upstream_keepalive_timeout=60 WHERE upstream_keepalive_timeout=0")
	DB.Exec("UPDATE global_config SET access_log_format='' WHERE access_log_format LIKE '{%'")
	DB.Exec("UPDATE global_config SET access_log_format = access_log_format || char(10) || 'request>headers>User-Agent -> user_agent' WHERE access_log_format != '' AND access_log_format NOT LIKE '%user_agent%'")

	// Headers are kept in access logs so User-Agent stats work; the filter
	// encoder cannot rename a field under a deleted parent.
	var lf string
	if err := DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&lf); err == nil && lf != "" {
		out := []string{}
		for _, l := range strings.Split(lf, "\n") {
			t := strings.TrimSpace(l)
			if t == "request>headers -> delete" || t == "request>headers>User-Agent -> user_agent" {
				continue
			}
			out = append(out, l)
		}
		DB.Exec("UPDATE global_config SET access_log_format=? WHERE id=1", strings.Join(out, "\n"))
	}

	// Sensitive credential headers are dropped from access logs (Cookie and
	// Authorization are redacted by Caddy itself; API keys are not).
	var lf2 string
	if err := DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&lf2); err == nil && lf2 != "" && !strings.Contains(lf2, "X-API-Key") {
		DB.Exec("UPDATE global_config SET access_log_format = ? WHERE id=1", lf2+"\nrequest>headers>X-API-Key -> delete")
	}

	// Create upstreams table if not exists
	DB.Exec(`CREATE TABLE IF NOT EXISTS upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		domain VARCHAR(255),
		dynamic_dns BOOLEAN DEFAULT 0,
		enabled BOOLEAN DEFAULT 1,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	`)

	// Create tls_certificates table if not exists
	DB.Exec(`CREATE TABLE IF NOT EXISTS tls_certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain VARCHAR(255) UNIQUE NOT NULL,
		cert_pem TEXT NOT NULL,
		key_pem TEXT NOT NULL,
		issuer VARCHAR(50) DEFAULT 'self-signed',
		acme_email VARCHAR(255),
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	`)

	// global_config new columns
	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='acme_email'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN acme_email VARCHAR(255)")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cert_expiry_days'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN cert_expiry_days INTEGER DEFAULT 30")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cert_renewal_days'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN cert_renewal_days INTEGER DEFAULT 30")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cert_renewal_attempts'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN cert_renewal_attempts INTEGER DEFAULT 5")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='metrics_public'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN metrics_public BOOLEAN DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='metrics_origins'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN metrics_origins VARCHAR(500)")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='caddy_log_path'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN caddy_log_path VARCHAR(500) DEFAULT '/app/logs/caddy.log'")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='caddy_log_level'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN caddy_log_level VARCHAR(10) DEFAULT 'info'")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='caddy_log_size_mb'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN caddy_log_size_mb INTEGER DEFAULT 100")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='request_body_max_size_mb'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN request_body_max_size_mb INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='http_read_timeout'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN http_read_timeout INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='http_write_timeout'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN http_write_timeout INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='http_idle_timeout'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN http_idle_timeout INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='upstream_keepalive_timeout'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN upstream_keepalive_timeout INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='server_tokens_hidden'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN server_tokens_hidden BOOLEAN DEFAULT FALSE")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='caddy_id'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN caddy_id VARCHAR(20)")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='dns_family'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN dns_family VARCHAR(20) DEFAULT 'ipv4'")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='updated_by'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN updated_by INTEGER")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name='dns_server'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE upstreams ADD COLUMN dns_server VARCHAR(255) DEFAULT ''")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name='max_connections'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE upstreams ADD COLUMN max_connections INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name='proxy_protocol'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE upstreams ADD COLUMN proxy_protocol VARCHAR(10) DEFAULT ''")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='tcp_health_check_port'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN tcp_health_check_port INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='tcp_try_duration'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN tcp_try_duration INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='tcp_try_interval'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN tcp_try_interval INTEGER DEFAULT 250")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='request_body_max_size_mb'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN request_body_max_size_mb INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='upstream_keepalive_timeout'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN upstream_keepalive_timeout INTEGER DEFAULT 0")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='server_tokens_hidden'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE lb_rules ADD COLUMN server_tokens_hidden INTEGER DEFAULT 0")
	}

	// certificate_configs schema migration: move from legacy dns_id/dns_key to JSON dns_credentials
	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('certificate_configs') WHERE name='dns_credentials'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE certificate_configs ADD COLUMN dns_credentials TEXT")
	}

	// cert_jobs unique index migration
	if _, err := DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain)"); err != nil {
		return fmt.Errorf("failed to create cert_jobs unique index: %w", err)
	}

	// Enforce cert_jobs status CHECK constraint and queued default on existing DBs.
	if err := migrateCertJobsStatusConstraint(); err != nil {
		return fmt.Errorf("failed to migrate cert_jobs status constraint: %w", err)
	}

	// Normalize ca_available_after to SQLite canonical UTC datetime format.
	// Older rows may contain Go time.Time strings like
	// "2026-07-02 11:56:03.432055881+00:00" which don't compare correctly
	// against datetime('now'). datetime() of an already-canonical string
	// returns the same value, so this is safe to run repeatedly.
	if _, err := DB.Exec("UPDATE cert_jobs SET ca_available_after = datetime(ca_available_after) WHERE ca_available_after IS NOT NULL"); err != nil {
		log.Printf("Warning: failed to normalize cert_jobs.ca_available_after: %v", err)
	}

	// Migrate legacy dns_id/dns_key into dns_credentials JSON
	rows, err := DB.Query("SELECT id, dns_id, dns_key FROM certificate_configs WHERE dns_credentials IS NULL OR dns_credentials = ''")
	if err == nil {
		for rows.Next() {
			var id int
			var dnsID, dnsKey string
			rows.Scan(&id, &dnsID, &dnsKey)
			if dnsID != "" || dnsKey != "" {
				creds, _ := json.Marshal(map[string]string{"app_id": dnsID, "app_token": dnsKey})
				DB.Exec("UPDATE certificate_configs SET dns_credentials = ? WHERE id = ?", string(creds), id)
			}
		}
		rows.Close()
	}

	// Drop legacy columns from lb_rules if they still exist (no longer used).
	legacyLbColumns := []string{"tls_auto_cert", "tls_email"}
	for _, col := range legacyLbColumns {
		DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name=?", col).Scan(&colCount)
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE lb_rules DROP COLUMN " + col); err != nil {
				log.Printf("Warning: failed to drop legacy column %s from lb_rules: %v", col, err)
			} else {
				log.Printf("Dropped legacy column %s from lb_rules", col)
			}
		}
	}

	// Migrate existing data: set caddy_id for rows that don't have it
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''").Scan(&count)
	if count > 0 {
		// Generate caddy_id for existing rules
		rows, err := DB.Query("SELECT id FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''")
		if err == nil {
			for rows.Next() {
				var ruleID int
				rows.Scan(&ruleID)
				caddyID := generateCaddyIDForMigration()
				DB.Exec("UPDATE lb_rules SET caddy_id = ? WHERE id = ?", caddyID, ruleID)
			}
			rows.Close()
		}
	}

	// Migration: Check if we need to rebuild lb_rules with caddy_id as primary key
	// SQLite doesn't support changing primary key directly, so we need to rebuild the table
	if err := migrateLbRulesPrimaryKey(); err != nil {
		log.Printf("Warning: lb_rules primary key migration failed: %v", err)
	}

	// Seed default CA providers if table is empty.
	var caCount int
	DB.QueryRow("SELECT COUNT(*) FROM ca_providers").Scan(&caCount)
	if caCount == 0 {
		_, err := DB.Exec(`
			INSERT INTO ca_providers (name, provider, directory_url, credentials, max_concurrent, min_interval_ms, enabled)
			VALUES
				('ZeroSSL', 'zerossl', 'https://acme.zerossl.com/v2/DV90', '{}', 1, 10000, 1),
				('Let''s Encrypt', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory', '{}', 2, 5000, 1)
		`)
		if err != nil {
			log.Printf("Warning: failed to seed CA providers: %v", err)
		} else {
			// LastInsertId returns the last row of the multi-row insert (Let's Encrypt),
			// so look up Let's Encrypt's actual ID directly and set it as the default.
			var leid int64
			if err := DB.QueryRow("SELECT id FROM ca_providers WHERE provider = 'letsencrypt' ORDER BY id LIMIT 1").Scan(&leid); err == nil {
				res, err := DB.Exec("UPDATE global_config SET default_ca_provider_id = ? WHERE id = 1", leid)
				if err != nil {
					log.Printf("Warning: failed to set default CA provider: %v", err)
				} else if rowsAffected, _ := res.RowsAffected(); rowsAffected == 0 {
					log.Printf("Warning: failed to set default CA provider to Let's Encrypt")
				}
			}
		}
	}

	// Backfill any existing CA providers that were seeded before updated_at had a default.
	_, _ = DB.Exec("UPDATE ca_providers SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL")

	return nil
}

// migrateLbRulesPrimaryKey rebuilds lb_rules and upstreams tables to use caddy_id as primary key
func migrateLbRulesPrimaryKey() error {
	// Check if lb_rules already has caddy_id as primary key (checked via pragma)
	var pkName string
	err := DB.QueryRow("SELECT name FROM pragma_table_info('lb_rules') WHERE pk = 1").Scan(&pkName)
	if err != nil {
		return fmt.Errorf("failed to check primary key: %w", err)
	}

	// If primary key is already 'caddy_id', nothing to do
	if pkName == "caddy_id" {
		log.Println("lb_rules already uses caddy_id as primary key")
		return nil
	}

	log.Println("Migrating lb_rules to use caddy_id as primary key...")

	// Disable foreign keys temporarily
	DB.Exec("PRAGMA foreign_keys = OFF")

	// Start transaction
	tx, err := DB.Begin()
	if err != nil {
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Create new lb_rules table with caddy_id as primary key
	_, err = tx.Exec(`
		CREATE TABLE lb_rules_new (
			id INTEGER,
			name VARCHAR(100) NOT NULL,
			description VARCHAR(300),
			protocol VARCHAR(10) NOT NULL,
			domain VARCHAR(255),
			listen_port INTEGER NOT NULL,
			strategy VARCHAR(20) DEFAULT 'weighted_round_robin',
			dynamic_dns BOOLEAN DEFAULT FALSE,
			enable_dns_server BOOLEAN DEFAULT FALSE,
			dns_server VARCHAR(255) DEFAULT '',
			dns_family VARCHAR(20) DEFAULT 'ipv4',
			health_check_path VARCHAR(255),
			health_check_interval INTEGER DEFAULT 10,
			health_check_timeout INTEGER DEFAULT 5,
			health_check_unhealthy_threshold INTEGER DEFAULT 3,
			health_check_healthy_threshold INTEGER DEFAULT 2,
			enable_active_health_check BOOLEAN DEFAULT FALSE,
			tcp_health_check_port INTEGER DEFAULT 0,
			tcp_try_duration INTEGER DEFAULT 0,
			tcp_try_interval INTEGER DEFAULT 250,
			request_body_max_size_mb INTEGER DEFAULT 0,
			upstream_keepalive_timeout INTEGER DEFAULT 0,
			server_tokens_hidden INTEGER DEFAULT 0,
			host_header VARCHAR(255),
			enable_tls BOOLEAN DEFAULT FALSE,
			tls_cert TEXT,
			tls_key TEXT,
			tls_http_redirect BOOLEAN DEFAULT FALSE,
			tls_source VARCHAR(20) DEFAULT 'manual',
			acme_config_id INTEGER DEFAULT 0,
			ca_provider_id INTEGER DEFAULT 0,
			enable_compress BOOLEAN DEFAULT TRUE,

			compress_types VARCHAR(100) DEFAULT 'gzip',
			enabled BOOLEAN DEFAULT TRUE,
			created_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			updated_by INTEGER,
			caddy_id VARCHAR(20) PRIMARY KEY
		)
	`)
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to create lb_rules_new: %w", err)
	}

	// Copy data from old table to new table
	_, err = tx.Exec(`
		INSERT INTO lb_rules_new (
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			host_header, enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, enabled,
			created_by, created_at, updated_at, updated_by, caddy_id
		)
		SELECT
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			host_header, enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, enabled,
			created_by, created_at, updated_at, updated_by, caddy_id
		FROM lb_rules
	`)
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to copy lb_rules data: %w", err)
	}

	// Drop old table
	_, err = tx.Exec("DROP TABLE lb_rules")
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to drop old lb_rules: %w", err)
	}

	// Rename new table
	_, err = tx.Exec("ALTER TABLE lb_rules_new RENAME TO lb_rules")
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to rename lb_rules_new: %w", err)
	}

	// Create new upstreams table with VARCHAR rule_id
	_, err = tx.Exec(`
		CREATE TABLE upstreams_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id VARCHAR(20) NOT NULL,
			host VARCHAR(255) NOT NULL,
			port INTEGER NOT NULL,
			weight INTEGER DEFAULT 1,
			domain VARCHAR(255),
			dynamic_dns BOOLEAN DEFAULT FALSE,
			enabled BOOLEAN DEFAULT TRUE,
			protocol VARCHAR(10) DEFAULT 'http',
			host_header VARCHAR(255),
			dns_server VARCHAR(255) DEFAULT '',
			max_connections INTEGER DEFAULT 0,
			proxy_protocol VARCHAR(10) DEFAULT '',
			FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to create upstreams_new: %w", err)
	}

	// Copy data from old upstreams table to new (convert rule_id from int to string)
	_, err = tx.Exec(`
		INSERT INTO upstreams_new (id, rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, host_header, dns_server, max_connections, proxy_protocol)
		SELECT u.id, r.caddy_id, u.host, u.port, u.weight, u.domain, u.dynamic_dns, u.enabled, u.protocol, u.host_header, 
		       COALESCE(u.dns_server, ''), 0, ''
		FROM upstreams u
		JOIN lb_rules r ON u.rule_id = r.id
	`)
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to copy upstreams data: %w", err)
	}

	// Drop old upstreams table
	_, err = tx.Exec("DROP TABLE upstreams")
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to drop old upstreams: %w", err)
	}

	// Rename new upstreams table
	_, err = tx.Exec("ALTER TABLE upstreams_new RENAME TO upstreams")
	if err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to rename upstreams_new: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Re-enable foreign keys
	DB.Exec("PRAGMA foreign_keys = ON")

	log.Println("Successfully migrated lb_rules to use caddy_id as primary key")
	return nil
}

// migrateCertJobsStatusConstraint rebuilds cert_jobs (and cert_job_logs, which
// references it) to enforce the allowed status CHECK constraint and the
// 'queued' default value on existing databases.
func migrateCertJobsStatusConstraint() error {
	var tableSQL string
	if err := DB.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='cert_jobs'").Scan(&tableSQL); err != nil {
		return fmt.Errorf("failed to read cert_jobs schema: %w", err)
	}
	// Idempotency: the expanded constraint must allow all intermediate ACME
	// stages logged by jobLogger.Log (e.g. 'presenting_dns', 'finalizing').
	// If the table already contains one of the new stage values in its CHECK,
	// the migration has already been applied.
	if strings.Contains(tableSQL, "'presenting_dns'") {
		return nil
	}

	log.Println("Migrating cert_jobs status constraint...")

	DB.Exec("PRAGMA foreign_keys = OFF")
	tx, err := DB.Begin()
	if err != nil {
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if _, err := tx.Exec("ALTER TABLE cert_jobs RENAME TO cert_jobs_old"); err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to rename cert_jobs: %w", err)
	}

	var logsExist int
	DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cert_job_logs'").Scan(&logsExist)
	if logsExist > 0 {
		if _, err := tx.Exec("ALTER TABLE cert_job_logs RENAME TO cert_job_logs_old"); err != nil {
			tx.Rollback()
			DB.Exec("PRAGMA foreign_keys = ON")
			return fmt.Errorf("failed to rename cert_job_logs: %w", err)
		}
	}

	if _, err := tx.Exec(`
		CREATE TABLE cert_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id VARCHAR(20) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			status VARCHAR(20) DEFAULT 'queued' CHECK (status IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid')),
			message TEXT,
			expires_at DATETIME,
			cert_pem TEXT,
			key_pem TEXT,
			ca_provider_id INTEGER DEFAULT 0,
			renewal_attempts INTEGER DEFAULT 0,
			ca_available_after DATETIME,
			last_error_code VARCHAR(20),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME
		)
	`); err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to create new cert_jobs table: %w", err)
	}

	if _, err := tx.Exec(`
		INSERT INTO cert_jobs (
			id, rule_id, domain, status, message, expires_at, cert_pem, key_pem,
			ca_provider_id, renewal_attempts, ca_available_after, last_error_code,
			created_at, updated_at
		)
		SELECT
			id, rule_id, domain,
			CASE WHEN status IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca') THEN status ELSE 'queued' END,
			message, expires_at, cert_pem, key_pem,
			ca_provider_id, renewal_attempts, ca_available_after, last_error_code,
			created_at, updated_at
		FROM cert_jobs_old
	`); err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to copy cert_jobs data: %w", err)
	}

	if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain ON cert_jobs(rule_id, domain)"); err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to recreate cert_jobs index: %w", err)
	}
	if _, err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain)"); err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to recreate cert_jobs unique index: %w", err)
	}

	if logsExist > 0 {
		if _, err := tx.Exec(`
			CREATE TABLE cert_job_logs (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				job_id INTEGER NOT NULL,
				level VARCHAR(10) DEFAULT 'info',
				message TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (job_id) REFERENCES cert_jobs(id) ON DELETE CASCADE
			)
		`); err != nil {
			tx.Rollback()
			DB.Exec("PRAGMA foreign_keys = ON")
			return fmt.Errorf("failed to create new cert_job_logs table: %w", err)
		}
		if _, err := tx.Exec(`
			INSERT INTO cert_job_logs (id, job_id, level, message, created_at)
			SELECT id, job_id, level, message, created_at
			FROM cert_job_logs_old
		`); err != nil {
			tx.Rollback()
			DB.Exec("PRAGMA foreign_keys = ON")
			return fmt.Errorf("failed to copy cert_job_logs data: %w", err)
		}
		if _, err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_cert_job_logs_job ON cert_job_logs(job_id)"); err != nil {
			tx.Rollback()
			DB.Exec("PRAGMA foreign_keys = ON")
			return fmt.Errorf("failed to recreate cert_job_logs index: %w", err)
		}
		if _, err := tx.Exec("DROP TABLE cert_job_logs_old"); err != nil {
			tx.Rollback()
			DB.Exec("PRAGMA foreign_keys = ON")
			return fmt.Errorf("failed to drop old cert_job_logs table: %w", err)
		}
	}

	if _, err := tx.Exec("DROP TABLE cert_jobs_old"); err != nil {
		tx.Rollback()
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to drop old cert_jobs table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		DB.Exec("PRAGMA foreign_keys = ON")
		return fmt.Errorf("failed to commit cert_jobs migration: %w", err)
	}
	DB.Exec("PRAGMA foreign_keys = ON")

	log.Println("cert_jobs status constraint migration completed")
	return nil
}

func Close() error {
	var err error
	if AuditDB != nil {
		err = AuditDB.Close()
	}
	if MetricsDB != nil {
		if closeErr := MetricsDB.Close(); err == nil {
			err = closeErr
		}
	}
	if DB != nil {
		if closeErr := DB.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

// generateCaddyIDForMigration generates a unique caddy_id for migration
func generateCaddyIDForMigration() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	id := make([]byte, 13)
	id[0] = 'l'
	id[1] = 'b'
	id[2] = '_'
	for i := 3; i < 13; i++ {
		n := len(charset)
		r := int(uint64(time.Now().UnixNano()) % uint64(n))
		id[i] = charset[r]
	}
	return string(id)
}
