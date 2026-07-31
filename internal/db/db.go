package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
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
	openDatabase   = sql.Open
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

func Initialize(dataDir string) (err error) {
	// Create data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "lazy-balancer.db")

	database, err := openDatabase("sqlite", dbPath+"?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=30000&_synchronous=NORMAL&_txlock=immediate")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	var metricsDB, auditDB *sql.DB
	defer func() {
		if err == nil {
			return
		}
		if auditDB != nil && auditDB != oldAuditDB {
			err = errors.Join(err, auditDB.Close())
		}
		if metricsDB != nil && metricsDB != oldMetricsDB {
			err = errors.Join(err, metricsDB.Close())
		}
		err = errors.Join(err, database.Close())
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	}()

	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(0)

	if err := database.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	DB = database

	// Initialize metrics database
	if err := InitializeMetricsDB(dataDir); err != nil {
		return fmt.Errorf("failed to initialize metrics database: %w", err)
	}
	metricsDB = MetricsDB

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Ensure default config row exists
	var configCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM global_config").Scan(&configCount); err != nil {
		return fmt.Errorf("failed to count global config rows: %w", err)
	}
	if configCount == 0 {
		if _, err := DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
			return fmt.Errorf("failed to insert global config singleton: %w", err)
		}
	}

	// Run migrations
	if err := runMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if initErr := InitializeAuditDB(dataDir); initErr != nil {
		auditDB = AuditDB
		return fmt.Errorf("failed to initialize audit database: %w", initErr)
	}
	auditDB = AuditDB
	currentDB.Store(database)

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
		ip_acl_mode TEXT NOT NULL DEFAULT '',
		ip_acl_list TEXT NOT NULL DEFAULT '[]',
		custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
		proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
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

	CREATE TABLE IF NOT EXISTS path_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0,
		match_type TEXT NOT NULL DEFAULT 'prefix',
		path TEXT NOT NULL,
		upstreams_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_path_rules_rule_order ON path_rules(rule_id, sort_order, id);

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
		deployment_attempts INTEGER DEFAULT 0,
		deployment_available_after DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);

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
		proxy_dial_timeout INTEGER DEFAULT 0,
		proxy_response_header_timeout INTEGER DEFAULT 0,
		proxy_read_timeout INTEGER DEFAULT 0,
		proxy_write_timeout INTEGER DEFAULT 0,
		proxy_stream_timeout INTEGER DEFAULT 0,
		server_tokens_hidden BOOLEAN DEFAULT FALSE,
		cert_expiry_days INTEGER DEFAULT 30,
		cert_renewal_days INTEGER DEFAULT 30,
		cert_job_log_size_mb INTEGER DEFAULT 10,
	runtime_log_size_mb INTEGER DEFAULT 100,
		access_log_json BOOLEAN DEFAULT TRUE,
		access_log_format TEXT DEFAULT '',
		audit_retention_months INTEGER DEFAULT 3,
		metrics_retention_days INTEGER DEFAULT 7,
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
		registration_secret_expires_at DATETIME,
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

	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='display_name'").Scan(&colCount); err != nil {
		return fmt.Errorf("failed to check users.display_name: %w", err)
	}
	if colCount == 0 {
		if _, err := DB.Exec("ALTER TABLE users ADD COLUMN display_name VARCHAR(100)"); err != nil {
			return fmt.Errorf("failed to add users.display_name: %w", err)
		}
	}

	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='is_enabled'").Scan(&colCount); err != nil {
		return fmt.Errorf("failed to check users.is_enabled: %w", err)
	}
	if colCount == 0 {
		if _, err := DB.Exec("ALTER TABLE users ADD COLUMN is_enabled BOOLEAN DEFAULT 1"); err != nil {
			return fmt.Errorf("failed to add users.is_enabled: %w", err)
		}
	}
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name='is_enabled'").Scan(&colCount); err != nil {
		return fmt.Errorf("failed to check api_keys.is_enabled: %w", err)
	}
	if colCount == 0 {
		if _, err := DB.Exec("ALTER TABLE api_keys ADD COLUMN is_enabled BOOLEAN DEFAULT 1"); err != nil {
			return fmt.Errorf("failed to add api_keys.is_enabled: %w", err)
		}
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
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check lb_rules.%s: %w", col, err)
		}
		if colCount == 0 {
			if _, err := DB.Exec("ALTER TABLE lb_rules ADD COLUMN " + col + " " + dtype); err != nil {
				return fmt.Errorf("failed to add lb_rules.%s: %w", col, err)
			}
		}
	}

	if _, err := DB.Exec("UPDATE lb_rules SET strategy='weighted_round_robin' WHERE strategy='round_robin'"); err != nil {
		return fmt.Errorf("failed to normalize lb_rules strategy: %w", err)
	}

	if _, err := DB.Exec("DROP TABLE IF EXISTS config_versions"); err != nil {
		return fmt.Errorf("failed to drop config_versions: %w", err)
	}
	var accessLogCol int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='access_log_enabled'").Scan(&accessLogCol); err != nil {
		return fmt.Errorf("failed to check global_config.access_log_enabled: %w", err)
	}
	if accessLogCol > 0 {
		if _, err := DB.Exec("ALTER TABLE global_config DROP COLUMN access_log_enabled"); err != nil {
			return fmt.Errorf("failed to drop global_config.access_log_enabled: %w", err)
		}
	}

	// ca_providers columns are created by createTables; here we only add columns to existing tables.
	newColumns := map[string]string{
		"lb_rules.ca_provider_id":                     "INTEGER DEFAULT 0",
		"lb_rules.caddy_id":                           "VARCHAR(20)",
		"lb_rules.dns_family":                         "VARCHAR(20) DEFAULT 'ipv4'",
		"lb_rules.updated_by":                         "INTEGER",
		"lb_rules.tcp_health_check_port":              "INTEGER DEFAULT 0",
		"lb_rules.tcp_proxy_protocol":                 "BOOLEAN DEFAULT 0",
		"lb_rules.tcp_try_duration":                   "INTEGER DEFAULT 0",
		"lb_rules.tcp_try_interval":                   "INTEGER DEFAULT 250",
		"lb_rules.request_body_max_size_mb":           "INTEGER DEFAULT 0",
		"lb_rules.upstream_keepalive_timeout":         "INTEGER DEFAULT 0",
		"lb_rules.server_tokens_hidden":               "INTEGER DEFAULT 0",
		"upstreams.dns_server":                        "VARCHAR(255) DEFAULT ''",
		"upstreams.max_connections":                   "INTEGER DEFAULT 0",
		"upstreams.proxy_protocol":                    "VARCHAR(10) DEFAULT ''",
		"certificate_configs.dns_credentials":         "TEXT",
		"cert_jobs.ca_provider_id":                    "INTEGER DEFAULT 0",
		"cert_jobs.renewal_attempts":                  "INTEGER DEFAULT 0",
		"cert_jobs.ca_available_after":                "DATETIME",
		"cert_jobs.last_error_code":                   "VARCHAR(20)",
		"cert_jobs.deployment_attempts":               "INTEGER DEFAULT 0",
		"cert_jobs.deployment_available_after":        "DATETIME",
		"global_config.default_ca_provider_id":        "INTEGER DEFAULT 0",
		"global_config.cert_renewal_days":             "INTEGER DEFAULT 30",
		"global_config.cert_renewal_attempts":         "INTEGER DEFAULT 5",
		"global_config.cert_job_log_size_mb":          "INTEGER DEFAULT 10",
		"global_config.runtime_log_size_mb":           "INTEGER DEFAULT 100",
		"global_config.acme_email":                    "VARCHAR(255)",
		"global_config.cert_expiry_days":              "INTEGER DEFAULT 30",
		"global_config.metrics_public":                "BOOLEAN DEFAULT 0",
		"global_config.metrics_origins":               "VARCHAR(500)",
		"global_config.caddy_log_path":                "VARCHAR(500) DEFAULT '/app/logs/caddy.log'",
		"global_config.caddy_log_level":               "VARCHAR(10) DEFAULT 'info'",
		"global_config.caddy_log_size_mb":             "INTEGER DEFAULT 100",
		"global_config.request_body_max_size_mb":      "INTEGER DEFAULT 0",
		"global_config.http_read_timeout":             "INTEGER DEFAULT 0",
		"global_config.http_write_timeout":            "INTEGER DEFAULT 0",
		"global_config.http_idle_timeout":             "INTEGER DEFAULT 0",
		"global_config.upstream_keepalive_timeout":    "INTEGER DEFAULT 0",
		"global_config.server_tokens_hidden":          "BOOLEAN DEFAULT FALSE",
		"global_config.admin_tls_enabled":             "BOOLEAN DEFAULT 0",
		"global_config.admin_tls_mode":                "VARCHAR(20) DEFAULT 'selfsigned'",
		"global_config.admin_tls_cert":                "TEXT DEFAULT ''",
		"global_config.admin_tls_key":                 "TEXT DEFAULT ''",
		"global_config.admin_tls_acme_rule_id":        "VARCHAR(50) DEFAULT ''",
		"global_config.admin_tls_port":                "INTEGER DEFAULT 8443",
		"global_config.access_log_json":               "BOOLEAN DEFAULT TRUE",
		"global_config.access_log_format":             "TEXT DEFAULT ''",
		"global_config.audit_retention_months":        "INTEGER DEFAULT 3",
		"global_config.metrics_retention_days":        "INTEGER DEFAULT 7",
		"global_config.jwt_expire_minutes":            "INTEGER DEFAULT 20",
		"global_config.timezone":                      "VARCHAR(50) DEFAULT 'Asia/Shanghai'",
		"lb_rules.log_enabled":                        "BOOLEAN DEFAULT 0",
		"lb_rules.ip_acl_mode":                        "TEXT NOT NULL DEFAULT ''",
		"lb_rules.ip_acl_list":                        "TEXT NOT NULL DEFAULT '[]'",
		"lb_rules.custom_routes_enabled":              "BOOLEAN NOT NULL DEFAULT 0",
		"lb_rules.proxy_dial_timeout":                 "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_response_header_timeout":      "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_read_timeout":                 "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_write_timeout":                "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_stream_timeout":               "INTEGER NOT NULL DEFAULT 0",
		"global_config.proxy_dial_timeout":            "INTEGER DEFAULT 0",
		"global_config.proxy_response_header_timeout": "INTEGER DEFAULT 0",
		"global_config.proxy_read_timeout":            "INTEGER DEFAULT 0",
		"global_config.proxy_write_timeout":           "INTEGER DEFAULT 0",
		"global_config.proxy_stream_timeout":          "INTEGER DEFAULT 0",
		"users.password_changed_at":                   "DATETIME",
		"users.password_version":                      "INTEGER NOT NULL DEFAULT 0",
		"global_config.cluster_version":               "INTEGER DEFAULT 0",
		"global_config.sync_caddy_config":             "BOOLEAN DEFAULT 0",
		"global_config.cluster_token":                 "TEXT DEFAULT ''",
		"global_config.registration_id":               "INTEGER DEFAULT 0",
		"global_config.registration_secret":           "TEXT DEFAULT ''",
		"global_config.applied_version":               "INTEGER DEFAULT 0",
		"global_config.last_sync_error":               "TEXT DEFAULT ''",
		"global_config.sync_fingerprint":              "TEXT DEFAULT ''",
		"nodes.cluster_token_hash":                    "VARCHAR(64)",
		"nodes.registration_secret":                   "VARCHAR(64)",
		"nodes.registration_secret_expires_at":        "DATETIME",
		"nodes.cluster_token_delivered":               "BOOLEAN DEFAULT 0",
		"nodes.reported_version":                      "INTEGER DEFAULT 0",
		"nodes.health_json":                           "TEXT",
		"nodes.last_sync_at":                          "DATETIME",
		"nodes.last_sync_error":                       "TEXT",
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
	if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS path_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0,
		match_type TEXT NOT NULL DEFAULT 'prefix',
		path TEXT NOT NULL,
		upstreams_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("failed to create path_rules: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_path_rules_rule_order ON path_rules(rule_id, sort_order, id)"); err != nil {
		return fmt.Errorf("failed to index path_rules: %w", err)
	}

	// Drop legacy cert_job_logs table — logs now stored in files under /app/logs/
	if _, err := DB.Exec("DROP TABLE IF EXISTS cert_job_logs"); err != nil {
		return fmt.Errorf("failed to drop cert_job_logs: %w", err)
	}

	// Set recommended defaults for timeout fields that are still 0
	defaultUpdates := []string{
		"UPDATE global_config SET jwt_expire_minutes=20 WHERE jwt_expire_minutes IS NULL OR jwt_expire_minutes<=0 OR jwt_expire_minutes>1440",
		"UPDATE global_config SET http_read_timeout=60 WHERE http_read_timeout=0",
		"UPDATE global_config SET http_write_timeout=60 WHERE http_write_timeout=0",
		"UPDATE global_config SET http_idle_timeout=120 WHERE http_idle_timeout=0",
		"UPDATE global_config SET upstream_keepalive_timeout=60 WHERE upstream_keepalive_timeout=0",
		"UPDATE global_config SET access_log_format='' WHERE access_log_format LIKE '{%'",
		"UPDATE global_config SET access_log_format = access_log_format || char(10) || 'request>headers>User-Agent -> user_agent' WHERE access_log_format != '' AND access_log_format NOT LIKE '%user_agent%'",
	}
	for _, statement := range defaultUpdates {
		if _, err := DB.Exec(statement); err != nil {
			return fmt.Errorf("failed to update global config defaults: %w", err)
		}
	}

	// Headers are kept in access logs so User-Agent stats work; the filter
	// encoder cannot rename a field under a deleted parent.
	var lf string
	if err := DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&lf); err != nil {
		return fmt.Errorf("failed to read global config access log format: %w", err)
	}
	if lf != "" {
		out := []string{}
		for _, l := range strings.Split(lf, "\n") {
			t := strings.TrimSpace(l)
			if t == "request>headers -> delete" || t == "request>headers>User-Agent -> user_agent" {
				continue
			}
			out = append(out, l)
		}
		if _, err := DB.Exec("UPDATE global_config SET access_log_format=? WHERE id=1", strings.Join(out, "\n")); err != nil {
			return fmt.Errorf("failed to clean global config access log format: %w", err)
		}
	}

	// Sensitive credential headers are dropped from access logs (Cookie and
	// Authorization are redacted by Caddy itself; API keys are not).
	var lf2 string
	if err := DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&lf2); err != nil {
		return fmt.Errorf("failed to reread global config access log format: %w", err)
	}
	if lf2 != "" && !strings.Contains(lf2, "X-API-Key") {
		if _, err := DB.Exec("UPDATE global_config SET access_log_format = ? WHERE id=1", lf2+"\nrequest>headers>X-API-Key -> delete"); err != nil {
			return fmt.Errorf("failed to redact API key access log header: %w", err)
		}
	}

	// Create upstreams table if not exists
	if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		domain VARCHAR(255),
		dynamic_dns BOOLEAN DEFAULT 0,
		enabled BOOLEAN DEFAULT 1,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("failed to create upstreams: %w", err)
	}

	// Create tls_certificates table if not exists
	if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS tls_certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain VARCHAR(255) UNIQUE NOT NULL,
		cert_pem TEXT NOT NULL,
		key_pem TEXT NOT NULL,
		issuer VARCHAR(50) DEFAULT 'self-signed',
		acme_email VARCHAR(255),
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	)`); err != nil {
		return fmt.Errorf("failed to create tls_certificates: %w", err)
	}

	if _, err := DB.Exec(`DELETE FROM cert_jobs WHERE id NOT IN (
		SELECT MAX(id) FROM cert_jobs GROUP BY rule_id, domain
	)`); err != nil {
		return fmt.Errorf("failed to deduplicate cert_jobs: %w", err)
	}

	// Enforce cert_jobs status CHECK constraint and queued default on existing DBs.
	if err := migrateCertJobsStatusConstraint(); err != nil {
		return fmt.Errorf("failed to migrate cert_jobs status constraint: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain ON cert_jobs(rule_id, domain)"); err != nil {
		return fmt.Errorf("failed to create cert_jobs rule-domain index: %w", err)
	}
	if _, err := DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain)"); err != nil {
		return fmt.Errorf("failed to create cert_jobs unique index: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_status_ca_available ON cert_jobs(status, ca_available_after)"); err != nil {
		return fmt.Errorf("failed to index cert_jobs CA availability: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_status_expires ON cert_jobs(status, expires_at)"); err != nil {
		return fmt.Errorf("failed to index cert_jobs expiration: %w", err)
	}

	// Normalize ca_available_after to SQLite canonical UTC datetime format.
	// Older rows may contain Go time.Time strings like
	// "2026-07-02 11:56:03.432055881+00:00" which don't compare correctly
	// against datetime('now'). datetime() of an already-canonical string
	// returns the same value, so this is safe to run repeatedly.
	if _, err := DB.Exec("UPDATE cert_jobs SET ca_available_after = datetime(ca_available_after) WHERE ca_available_after IS NOT NULL"); err != nil {
		return fmt.Errorf("failed to normalize cert_jobs.ca_available_after: %w", err)
	}

	if err := migrateLegacyDNSCredentials(); err != nil {
		return err
	}

	// Drop legacy columns from lb_rules if they still exist (no longer used).
	legacyLbColumns := []string{"tls_auto_cert", "tls_email"}
	for _, col := range legacyLbColumns {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check legacy lb_rules.%s: %w", col, err)
		}
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE lb_rules DROP COLUMN " + col); err != nil {
				return fmt.Errorf("failed to drop legacy lb_rules.%s: %w", col, err)
			}
			log.Printf("Dropped legacy column %s from lb_rules", col)
		}
	}

	// Migrate existing data: set caddy_id for rows that don't have it
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''").Scan(&count); err != nil {
		return fmt.Errorf("failed to count lb_rules without caddy_id: %w", err)
	}
	if count > 0 {
		// Generate caddy_id for existing rules
		rows, err := DB.Query("SELECT id FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''")
		if err != nil {
			return fmt.Errorf("failed to query lb_rules without caddy_id: %w", err)
		}
		for rows.Next() {
			var ruleID int
			if err := rows.Scan(&ruleID); err != nil {
				rows.Close()
				return fmt.Errorf("failed to scan lb_rule without caddy_id: %w", err)
			}
			caddyID := generateCaddyIDForMigration()
			if _, err := DB.Exec("UPDATE lb_rules SET caddy_id = ? WHERE id = ?", caddyID, ruleID); err != nil {
				rows.Close()
				return fmt.Errorf("failed to set caddy_id for lb_rule %d: %w", ruleID, err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("failed to iterate lb_rules without caddy_id: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("failed to close lb_rules migration rows: %w", err)
		}
	}

	// Migration: Check if we need to rebuild lb_rules with caddy_id as primary key
	// SQLite doesn't support changing primary key directly, so we need to rebuild the table
	if err := migrateLbRulesPrimaryKey(); err != nil {
		return fmt.Errorf("failed to migrate lb_rules primary key: %w", err)
	}

	// Seed default CA providers if table is empty.
	var caCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM ca_providers").Scan(&caCount); err != nil {
		return fmt.Errorf("failed to count CA providers: %w", err)
	}
	if caCount == 0 {
		if _, err := DB.Exec(`
			INSERT INTO ca_providers (name, provider, directory_url, credentials, max_concurrent, min_interval_ms, enabled)
			VALUES
				('ZeroSSL', 'zerossl', 'https://acme.zerossl.com/v2/DV90', '{}', 1, 10000, 1),
				('Let''s Encrypt', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory', '{}', 2, 5000, 1)
		`); err != nil {
			return fmt.Errorf("failed to seed CA providers: %w", err)
		}
		// LastInsertId returns the last row of the multi-row insert (Let's Encrypt),
		// so look up Let's Encrypt's actual ID directly and set it as the default.
		var leid int64
		if err := DB.QueryRow("SELECT id FROM ca_providers WHERE provider = 'letsencrypt' ORDER BY id LIMIT 1").Scan(&leid); err != nil {
			return fmt.Errorf("failed to find seeded Let's Encrypt provider: %w", err)
		}
		res, err := DB.Exec("UPDATE global_config SET default_ca_provider_id = ? WHERE id = 1", leid)
		if err != nil {
			return fmt.Errorf("failed to set default CA provider: %w", err)
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to read default CA provider update result: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("failed to set default CA provider: global config singleton not found")
		}
	}

	// Backfill any existing CA providers that were seeded before updated_at had a default.
	if _, err := DB.Exec("UPDATE ca_providers SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill CA provider timestamps: %w", err)
	}

	return nil
}

func migrateLegacyDNSCredentials() error {
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin legacy certificate credential migration: %w", err)
	}
	var columnCount int
	if err := tx.QueryRow("SELECT COUNT(*) FROM pragma_table_info('certificate_configs') WHERE name IN ('dns_id','dns_key')").Scan(&columnCount); err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to check legacy certificate credential columns: %w", err))
	}
	if columnCount == 2 {
		rows, err := tx.Query("SELECT id, dns_id, dns_key FROM certificate_configs WHERE dns_credentials IS NULL OR dns_credentials = ''")
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to query legacy certificate credentials: %w", err))
		}
		type legacyCredential struct {
			id            int
			dnsID, dnsKey string
		}
		var credentials []legacyCredential
		for rows.Next() {
			var credential legacyCredential
			if err := rows.Scan(&credential.id, &credential.dnsID, &credential.dnsKey); err != nil {
				closeErr := rows.Close()
				return rollbackMigration(tx, errors.Join(fmt.Errorf("failed to scan legacy certificate credentials: %w", err), closeErr))
			}
			credentials = append(credentials, credential)
		}
		if err := rows.Err(); err != nil {
			closeErr := rows.Close()
			return rollbackMigration(tx, errors.Join(fmt.Errorf("failed to iterate legacy certificate credentials: %w", err), closeErr))
		}
		if err := rows.Close(); err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to close legacy certificate credential rows: %w", err))
		}
		for _, credential := range credentials {
			if credential.dnsID == "" && credential.dnsKey == "" {
				continue
			}
			encoded, err := json.Marshal(map[string]string{"app_id": credential.dnsID, "app_token": credential.dnsKey})
			if err != nil {
				return rollbackMigration(tx, fmt.Errorf("failed to encode legacy certificate credentials: %w", err))
			}
			if _, err := tx.Exec("UPDATE certificate_configs SET dns_credentials = ? WHERE id = ?", string(encoded), credential.id); err != nil {
				return rollbackMigration(tx, fmt.Errorf("failed to migrate certificate credentials for config %d: %w", credential.id, err))
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit legacy certificate credential migration: %w", err)
	}
	return nil
}

func rollbackMigration(tx *sql.Tx, migrationErr error) error {
	if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
		return errors.Join(migrationErr, rollbackErr)
	}
	return migrationErr
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

	// PRAGMA 是会话级设置，必须与后续事务使用同一连接
	conn, err := DB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("failed to disable foreign keys: %w", err)
	}
	fkRestored := false
	defer func() {
		if !fkRestored {
			_, _ = conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON")
		}
	}()

	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
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
			tcp_proxy_protocol BOOLEAN DEFAULT 0,
			tcp_try_duration INTEGER DEFAULT 0,
			tcp_try_interval INTEGER DEFAULT 250,
			request_body_max_size_mb INTEGER DEFAULT 0,
			upstream_keepalive_timeout INTEGER DEFAULT 0,
			server_tokens_hidden INTEGER DEFAULT 0,
			ip_acl_mode TEXT NOT NULL DEFAULT '',
			ip_acl_list TEXT NOT NULL DEFAULT '[]',
			custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
			proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
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
			log_enabled BOOLEAN DEFAULT 0,
			created_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			updated_by INTEGER,
			caddy_id VARCHAR(20) PRIMARY KEY
		)
	`)
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to create lb_rules_new: %w", err))
	}

	// Copy data from old table to new table
	_, err = tx.Exec(`
		INSERT INTO lb_rules_new (
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			ip_acl_mode, ip_acl_list, custom_routes_enabled,
			proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout,
			host_header, enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, enabled, log_enabled,
			created_by, created_at, updated_at, updated_by, caddy_id
		)
		SELECT
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
			host_header, enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, enabled, COALESCE(log_enabled,0),
			created_by, created_at, updated_at, updated_by, caddy_id
		FROM lb_rules
	`)
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to copy lb_rules data: %w", err))
	}

	// Drop old table
	_, err = tx.Exec("DROP TABLE lb_rules")
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to drop old lb_rules: %w", err))
	}

	// Rename new table
	_, err = tx.Exec("ALTER TABLE lb_rules_new RENAME TO lb_rules")
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to rename lb_rules_new: %w", err))
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
		return rollbackMigration(tx, fmt.Errorf("failed to create upstreams_new: %w", err))
	}

	// Copy data from old upstreams table to new (convert rule_id from int to string)
	_, err = tx.Exec(`
		INSERT INTO upstreams_new (id, rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, host_header, dns_server, max_connections, proxy_protocol)
		SELECT u.id, r.caddy_id, u.host, u.port, u.weight, u.domain, u.dynamic_dns, u.enabled, u.protocol, u.host_header, 
		       COALESCE(u.dns_server, ''), COALESCE(u.max_connections, 0), COALESCE(u.proxy_protocol, '')
		FROM upstreams u
		JOIN lb_rules r ON u.rule_id = r.id
	`)
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to copy upstreams data: %w", err))
	}

	// Drop old upstreams table
	_, err = tx.Exec("DROP TABLE upstreams")
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to drop old upstreams: %w", err))
	}

	// Rename new upstreams table
	_, err = tx.Exec("ALTER TABLE upstreams_new RENAME TO upstreams")
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to rename upstreams_new: %w", err))
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to re-enable foreign keys: %w", err)
	}
	fkRestored = true

	log.Println("Successfully migrated lb_rules to use caddy_id as primary key")
	return nil
}

var statusInConstraintPattern = regexp.MustCompile(`(?i)\bstatus\s+IN\s*\(([^)]*)\)`)

func hasExactStatusConstraint(tableSQL string, requiredStatuses []string) bool {
	match := statusInConstraintPattern.FindStringSubmatch(tableSQL)
	if len(match) != 2 {
		return false
	}
	statuses := strings.Split(match[1], ",")
	if len(statuses) != len(requiredStatuses) {
		return false
	}
	required := make(map[string]struct{}, len(requiredStatuses))
	for _, status := range requiredStatuses {
		required[status] = struct{}{}
	}
	seen := make(map[string]struct{}, len(statuses))
	for _, rawStatus := range statuses {
		rawStatus = strings.Join(strings.Fields(rawStatus), "")
		if len(rawStatus) < 2 || rawStatus[0] != rawStatus[len(rawStatus)-1] || (rawStatus[0] != '\'' && rawStatus[0] != '"') {
			return false
		}
		status := rawStatus[1 : len(rawStatus)-1]
		if _, ok := required[status]; !ok {
			return false
		}
		seen[status] = struct{}{}
	}
	return len(seen) == len(required)
}

// migrateCertJobsStatusConstraint rebuilds cert_jobs to enforce the allowed
// status CHECK constraint and the 'queued' default value on existing databases.
func migrateCertJobsStatusConstraint() error {
	var tableSQL string
	if err := DB.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='cert_jobs'").Scan(&tableSQL); err != nil {
		return fmt.Errorf("failed to read cert_jobs schema: %w", err)
	}
	requiredStatuses := []string{
		"queued", "pending", "processing", "creating_account", "creating_order", "order_created",
		"cleanup_dns", "cleanup_warning", "presenting_dns", "waiting_propagation", "dns_propagated",
		"accepting_challenge", "validating", "validated", "finalizing", "finalized", "downloading",
		"downloaded", "issued", "failed", "waiting_ca", "disabled", "waiting_order_ready", "order_ready",
		"waiting_order_valid", "order_valid",
	}
	constraintComplete := hasExactStatusConstraint(tableSQL, requiredStatuses)
	defaultQueued := false
	rows, err := DB.Query("PRAGMA table_info(cert_jobs)")
	if err != nil {
		return fmt.Errorf("failed to read cert_jobs columns: %w", err)
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan cert_jobs columns: %w", err)
		}
		if name == "status" {
			defaultQueued = defaultValue.Valid && strings.Trim(defaultValue.String, "'\"") == "queued"
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate cert_jobs columns: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close cert_jobs columns: %w", err)
	}
	if constraintComplete && defaultQueued {
		return nil
	}

	log.Println("Migrating cert_jobs status constraint...")

	conn, err := DB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("failed to disable foreign keys: %w", err)
	}
	fkRestored := false
	defer func() {
		if !fkRestored {
			_, _ = conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON")
		}
	}()

	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if _, err := tx.Exec("ALTER TABLE cert_jobs RENAME TO cert_jobs_old"); err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to rename cert_jobs: %w", err))
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
			deployment_attempts INTEGER DEFAULT 0,
			deployment_available_after DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME
		)
	`); err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to create new cert_jobs table: %w", err))
	}

	if _, err := tx.Exec(`
		INSERT INTO cert_jobs (
			id, rule_id, domain, status, message, expires_at, cert_pem, key_pem,
			ca_provider_id, renewal_attempts, ca_available_after, last_error_code, deployment_attempts, deployment_available_after,
			created_at, updated_at
		)
		SELECT
			id, rule_id, domain,
			CASE WHEN status IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid') THEN status ELSE 'queued' END,
			message, expires_at, cert_pem, key_pem,
			ca_provider_id, renewal_attempts, ca_available_after, last_error_code, deployment_attempts, deployment_available_after,
			created_at, updated_at
		FROM cert_jobs_old
	`); err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to copy cert_jobs data: %w", err))
	}

	if _, err := tx.Exec("DROP TABLE cert_jobs_old"); err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to drop old cert_jobs table: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit cert_jobs migration: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to re-enable foreign keys: %w", err)
	}
	fkRestored = true

	log.Println("cert_jobs status constraint migration completed")
	return nil
}

func Close() error {
	var err error
	if AuditDB != nil {
		err = errors.Join(err, AuditDB.Close())
	}
	if MetricsDB != nil {
		err = errors.Join(err, MetricsDB.Close())
	}
	if DB != nil {
		err = errors.Join(err, DB.Close())
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
