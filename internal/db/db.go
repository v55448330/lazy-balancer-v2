package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"lazy-balancer-v2/internal/models"

	_ "github.com/glebarez/sqlite"
	"golang.org/x/net/idna"
)

var (
	DB             *sql.DB
	currentDB      atomic.Value
	MetricsDB      *sql.DB
	AuditDB        *sql.DB
	BackgroundDBMu sync.Mutex
	openDatabase   = sql.Open
	domainProfile  = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true))
)

func CanonicalDomains(value string) (string, error) {
	seen := make(map[string]struct{})
	domains := make([]string, 0)
	for _, rawDomain := range strings.Split(value, ",") {
		domain := strings.TrimSpace(strings.ToLower(rawDomain))
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" {
			continue
		}
		ascii, err := domainProfile.ToASCII(domain)
		if err != nil {
			return "", fmt.Errorf("invalid domain %q: %w", rawDomain, err)
		}
		ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
		if ascii == "" || net.ParseIP(ascii) != nil {
			return "", fmt.Errorf("invalid domain %q", rawDomain)
		}
		if _, exists := seen[ascii]; exists {
			continue
		}
		seen[ascii] = struct{}{}
		domains = append(domains, ascii)
	}
	if len(domains) == 0 {
		return "", fmt.Errorf("domain is empty")
	}
	return strings.Join(domains, ","), nil
}

// SetDB registers the handle background goroutines should use; tests that
// swap DB directly should call this too so refresh loops follow.
func SetDB(d *sql.DB) {
	if current := GetDB(); current != nil && current != d {
		if err := FlushAPIKeyLastUsed(); err != nil {
			logDBError("flush API key usage before database swap", err)
		}
	}
	currentDB.Store(d)
}

func logDBError(operation string, err error) {
	log.Printf("ERROR: %s: %v", operation, err)
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
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "lazy-balancer.db")
	if err := prepareSQLiteDatabase(dbPath); err != nil {
		return fmt.Errorf("failed to secure database file: %w", err)
	}

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
	if err := migrateSyncSwitches(); err != nil {
		return fmt.Errorf("failed to migrate sync switches: %w", err)
	}
	if err := ensureClusterAppliedSections(); err != nil {
		return fmt.Errorf("failed to ensure cluster_applied_sections: %w", err)
	}

	if initErr := InitializeAuditDB(dataDir); initErr != nil {
		auditDB = AuditDB
		return fmt.Errorf("failed to initialize audit database: %w", initErr)
	}
	auditDB = AuditDB
	if err := secureSQLiteArtifacts(dbPath); err != nil {
		return fmt.Errorf("failed to secure database artifacts: %w", err)
	}
	SetDB(database)
	startAPIKeyLastUsedFlusher()

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
		is_enabled BOOLEAN NOT NULL DEFAULT 1,
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
		mcp_enabled INTEGER DEFAULT 0,
		read_only INTEGER DEFAULT 0,
		mcp_ip_whitelist TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (created_by) REFERENCES users(id)
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_prefix_hash ON api_keys(key_prefix, key_hash);

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
		-- R41 C-3: schema 默认仅新库/重建生效（SQLite 不支持 ALTER COLUMN DEFAULT）；
		-- 存量行 health_check_timeout 值不变；全部生产 INSERT 显式带值，DEFAULT 惰性。
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
		custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
		proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_flush_interval INTEGER NOT NULL DEFAULT 0,
		proxy_stream_close_delay INTEGER NOT NULL DEFAULT 0,
		host_header VARCHAR(255),
		enable_tls BOOLEAN DEFAULT FALSE,
		tls_cert TEXT,
		tls_key TEXT,
		tls_http_redirect BOOLEAN DEFAULT FALSE,
		enable_compress BOOLEAN DEFAULT FALSE,
		compress_types VARCHAR(100) DEFAULT 'gzip',
		enabled BOOLEAN NOT NULL DEFAULT 1,
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
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		protocol VARCHAR(10) DEFAULT 'http',
		max_connections INTEGER DEFAULT 0,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_upstreams_rule_enabled_id ON upstreams(rule_id, enabled, id);

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
		status VARCHAR(20) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid')),
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
		proxy_flush_interval INTEGER DEFAULT 0,
		proxy_stream_close_delay INTEGER DEFAULT 0,
		server_tokens_hidden BOOLEAN DEFAULT FALSE,
		cert_expiry_days INTEGER DEFAULT 30,
		cert_renewal_days INTEGER DEFAULT 30,
		cert_job_log_size_mb INTEGER DEFAULT 10,
		audit_log_size_mb INTEGER DEFAULT 10,
		caddy_apply_error TEXT DEFAULT '',
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
		protocol VARCHAR(10) DEFAULT 'http',
		master_id INTEGER,
		is_approved BOOLEAN DEFAULT FALSE,
		sync_interval INTEGER DEFAULT 60,
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

	CREATE TABLE IF NOT EXISTS used_login_tickets (
		jti_hash TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_used_login_tickets_expires_at ON used_login_tickets(expires_at);

	CREATE TABLE IF NOT EXISTS revoked_jti (
		jti_hash TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_revoked_jti_expires_at ON revoked_jti(expires_at);

	CREATE TABLE IF NOT EXISTS security_custom_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		conditions TEXT DEFAULT '[]',
		action TEXT DEFAULT 'block',
		score INTEGER DEFAULT 5,
		enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS security_block_pages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		content TEXT DEFAULT '',
		is_default BOOLEAN DEFAULT FALSE,
		created_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_by INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT (datetime('now'))
	);

	INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, created_at, updated_at)
		VALUES (1, '默认拦截页面', '系统默认 403 拦截页面',
			'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f9fafb;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#fff;border-radius:12px;padding:48px 40px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08);max-width:640px;width:95%}.icon{font-size:48px;margin-bottom:16px}h1{font-size:24px;color:#1f2937;margin-bottom:12px}p{font-size:14px;color:#6b7280;line-height:1.6;margin-bottom:8px}.footer{margin-top:24px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af}.footer .name{font-weight:600;color:#4b5563}</style></head><body><div class="card"><div class="icon">🚫</div><h1>Access Denied</h1><p>Your request has been blocked by the security policy.</p><p>If you believe this is an error, please contact the administrator.</p><div class="footer">Powered by <span class="name">Lazy Balancer</span></div></div></body></html>',
			TRUE, datetime('now'), datetime('now'));

	CREATE TABLE IF NOT EXISTS security_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		mode TEXT DEFAULT 'off',
		anomaly_threshold INTEGER DEFAULT 5,
		ip_acl_mode TEXT DEFAULT '',
		ip_acl_list TEXT DEFAULT '[]',
		ip_acl_enabled BOOLEAN DEFAULT FALSE,
		ip_whitelist TEXT DEFAULT '[]',
		ip_blacklist TEXT DEFAULT '[]',
		rate_limit_enabled BOOLEAN DEFAULT FALSE,
		rate_limit_rps INTEGER DEFAULT 0,
		rate_limit_burst INTEGER DEFAULT 0,
		crs_rule_groups TEXT DEFAULT '[]',
		crs_excluded_rules TEXT DEFAULT '[]',
	custom_rules TEXT DEFAULT '[]',
	block_page_id INTEGER DEFAULT 0,
	block_status_code INTEGER DEFAULT 0,
	enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now')),
		geoip_countries TEXT DEFAULT '[]',
		geoip_mode TEXT DEFAULT 'deny',
		waf_check_response INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS security_policy_bindings (
		rule_caddy_id TEXT NOT NULL,
		policy_id INTEGER NOT NULL,
		PRIMARY KEY (rule_caddy_id, policy_id)
	);
	CREATE INDEX IF NOT EXISTS idx_lb_rules_enabled ON lb_rules(enabled);
	CREATE TABLE IF NOT EXISTS security_crs_version (
		id INTEGER PRIMARY KEY,
		version TEXT NOT NULL,
		updated_at DATETIME DEFAULT (datetime('now')),
		auto_update BOOLEAN DEFAULT TRUE
	);
	CREATE TABLE IF NOT EXISTS security_ip2region_version (
		id INTEGER PRIMARY KEY,
		version TEXT NOT NULL,
		updated_at DATETIME DEFAULT (datetime('now')),
		auto_update BOOLEAN DEFAULT TRUE,
		update_status TEXT DEFAULT 'idle',
		message TEXT DEFAULT '',
		last_checked DATETIME,
		next_update DATETIME,
		trigger TEXT DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME
	);
	INSERT OR IGNORE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'unknown', 0);
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
	apiKeyColumns := map[string]string{
		"mcp_enabled":      "INTEGER DEFAULT 0",
		"read_only":        "INTEGER DEFAULT 0",
		"mcp_ip_whitelist": "TEXT DEFAULT ''",
	}
	for name, dtype := range apiKeyColumns {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name=?", name).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check api_keys.%s: %w", name, err)
		}
		if colCount == 0 {
			if _, err := DB.Exec("ALTER TABLE api_keys ADD COLUMN " + name + " " + dtype); err != nil {
				return fmt.Errorf("failed to add api_keys.%s: %w", name, err)
			}
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
		"lb_rules.ca_provider_id":                         "INTEGER DEFAULT 0",
		"lb_rules.caddy_id":                               "VARCHAR(20)",
		"lb_rules.dns_family":                             "VARCHAR(20) DEFAULT 'ipv4'",
		"lb_rules.updated_by":                             "INTEGER",
		"lb_rules.tcp_health_check_port":                  "INTEGER DEFAULT 0",
		"lb_rules.tcp_proxy_protocol":                     "BOOLEAN DEFAULT 0",
		"lb_rules.tcp_try_duration":                       "INTEGER DEFAULT 0",
		"lb_rules.tcp_try_interval":                       "INTEGER DEFAULT 250",
		"lb_rules.request_body_max_size_mb":               "INTEGER DEFAULT 0",
		"lb_rules.upstream_keepalive_timeout":             "INTEGER DEFAULT 0",
		"lb_rules.server_tokens_hidden":                   "INTEGER DEFAULT 0",
		"security_custom_rules.updated_by":                "INTEGER DEFAULT 0",
		"security_crs_version.update_status":              "TEXT DEFAULT 'idle'",
		"security_crs_version.message":                    "TEXT DEFAULT ''",
		"security_crs_version.last_checked":               "DATETIME",
		"security_crs_version.next_update":                "DATETIME",
		"security_crs_version.trigger":                    "TEXT DEFAULT ''",
		"security_crs_version.started_at":                 "DATETIME",
		"security_crs_version.finished_at":                "DATETIME",
		"security_crs_version.consecutive_failures":       "INTEGER DEFAULT 0",
		"security_ip2region_version.update_status":        "TEXT DEFAULT 'idle'",
		"security_ip2region_version.message":              "TEXT DEFAULT ''",
		"security_ip2region_version.last_checked":         "DATETIME",
		"security_ip2region_version.next_update":          "DATETIME",
		"security_ip2region_version.trigger":              "TEXT DEFAULT ''",
		"security_ip2region_version.started_at":           "DATETIME",
		"security_ip2region_version.finished_at":          "DATETIME",
		"security_ip2region_version.consecutive_failures": "INTEGER DEFAULT 0",
		"upstreams.max_connections":                       "INTEGER DEFAULT 0",
		"certificate_configs.dns_credentials":             "TEXT",
		"cert_jobs.ca_provider_id":                        "INTEGER DEFAULT 0",
		"cert_jobs.renewal_attempts":                      "INTEGER DEFAULT 0",
		"cert_jobs.ca_available_after":                    "DATETIME",
		"cert_jobs.last_error_code":                       "VARCHAR(20)",
		"cert_jobs.deployment_attempts":                   "INTEGER DEFAULT 0",
		"cert_jobs.deployment_available_after":            "DATETIME",
		"global_config.default_ca_provider_id":            "INTEGER DEFAULT 0",
		"global_config.cert_renewal_days":                 "INTEGER DEFAULT 30",
		"global_config.cert_renewal_attempts":             "INTEGER DEFAULT 5",
		"global_config.cert_job_log_size_mb":              "INTEGER DEFAULT 10",
		"global_config.audit_log_size_mb":                 "INTEGER DEFAULT 10",
		"global_config.caddy_apply_error":                 "TEXT DEFAULT ''",
		"global_config.runtime_log_size_mb":               "INTEGER DEFAULT 100",
		"global_config.acme_email":                        "VARCHAR(255)",
		"global_config.cert_expiry_days":                  "INTEGER DEFAULT 30",
		"global_config.metrics_public":                    "BOOLEAN DEFAULT 0",
		"global_config.metrics_origins":                   "VARCHAR(500)",
		"global_config.caddy_log_level":                   "VARCHAR(10) DEFAULT 'info'",
		"global_config.caddy_log_size_mb":                 "INTEGER DEFAULT 100",
		"global_config.request_body_max_size_mb":          "INTEGER DEFAULT 0",
		"global_config.http_read_timeout":                 "INTEGER DEFAULT 0",
		"global_config.http_write_timeout":                "INTEGER DEFAULT 0",
		"global_config.http_idle_timeout":                 "INTEGER DEFAULT 0",
		"global_config.upstream_keepalive_timeout":        "INTEGER DEFAULT 0",
		"global_config.server_tokens_hidden":              "BOOLEAN DEFAULT FALSE",
		"global_config.admin_tls_enabled":                 "BOOLEAN DEFAULT 0",
		"global_config.admin_tls_mode":                    "VARCHAR(20) DEFAULT 'selfsigned'",
		"global_config.admin_tls_cert":                    "TEXT DEFAULT ''",
		"global_config.admin_tls_key":                     "TEXT DEFAULT ''",
		"global_config.access_log_json":                   "BOOLEAN DEFAULT TRUE",
		"global_config.access_log_format":                 "TEXT DEFAULT ''",
		"global_config.audit_retention_months":            "INTEGER DEFAULT 3",
		"global_config.metrics_retention_days":            "INTEGER DEFAULT 7",
		"global_config.jwt_expire_minutes":                "INTEGER DEFAULT 20",
		"global_config.timezone":                          "VARCHAR(50) DEFAULT 'Asia/Shanghai'",
		"lb_rules.log_enabled":                            "BOOLEAN DEFAULT 0",
		"lb_rules.custom_routes_enabled":                  "BOOLEAN NOT NULL DEFAULT 0",
		"lb_rules.proxy_dial_timeout":                     "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_response_header_timeout":          "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_read_timeout":                     "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_write_timeout":                    "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_stream_timeout":                   "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_flush_interval":                   "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_stream_close_delay":               "INTEGER NOT NULL DEFAULT 0",
		"global_config.proxy_dial_timeout":                "INTEGER DEFAULT 0",
		"global_config.proxy_response_header_timeout":     "INTEGER DEFAULT 0",
		"global_config.proxy_read_timeout":                "INTEGER DEFAULT 0",
		"global_config.proxy_write_timeout":               "INTEGER DEFAULT 0",
		"global_config.proxy_stream_timeout":              "INTEGER DEFAULT 0",
		"global_config.proxy_flush_interval":              "INTEGER DEFAULT 0",
		"global_config.proxy_stream_close_delay":          "INTEGER DEFAULT 0",
		"users.password_changed_at":                       "DATETIME",
		"users.password_version":                          "INTEGER NOT NULL DEFAULT 0",
		"global_config.cluster_version":                   "INTEGER DEFAULT 0",
		"global_config.sync_global_config":                "BOOLEAN DEFAULT 1",
		"global_config.sync_users":                        "BOOLEAN DEFAULT 1",
		"global_config.sync_rules":                        "BOOLEAN DEFAULT 1",
		"global_config.sync_waf_files":                    "BOOLEAN DEFAULT 1",
		"global_config.sync_security":                     "BOOLEAN DEFAULT 1",
		"global_config.cluster_token":                     "TEXT DEFAULT ''",
		"global_config.registration_id":                   "INTEGER DEFAULT 0",
		"global_config.registration_secret":               "TEXT DEFAULT ''",
		"global_config.registration_confirm_failures":     "INTEGER DEFAULT 0",
		"global_config.applied_version":                   "INTEGER DEFAULT 0",
		"global_config.last_sync_error":                   "TEXT DEFAULT ''",
		"global_config.sync_fingerprint":                  "TEXT DEFAULT ''",
		"nodes.cluster_token_hash":                        "VARCHAR(64)",
		"nodes.protocol":                                  "VARCHAR(10) DEFAULT 'http'",
		"nodes.access_url":                                "VARCHAR(255) DEFAULT ''",
		"nodes.registration_secret":                       "VARCHAR(64)",
		"nodes.registration_secret_expires_at":            "DATETIME",
		"nodes.cluster_token_delivered":                   "BOOLEAN DEFAULT 0",
		"nodes.reported_version":                          "INTEGER DEFAULT 0",
		"nodes.health_json":                               "TEXT",
		"nodes.last_sync_at":                              "DATETIME",
		"nodes.last_sync_error":                           "TEXT",
		"security_policies.crs_excluded_rules":            "TEXT DEFAULT '[]'",
		"security_policies.ip_acl_mode":                   "TEXT DEFAULT ''",
		"security_policies.ip_acl_list":                   "TEXT DEFAULT '[]'",
		"security_policies.ip_acl_enabled":                "BOOLEAN DEFAULT FALSE",
		"security_policies.block_page_id":                 "INTEGER DEFAULT 0",
		"security_block_pages.created_by":                 "INTEGER DEFAULT 0",
		"security_block_pages.updated_by":                 "INTEGER DEFAULT 0",
		"security_policies.updated_by":                    "INTEGER DEFAULT 0",
		"security_policies.geoip_countries":               "TEXT NOT NULL DEFAULT '[]'",
		"security_policies.geoip_mode":                    "TEXT NOT NULL DEFAULT 'deny'",
		"security_policies.waf_check_response":            "INTEGER NOT NULL DEFAULT 0",
		"security_policies.block_status_code":             "INTEGER NOT NULL DEFAULT 0",
	}
	// R42 F1: 四个全局超时列的 0→推荐默认回填只在「新增列」时执行一次——
	// 历史存量行在新列 ADD 后恰好为 0，才是真正需要回填的场景；渲染层把 0 当作
	// 「省略=用 Caddy 默认」的有效值（仅 >0 才输出超时指令），若每次启动都无条件
	// 回填，会把用户显式设置的 0 静默改写，导致运行行为与界面展示不一致。
	newColumnBackfills := map[string]string{
		"global_config.http_read_timeout":          "UPDATE global_config SET http_read_timeout=60 WHERE http_read_timeout=0",
		"global_config.http_write_timeout":         "UPDATE global_config SET http_write_timeout=60 WHERE http_write_timeout=0",
		"global_config.http_idle_timeout":          "UPDATE global_config SET http_idle_timeout=120 WHERE http_idle_timeout=0",
		"global_config.upstream_keepalive_timeout": "UPDATE global_config SET upstream_keepalive_timeout=60 WHERE upstream_keepalive_timeout=0",
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
			if backfill, ok := newColumnBackfills[col]; ok {
				if _, err := DB.Exec(backfill); err != nil {
					return fmt.Errorf("failed to backfill column %s.%s: %w", table, name, err)
				}
			}
		}
	}
	if err := migrateUsersIsEnabledNotNull(); err != nil {
		return fmt.Errorf("failed to migrate users.is_enabled: %w", err)
	}
	if err := migrateNodesDeadColumns(); err != nil {
		return fmt.Errorf("failed to migrate nodes legacy columns: %w", err)
	}
	if _, err := DB.Exec("DROP TABLE IF EXISTS tls_certificates"); err != nil {
		return fmt.Errorf("failed to drop tls_certificates: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix_hash ON api_keys(key_prefix,key_hash)"); err != nil {
		return fmt.Errorf("failed to index API key authentication: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_upstreams_rule_enabled_id ON upstreams(rule_id,enabled,id)"); err != nil {
		return fmt.Errorf("failed to index upstream rule loading: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_path_rules_rule_order ON path_rules(rule_id, sort_order, id)"); err != nil {
		return fmt.Errorf("failed to index path_rules: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_security_bindings_policy ON security_policy_bindings(policy_id)"); err != nil {
		return fmt.Errorf("failed to index security_policy_bindings: %w", err)
	}

	// Drop legacy cert_job_logs table — logs now stored in files under /app/logs/
	if _, err := DB.Exec("DROP TABLE IF EXISTS cert_job_logs"); err != nil {
		return fmt.Errorf("failed to drop cert_job_logs: %w", err)
	}

	// Normalize legacy/global default values that are invalid regardless of version
	defaultUpdates := []string{
		"UPDATE global_config SET jwt_expire_minutes=20 WHERE jwt_expire_minutes IS NULL OR jwt_expire_minutes<=0 OR jwt_expire_minutes>1440",
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

	// Migrate existing data: set caddy_id for rows that don't have it.
	// Must run before migrateCanonicalDomains, which keys lb_rules updates
	// by caddy_id and would match zero rows while it is still NULL.
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''").Scan(&count); err != nil {
		return fmt.Errorf("failed to count lb_rules without caddy_id: %w", err)
	}
	if count > 0 {
		// Generate caddy_id for existing rules. Collect ids before writing: an
		// open SELECT cursor on one pooled connection blocks the UPDATE on
		// another under _txlock=immediate.
		rows, err := DB.Query("SELECT id FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''")
		if err != nil {
			return fmt.Errorf("failed to query lb_rules without caddy_id: %w", err)
		}
		var ruleIDs []int
		for rows.Next() {
			var ruleID int
			if err := rows.Scan(&ruleID); err != nil {
				rows.Close()
				return fmt.Errorf("failed to scan lb_rule without caddy_id: %w", err)
			}
			ruleIDs = append(ruleIDs, ruleID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("failed to iterate lb_rules without caddy_id: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("failed to close lb_rules migration rows: %w", err)
		}
		for _, ruleID := range ruleIDs {
			caddyID := generateCaddyIDForMigration()
			if _, err := DB.Exec("UPDATE lb_rules SET caddy_id = ? WHERE id = ?", caddyID, ruleID); err != nil {
				return fmt.Errorf("failed to set caddy_id for lb_rule %d: %w", ruleID, err)
			}
		}
	}

	if err := migrateCanonicalDomains(); err != nil {
		return fmt.Errorf("failed to normalize stored domains: %w", err)
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
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_updated_id_expires ON cert_jobs(rule_id, updated_at DESC, id DESC, expires_at)"); err != nil {
		return fmt.Errorf("failed to index cluster certificate selection: %w", err)
	}
	// Round 35 I-18/I-19: lb_rules 高频 WHERE 字段补索引。
	// listen_port 用于创建/更新规则的端口冲突检查（避免全表扫描）。
	// enabled 用于 Caddy 配置生成与每 5s 指标采集。
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_lb_rules_listen_port ON lb_rules(listen_port)"); err != nil {
		return fmt.Errorf("failed to index lb_rules listen_port: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_lb_rules_enabled ON lb_rules(enabled)"); err != nil {
		return fmt.Errorf("failed to index lb_rules enabled: %w", err)
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

	// Migration: Check if we need to rebuild lb_rules with caddy_id as primary key
	// SQLite doesn't support changing primary key directly, so we need to rebuild the table
	if err := migrateLbRulesPrimaryKey(); err != nil {
		return fmt.Errorf("failed to migrate lb_rules primary key: %w", err)
	}

	// R44 B1: 须在 lb_rules 重建之后——重建前的遗留表可能没有 enable_tls 列。
	if err := migrateLegacyHTTPSProtocol(); err != nil {
		return fmt.Errorf("failed to migrate legacy https protocol: %w", err)
	}

	// Drop legacy columns from upstreams if they still exist (no longer used).
	legacyUpstreamHostHeaderColumns := []string{"host_header"}
	for _, col := range legacyUpstreamHostHeaderColumns {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check legacy upstreams.%s: %w", col, err)
		}
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE upstreams DROP COLUMN " + col); err != nil {
				return fmt.Errorf("failed to drop legacy upstreams.%s: %w", col, err)
			}
			log.Printf("Dropped legacy column %s from upstreams", col)
		}
	}

	// Drop legacy columns from upstreams if they still exist (no longer used).
	legacyUpstreamDomainColumns := []string{"domain"}
	for _, col := range legacyUpstreamDomainColumns {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check legacy upstreams.%s: %w", col, err)
		}
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE upstreams DROP COLUMN " + col); err != nil {
				return fmt.Errorf("failed to drop legacy upstreams.%s: %w", col, err)
			}
			log.Printf("Dropped legacy column %s from upstreams", col)
		}
	}

	// Drop legacy columns from upstreams if they still exist (no longer used).
	legacyUpstreamDeadColumns := []string{"proxy_protocol", "dns_server"}
	for _, col := range legacyUpstreamDeadColumns {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('upstreams') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check legacy upstreams.%s: %w", col, err)
		}
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE upstreams DROP COLUMN " + col); err != nil {
				return fmt.Errorf("failed to drop legacy upstreams.%s: %w", col, err)
			}
			log.Printf("Dropped legacy column %s from upstreams", col)
		}
	}

	// Round 35: 一次性迁移——存量 upstreams.enabled 为 NULL 的遗留行归一化为 0
	// （NULL 视禁用，与渲染/CRUD/度量侧 IIF 口径一致；幂等，重跑无副作用）。
	if _, err := DB.Exec("UPDATE upstreams SET enabled=0 WHERE enabled IS NULL"); err != nil {
		return fmt.Errorf("failed to normalize NULL upstreams.enabled: %w", err)
	}

	// Round 36: 一次性迁移——存量 lb_rules.enabled 为 NULL 的遗留行归一化为 0
	// （NULL 视禁用，与渲染侧 WHERE enabled=1 口径一致；幂等，重跑无副作用）。
	// migrateLbRulesPrimaryKey 的重建拷贝已用 COALESCE(enabled,0) 兜底，顺序无关。
	if _, err := DB.Exec("UPDATE lb_rules SET enabled=0 WHERE enabled IS NULL"); err != nil {
		return fmt.Errorf("failed to normalize NULL lb_rules.enabled: %w", err)
	}

	// Drop legacy global_config.sync_caddy_config if it still exists. 旧开关仅覆盖
	// Caddy 全局配置，已被 sync_global_config 取代，且不再被快照构建或同步开关读取，
	// 切换它只会触发无意义的全量重拉。
	legacyGlobalConfigDeadColumns := []string{"sync_caddy_config"}
	for _, col := range legacyGlobalConfigDeadColumns {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check legacy global_config.%s: %w", col, err)
		}
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE global_config DROP COLUMN " + col); err != nil {
				return fmt.Errorf("failed to drop legacy global_config.%s: %w", col, err)
			}
			log.Printf("Dropped legacy column %s from global_config", col)
		}
	}

	// Drop dead columns that are no longer read or written anywhere:
	// - security_block_pages.status_code / security_custom_rules.status_code
	//   已由 security_policies.block_status_code 统一承载拦截状态码，页面与自定义
	//   规则的状态码列不再写入也不被读取（Caddy 配置渲染统一走策略的 block_status_code）。
	// - global_config.admin_tls_acme_rule_id / admin_tls_port 在 UpdateAdminTLS 中仅写入
	//   空值/监听端口，从未被任何读取路径消费（管理面板 HTTPS 只使用 enabled/mode/cert/key）。
	// - lb_rules.ip_acl_mode / ip_acl_list 为规则级 IP 访问控制的遗留列，规则级 IP ACL 早已
	//   迁入 security_policies（策略级 ip_acl_* 仍在使用），这两列不再被读取或写入。
	deadColumnDrops := []struct{ table, column string }{
		{"global_config", "caddy_log_path"}, // 读取但从未使用，日志文件名由渲染层硬编码
		{"security_block_pages", "status_code"},
		{"security_custom_rules", "status_code"},
		{"global_config", "admin_tls_acme_rule_id"},
		{"global_config", "admin_tls_port"},
		{"lb_rules", "ip_acl_mode"},
		{"lb_rules", "ip_acl_list"},
	}
	for _, drop := range deadColumnDrops {
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", drop.table, drop.column).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check dead column %s.%s: %w", drop.table, drop.column, err)
		}
		if colCount > 0 {
			if _, err := DB.Exec("ALTER TABLE " + drop.table + " DROP COLUMN " + drop.column); err != nil {
				return fmt.Errorf("failed to drop dead column %s.%s: %w", drop.table, drop.column, err)
			}
			log.Printf("Dropped dead column %s from %s", drop.column, drop.table)
		}
	}

	// 一次性迁移：清理 R15 校验落地之前写入的存量自定义规则（尾部反斜杠/空条件），
	// 避免它们在每次配置重生成时产出畸形 SecRule 行而被 coraza 整体拒绝。
	if err := sanitizeLegacyCustomRulePatterns(); err != nil {
		return fmt.Errorf("failed to sanitize legacy custom rule patterns: %w", err)
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

// legacyHTTPSHasCertPredicate 是 migrateLegacyHTTPSProtocol 的「有证」判定
// （SELECT 预判与 UPDATE 归一必须同谓词，否则审计详情与实际分支发散）。
const legacyHTTPSHasCertPredicate = `(
	(COALESCE(tls_cert,'') != '' AND COALESCE(tls_key,'') != '')
	OR (tls_source = 'acme_dns' AND EXISTS (
		SELECT 1 FROM cert_jobs
		WHERE cert_jobs.rule_id = lb_rules.caddy_id
		  AND COALESCE(cert_jobs.cert_pem,'') != ''
		  AND COALESCE(cert_jobs.key_pem,'') != ''
		  AND cert_jobs.status != 'disabled'
	))
)`

// migrateLegacyHTTPSProtocol 一次性迁移：a1ecbe3a 期写入路径曾接受 protocol='https'
// （语义即 http+TLS），b6e2b624 起写侧白名单收敛为 http/tcp，存量 https 行编辑/复制
// 全部 400、启用后按「非 http 即 TCP」渲染（域名匹配静默丢失）。归一规则（R45 F-1）：
//   - 有证行 → protocol='http' + enable_tls=1，保持原意图（含 enable_tls 已为 0 的
//     行——https 协议本身隐含 TLS）；
//   - 无证行 → protocol='http' + enable_tls=0 且清 tls_http_redirect：渲染为普通
//     HTTP，保持可编辑，避免 TLS 端口明文与指向非 TLS 端口的幻影跳转（F-C 形态的
//     迁移再制造）。
//
// 「有证」判定（R46 C-1）：内联 tls_cert/tls_key 均非空，或 tls_source='acme_dns'
// 且 cert_jobs 中存有该规则已签发的证书（cert_pem/key_pem 非空、任务未禁用）——
// 签发门控（caqueue）不筛 protocol，历史 https 行可能经 ACME 签出证书，仅查内联
// 列会把此类行当无证处理，导致已签发证书静默不再加载且永不续期。
//
// 幂等，重跑零命中。受影响规则记入操作日志（R45 F-2：迁移跑在审计库初始化之前，
// 先缓冲、InitializeAuditDB 就绪后落库）。
func migrateLegacyHTTPSProtocol() error {
	rows, err := DB.Query(`SELECT caddy_id, name,
		CASE WHEN ` + legacyHTTPSHasCertPredicate + ` THEN 1 ELSE 0 END
		FROM lb_rules WHERE protocol='https'`)
	if err != nil {
		return fmt.Errorf("failed to query legacy https lb_rules: %w", err)
	}
	type legacyHTTPSRule struct {
		caddyID string
		name    string
		hasCert bool
	}
	var legacy []legacyHTTPSRule
	for rows.Next() {
		var rule legacyHTTPSRule
		if err := rows.Scan(&rule.caddyID, &rule.name, &rule.hasCert); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan legacy https lb_rules: %w", err)
		}
		legacy = append(legacy, rule)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate legacy https lb_rules: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close legacy https lb_rules rows: %w", err)
	}
	if len(legacy) == 0 {
		return nil
	}
	if _, err := DB.Exec(`UPDATE lb_rules SET protocol='http', enable_tls=1
		WHERE protocol='https' AND ` + legacyHTTPSHasCertPredicate); err != nil {
		return fmt.Errorf("failed to normalize cert-bearing legacy https lb_rules: %w", err)
	}
	if _, err := DB.Exec(`UPDATE lb_rules SET protocol='http', enable_tls=0, tls_http_redirect=0
		WHERE protocol='https'`); err != nil {
		return fmt.Errorf("failed to normalize certless legacy https lb_rules: %w", err)
	}
	for _, rule := range legacy {
		var detail string
		if rule.hasCert {
			detail = fmt.Sprintf("存量 https 协议规则已迁移为 http+TLS：caddy_id=%s name=%s", rule.caddyID, rule.name)
		} else {
			detail = fmt.Sprintf("存量 https 协议规则已迁移为普通 HTTP（无可用证书，未启用 TLS）：caddy_id=%s name=%s", rule.caddyID, rule.name)
		}
		log.Print(detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	return nil
}

type canonicalDomainMigrationRow struct {
	table  string
	key    any
	value  string
	column string
}

// sanitizeLegacyCustomRulePatterns 一次性迁移：清理 R15 校验落地之前写入的存量自定义
// 规则。尾部反斜杠或空条件的规则在发射时会被跳过（见 services.emitCustomRules 的发射
// 侧防御），这里改为「保留数据、禁用即可」，避免它们在配置重生成时产出畸形 SecRule。
//
//  1. security_custom_rules 表：conditions JSON 为空或任一 pattern 以 `\` 结尾 → enabled=0。
//  2. security_policies.custom_rules 内嵌 JSON：条目 conditions 含尾部反斜杠 pattern 或
//     为占位形状（无条件且无 target/operator）→ 将条目 enabled 置 false（内嵌形状的
//     CustomRule 带 enabled 字段，无需整条删除）。
//
// 幂等：已禁用的行/条目保持禁用，重复执行无副作用；不可解析的 JSON 保持原样不动，
// 绝不 brick 一条策略或一条规则。
func sanitizeLegacyCustomRulePatterns() error {
	hasTrailingBackslash := func(conditions []models.CustomRuleCondition, legacyPattern string) bool {
		for _, cond := range conditions {
			if strings.HasSuffix(cond.Pattern, `\`) {
				return true
			}
		}
		return strings.HasSuffix(legacyPattern, `\`)
	}

	disabled := 0

	// 1. 独立自定义规则表
	rows, err := DB.Query("SELECT id, conditions FROM security_custom_rules")
	if err != nil {
		return fmt.Errorf("failed to query security_custom_rules: %w", err)
	}
	type customRuleRow struct {
		id         int
		conditions string
	}
	var ruleRows []customRuleRow
	for rows.Next() {
		var row customRuleRow
		if err := rows.Scan(&row.id, &row.conditions); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan security_custom_rules: %w", err)
		}
		ruleRows = append(ruleRows, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate security_custom_rules: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close security_custom_rules rows: %w", err)
	}
	for _, row := range ruleRows {
		var conditions []models.CustomRuleCondition
		// 不可解析的 conditions 一并禁用：发射阶段同样无法判定其合法性。
		if err := json.Unmarshal([]byte(row.conditions), &conditions); err != nil || len(conditions) == 0 || hasTrailingBackslash(conditions, "") {
			res, err := DB.Exec("UPDATE security_custom_rules SET enabled=0 WHERE id=? AND enabled=1", row.id)
			if err != nil {
				return fmt.Errorf("failed to disable security_custom_rule %d: %w", row.id, err)
			}
			if affected, _ := res.RowsAffected(); affected > 0 {
				disabled++
			}
		}
	}

	// 2. 策略内嵌自定义规则
	policyRows, err := DB.Query("SELECT id, custom_rules FROM security_policies")
	if err != nil {
		return fmt.Errorf("failed to query security_policies: %w", err)
	}
	type policyRow struct {
		id          int
		customRules string
	}
	var policies []policyRow
	for policyRows.Next() {
		var row policyRow
		if err := policyRows.Scan(&row.id, &row.customRules); err != nil {
			policyRows.Close()
			return fmt.Errorf("failed to scan security_policies: %w", err)
		}
		policies = append(policies, row)
	}
	if err := policyRows.Err(); err != nil {
		policyRows.Close()
		return fmt.Errorf("failed to iterate security_policies: %w", err)
	}
	if err := policyRows.Close(); err != nil {
		return fmt.Errorf("failed to close security_policies rows: %w", err)
	}
	for _, policy := range policies {
		var embedded []models.CustomRule
		// 规则 ID 数组或不可解析的 JSON 保持原样（ID 数组对应的独立规则已在上一步处理）。
		if err := json.Unmarshal([]byte(policy.customRules), &embedded); err != nil {
			continue
		}
		changed := false
		for i := range embedded {
			rule := &embedded[i]
			isPlaceholder := len(rule.Conditions) == 0 && rule.Target == "" && rule.Operator == ""
			if !isPlaceholder && !hasTrailingBackslash(rule.Conditions, rule.Pattern) {
				continue
			}
			if rule.Enabled {
				rule.Enabled = false
				changed = true
				disabled++
			}
		}
		if !changed {
			continue
		}
		encoded, err := json.Marshal(embedded)
		if err != nil {
			continue
		}
		if _, err := DB.Exec("UPDATE security_policies SET custom_rules=? WHERE id=?", string(encoded), policy.id); err != nil {
			return fmt.Errorf("failed to update security_policy %d custom_rules: %w", policy.id, err)
		}
	}

	if disabled > 0 {
		log.Printf("已禁用 %d 条含非法 pattern 的存量自定义规则（尾部反斜杠/空条件）", disabled)
	}
	return nil
}

func migrateCanonicalDomains() error {
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("begin domain normalization: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec("DROP INDEX IF EXISTS idx_cert_jobs_rule_domain_unique"); err != nil {
		return fmt.Errorf("drop cert_jobs domain index: %w", err)
	}

	queries := []struct {
		table  string
		column string
		query  string
	}{
		{table: "lb_rules", column: "domain", query: "SELECT caddy_id, domain FROM lb_rules WHERE domain IS NOT NULL AND trim(domain) != ''"},
		{table: "cert_jobs", column: "domain", query: "SELECT id, domain FROM cert_jobs WHERE trim(domain) != ''"},
		{table: "upstreams", column: "host", query: "SELECT id, host FROM upstreams WHERE trim(host) != ''"},
	}
	rowsToNormalize := make([]canonicalDomainMigrationRow, 0)
	for _, source := range queries {
		rows, err := tx.Query(source.query)
		if err != nil {
			return fmt.Errorf("query %s.%s: %w", source.table, source.column, err)
		}
		for rows.Next() {
			var key any
			var value string
			if err := rows.Scan(&key, &value); err != nil {
				rows.Close()
				return fmt.Errorf("scan %s.%s: %w", source.table, source.column, err)
			}
			rowsToNormalize = append(rowsToNormalize, canonicalDomainMigrationRow{table: source.table, key: key, value: value, column: source.column})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate %s.%s: %w", source.table, source.column, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close %s.%s rows: %w", source.table, source.column, err)
		}
	}

	for _, row := range rowsToNormalize {
		if row.table == "upstreams" && net.ParseIP(strings.TrimSpace(row.value)) != nil {
			continue
		}
		canonical, err := CanonicalDomains(row.value)
		if err != nil {
			log.Printf("Skipping invalid domain during migration: table=%s column=%s row=%v value=%q: %v", row.table, row.column, row.key, row.value, err)
			continue
		}
		if canonical == row.value {
			continue
		}
		keyColumn := "id"
		if row.table == "lb_rules" {
			keyColumn = "caddy_id"
		}
		if _, err := tx.Exec("UPDATE "+row.table+" SET "+row.column+"=? WHERE "+keyColumn+"=?", canonical, row.key); err != nil {
			return fmt.Errorf("update %s.%s row %v: %w", row.table, row.column, row.key, err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM cert_jobs WHERE id NOT IN (
		SELECT MAX(id) FROM cert_jobs GROUP BY rule_id, domain
	)`); err != nil {
		return fmt.Errorf("deduplicate cert_jobs: %w", err)
	}
	if _, err := tx.Exec("CREATE UNIQUE INDEX idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain)"); err != nil {
		return fmt.Errorf("create cert_jobs domain index: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit domain normalization: %w", err)
	}
	committed = true
	return nil
}

func migrateUsersIsEnabledNotNull() error {
	var notNull int
	if err := DB.QueryRow("SELECT \"notnull\" FROM pragma_table_info('users') WHERE name='is_enabled'").Scan(&notNull); err != nil {
		return fmt.Errorf("inspect users.is_enabled: %w", err)
	}
	if notNull == 1 {
		return nil
	}
	ctx := context.Background()
	conn, err := DB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("disable foreign keys: %w", err)
	}
	defer func() {
		if _, enableErr := conn.ExecContext(ctx, "PRAGMA foreign_keys=ON"); enableErr != nil {
			log.Printf("failed to re-enable foreign keys after users migration: %v", enableErr)
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin users migration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`UPDATE users SET is_enabled=1 WHERE is_enabled IS NULL;
		CREATE TABLE users_not_null (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'user',
			display_name VARCHAR(100),
			is_enabled BOOLEAN NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login DATETIME,
			password_changed_at DATETIME,
			password_version INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO users_not_null (id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_changed_at,password_version)
		SELECT id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_changed_at,password_version FROM users;
		DROP TABLE users;
		ALTER TABLE users_not_null RENAME TO users;`); err != nil {
		return fmt.Errorf("rebuild users table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit users migration: %w", err)
	}
	committed = true
	return nil
}

func migrateNodesDeadColumns() error {
	var legacyColumns int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name IN ('sync_enabled','sync_scope')").Scan(&legacyColumns); err != nil {
		return fmt.Errorf("inspect nodes legacy columns: %w", err)
	}
	if legacyColumns == 0 {
		return nil
	}
	ctx := context.Background()
	conn, err := DB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire nodes migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("disable foreign keys: %w", err)
	}
	defer func() {
		if _, enableErr := conn.ExecContext(ctx, "PRAGMA foreign_keys=ON"); enableErr != nil {
			log.Printf("failed to re-enable foreign keys after nodes migration: %v", enableErr)
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin nodes migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE nodes_without_legacy_sync (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(100) NOT NULL, mode VARCHAR(10) NOT NULL DEFAULT 'slave',
		ip_address VARCHAR(45) NOT NULL, port INTEGER DEFAULT 8000, protocol VARCHAR(10) DEFAULT 'http', access_url VARCHAR(255) DEFAULT '',
		master_id INTEGER, is_approved BOOLEAN DEFAULT FALSE, sync_interval INTEGER DEFAULT 60, status VARCHAR(20) DEFAULT 'offline',
		cluster_token_hash VARCHAR(64), registration_secret VARCHAR(64), registration_secret_expires_at DATETIME,
		cluster_token_delivered BOOLEAN DEFAULT 0, reported_version INTEGER DEFAULT 0, health_json TEXT,
		last_sync_at DATETIME, last_sync_error TEXT, last_seen DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (master_id) REFERENCES nodes_without_legacy_sync(id));
		INSERT INTO nodes_without_legacy_sync (id,name,mode,ip_address,port,protocol,access_url,master_id,is_approved,sync_interval,status,cluster_token_hash,registration_secret,registration_secret_expires_at,cluster_token_delivered,reported_version,health_json,last_sync_at,last_sync_error,last_seen,created_at)
		SELECT id,name,COALESCE(mode,'slave'),ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),master_id,is_approved,sync_interval,status,cluster_token_hash,registration_secret,registration_secret_expires_at,cluster_token_delivered,reported_version,health_json,last_sync_at,last_sync_error,last_seen,created_at FROM nodes;
		DROP TABLE nodes;
		ALTER TABLE nodes_without_legacy_sync RENAME TO nodes;
		CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
		CREATE INDEX IF NOT EXISTS idx_nodes_master ON nodes(master_id);`); err != nil {
		return fmt.Errorf("rebuild nodes table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit nodes migration: %w", err)
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
			custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
			proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_flush_interval INTEGER NOT NULL DEFAULT 0,
			proxy_stream_close_delay INTEGER NOT NULL DEFAULT 0,
			host_header VARCHAR(255),
			enable_tls BOOLEAN DEFAULT FALSE,
			tls_cert TEXT,
			tls_key TEXT,
			tls_http_redirect BOOLEAN DEFAULT FALSE,
			tls_source VARCHAR(20) DEFAULT 'manual',
			acme_config_id INTEGER DEFAULT 0,
			ca_provider_id INTEGER DEFAULT 0,
			enable_compress BOOLEAN DEFAULT FALSE,
			compress_types VARCHAR(100) DEFAULT 'gzip',
			enabled BOOLEAN NOT NULL DEFAULT 1,
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

	// Copy data from old table to new table。注意：ip_acl_mode / ip_acl_list 是已废弃的规则级
	// IP ACL 列（已迁入 security_policies 的策略级 ip_acl_*），此处列清单与 INSERT...SELECT
	// 映射有意排除它们，重建时随旧表一并丢弃。
	_, err = tx.Exec(`
		INSERT INTO lb_rules_new (
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			custom_routes_enabled,
			proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout, proxy_flush_interval, proxy_stream_close_delay,
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
			COALESCE(custom_routes_enabled,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
			host_header, enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, COALESCE(enabled,0), COALESCE(log_enabled,0),
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
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN DEFAULT TRUE,
		protocol VARCHAR(10) DEFAULT 'http',
		max_connections INTEGER DEFAULT 0,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	)
`)
	if err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to create upstreams_new: %w", err))
	}

	// Copy data from old upstreams table to new (convert rule_id from int to string)
	_, err = tx.Exec(`
	INSERT INTO upstreams_new (id, rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
	SELECT u.id, r.caddy_id, u.host, u.port, u.weight, u.dynamic_dns, u.enabled, u.protocol,
		       COALESCE(u.max_connections, 0)
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
	statusNotNull := false
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
			statusNotNull = notNull == 1
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate cert_jobs columns: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close cert_jobs columns: %w", err)
	}
	if constraintComplete && defaultQueued && statusNotNull {
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
			status VARCHAR(20) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid')),
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
			CASE WHEN COALESCE(status,'queued') IN ('queued','pending','processing','creating_account','creating_order','order_created','cleanup_dns','cleanup_warning','presenting_dns','waiting_propagation','dns_propagated','accepting_challenge','validating','validated','finalizing','finalized','downloading','downloaded','issued','failed','waiting_ca','disabled','waiting_order_ready','order_ready','waiting_order_valid','order_valid') THEN COALESCE(status,'queued') ELSE 'queued' END,
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
	stopAPIKeyLastUsedFlusher()
	flushErr := FlushAPIKeyLastUsed()
	var err error
	err = errors.Join(err, flushErr)
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
	randomBytes := make([]byte, 10)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable for migration id: %v", err))
	}
	id := make([]byte, 13)
	id[0] = 'l'
	id[1] = 'b'
	id[2] = '_'
	for i := 3; i < 13; i++ {
		id[i] = charset[int(randomBytes[i-3])%len(charset)]
	}
	return string(id)
}

func migrateSyncSwitches() error {
	var marker int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='sync_switches_migrated'").Scan(&marker); err != nil {
		return err
	}
	if marker == 0 {
		if _, err := DB.Exec("ALTER TABLE global_config ADD COLUMN sync_switches_migrated BOOLEAN DEFAULT 0"); err != nil {
			return err
		}
	}
	var done bool
	if err := DB.QueryRow("SELECT COALESCE(sync_switches_migrated,0) FROM global_config WHERE id=1").Scan(&done); err != nil && err != sql.ErrNoRows {
		return err
	}
	if done {
		return nil
	}
	// 新分类（sync_global_config 等五类）语义覆盖旧 sync_caddy_config 开关
	// （旧开关仅覆盖 Caddy 全局配置且默认关，新开关覆盖日志/时区/Caddy 全部
	// 全局项且默认开），因此不搬运旧值；曾依赖旧开关关闭同步的用户需在新设置
	// 卡片重新关闭对应类别。旧 sync_caddy_config 列已随迁移删除。
	_, err := DB.Exec("UPDATE global_config SET sync_switches_migrated=1 WHERE id=1")
	return err
}

func ensureClusterAppliedSections() error {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS cluster_applied_sections (
		section TEXT PRIMARY KEY,
		hash TEXT NOT NULL DEFAULT '',
		applied_version INTEGER NOT NULL DEFAULT 0,
		applied_at DATETIME
	)`)
	return err
}
