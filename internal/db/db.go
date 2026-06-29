package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/glebarez/sqlite"
)

var (
	DB       *sql.DB
	MetricsDB *sql.DB
	BackgroundDBMu sync.Mutex
)

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

	// Initialize metrics database
	if err := InitializeMetricsDB(dataDir); err != nil {
		return fmt.Errorf("failed to initialize metrics database: %w", err)
	}

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Run migrations
	if err := runMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Ensure default config row exists
	var configCount int
	DB.QueryRow("SELECT COUNT(*) FROM global_config").Scan(&configCount)
	if configCount == 0 {
		DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')")
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
		strategy VARCHAR(20) DEFAULT 'round_robin',
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
		host_header VARCHAR(255),
		enable_tls BOOLEAN DEFAULT FALSE,
		tls_cert TEXT,
		tls_key TEXT,
		tls_auto_cert BOOLEAN DEFAULT FALSE,
		tls_email VARCHAR(255),
		tls_http_redirect BOOLEAN DEFAULT FALSE,
		enable_compress BOOLEAN DEFAULT TRUE,
		compress_types VARCHAR(100) DEFAULT 'gzip',
		enabled BOOLEAN DEFAULT TRUE,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		updated_by INTEGER,
		caddy_id VARCHAR(20) PRIMARY KEY
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
		status VARCHAR(20) DEFAULT 'pending',
		message TEXT,
		expires_at DATETIME,
		cert_pem TEXT,
		key_pem TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain ON cert_jobs(rule_id, domain);

	-- Global Config table
	CREATE TABLE IF NOT EXISTS global_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		caddy_config TEXT DEFAULT '{}',
		dns_provider VARCHAR(50) DEFAULT 'dnspod',
		dns_credentials TEXT,
		letsencrypt_email VARCHAR(255),
		log_level VARCHAR(10) DEFAULT 'info',
		access_log_enabled BOOLEAN DEFAULT TRUE,
		is_master BOOLEAN DEFAULT TRUE,
		master_url VARCHAR(255),
		sync_interval INTEGER DEFAULT 60,
		caddy_log_path VARCHAR(500) DEFAULT '/app/logs/caddy.log',
		caddy_log_level VARCHAR(10) DEFAULT 'info',
		caddy_log_size_mb INTEGER DEFAULT 100,
		last_sync DATETIME,
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
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (master_id) REFERENCES nodes(id)
	);

	-- Config versions table (for sync)
	CREATE TABLE IF NOT EXISTS config_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version INTEGER NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		change_type VARCHAR(20) NOT NULL,
		description TEXT
	);

	-- Create indexes
	CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
	CREATE INDEX IF NOT EXISTS idx_nodes_master ON nodes(master_id);
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

	// lb_rules new columns
	newLbColumns := map[string]string{
		"domain":                     "VARCHAR(255)",
		"tls_cert":                   "TEXT",
		"tls_key":                    "TEXT",
		"tls_auto_cert":              "BOOLEAN DEFAULT 0",
		"tls_email":                  "VARCHAR(255)",
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
	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='letsencrypt_email'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN letsencrypt_email VARCHAR(255)")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='acme_email'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN acme_email VARCHAR(255)")
	}

	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cert_expiry_days'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE global_config ADD COLUMN cert_expiry_days INTEGER DEFAULT 30")
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

	// certificate_configs schema migration: move from legacy dns_id/dns_key to JSON dns_credentials
	DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('certificate_configs') WHERE name='dns_credentials'").Scan(&colCount)
	if colCount == 0 {
		DB.Exec("ALTER TABLE certificate_configs ADD COLUMN dns_credentials TEXT")
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
			strategy VARCHAR(20) DEFAULT 'round_robin',
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
			host_header VARCHAR(255),
			enable_tls BOOLEAN DEFAULT FALSE,
			tls_cert TEXT,
			tls_key TEXT,
			tls_auto_cert BOOLEAN DEFAULT FALSE,
			tls_email VARCHAR(255),
			tls_http_redirect BOOLEAN DEFAULT FALSE,
			tls_source VARCHAR(20) DEFAULT 'manual',
			acme_config_id INTEGER DEFAULT 0,
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
		INSERT INTO lb_rules_new SELECT * FROM lb_rules
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

func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
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
