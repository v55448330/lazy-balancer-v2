package db

import (
	"database/sql"
	"encoding/json"
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

func TestRunMigrations_migratesLegacyHTTPSRulesToHTTPWithTLS(t *testing.T) {
	// Given 存量 a1ecbe3a 期写入的 https 规则行：一行内联证书齐备（tls_cert/tls_key
	// 非空）、一行无证书且带 tls_http_redirect=1，及正常 http/tcp 行
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		INSERT INTO lb_rules (name,protocol,domain,listen_port,enable_tls,tls_cert,tls_key,tls_http_redirect,caddy_id) VALUES
			('legacy-https-tls','https','a.example.test',8443,0,'PEM-CERT','PEM-KEY',1,'lb_https_tls'),
			('legacy-https-notls','https','b.example.test',8444,0,'','',1,'lb_https_notls'),
			('plain-http','http','c.example.test',8080,0,'','',0,'lb_http'),
			('plain-tcp','tcp','',9090,0,'','',0,'lb_tcp');`); err != nil {
		t.Fatalf("seed legacy https rules: %v", err)
	}
	drainSystemAuditBuffer()

	// When migrations run (twice, to prove idempotence)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then 证书齐备的 https 行归一为 http+enable_tls=1（https 语义隐含 TLS）
	var protocol string
	var enableTLS int
	if err := database.QueryRow("SELECT protocol, enable_tls FROM lb_rules WHERE caddy_id='lb_https_tls'").Scan(&protocol, &enableTLS); err != nil {
		t.Fatalf("read migrated cert-bearing rule: %v", err)
	}
	if protocol != "http" || enableTLS != 1 {
		t.Fatalf("cert-bearing rule protocol=%q enable_tls=%d, want http/1", protocol, enableTLS)
	}

	// And 无证书的 https 行归一为普通 HTTP（enable_tls=0 且清 tls_http_redirect，
	// 不制造 TLS 端口明文/幻影跳转的 F-C 形态）
	var redirect int
	if err := database.QueryRow("SELECT protocol, enable_tls, tls_http_redirect FROM lb_rules WHERE caddy_id='lb_https_notls'").Scan(&protocol, &enableTLS, &redirect); err != nil {
		t.Fatalf("read migrated certless rule: %v", err)
	}
	if protocol != "http" || enableTLS != 0 || redirect != 0 {
		t.Fatalf("certless rule protocol=%q enable_tls=%d tls_http_redirect=%d, want http/0/0", protocol, enableTLS, redirect)
	}

	// And 受影响规则逐条进入操作日志缓冲（待审计库就绪落库），重跑零命中
	entries := drainSystemAuditBuffer()
	if len(entries) != 2 {
		t.Fatalf("system audit entries=%d, want 2（重跑幂等）", len(entries))
	}
	for _, entry := range entries {
		if entry.action != "启动迁移" || entry.resource != "系统配置" {
			t.Fatalf("audit entry action=%q resource=%q, want 启动迁移/系统配置", entry.action, entry.resource)
		}
	}

	// And 非 https 行不受影响
	for caddyID, want := range map[string]string{"lb_http": "http", "lb_tcp": "tcp"} {
		var protocol string
		var enableTLS int
		if err := database.QueryRow("SELECT protocol, enable_tls FROM lb_rules WHERE caddy_id=?", caddyID).Scan(&protocol, &enableTLS); err != nil {
			t.Fatalf("read untouched rule %s: %v", caddyID, err)
		}
		if protocol != want || enableTLS != 0 {
			t.Fatalf("rule %s protocol=%q enable_tls=%d, want %s/0", caddyID, protocol, enableTLS, want)
		}
	}
}

// R46 C-1: 存量 https 行的「有证」判定须覆盖 cert_jobs 承载的 ACME 证书——签发
// 门控不筛 protocol，历史 https 行可能已签出证书，仅查内联列会误归无证分支，
// 导致已签发证书静默不再加载且永不续期。
func TestRunMigrations_migratesLegacyHTTPSRulesWithACMECertJobToHTTPWithTLS(t *testing.T) {
	// Given 存量 https 行：一行无内联证书但 cert_jobs 存有已签发 ACME 证书，
	// 一行的证书任务已禁用（证书不可用），一行完全无证
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE lb_rules ADD COLUMN tls_source VARCHAR(20) DEFAULT 'manual';
		INSERT INTO lb_rules (name,protocol,domain,listen_port,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect,caddy_id) VALUES
			('legacy-https-acme','https','acme.example.test',8443,1,'acme_dns','','',1,'lb_https_acme'),
			('legacy-https-acme-disabled','https','disabled.example.test',8444,1,'acme_dns','','',1,'lb_https_acme_disabled'),
			('legacy-https-certless','https','plain.example.test',8445,0,'','','',1,'lb_https_certless');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
			('lb_https_acme','acme.example.test','issued','PEM-CERT','PEM-KEY'),
			('lb_https_acme_disabled','disabled.example.test','disabled','PEM-CERT','PEM-KEY');`); err != nil {
		t.Fatalf("seed legacy https rules with certificate jobs: %v", err)
	}
	drainSystemAuditBuffer()

	// When migrations run (twice, to prove idempotence)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then cert_jobs 存有已签发证书的 https 行归入有证分支：http+enable_tls=1，
	// 且保留 tls_http_redirect（TLS 意图完整保留，证书继续加载/续期）
	var protocol string
	var enableTLS, redirect int
	if err := database.QueryRow("SELECT protocol, enable_tls, tls_http_redirect FROM lb_rules WHERE caddy_id='lb_https_acme'").Scan(&protocol, &enableTLS, &redirect); err != nil {
		t.Fatalf("read migrated ACME-cert rule: %v", err)
	}
	if protocol != "http" || enableTLS != 1 || redirect != 1 {
		t.Fatalf("ACME-cert rule protocol=%q enable_tls=%d tls_http_redirect=%d, want http/1/1", protocol, enableTLS, redirect)
	}

	// And 证书任务已禁用（证书不可用）的行仍按无证归一
	if err := database.QueryRow("SELECT protocol, enable_tls, tls_http_redirect FROM lb_rules WHERE caddy_id='lb_https_acme_disabled'").Scan(&protocol, &enableTLS, &redirect); err != nil {
		t.Fatalf("read migrated disabled-cert-job rule: %v", err)
	}
	if protocol != "http" || enableTLS != 0 || redirect != 0 {
		t.Fatalf("disabled-cert-job rule protocol=%q enable_tls=%d tls_http_redirect=%d, want http/0/0", protocol, enableTLS, redirect)
	}

	// And 完全无证行保持既有无证分支（R45 F-1 行为不回退）
	if err := database.QueryRow("SELECT protocol, enable_tls FROM lb_rules WHERE caddy_id='lb_https_certless'").Scan(&protocol, &enableTLS); err != nil {
		t.Fatalf("read migrated certless rule: %v", err)
	}
	if protocol != "http" || enableTLS != 0 {
		t.Fatalf("certless rule protocol=%q enable_tls=%d, want http/0", protocol, enableTLS)
	}

	// And 三条受影响规则各入一条迁移审计（重跑零命中）
	entries := drainSystemAuditBuffer()
	if len(entries) != 3 {
		t.Fatalf("system audit entries=%d, want 3（重跑幂等）", len(entries))
	}
}

func drainSystemAuditBuffer() []systemAuditEntry {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	entries := systemAuditBuffer.entries
	systemAuditBuffer.entries = nil
	return entries
}

// R45 F-2: 迁移缓冲的系统事件在审计库就绪后落 audit_log 表（UI 操作日志可见），
// 并清空缓冲不重复写。
func TestFlushSystemAuditLogs_writesBufferedEntriesToAuditDB(t *testing.T) {
	// Given 一条迁移期缓冲的系统事件 + 就位的审计库
	auditDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	t.Cleanup(func() { _ = auditDB.Close() })
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100),
		action VARCHAR(50) NOT NULL,
		resource VARCHAR(100),
		detail TEXT,
		ip_address VARCHAR(45),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create audit_log table: %v", err)
	}
	oldAuditDB := AuditDB
	AuditDB = auditDB
	t.Cleanup(func() { AuditDB = oldAuditDB })
	drainSystemAuditBuffer()
	recordSystemAudit("启动迁移", "系统配置", "存量 https 协议规则已迁移为 http+TLS：caddy_id=lb_x name=demo")

	// When
	flushSystemAuditLogs()

	// Then 事件落库且缓冲清空
	var count int
	if err := auditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE username='system' AND action='启动迁移' AND resource='系统配置' AND detail LIKE '%lb_x%'").Scan(&count); err != nil {
		t.Fatalf("count flushed audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("flushed audit rows=%d, want 1", count)
	}
	flushSystemAuditLogs()
	if err := auditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count); err != nil {
		t.Fatalf("recount audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit rows after second flush=%d, want 1（缓冲已清空不得重放）", count)
	}
}

// R46 C-2: flush 写失败时条目按原序留回缓冲等待下轮重试，不再先清缓冲导致
// 事件永久丢失；审计库未就绪（InitializeAuditDB 中途失败）同样保留。
func TestFlushSystemAuditLogs_retainsEntriesOnInsertFailure(t *testing.T) {
	// Given 一个 audit_log 表被改名（INSERT 必失败）的审计库 + 两条缓冲事件
	auditDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	t.Cleanup(func() { _ = auditDB.Close() })
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100),
		action VARCHAR(50) NOT NULL,
		resource VARCHAR(100),
		detail TEXT,
		ip_address VARCHAR(45),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	ALTER TABLE audit_log RENAME TO audit_log_bak`); err != nil {
		t.Fatalf("create then rename audit_log table: %v", err)
	}
	oldAuditDB := AuditDB
	AuditDB = auditDB
	t.Cleanup(func() { AuditDB = oldAuditDB })
	drainSystemAuditBuffer()
	recordSystemAudit("启动迁移", "系统配置", "事件一")
	recordSystemAudit("启动迁移", "系统配置", "事件二")

	// When flush 全部写失败
	flushSystemAuditLogs()

	// Then 两条事件原序留回缓冲
	if got := systemAuditBufferLen(); got != 2 {
		t.Fatalf("buffered entries after failed flush=%d, want 2", got)
	}

	// And When 表名恢复后再次 flush
	if _, err := auditDB.Exec("ALTER TABLE audit_log_bak RENAME TO audit_log"); err != nil {
		t.Fatalf("restore audit_log table: %v", err)
	}
	flushSystemAuditLogs()

	// Then 事件按原顺序落库且缓冲清空
	if got := systemAuditBufferLen(); got != 0 {
		t.Fatalf("buffered entries after successful flush=%d, want 0", got)
	}
	rows, err := auditDB.Query("SELECT detail FROM audit_log ORDER BY id")
	if err != nil {
		t.Fatalf("query flushed audit rows: %v", err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("scan flushed audit row: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate flushed audit rows: %v", err)
	}
	if len(details) != 2 || details[0] != "事件一" || details[1] != "事件二" {
		t.Fatalf("flushed audit details=%v, want [事件一 事件二]（原序保留）", details)
	}
}

func TestFlushSystemAuditLogs_retainsEntriesWhenAuditDBNotReady(t *testing.T) {
	// Given 审计库未就绪（InitializeAuditDB 中途失败、AuditDB 仍为 nil）+ 一条缓冲事件
	oldAuditDB := AuditDB
	AuditDB = nil
	t.Cleanup(func() { AuditDB = oldAuditDB })
	drainSystemAuditBuffer()
	recordSystemAudit("启动迁移", "系统配置", "事件待重放")

	// When
	flushSystemAuditLogs()

	// Then 事件保留在缓冲中等待审计库就绪，而非随缓冲清空永久丢失
	if got := systemAuditBufferLen(); got != 1 {
		t.Fatalf("buffered entries with nil AuditDB=%d, want 1", got)
	}
	drainSystemAuditBuffer()
}

// R46 C-2: 缓冲设上限，审计库长期不可用时丢弃最旧条目，内存不无界增长。
func TestRecordSystemAudit_capsBufferDroppingOldest(t *testing.T) {
	// Given 缓冲已被灌入超过上限的事件
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })
	total := systemAuditBufferCap + 3
	for index := 0; index < total; index++ {
		recordSystemAudit("启动迁移", "系统配置", fmt.Sprintf("entry-%d", index))
	}

	// When 读取缓冲
	entries := drainSystemAuditBuffer()

	// Then 缓冲恒等于上限，最旧的 3 条被丢弃、最新的一条保留
	if len(entries) != systemAuditBufferCap {
		t.Fatalf("buffered entries=%d, want cap %d", len(entries), systemAuditBufferCap)
	}
	if entries[0].detail != "entry-3" {
		t.Fatalf("oldest retained entry=%q, want entry-3（最旧三条已丢弃）", entries[0].detail)
	}
	if entries[len(entries)-1].detail != fmt.Sprintf("entry-%d", total-1) {
		t.Fatalf("newest retained entry=%q, want entry-%d", entries[len(entries)-1].detail, total-1)
	}
}

func TestRunMigrations_dropsDeadLbRulesIPACLColumns(t *testing.T) {
	// Given a schema still carrying the dead rule-level IP ACL columns
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE lb_rules ADD COLUMN ip_acl_mode TEXT NOT NULL DEFAULT '';
		ALTER TABLE lb_rules ADD COLUMN ip_acl_list TEXT NOT NULL DEFAULT '[]';
		INSERT INTO lb_rules (name, protocol, listen_port, caddy_id) VALUES ('legacy rule', 'http', 80, 'lb_legacy');`); err != nil {
		t.Fatalf("seed legacy dead columns: %v", err)
	}

	// When migrations run (twice, to prove idempotence)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then the dead columns are dropped while the row survives
	for _, column := range []string{"ip_acl_mode", "ip_acl_list"} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name=?", column).Scan(&count); err != nil {
			t.Fatalf("query lb_rules.%s: %v", column, err)
		}
		if count != 0 {
			t.Fatalf("lb_rules.%s count=%d, want dropped", column, count)
		}
	}
	var ruleName string
	if err := database.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_legacy'").Scan(&ruleName); err != nil {
		t.Fatalf("read migrated lb_rule: %v", err)
	}
	if ruleName != "legacy rule" {
		t.Fatalf("row lost after drop: name=%q", ruleName)
	}
}

func TestRunMigrations_makes_users_isEnabled_notNull_and_backfills_null(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	// R72 C-I-5：生产迁移顺序是 newColumns 先补齐 mfa 列再执行本重建——种子
	// 表按同一形状建（重建白名单含 mfa 列，缺列即报错，这本身就是 C-I-5 修复
	// 的回归锚点）。
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
		password_version INTEGER NOT NULL DEFAULT 0,
		mfa_enabled BOOLEAN DEFAULT 0,
		mfa_secret TEXT DEFAULT '',
		mfa_pending_secret TEXT DEFAULT '',
		mfa_recovery_codes TEXT DEFAULT '[]',
		mfa_last_timestep INTEGER DEFAULT 0,
		mfa_failed_attempts INTEGER DEFAULT 0,
		mfa_locked_until DATETIME,
		mfa_pending_fails INTEGER DEFAULT 0
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

func TestInitialize_freshSecurityPoliciesColumnsStayNullableLikeMigration(t *testing.T) {
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
	for _, name := range []string{"block_status_code", "geoip_countries", "geoip_mode", "waf_check_response"} {
		var notNull int
		if err := DB.QueryRow(`SELECT "notnull" FROM pragma_table_info('security_policies') WHERE name=?`, name).Scan(&notNull); err != nil {
			t.Fatalf("read security_policies.%s schema: %v", name, err)
		}
		if notNull != 0 {
			t.Fatalf("security_policies.%s notnull=%d, want 0 (nullable)", name, notNull)
		}
	}
	if _, err := DB.Exec(`INSERT INTO security_policies (name) VALUES ('schema-tripwire')`); err != nil {
		t.Fatalf("insert security policy with column defaults: %v", err)
	}
	var countries, mode string
	var wafCheckResponse, statusCode int
	if err := DB.QueryRow(`SELECT geoip_countries, geoip_mode, waf_check_response, block_status_code FROM security_policies WHERE name='schema-tripwire'`).Scan(&countries, &mode, &wafCheckResponse, &statusCode); err != nil {
		t.Fatalf("read security policy defaults: %v", err)
	}
	if countries != "[]" || mode != "deny" || wafCheckResponse != 0 || statusCode != 0 {
		t.Fatalf("column defaults=(%q,%q,%d,%d), want ([] deny 0 0)", countries, mode, wafCheckResponse, statusCode)
	}
}

func TestInitialize_certJobNormalizationPreservesUnparseableValues(t *testing.T) {
	// Given
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, ca_available_after) VALUES
		('r1','garbage.example.com','not-a-date'),
		('r2','legacy.example.com','2026-07-02'),
		('r3','null.example.com',NULL)`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-run migrations: %v", err)
	}

	// Then（SQL 侧比较存储原文，避免驱动把 DATETIME 重排成 RFC3339 干扰断言）
	var garbageKept int
	if err := DB.QueryRow(`SELECT ca_available_after = 'not-a-date' FROM cert_jobs WHERE domain='garbage.example.com'`).Scan(&garbageKept); err != nil {
		t.Fatalf("read garbage row: %v", err)
	}
	if garbageKept != 1 {
		var actual string
		_ = DB.QueryRow(`SELECT ca_available_after FROM cert_jobs WHERE domain='garbage.example.com'`).Scan(&actual)
		t.Fatalf("garbage value=%q, want 'not-a-date' preserved", actual)
	}
	var normalized int
	if err := DB.QueryRow(`SELECT ca_available_after = '2026-07-02 00:00:00' FROM cert_jobs WHERE domain='legacy.example.com'`).Scan(&normalized); err != nil {
		t.Fatalf("read legacy row: %v", err)
	}
	if normalized != 1 {
		var actual string
		_ = DB.QueryRow(`SELECT ca_available_after FROM cert_jobs WHERE domain='legacy.example.com'`).Scan(&actual)
		t.Fatalf("normalized value=%q, want '2026-07-02 00:00:00'", actual)
	}
	var nullKept int
	if err := DB.QueryRow(`SELECT ca_available_after IS NULL FROM cert_jobs WHERE domain='null.example.com'`).Scan(&nullKept); err != nil {
		t.Fatalf("read null row: %v", err)
	}
	if nullKept != 1 {
		t.Fatalf("null row not preserved as NULL")
	}
}

// D4-S1 回归：ca_available_after 规范化必须是一次性回填——WHERE 排除已
// 规范化的行（值未变不重写），否则每次启动全量重写匹配行（页脏 + WAL
// 增长）。不可解析值仍由 datetime(...) IS NOT NULL 守卫保留。
func TestInitialize_certJobCAAvailableAfterNormalizationRewritesOnlyStaleRows(t *testing.T) {
	// Given
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, ca_available_after) VALUES
		('r1','canonical.example.com','2026-07-02 00:00:00'),
		('r2','legacy.example.com','2026-07-02'),
		('r3','garbage.example.com','not-a-date')`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}

	// When：模拟下一次启动重跑生产同款规范化语句
	res, err := normalizeCertJobsCAAvailableAfter()
	if err != nil {
		t.Fatalf("normalize ca_available_after: %v", err)
	}
	stale, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("rows affected: %v", err)
	}
	resAgain, err := normalizeCertJobsCAAvailableAfter()
	if err != nil {
		t.Fatalf("normalize ca_available_after again: %v", err)
	}
	again, err := resAgain.RowsAffected()
	if err != nil {
		t.Fatalf("rows affected again: %v", err)
	}

	// Then：首遍仅 legacy 1 行待回填（canonical 不再匹配）；第二遍零行
	if stale != 1 {
		t.Fatalf("rows rewritten=%d, want 1 (legacy only; canonical row must not match)", stale)
	}
	if again != 0 {
		t.Fatalf("second pass rewrote %d rows, want 0 — backfill must be one-shot", again)
	}
	// SQL 侧比较存储原文，避免驱动把 DATETIME 重排成 RFC3339 干扰断言
	var normalized, garbageKept int
	if err := DB.QueryRow(`SELECT ca_available_after = '2026-07-02 00:00:00' FROM cert_jobs WHERE domain='legacy.example.com'`).Scan(&normalized); err != nil {
		t.Fatalf("read legacy row: %v", err)
	}
	if normalized != 1 {
		t.Fatalf("legacy row not normalized to canonical format")
	}
	if err := DB.QueryRow(`SELECT ca_available_after = 'not-a-date' FROM cert_jobs WHERE domain='garbage.example.com'`).Scan(&garbageKept); err != nil {
		t.Fatalf("read garbage row: %v", err)
	}
	if garbageKept != 1 {
		t.Fatalf("garbage value not preserved")
	}
}

// A4-S2: 历史 NOT-NULL 窗口期建库的 security_policies 四列停留 NOT NULL，
// fresh CREATE 与 newColumns 迁移对「列已存在」的库均不生效；启动迁移必须
// 收敛为可空并保数据。
func TestInitialize_convergesWindowEraSecurityPoliciesNotNullColumns(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`DROP TABLE security_policies;
		CREATE TABLE security_policies (
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
			block_status_code INTEGER NOT NULL DEFAULT 0,
			enabled BOOLEAN DEFAULT TRUE,
			updated_by INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT (datetime('now')),
			updated_at DATETIME DEFAULT (datetime('now')),
			geoip_countries TEXT NOT NULL DEFAULT '[]',
			geoip_mode TEXT NOT NULL DEFAULT 'deny',
			waf_check_response INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO security_policies (id,name,geoip_countries,geoip_mode,waf_check_response,block_status_code,enabled)
		VALUES (1,'window-era','["CN"]','allow',1,429,1);`); err != nil {
		t.Fatalf("seed window-era security_policies: %v", err)
	}

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}

	// Then: 四列收敛为可空，数据保留
	for _, name := range []string{"block_status_code", "geoip_countries", "geoip_mode", "waf_check_response"} {
		var notNull int
		if err := DB.QueryRow(`SELECT "notnull" FROM pragma_table_info('security_policies') WHERE name=?`, name).Scan(&notNull); err != nil {
			t.Fatalf("read security_policies.%s schema: %v", name, err)
		}
		if notNull != 0 {
			t.Fatalf("security_policies.%s notnull=%d, want 0 (converged nullable)", name, notNull)
		}
	}
	var countries, mode string
	var wafCheckResponse, statusCode, enabled int
	if err := DB.QueryRow(`SELECT geoip_countries, geoip_mode, waf_check_response, block_status_code, enabled
		FROM security_policies WHERE id=1`).Scan(&countries, &mode, &wafCheckResponse, &statusCode, &enabled); err != nil {
		t.Fatalf("read migrated policy: %v", err)
	}
	if countries != `["CN"]` || mode != "allow" || wafCheckResponse != 1 || statusCode != 429 || enabled != 1 {
		t.Fatalf("policy data=(%q,%q,%d,%d,%d), want ([\"CN\"],allow,1,429,1)", countries, mode, wafCheckResponse, statusCode, enabled)
	}
	// 收敛后 NULL 行恢复（restoreTable/快照通道）不再被约束拒绝
	if _, err := DB.Exec(`INSERT INTO security_policies (id,name,geoip_countries) VALUES (2,'null-restore',NULL)`); err != nil {
		t.Fatalf("insert NULL geoip_countries after convergence: %v", err)
	}
}

// A4-S3: PK 重建迁移的 upstreams_new.enabled 此前为可空（与 fresh CREATE 的
// NOT NULL DEFAULT 1 漂移）；对齐后重建结果必须 notnull=1，且遗留 NULL 行
// 经 COALESCE 拷贝归一为 0。
func TestMigrateLbRulesPrimaryKey_rebuildsUpstreamEnabledNotNull(t *testing.T) {
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
			weight INTEGER, dynamic_dns BOOLEAN, enabled BOOLEAN, protocol TEXT, max_connections INTEGER
		);
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'tcp', 443, 'lb_enabled_nn');
		INSERT INTO upstreams (id, rule_id, host, port, enabled) VALUES (9, 7, '127.0.0.1', 8443, NULL);
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	if err := migrateLbRulesPrimaryKey(); err != nil {
		t.Fatalf("migrate load-balancer primary key: %v", err)
	}

	var notNull int
	if err := database.QueryRow(`SELECT "notnull" FROM pragma_table_info('upstreams') WHERE name='enabled'`).Scan(&notNull); err != nil {
		t.Fatalf("read upstreams.enabled schema: %v", err)
	}
	if notNull != 1 {
		t.Fatalf("upstreams.enabled notnull=%d, want 1 (aligned to fresh CREATE)", notNull)
	}
	var enabled int
	if err := database.QueryRow("SELECT enabled FROM upstreams WHERE id=9").Scan(&enabled); err != nil {
		t.Fatalf("read migrated upstream: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("upstreams.enabled=%d, want 0 (legacy NULL normalized via COALESCE copy)", enabled)
	}
}

// A4-S4/A5-N2: 版本表 consecutive_failures 与 global_config.is_master 的
// 遗留 NULL 由启动迁移一次性回填（0/0/1），消灭读侧 COALESCE 语义分裂。
func TestInitialize_backfillsNullConsecutiveFailuresAndIsMaster(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id,version,consecutive_failures) VALUES (1,'v4.28.0',NULL);
		UPDATE security_ip2region_version SET consecutive_failures=NULL WHERE id=1;
		UPDATE global_config SET is_master=NULL WHERE id=1`); err != nil {
		t.Fatalf("seed NULL bookkeeping values: %v", err)
	}

	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}

	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		var nullLeft int
		if err := DB.QueryRow("SELECT consecutive_failures IS NULL FROM " + table + " WHERE id=1").Scan(&nullLeft); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		if nullLeft != 0 {
			t.Fatalf("%s.consecutive_failures still NULL after backfill", table)
		}
	}
	var isMaster int
	if err := DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		t.Fatalf("read global_config.is_master: %v", err)
	}
	if isMaster != 1 {
		t.Fatalf("global_config.is_master=%d, want 1 (NULL backfilled)", isMaster)
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

func TestSanitizeLegacyCustomRulePatterns_disablesDirtyRulesIdempotently(t *testing.T) {
	// Given a database carrying a dirty standalone rule, a clean rule, an empty-conditions
	// rule, and a policy with an embedded dirty entry plus a clean entry
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		INSERT INTO security_custom_rules (id,name,conditions,action,score,enabled) VALUES
			(1,'脏规则','[{"target":"uri","operator":"contains","pattern":"C:\\"}]','block',5,1),
			(2,'干净规则','[{"target":"uri","operator":"contains","pattern":"/admin"}]','block',5,1),
			(3,'空条件规则','[]','block',5,1);
		INSERT INTO security_policies (id,name,custom_rules) VALUES
			(1,'策略A','[{"id":10,"name":"内嵌脏","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"C:\\"}]},{"id":11,"name":"内嵌干净","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/ok"}]}]');`); err != nil {
		t.Fatalf("seed legacy dirty rules: %v", err)
	}

	// When the migration runs twice (idempotency)
	if err := sanitizeLegacyCustomRulePatterns(); err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if err := sanitizeLegacyCustomRulePatterns(); err != nil {
		t.Fatalf("repeat sanitize: %v", err)
	}

	// Then standalone dirty/empty rules are disabled and the clean rule is untouched
	assertRuleEnabled := func(id, want int) {
		t.Helper()
		var enabled int
		if err := database.QueryRow("SELECT enabled FROM security_custom_rules WHERE id=?", id).Scan(&enabled); err != nil {
			t.Fatalf("read custom rule %d: %v", id, err)
		}
		if enabled != want {
			t.Fatalf("custom rule %d enabled=%d, want %d", id, enabled, want)
		}
	}
	assertRuleEnabled(1, 0)
	assertRuleEnabled(2, 1)
	assertRuleEnabled(3, 0)

	// And the policy's embedded dirty entry is disabled while the clean entry survives
	var raw string
	if err := database.QueryRow("SELECT custom_rules FROM security_policies WHERE id=1").Scan(&raw); err != nil {
		t.Fatalf("read policy custom_rules: %v", err)
	}
	var embedded []struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(raw), &embedded); err != nil {
		t.Fatalf("rewritten policy JSON unparseable: %v (%s)", err, raw)
	}
	if len(embedded) != 2 {
		t.Fatalf("embedded entries=%d, want 2 (%s)", len(embedded), raw)
	}
	if embedded[0].Name != "内嵌脏" || embedded[0].Enabled {
		t.Fatalf("embedded dirty entry = %+v, want disabled", embedded[0])
	}
	if embedded[1].Name != "内嵌干净" || !embedded[1].Enabled {
		t.Fatalf("embedded clean entry = %+v, want enabled", embedded[1])
	}
}

func TestSanitizeLegacyCustomRulePatterns_survivesNullColumns(t *testing.T) {
	// Given a database whose legacy rows carry NULL conditions / custom_rules
	// (reachable via verbatim snapshot apply and backup restoreTable round-trips)
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_custom_rules (id,name,conditions,action,score,enabled) VALUES
		(1,'空值规则',NULL,'block',5,1);
		INSERT INTO security_policies (id,name,custom_rules,enabled) VALUES
		(1,'空值策略',NULL,1);`); err != nil {
		t.Fatalf("seed NULL rows: %v", err)
	}

	// When the startup migration runs
	if err := sanitizeLegacyCustomRulePatterns(); err != nil {
		t.Fatalf("sanitize: %v", err)
	}

	// Then the NULL-conditions row flows into the unparseable-JSON branch and is disabled
	var enabled int
	if err := database.QueryRow("SELECT enabled FROM security_custom_rules WHERE id=1").Scan(&enabled); err != nil {
		t.Fatalf("read custom rule: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("custom rule enabled=%d, want 0 (unparseable-JSON branch disables)", enabled)
	}

	// And the NULL-custom_rules policy flows into the unparseable-JSON branch and is left untouched
	var nullPolicies int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_policies WHERE id=1 AND custom_rules IS NULL").Scan(&nullPolicies); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if nullPolicies != 1 {
		t.Fatalf("policy with NULL custom_rules rows=%d, want 1 (unparseable-JSON branch keeps as-is)", nullPolicies)
	}
}

func TestInitialize_backfillsLegacyTimeoutColumnsOnceAndPreservesExplicitZero(t *testing.T) {
	// Given a legacy database whose global_config predates the four timeout columns
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, caddy_config TEXT);
		INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');`); err != nil {
		t.Fatalf("seed legacy global config: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	readTimeouts := func() (int, int, int, int) {
		t.Helper()
		var readTimeout, writeTimeout, idleTimeout, keepaliveTimeout int
		if err := DB.QueryRow(`SELECT http_read_timeout, http_write_timeout, http_idle_timeout, upstream_keepalive_timeout
			FROM global_config WHERE id=1`).Scan(&readTimeout, &writeTimeout, &idleTimeout, &keepaliveTimeout); err != nil {
			t.Fatalf("read timeout columns: %v", err)
		}
		return readTimeout, writeTimeout, idleTimeout, keepaliveTimeout
	}

	// When the legacy database is upgraded (columns newly added → one-time backfill)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then the newly added timeout columns are backfilled to the recommended defaults
	//（R72 三次：keepalive 默认 0——60s 空闲关闭会中断 SSE/WebSocket 上游长连接，
	// 0 继承 Caddy/Go Transport 默认 2 分钟）
	if r, w, i, k := readTimeouts(); r != 60 || w != 60 || i != 120 || k != 0 {
		t.Fatalf("backfilled timeouts=(%d,%d,%d,%d), want (60,60,120,0)", r, w, i, k)
	}

	// And when the user explicitly sets 0 (= 省略超时指令、用 Caddy 默认) and the service restarts
	if _, err := DB.Exec(`UPDATE global_config SET http_read_timeout=0, http_write_timeout=0, http_idle_timeout=0, upstream_keepalive_timeout=0 WHERE id=1`); err != nil {
		t.Fatalf("set explicit zero timeouts: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close database before restart: %v", err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("reinitialize database: %v", err)
	}

	// Then the explicit zeros survive the restart migration unchanged
	if r, w, i, k := readTimeouts(); r != 0 || w != 0 || i != 0 || k != 0 {
		t.Fatalf("explicit zero timeouts rewritten to (%d,%d,%d,%d), want (0,0,0,0)", r, w, i, k)
	}
}

func TestMigrateCanonicalDomains_skipsIndexRebuildWhenNothingToDo(t *testing.T) {
	// C5 SUG-2：无事可做时迁移不得白跑 DROP/CREATE 唯一索引（每次启动一次立即
	// 写事务 + 三次全表扫描）。观察缝：预先把唯一索引移除——若迁移仍执行
	// DROP/CREATE，索引会被重建回来；整段跳过时索引保持缺失。
	// Given：存量域/host 全部已是规范形，cert_jobs 无重复组；唯一索引不存在
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (name, protocol, domain, listen_port, caddy_id) VALUES ('r1','http','example.com',8080,'lb_test0001');
		INSERT INTO upstreams (rule_id, host, port) VALUES ('lb_test0001','backend.example.com',9000);
		INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_test0001','example.com','issued')`); err != nil {
		t.Fatalf("seed clean data: %v", err)
	}

	// When
	if err := migrateCanonicalDomains(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：索引未被重建（sqlite_master 中仍缺失，证明 DROP/CREATE 未执行）
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cert_jobs_rule_domain_unique'").Scan(&count); err != nil {
		t.Fatalf("query index: %v", err)
	}
	if count != 0 {
		t.Fatalf("index rebuilt despite nothing to normalize (count=%d), want untouched", count)
	}
}

func TestMigrateCanonicalDomains_normalizesAndRebuildsIndexWhenWorkNeeded(t *testing.T) {
	// Given：非规范域（大写）存量行——迁移必须照常工作（行为不得因跳过门改变）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (name, protocol, domain, listen_port, caddy_id) VALUES ('r1','http','Example.COM',8080,'lb_test0001')`); err != nil {
		t.Fatalf("seed non-canonical data: %v", err)
	}

	// When
	if err := migrateCanonicalDomains(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：域被归一，唯一索引被重建
	var domain string
	if err := database.QueryRow("SELECT domain FROM lb_rules WHERE caddy_id='lb_test0001'").Scan(&domain); err != nil {
		t.Fatalf("read domain: %v", err)
	}
	if domain != "example.com" {
		t.Fatalf("domain=%q, want normalized example.com", domain)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cert_jobs_rule_domain_unique'").Scan(&count); err != nil {
		t.Fatalf("query index: %v", err)
	}
	if count != 1 {
		t.Fatalf("index count=%d, want rebuilt when normalization ran", count)
	}
}

func TestMigrateCanonicalDomains_deduplicatesAndRebuildsIndexWhenDuplicatesExist(t *testing.T) {
	// Given：域均已规范但 cert_jobs 存在 (rule_id, domain) 重复组
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_test0001','dup.example.com','issued');
		INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_test0001','dup.example.com','failed')`); err != nil {
		t.Fatalf("seed duplicate data: %v", err)
	}

	// When
	if err := migrateCanonicalDomains(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：重复组被去重，唯一索引被重建
	var rows int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_test0001' AND domain='dup.example.com'").Scan(&rows); err != nil {
		t.Fatalf("read cert_jobs: %v", err)
	}
	if rows != 1 {
		t.Fatalf("duplicate group rows=%d, want deduplicated to 1", rows)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cert_jobs_rule_domain_unique'").Scan(&count); err != nil {
		t.Fatalf("query index: %v", err)
	}
	if count != 1 {
		t.Fatalf("index count=%d, want rebuilt when dedup ran", count)
	}
}

// B4-S2（审计 N+8）：migrateLbRulesPrimaryKey 重建 lb_rules/upstreams 时，随表
// DROP 级联删除既有索引——三张高频索引若只在重建前创建，则整个启动周期内缺失，
// 要到下次启动才被 IF NOT EXISTS 自愈。同一启动内必须补齐。
func TestInitialize_recreatesIndexesDroppedByPkRebuildInSameBoot(t *testing.T) {
	// Given：lb_rules 仍以 id 为主键的遗留库（触发 PK 重建）
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
			updated_at DATETIME, updated_by INTEGER, caddy_id TEXT
		);
		CREATE TABLE upstreams (
			id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
			weight INTEGER, domain TEXT, dynamic_dns BOOLEAN, enabled BOOLEAN, protocol TEXT, host_header TEXT,
			dns_server TEXT, max_connections INTEGER, proxy_protocol TEXT
		);
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'http', 8080, 'lb_rebuild');
		INSERT INTO upstreams (id, rule_id, host, port) VALUES (9, 7, '127.0.0.1', 9000);
	`); err != nil {
		t.Fatalf("seed legacy load-balancer schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When：遗留库启动一次（PK 重建 DROP 并重建两张表）
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then：随表删除的三张索引在同一启动内重新存在
	for _, index := range []string{"idx_upstreams_rule_enabled_id", "idx_lb_rules_listen_port", "idx_lb_rules_enabled"} {
		var count int
		if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count); err != nil {
			t.Fatalf("query index %s: %v", index, err)
		}
		if count != 1 {
			t.Fatalf("index %s count=%d after PK rebuild boot, want 1", index, count)
		}
	}
}

// B4-S3（审计 N+8）：备份恢复通道的 epoch 归一（backupTableNullDefaults）只守住
// 「新恢复」的行——修复前已恢复的存量 NULL 时间戳持续毒化集群 dump（裸扫
// time.Time 对 NULL 失败）。启动幂等回填 epoch，真实时间戳的对照行不得被改写。
// C4-F1（审计 N+9）：同一恢复通道还归一 users/api_keys/path_rules/cert_jobs 的
// created_at（裸 time.Time 消费端：登录/用户列表/密钥列表/证书任务/集群快照），
// 回填范围随之补齐这四列。
func TestInitialize_backfillsLegacyNullTimestampColumns(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	// 模拟修复前恢复通道落下的行：显式 NULL 覆盖 CURRENT_TIMESTAMP 默认值；
	// 另带一条真实时间戳对照行，回填不得触碰。
	if _, err := DB.Exec(`
		INSERT INTO lb_rules (name, protocol, listen_port, caddy_id, created_at) VALUES
			('null-ts', 'http', 8081, 'lb_null_ts', NULL),
			('kept-ts', 'http', 8082, 'lb_kept_ts', '2026-01-02 03:04:05');
		INSERT INTO ca_providers (name, provider, directory_url, credentials, created_at, updated_at)
			VALUES ('ca-null', 'letsencrypt', 'https://acme.example/dir', '{}', NULL, NULL);
		INSERT INTO certificate_configs (name, dns_provider, dns_credentials, created_at)
			VALUES ('cert-null', 'dnspod', '{}', NULL);
		INSERT INTO users (id, username, password_hash, role, is_enabled, created_at) VALUES
			(100, 'null-ts-user', 'x', 'admin', 1, NULL),
			(101, 'kept-ts-user', 'x', 'admin', 1, '2026-01-02 03:04:05');
		INSERT INTO api_keys (name, key_hash, key_prefix, created_by, created_at)
			VALUES ('null-ts-key', 'hash', 'lb_null', 100, NULL);
		INSERT INTO path_rules (rule_id, sort_order, match_type, path, created_at)
			VALUES ('lb_null_ts', 0, 'prefix', '/', NULL);
		INSERT INTO cert_jobs (rule_id, domain, status, created_at)
			VALUES ('lb_null_ts', 'null-ts.example.com', 'issued', NULL);
	`); err != nil {
		t.Fatalf("seed NULL timestamps: %v", err)
	}

	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}

	const epoch = "1970-01-01 00:00:00"
	// SQL 内联比较字面量而非 Go 侧扫描值：DATETIME 声明列经驱动读取会被转成
	// time.Time（'1970-01-01 00:00:00' → '1970-01-01T00:00:00Z'），无法与
	// 存储字面量直接比对；存储值本身就是 UPDATE 写入的 epoch 文本。
	assertEpoch := func(query string) {
		t.Helper()
		var count int
		if err := DB.QueryRow(query).Scan(&count); err != nil {
			t.Fatalf("read backfilled timestamp (%s): %v", query, err)
		}
		if count != 1 {
			t.Fatalf("query %q matched %d rows, want the epoch-backfilled row", query, count)
		}
	}
	assertEpoch("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_null_ts' AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM ca_providers WHERE name='ca-null' AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM ca_providers WHERE name='ca-null' AND updated_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM certificate_configs WHERE name='cert-null' AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM users WHERE id=100 AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM api_keys WHERE name='null-ts-key' AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_null_ts' AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM cert_jobs WHERE domain='null-ts.example.com' AND created_at='" + epoch + "'")

	// 幂等：第三次启动后回填值不变，对照行真实时间戳原样保留。
	if err := Initialize(dir); err != nil {
		t.Fatalf("third initialize: %v", err)
	}
	var kept int
	if err := DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_kept_ts' AND created_at='2026-01-02 03:04:05'").Scan(&kept); err != nil {
		t.Fatalf("read control timestamp: %v", err)
	}
	if kept != 1 {
		t.Fatalf("control row created_at was overwritten, want untouched real timestamp")
	}
	if err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=101 AND created_at='2026-01-02 03:04:05'").Scan(&kept); err != nil {
		t.Fatalf("read users control timestamp: %v", err)
	}
	if kept != 1 {
		t.Fatalf("users control row created_at was overwritten, want untouched real timestamp")
	}
	assertEpoch("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_null_ts' AND created_at='" + epoch + "'")
	assertEpoch("SELECT COUNT(*) FROM users WHERE id=100 AND created_at='" + epoch + "'")
}

func openMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration.db")+"?_pragma=foreign_keys(1)")
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
