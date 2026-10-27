package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

// 一次性迁移 marker 的可观察契约：启动迁移执行后每个 marker 列/键都必须已
// 置位（行为断言）。marker 的作用是让下一次启动零扫描/零写入——只断言源码
// 里登记了列名无法证明迁移真的落位，也无法发现「登记了列但迁移未写 marker」。
func TestRunMigrations_oneShotMarkersPersistedByMigration(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := migrateSyncSwitches(); err != nil {
		t.Fatalf("migrate sync switches: %v", err)
	}

	// 六个一次性 marker（newColumns 登记点）：迁移完成后必须全部置位。
	for _, tc := range []struct {
		name  string
		query string
		want  string
	}{
		{name: "global_config.waf_mode4_migrated", query: `SELECT CAST(COALESCE(waf_mode4_migrated,0) AS TEXT) FROM global_config WHERE id=1`, want: "1"},
		{name: "global_config.sync_switches_migrated", query: `SELECT CAST(COALESCE(sync_switches_migrated,0) AS TEXT) FROM global_config WHERE id=1`, want: "1"},
		{name: "global_config.legacy_custom_rule_sanitize_fp", query: `SELECT COALESCE(legacy_custom_rule_sanitize_fp,'') FROM global_config WHERE id=1`, want: legacyCustomRuleSanitizeFingerprint},
		{name: "global_config.threat_traffic_sample_unified_migrated", query: `SELECT CAST(COALESCE(threat_traffic_sample_unified_migrated,0) AS TEXT) FROM global_config WHERE id=1`, want: "1"},
		{name: "global_config.security_events_retention_migrated", query: `SELECT CAST(COALESCE(security_events_retention_migrated,0) AS TEXT) FROM global_config WHERE id=1`, want: "1"},
		{name: "global_config.ca_providers_seeded", query: `SELECT CAST(COALESCE(ca_providers_seeded,0) AS TEXT) FROM global_config WHERE id=1`, want: "1"},
	} {
		var got string
		if err := database.QueryRow(tc.query).Scan(&got); err != nil {
			t.Errorf("%s: marker column must exist and be readable after migration: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s=%q, want %q（一次性迁移必须落位 marker）", tc.name, got, tc.want)
		}
	}
}

// marker 列必须登记在 newColumns 统一补列通道（否则存量库升级缺列、迁移直接
// 报 no such column）。用 AST 读取 newColumnsRegistry 复合字面量的键集——
// 文本切片会把注释中的列名也算作登记。
func TestRunMigrations_oneShotMarkerColumnsRegisteredInNewColumns(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "db.go", nil, 0)
	if err != nil {
		t.Fatalf("parse db.go: %v", err)
	}
	registered := map[string]struct{}{}
	collectKeys := func(literal *ast.CompositeLit) {
		for _, element := range literal.Elts {
			kv, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING {
				continue
			}
			unquoted, err := strconv.Unquote(key.Value)
			if err != nil {
				continue
			}
			registered[unquoted] = struct{}{}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		// 包级登记单源：var newColumnsRegistry = map[string]string{...}
		if spec, ok := node.(*ast.ValueSpec); ok && len(spec.Names) == 1 && len(spec.Values) == 1 && spec.Names[0].Name == "newColumnsRegistry" {
			if literal, ok := spec.Values[0].(*ast.CompositeLit); ok {
				collectKeys(literal)
			}
			return false
		}
		return true
	})
	if len(registered) == 0 {
		t.Fatal("newColumns registry not found（AST 形态漂移）")
	}
	for _, key := range []string{
		"global_config.waf_mode4_migrated",
		"global_config.sync_switches_migrated",
		"global_config.legacy_custom_rule_sanitize_fp",
		"global_config.threat_traffic_sample_unified_migrated",
		"global_config.security_events_retention_migrated",
		"global_config.ca_providers_seeded",
	} {
		if _, ok := registered[key]; !ok {
			t.Errorf("one-shot migration marker %s must use the idempotent newColumns ALTER path", key)
		}
	}
}

// 存量库补列——task_runs.operator（TEXT NOT NULL DEFAULT ”）。
// fresh DDL 建表含列；pre-升级库经 runMigrations 幂等补列（schedule_days
// 曾漏登记致升级安装必报 no such column——同位点回归钉）。
func TestRunMigrationsAddsTaskRunsOperatorColumn(t *testing.T) {
	// Given 存量库：task_runs 无 operator 列
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// runMigrations 的 access-log-format 迁移要求 global_config 行存在（同 TestRunMigrationsCreates… 前置）
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec("ALTER TABLE task_runs DROP COLUMN operator"); err != nil {
		t.Fatalf("simulate legacy task_runs: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then：补列存在，存量行回填默认空串
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('task_runs') WHERE name='operator'").Scan(&count); err != nil {
		t.Fatalf("query task_runs schema: %v", err)
	}
	if count != 1 {
		t.Fatalf("task_runs.operator count=%d, want 1", count)
	}
	if _, err := database.Exec("INSERT INTO task_runs (task_id, family) VALUES ('t','f')"); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	var op string
	if err := database.QueryRow("SELECT operator FROM task_runs WHERE task_id='t'").Scan(&op); err != nil {
		t.Fatalf("read operator: %v", err)
	}
	if op != "" {
		t.Fatalf("legacy row operator=%q, want empty", op)
	}
}

// task_runs.stage/entry_count 零写入方死列清理——
// fresh DDL 不含两列；存量库经 runMigrations 的 deadColumnDrops 幂等删除。
func TestRunMigrationsDropsTaskRunsStageEntryCount(t *testing.T) {
	// Given 存量库形态：task_runs 带 stage/entry_count 两列（fresh DDL 已删
	// 时补回模拟旧库；未删时本已存在——条件补列两种形态通用）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	for _, col := range []struct{ name, ddl string }{
		{"stage", "TEXT DEFAULT ''"},
		{"entry_count", "INTEGER DEFAULT 0"},
	} {
		var cnt int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('task_runs') WHERE name=?", col.name).Scan(&cnt); err != nil {
			t.Fatalf("query task_runs schema: %v", err)
		}
		if cnt == 0 {
			if _, err := database.Exec("ALTER TABLE task_runs ADD COLUMN " + col.name + " " + col.ddl); err != nil {
				t.Fatalf("simulate legacy column %s: %v", col.name, err)
			}
		}
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 两死列均被移除
	for _, col := range []string{"stage", "entry_count"} {
		var cnt int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('task_runs') WHERE name=?", col).Scan(&cnt); err != nil {
			t.Fatalf("query task_runs schema: %v", err)
		}
		if cnt != 0 {
			t.Fatalf("task_runs.%s count=%d, want 0（死列未删）", col, cnt)
		}
	}
}

func TestRunMigrationsCreatesAuthenticationAndUpstreamIndexes(t *testing.T) {
	// Given：fresh DDL 先建索引，再显式删除模拟存量库缺失形态。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		DROP INDEX IF EXISTS idx_api_keys_prefix_hash;
		DROP INDEX IF EXISTS idx_upstreams_rule_enabled_id;`); err != nil {
		t.Fatalf("seed global config and drop legacy indexes: %v", err)
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
	// MCP/apiKeyAuth 的复合索引必须保持左前缀 key_prefix，再 key_hash。
	for seqno, want := range []string{"key_prefix", "key_hash"} {
		var column string
		if err := database.QueryRow(`SELECT name FROM pragma_index_info('idx_api_keys_prefix_hash') WHERE seqno=?`, seqno).Scan(&column); err != nil {
			t.Fatalf("read API key index column %d: %v", seqno, err)
		}
		if column != want {
			t.Fatalf("API key index column %d=%q, want %q", seqno, column, want)
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

func TestRunMigrationsNodesDeadColumnsPreservesServerMapCoordinates(t *testing.T) {
	// Given 存量库：nodes 仍带 sync_enabled/sync_scope 死列（触发
	// migrateNodesDeadColumns 整表重建），且节点已写入大屏坐标——
	// 重建 DDL 必须携 server_map_lat/lon 并保值。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE nodes ADD COLUMN sync_enabled BOOLEAN DEFAULT 1;
		ALTER TABLE nodes ADD COLUMN sync_scope TEXT DEFAULT 'all';
		INSERT INTO nodes (id,name,ip_address,port,status,sync_enabled,sync_scope,server_map_lat,server_map_lon)
		VALUES (7,'mapped-node','10.0.0.7',9000,'online',1,'all',31.2304,121.4737);`); err != nil {
		t.Fatalf("seed legacy schema with coordinates: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 死列已删、行存活、坐标保值。
	var columnCount int
	var lat, lon float64
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name IN ('sync_enabled','sync_scope')").Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != 0 {
		t.Fatalf("legacy columns=%d, want 0", columnCount)
	}
	if err := database.QueryRow("SELECT server_map_lat,server_map_lon FROM nodes WHERE id=7").Scan(&lat, &lon); err != nil {
		t.Fatalf("coordinates must survive rebuild: %v", err)
	}
	if lat != 31.2304 || lon != 121.4737 {
		t.Fatalf("rebuild lost coordinates: got (%v,%v), want (31.2304,121.4737)", lat, lon)
	}

	// And 幂等重跑不再触发重建，坐标不变。
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}
	if err := database.QueryRow("SELECT server_map_lat,server_map_lon FROM nodes WHERE id=7").Scan(&lat, &lon); err != nil {
		t.Fatal(err)
	}
	if lat != 31.2304 || lon != 121.4737 {
		t.Fatalf("idempotent rerun changed coordinates: got (%v,%v)", lat, lon)
	}
}

func TestRunMigrationsNodesDeadColumnsBackfillsCoordinatesOnPreCoordinateDB(t *testing.T) {
	// Given 回归形状：坐标功能前的老库——nodes 无 server_map_lat/lon 且带死列。
	// ensureNewColumns 先补列（默认 0），重建搬运后坐标为 0 而非列丢失。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE nodes ADD COLUMN sync_enabled BOOLEAN DEFAULT 1;
		ALTER TABLE nodes ADD COLUMN sync_scope TEXT DEFAULT 'all';
		INSERT INTO nodes (id,name,ip_address,port,status,sync_enabled,sync_scope)
		VALUES (8,'old-node','10.0.0.8',9000,'online',1,'all');`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	// 模拟坐标功能前时代：把两列去掉（通过重建出不带坐标的 nodes 表）。
	if _, err := database.Exec(`CREATE TABLE nodes_pre_coord (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(100) NOT NULL, mode VARCHAR(10) NOT NULL DEFAULT 'slave',
		ip_address VARCHAR(45) NOT NULL, port INTEGER DEFAULT 8000, protocol VARCHAR(10) DEFAULT 'http', access_url VARCHAR(255) DEFAULT '',
		is_approved BOOLEAN DEFAULT FALSE, sync_interval INTEGER DEFAULT 60, status VARCHAR(20) DEFAULT 'offline',
		cluster_token_hash VARCHAR(64), registration_secret VARCHAR(64), registration_secret_expires_at DATETIME,
		cluster_token_delivered BOOLEAN DEFAULT 0, reported_version INTEGER DEFAULT 0, health_json TEXT,
		last_sync_at DATETIME, last_sync_error TEXT, last_seen DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		sync_enabled BOOLEAN DEFAULT 1, sync_scope TEXT DEFAULT 'all',
		UNIQUE(ip_address, port));
		INSERT INTO nodes_pre_coord (id,name,mode,ip_address,port,protocol,is_approved,sync_interval,status,cluster_token_hash,registration_secret,registration_secret_expires_at,cluster_token_delivered,reported_version,health_json,last_sync_at,last_sync_error,last_seen,created_at,sync_enabled,sync_scope)
		SELECT id,name,mode,ip_address,port,protocol,is_approved,sync_interval,status,cluster_token_hash,registration_secret,registration_secret_expires_at,cluster_token_delivered,reported_version,health_json,last_sync_at,last_sync_error,last_seen,created_at,sync_enabled,sync_scope FROM nodes;
		DROP TABLE nodes;
		ALTER TABLE nodes_pre_coord RENAME TO nodes;`); err != nil {
		t.Fatalf("simulate pre-coordinate nodes table: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 坐标列存在、行存活、值为默认 0。
	var lat, lon float64
	if err := database.QueryRow("SELECT server_map_lat,server_map_lon FROM nodes WHERE id=8").Scan(&lat, &lon); err != nil {
		t.Fatalf("coordinate columns must exist after rebuild: %v", err)
	}
	if lat != 0 || lon != 0 {
		t.Fatalf("pre-coordinate DB coordinates=(%v,%v), want backfilled (0,0)", lat, lon)
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
	// 不制造 TLS 端口明文/幻影跳转的形态）
	var redirect int
	if err := database.QueryRow("SELECT protocol, enable_tls, tls_http_redirect FROM lb_rules WHERE caddy_id='lb_https_notls'").Scan(&protocol, &enableTLS, &redirect); err != nil {
		t.Fatalf("read migrated certless rule: %v", err)
	}
	if protocol != "http" || enableTLS != 0 || redirect != 0 {
		t.Fatalf("certless rule protocol=%q enable_tls=%d tls_http_redirect=%d, want http/0/0", protocol, enableTLS, redirect)
	}

	// And 受影响规则进入操作日志缓冲（待审计库就绪落库），重跑零命中。
	// https 迁移按批聚合为一行（含 caddy_id 清单）；第二个条目是新增的 TCP
	// 死字段清零聚合审计（本夹具的 tcp 行 compress_types 默认 'gzip' 命中死值
	// 谓词，首轮被归一）。
	entries := drainSystemAuditBuffer()
	if len(entries) != 2 {
		t.Fatalf("system audit entries=%d, want 2（1 条 https 聚合 + 1 条 TCP 死字段聚合；重跑幂等）", len(entries))
	}
	details := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.action != "启动迁移" {
			t.Fatalf("audit entry action=%q, want 启动迁移", entry.action)
		}
		details = append(details, entry.detail)
	}
	for _, want := range []string{"lb_https_tls", "lb_https_notls", "TCP 规则 HTTP 专属死字段已清零"} {
		found := false
		for _, detail := range details {
			if strings.Contains(detail, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺少审计条目 %q: %v", want, details)
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

// 存量 https 行的「有证」判定须覆盖 cert_jobs 承载的 ACME 证书——签发
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

	// And 完全无证行保持既有无证分支
	if err := database.QueryRow("SELECT protocol, enable_tls FROM lb_rules WHERE caddy_id='lb_https_certless'").Scan(&protocol, &enableTLS); err != nil {
		t.Fatalf("read migrated certless rule: %v", err)
	}
	if protocol != "http" || enableTLS != 0 {
		t.Fatalf("certless rule protocol=%q enable_tls=%d, want http/0", protocol, enableTLS)
	}

	// And 三条受影响规则聚合成一条迁移审计（重跑零命中）
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("system audit entries=%d, want 1（按批聚合，避免逐规则写满缓冲）: %+v", len(entries), entries)
	}
	if !strings.Contains(entries[0].detail, "3 条") || !strings.Contains(entries[0].detail, "lb_https_acme") {
		t.Fatalf("audit detail=%q, want 命中条数与 caddy_id 清单", entries[0].detail)
	}
}

func TestMigrateLegacyHTTPSProtocol_secondUpdateFailureRollsBackAndDefersAudit(t *testing.T) {
	// Given 一条有证与一条无证 legacy HTTPS 规则，并用真实 SQLite 触发器让第二条 UPDATE 失败。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules
		(name,protocol,domain,listen_port,enable_tls,tls_cert,tls_key,tls_http_redirect,caddy_id) VALUES
		('cert-bearing','https','cert.example.test',8443,0,'CERT','KEY',1,'lb_https_atomic_cert'),
		('certless','https','plain.example.test',8444,1,'','',1,'lb_https_atomic_plain');
		CREATE TRIGGER fail_second_legacy_https_update
		BEFORE UPDATE OF protocol,enable_tls ON lb_rules
		WHEN OLD.protocol='https' AND NEW.enable_tls=0
		BEGIN SELECT RAISE(ABORT, 'injected certless update failure'); END;`); err != nil {
		t.Fatalf("seed legacy HTTPS rows and failure trigger: %v", err)
	}
	drainSystemAuditBuffer()

	// When 第一条 UPDATE 成功、第二条失败。
	err := migrateLegacyHTTPSProtocol()

	// Then 两条规则与审计缓冲均保持迁移前状态，不得留下半迁移且无审计的有证行。
	if err == nil || !strings.Contains(err.Error(), "injected certless update failure") {
		t.Fatalf("migration error=%v, want injected second-update failure", err)
	}
	var migrated int
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN
		('lb_https_atomic_cert','lb_https_atomic_plain') AND protocol<>'https'`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != 0 {
		t.Fatalf("partially migrated rows=%d, want transactional rollback", migrated)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("audit entries=%d after rollback, want 0: %+v", len(entries), entries)
	}

	// And 故障解除后同一迁移可完整重试，两行迁移且各留一条审计。
	if _, err := database.Exec(`DROP TRIGGER fail_second_legacy_https_update`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if err := migrateLegacyHTTPSProtocol(); err != nil {
		t.Fatalf("retry migration after recovery: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN
		('lb_https_atomic_cert','lb_https_atomic_plain') AND protocol='http'`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated != 2 {
		t.Fatalf("migrated rows=%d after retry, want 2", migrated)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 1 {
		t.Fatalf("audit entries=%d after complete retry, want 1（整批聚合一行）: %+v", len(entries), entries)
	}
}

func drainSystemAuditBuffer() []systemAuditEntry {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	entries := systemAuditBuffer.entries
	systemAuditBuffer.entries = nil
	return entries
}

// 迁移缓冲的系统事件在审计库就绪后落 audit_log 表（UI 操作日志可见），
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

// flush 写失败时条目按原序留回缓冲等待下轮重试，不再先清缓冲导致
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

// 缓冲设上限，审计库长期不可用时丢弃最旧条目，内存不无界增长。
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
	// 生产迁移顺序是 newColumns 先补齐 mfa 列再执行本重建——种子
	// 表按同一形状建（重建白名单含 mfa 列，缺列即报错，这本身就是修复
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
		mfa_pending_fails INTEGER DEFAULT 0,
			login_failed_attempts INTEGER NOT NULL DEFAULT 0,
			login_locked_until TEXT,
			auth_provider TEXT NOT NULL DEFAULT 'local',
			oidc_subject TEXT DEFAULT '',
			oidc_issuer TEXT DEFAULT ''
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
	// 重建白名单含登录锁定列（newColumns 先补齐、重建保留，缺列即报错——
	// 与 mfa 列同为回归锚点），且 NOT NULL 约束在重建后保持。
	var loginColsNull int
	if err := database.QueryRow(`SELECT "notnull" FROM pragma_table_info('users') WHERE name='login_failed_attempts'`).Scan(&loginColsNull); err != nil {
		t.Fatalf("read users.login_failed_attempts schema: %v", err)
	}
	if loginColsNull != 1 {
		t.Fatalf("login_failed_attempts notnull=%d, want 1（重建须保留 NOT NULL）", loginColsNull)
	}
}

func TestMigrateLbRulesPrimaryKey_preserves_upstream_connection_settings(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	createLegacyLbRulesTables(t, database, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsLegacyOrigin})
	if _, err := database.Exec(`
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

func TestMigrateLbRulesPrimaryKey_auditsDiscardedOrphanUpstreams(t *testing.T) {
	// Given 旧 PK 表中一条正常 upstream 与一条无对应规则的孤儿 upstream。
	database := openMigrationTestDB(t)
	createLegacyLbRulesTables(t, database, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsLegacyOrigin})
	if _, err := database.Exec(`
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'tcp', 443, 'lb_orphan_audit');
		INSERT INTO upstreams (id, rule_id, host, port) VALUES
			(9, 7, '127.0.0.1', 8443),
			(10, 999, '192.0.2.10', 9000);
	`); err != nil {
		t.Fatalf("seed legacy upstreams: %v", err)
	}
	drainSystemAuditBuffer()

	// When
	if err := migrateLbRulesPrimaryKey(); err != nil {
		t.Fatalf("migrate load-balancer primary key: %v", err)
	}

	// Then 内连接丢弃孤儿行的既有数据语义不变，但必须留下可追溯审计。
	var validRows, orphanRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE id=9 AND rule_id='lb_orphan_audit'`).Scan(&validRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE id=10`).Scan(&orphanRows); err != nil {
		t.Fatal(err)
	}
	if validRows != 1 || orphanRows != 0 {
		t.Fatalf("migrated upstream rows valid=%d orphan=%d, want 1/0", validRows, orphanRows)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("system audit entries=%d, want one orphan-discard record: %+v", len(entries), entries)
	}
	wantDetail := "lb_rules 主键迁移丢弃 1 条孤儿 upstream 行（rule_id 无对应规则）"
	if entries[0].detail != wantDetail {
		t.Fatalf("orphan audit detail=%q, want %q", entries[0].detail, wantDetail)
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
	// 枚举外状态归一到终态 failed——'queued' 是活跃
	// 起始态会被签发队列立即拾取，等于升级时静默发起一次签发/部署尝试。
	if status != "failed" {
		t.Fatalf("migrated deprecated status=%q, want failed", status)
	}
	// 改写用户可见数据必须留痕（系统审计聚合一行）。
	audited := false
	for _, entry := range drainSystemAuditBuffer() {
		if strings.Contains(entry.detail, "枚举外或 NULL 状态归一到 failed") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("枚举外状态改写缺少系统审计记录")
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
	if notNull != 1 || status != "failed" {
		t.Fatalf("cert_jobs.status notnull=%d value=%q, want 1/failed（NULL 与枚举外同保守度）", notNull, status)
	}
	if _, err := database.Exec("UPDATE cert_jobs SET status=NULL WHERE rule_id='lb_null'"); err == nil {
		t.Fatal("cert_jobs.status accepted NULL after migration")
	}
	// NULL 改写同样必须留痕（与枚举外值同一条系统审计）。
	audited := false
	for _, entry := range drainSystemAuditBuffer() {
		if strings.Contains(entry.detail, "枚举外或 NULL 状态归一到 failed") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("NULL 状态改写缺少系统审计记录")
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
	preserveDatabaseHandles(t)

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
	createLegacyLbRulesTables(t, legacy, legacyLbRulesSchema{})
	if _, err := legacy.Exec(`
		INSERT INTO lb_rules (id, name, protocol, listen_port, domain) VALUES (7, 'legacy', 'http', 80, 'Example.COM.');`); err != nil {
		t.Fatalf("seed legacy lb_rules: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	preserveDatabaseHandles(t)

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
	preserveDatabaseHandles(t)
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
	preserveDatabaseHandles(t)

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
	oldCurrent := GetDB()
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
		SetDB(oldCurrent)
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
	preserveDatabaseHandles(t)

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
	preserveDatabaseHandles(t)

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
	preserveDatabaseHandles(t)
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

// 回归：ca_available_after 规范化必须是一次性回填——WHERE 排除已
// 规范化的行（值未变不重写），否则每次启动全量重写匹配行（页脏 + WAL
// 增长）。不可解析值仍由 datetime(...) IS NOT NULL 守卫保留。
func TestInitialize_certJobCAAvailableAfterNormalizationRewritesOnlyStaleRows(t *testing.T) {
	// Given
	dir := t.TempDir()
	preserveDatabaseHandles(t)
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
	// 探测门：第二遍零命中时连写语句都不执行（返回 nil Result 即 0 行改写）。
	var again int64
	if resAgain != nil {
		var err error
		again, err = resAgain.RowsAffected()
		if err != nil {
			t.Fatalf("rows affected again: %v", err)
		}
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

// 历史 NOT-NULL 窗口期建库的 security_policies 四列停留 NOT NULL，
// fresh CREATE 与 newColumns 迁移对「列已存在」的库均不生效；启动迁移必须
// 收敛为可空并保数据。
func TestInitialize_convergesWindowEraSecurityPoliciesNotNullColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
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
	// 窗口期收敛不得丢失 refs 两列——rebuild 曾以陈旧 DDL 重建，
	// 把同一 runMigrations 早前 newColumns 刚加的列丢掉，安全策略子系统当次
	// 启动整体 500（no such column）、启动配置不应用、集群快照停摆。
	for _, name := range []string{"ip_acl_list_refs", "ip_whitelist_refs"} {
		var cnt int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_policies') WHERE name=?`, name).Scan(&cnt); err != nil {
			t.Fatalf("read security_policies.%s schema: %v", name, err)
		}
		if cnt != 1 {
			t.Fatalf("security_policies.%s missing after window-era convergence", name)
		}
	}
	var aclRefs string
	if err := DB.QueryRow(`SELECT COALESCE(ip_acl_list_refs,'') FROM security_policies WHERE id=1`).Scan(&aclRefs); err != nil {
		t.Fatalf("read migrated policy refs: %v", err)
	}
	if aclRefs != "[]" {
		t.Fatalf("ip_acl_list_refs=%q, want []", aclRefs)
	}
}

// users.is_enabled 重建迁移的 DDL 停留在 OIDC 集成之前——
// runMigrations 早前 newColumns 循环补的 auth_provider/oidc_subject/oidc_issuer
// 三列随 DROP TABLE 一并丢失；存量 OIDC 用户升级重启后无法再按
// (issuer,subject) 命中，下次登录退化为重复建行。重建必须携带三列并保数据。
func TestMigrateUsersRebuildPreservesOIDCColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	// 构造窗口期形态：is_enabled 可空（触发重建）+ 已携带 OIDC 三列与存量 OIDC 用户
	if _, err := DB.Exec(`DROP TABLE users;
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'user',
			display_name VARCHAR(100),
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
			mfa_pending_fails INTEGER DEFAULT 0,
			login_failed_attempts INTEGER NOT NULL DEFAULT 0,
			login_locked_until TEXT,
			auth_provider TEXT NOT NULL DEFAULT 'local',
			oidc_subject TEXT DEFAULT '',
			oidc_issuer TEXT DEFAULT ''
		);
		INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES (42,'oidc-user','x','user',1,'oidc','sub-123','https://issuer.example.com');`); err != nil {
		t.Fatalf("seed window-era users: %v", err)
	}

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}

	// Then: 三列保留，OIDC 身份数据不丢
	for _, name := range []string{"auth_provider", "oidc_subject", "oidc_issuer"} {
		var cnt int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name=?`, name).Scan(&cnt); err != nil {
			t.Fatalf("read users.%s schema: %v", name, err)
		}
		if cnt != 1 {
			t.Fatalf("users.%s missing after is_enabled rebuild", name)
		}
	}
	var provider, subject, issuer string
	if err := DB.QueryRow(`SELECT auth_provider, oidc_subject, oidc_issuer FROM users WHERE id=42`).Scan(&provider, &subject, &issuer); err != nil {
		t.Fatalf("read migrated oidc user: %v", err)
	}
	if provider != "oidc" || subject != "sub-123" || issuer != "https://issuer.example.com" {
		t.Fatalf("oidc identity=(%q,%q,%q), want (oidc,sub-123,https://issuer.example.com)", provider, subject, issuer)
	}
}

// PK 重建迁移的 upstreams_new.enabled 此前为可空（与 fresh CREATE 的
// NOT NULL DEFAULT 1 漂移）；对齐后重建结果必须 notnull=1，且遗留 NULL 行
// 经 COALESCE 拷贝归一为 0。
// FK OFF 时代积累的 path_rules 孤儿（rule_id 不在 lb_rules）在
// 启动迁移中被一次性清理；DeleteRule/removeCreatedRule 已补显式删除断新增。
func TestInitialize_cleansOrphanedPathRules(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_alive','r','http','a.test',8081,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_alive',1,'prefix','/api'), ('lb_ghost',1,'prefix','/x')`); err != nil {
		t.Fatal(err)
	}
	drainSystemAuditBuffer()
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}
	// 删除用户数据（孤儿 path_rules）必须留痕。完整 Initialize 会把
	// 迁移期缓冲 flush 进审计库，故在 AuditDB 断言而非内存缓冲。
	var audited int
	if err := AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='启动迁移' AND detail LIKE '%孤儿 path_rules%'`).Scan(&audited); err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if audited != 1 {
		t.Fatalf("孤儿 path_rules 清理审计记录=%d, want 1", audited)
	}
	var orphan, alive int
	_ = DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_ghost'`).Scan(&orphan)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_alive'`).Scan(&alive)
	if orphan != 0 {
		t.Fatalf("orphan path_rules not cleaned: %d", orphan)
	}
	if alive != 1 {
		t.Fatalf("live path_rules must survive cleanup: %d", alive)
	}
}

func TestMigrateLbRulesPrimaryKey_rebuildsUpstreamEnabledNotNull(t *testing.T) {
	database := openMigrationTestDB(t)
	createLegacyLbRulesTables(t, database, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsMinimal})
	if _, err := database.Exec(`
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

// 版本表 consecutive_failures 与 global_config.is_master 的
// 遗留 NULL 由启动迁移一次性回填（0/0/1），消灭读侧 COALESCE 语义分裂。
func TestInitialize_backfillsNullConsecutiveFailuresAndIsMaster(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
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

func TestMigrateLegacyDNSCredentials_migratesAndDropsRetiredColumns(t *testing.T) {
	// Given：待迁移凭据、已有新格式凭据（回归）与空旧凭据（边界）。
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE certificate_configs (
		id INTEGER PRIMARY KEY, dns_id TEXT, dns_key TEXT, dns_credentials TEXT
	);
	INSERT INTO certificate_configs VALUES
		(1, 'id-1', 'key-1', NULL),
		(2, 'stale-id', 'stale-key', '{"app_id":"keep","app_token":"keep-token"}'),
		(3, '', '', NULL);`); err != nil {
		t.Fatalf("seed legacy certificate configs: %v", err)
	}

	// When
	if err := migrateLegacyDNSCredentials(); err != nil {
		t.Fatalf("migrate legacy credentials: %v", err)
	}

	// Then：值迁入新 JSON 列后，两个明文凭据退役列必须消失。
	var retiredColumns int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('certificate_configs') WHERE name IN ('dns_id','dns_key')`).Scan(&retiredColumns); err != nil {
		t.Fatal(err)
	}
	if retiredColumns != 0 {
		t.Errorf("retired DNS credential columns=%d, want 0", retiredColumns)
	}
	var migratedText, existingText string
	if err := database.QueryRow(`SELECT dns_credentials FROM certificate_configs WHERE id=1`).Scan(&migratedText); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT dns_credentials FROM certificate_configs WHERE id=2`).Scan(&existingText); err != nil {
		t.Fatal(err)
	}
	var migrated map[string]string
	if err := json.Unmarshal([]byte(migratedText), &migrated); err != nil {
		t.Fatalf("decode migrated credentials %q: %v", migratedText, err)
	}
	if migrated["app_id"] != "id-1" || migrated["app_token"] != "key-1" {
		t.Errorf("migrated credentials=%v, want id-1/key-1", migrated)
	}
	if existingText != `{"app_id":"keep","app_token":"keep-token"}` {
		t.Errorf("existing credentials=%q, want preserved", existingText)
	}
	var emptyCredentials sql.NullString
	if err := database.QueryRow(`SELECT dns_credentials FROM certificate_configs WHERE id=3`).Scan(&emptyCredentials); err != nil {
		t.Fatal(err)
	}
	if emptyCredentials.Valid {
		t.Errorf("empty legacy credentials=%q, want NULL unchanged", emptyCredentials.String)
	}
	// 幂等：列已退役后重跑不影响新格式数据。
	if err := migrateLegacyDNSCredentials(); err != nil {
		t.Fatalf("repeat migration: %v", err)
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

func TestEnsureNewColumns_rejectsMalformedKey(t *testing.T) {
	// Given：登记 key 非 "table.column" 形态时须启动期响亮
	// 失败——此前静默跳过（continue），笔误列静默不补、运行时才以 no such column 暴露。
	openMigrationTestDB(t)

	// When
	err := ensureNewColumns(map[string]string{"lb_rules.no.dot": "TEXT"}, nil)

	// Then
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("err=%v, want malformed-key error（畸形登记键必须响亮失败）", err)
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
	drainSystemAuditBuffer()
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

	// And：改写用户规则留痕（独立 2 条 + 内嵌 1 条 = 聚合审计一行）。
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || entries[0].action != "启动迁移" || !strings.Contains(entries[0].detail, "已禁用 3 条") {
		t.Fatalf("自定义规则清洗审计=%+v, want 一行「已禁用 3 条」", entries)
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

func TestInitialize_backfillsLegacyTimeoutColumnsAndNormalizesZeroOnRestart(t *testing.T) {
	// 库值唯一真相（批 1+2，2026-10-14 用户裁定）改判：http_read/write/idle_timeout
	// 为类型①值型列（0 无效）——旧 「显式 0 跨重启保留」语义随渲染层
	// 「0=省略」形态一并废除：新增列一次性回填照旧（60/60/120），此后每启动
	// 幂等回填把 0/NULL 行归默认（带外直写/旧备份恢复的脏行在下次启动收敛）。
	// upstream_keepalive_timeout 保持类型②省略型（0=继承 Caddy/Go Transport
	// 默认 2 分钟，三次用户反馈）——显式 0 跨重启原样保留，任何迁移不改写。
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
	preserveDatabaseHandles(t)
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
	//（keepalive 默认 0——60s 空闲关闭会中断 SSE/WebSocket 上游长连接，
	// 0 继承 Caddy/Go Transport 默认 2 分钟）
	if r, w, i, k := readTimeouts(); r != 60 || w != 60 || i != 120 || k != 0 {
		t.Fatalf("backfilled timeouts=(%d,%d,%d,%d), want (60,60,120,0)", r, w, i, k)
	}

	// And when a band-out write leaves 0 (= 旧省略语义残留/旧备份恢复形态) and the service restarts
	if _, err := DB.Exec(`UPDATE global_config SET http_read_timeout=0, http_write_timeout=0, http_idle_timeout=0, upstream_keepalive_timeout=0 WHERE id=1`); err != nil {
		t.Fatalf("set zero timeouts: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close database before restart: %v", err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("reinitialize database: %v", err)
	}

	// Then the value-typed columns are normalized back to governed defaults on
	// restart, while the omission-typed keepalive zero survives unchanged
	if r, w, i, k := readTimeouts(); r != 60 || w != 60 || i != 120 || k != 0 {
		t.Fatalf("post-restart timeouts=(%d,%d,%d,%d), want (60,60,120,0)（类型①回填+类型②0 保留）", r, w, i, k)
	}
}

func TestMigrateCanonicalDomains_skipsIndexRebuildWhenNothingToDo(t *testing.T) {
	// 无事可做时迁移不得白跑 DROP/CREATE 唯一索引（每次启动一次立即
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
	drainSystemAuditBuffer()
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
	// 域名归一改写用户数据 → 聚合审计一行。
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || !strings.Contains(entries[0].detail, "域名归一为规范形") {
		t.Fatalf("域名归一审计=%+v, want 一行归一记录", entries)
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
	drainSystemAuditBuffer()
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
	// 删除重复证书任务行（用户数据）→ 聚合审计一行。
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || !strings.Contains(entries[0].detail, "重复行已去重") {
		t.Fatalf("cert_jobs 去重审计=%+v, want 一行去重记录", entries)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cert_jobs_rule_domain_unique'").Scan(&count); err != nil {
		t.Fatalf("query index: %v", err)
	}
	if count != 1 {
		t.Fatalf("index count=%d, want rebuilt when dedup ran", count)
	}
}

// cert_jobs (rule_id,domain) 去重判据单源=certJobsDedupeSQL 常量：
// 保留「有证书材料优先，同列 id 大者」（与原逐行相关子查询判据逐行等价）。
// 实现必须单趟窗口函数——旧相关子查询每行对全表做一次匹配子扫（O(n²)），
// EXPLAIN QUERY PLAN 不得再出现 CORRELATED 子查询。
func TestMigrateCanonicalDomains_dedupeKeepsCertMaterialRowInSinglePass(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 三组：①晚行有证书材料、早行无 → 保留晚行；②均无材料 → 保留 id 大者；
	// ③单行组不动。
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem) VALUES
		('lb_d','a.example.com','failed','',''),
		('lb_d','a.example.com','issued','PEM','KEY'),
		('lb_d','b.example.com','failed','',''),
		('lb_d','b.example.com','failed','',''),
		('lb_d','c.example.com','issued','PEM','KEY')`); err != nil {
		t.Fatalf("seed duplicate groups: %v", err)
	}

	if err := migrateCanonicalDomains(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var pem string
	if err := database.QueryRow(`SELECT cert_pem FROM cert_jobs WHERE domain='a.example.com'`).Scan(&pem); err != nil {
		t.Fatalf("group a survivor: %v", err)
	}
	if pem != "PEM" {
		t.Fatalf("group a survivor cert_pem=%q, want PEM（有证书材料行优先存活）", pem)
	}
	var survivingID int
	if err := database.QueryRow(`SELECT id FROM cert_jobs WHERE domain='b.example.com'`).Scan(&survivingID); err != nil {
		t.Fatalf("group b survivor: %v", err)
	}
	var bIDs []int
	idRows, err := database.Query(`SELECT id FROM cert_jobs WHERE domain='b.example.com'`)
	if err != nil {
		t.Fatal(err)
	}
	for idRows.Next() {
		var id int
		if err := idRows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		bIDs = append(bIDs, id)
	}
	idRows.Close()
	if len(bIDs) != 1 {
		t.Fatalf("group b rows=%v, want 单行存活", bIDs)
	}
	if survivingID != 4 {
		t.Fatalf("group b survivor id=%d, want 4（均无证书材料时 id 大者存活）", survivingID)
	}
	var singles int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE domain='c.example.com'`).Scan(&singles); err != nil {
		t.Fatal(err)
	}
	if singles != 1 {
		t.Fatalf("group c rows=%d, want 1（单行组不动）", singles)
	}

	// 计划钉：单趟窗口函数，无逐行相关子查询。
	planRows, err := database.Query("EXPLAIN QUERY PLAN " + certJobsDedupeSQL)
	if err != nil {
		t.Fatalf("explain dedupe sql: %v", err)
	}
	var plan strings.Builder
	for planRows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := planRows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			planRows.Close()
			t.Fatalf("scan plan: %v", err)
		}
		plan.WriteString(detail)
		plan.WriteString("\n")
	}
	planRows.Close()
	if strings.Contains(strings.ToUpper(plan.String()), "CORRELATED") {
		t.Fatalf("去重计划仍含逐行相关子查询（O(n²)）：\n%s", plan.String())
	}
}

// migrateLbRulesPrimaryKey 重建 lb_rules/upstreams 时，随表
// DROP 级联删除既有索引——三张高频索引若只在重建前创建，则整个启动周期内缺失，
// 要到下次启动才被 IF NOT EXISTS 自愈。同一启动内必须补齐。
func TestInitialize_recreatesIndexesDroppedByPkRebuildInSameBoot(t *testing.T) {
	// Given：lb_rules 仍以 id 为主键的遗留库（触发 PK 重建）
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	createLegacyLbRulesTables(t, legacy, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, upstreams: legacyUpstreamsLegacy})
	if _, err := legacy.Exec(`
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'http', 8080, 'lb_rebuild');
		INSERT INTO upstreams (id, rule_id, host, port) VALUES (9, 7, '127.0.0.1', 9000);
	`); err != nil {
		t.Fatalf("seed legacy load-balancer schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	preserveDatabaseHandles(t)

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

// 备份恢复通道的 epoch 归一（backupTableNullDefaults）只守住
// 「新恢复」的行——修复前已恢复的存量 NULL 时间戳持续毒化集群 dump（裸扫
// time.Time 对 NULL 失败）。启动幂等回填 epoch，真实时间戳的对照行不得被改写。
// 同一恢复通道还归一 users/api_keys/path_rules/cert_jobs 的
// created_at（裸 time.Time 消费端：登录/用户列表/密钥列表/证书任务/集群快照），
// 回填范围随之补齐这四列。
func TestInitialize_backfillsLegacyNullTimestampColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
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

func TestNormalizeRuleTimestampsMigration_preservesMalformedAndCanonicalizesValidValues(t *testing.T) {
	// Given：可解析 RFC3339、不可解析但带 T 的垃圾值、平面格式与 NULL 四种形态。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	const malformed = "2026-13-45T99:99:99Z"
	// 分钟精度与 9 位小数秒是导入校验明确接受的两种布局（backupTimeFormats），
	// 既无 T 也无 +：LIKE '%T%' OR '%+%' 启发式会把它们判成「已规范」而跳过。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,created_at,updated_at) VALUES
		('lb_ts_valid','valid','http',8080,'2026-01-02T03:04:05Z','2026-01-02 03:04:05'),
		('lb_ts_bad','bad','http',8081,'2026-13-45T99:99:99Z','2026-02-03T04:05:06Z'),
		('lb_ts_minute','minute','http',8082,'2026-01-02 03:04','2026-01-02 03:04'),
		('lb_ts_frac','frac','http',8083,'2026-01-02 03:04:05.123456789','2026-01-02 03:04:05.000000001');
		INSERT INTO path_rules (rule_id,sort_order,match_type,path,created_at,updated_at)
		VALUES ('lb_ts_valid',0,'prefix','/','2026-13-45T99:99:99Z',NULL),
		('lb_ts_minute',0,'prefix','/m','2026-01-02 03:04','2026-01-02 03:04')`); err != nil {
		t.Fatalf("seed timestamp shapes: %v", err)
	}

	// When：真实迁移执行两次，验证幂等。
	for round := range 2 {
		if err := normalizeRuleTimestampsMigration(); err != nil {
			t.Fatalf("normalize round %d: %v", round, err)
		}
	}

	// Then：有效值归一，平面值不变，垃圾值保留异常信号而非写成 NULL。
	assertText := func(query, want string) {
		t.Helper()
		var got sql.NullString
		if err := database.QueryRow(query).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", query, err)
		}
		if !got.Valid || got.String != want {
			t.Errorf("query %s = %+v, want %q", query, got, want)
		}
	}
	assertText(`SELECT CAST(created_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_valid'`, "2026-01-02 03:04:05")
	assertText(`SELECT CAST(updated_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_valid'`, "2026-01-02 03:04:05")
	assertText(`SELECT CAST(created_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_bad'`, malformed)
	assertText(`SELECT CAST(updated_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_bad'`, "2026-02-03 04:05:06")
	assertText(`SELECT CAST(created_at AS TEXT) FROM path_rules WHERE rule_id='lb_ts_valid'`, malformed)
	// 分钟精度与小数秒必须归一到平面格式（否则未来严格 Parse 消费点复现
	// 证书域 +00:00 同型事故）。
	assertText(`SELECT CAST(created_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_minute'`, "2026-01-02 03:04:00")
	assertText(`SELECT CAST(updated_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_minute'`, "2026-01-02 03:04:00")
	assertText(`SELECT CAST(created_at AS TEXT) FROM path_rules WHERE rule_id='lb_ts_minute'`, "2026-01-02 03:04:00")
	assertText(`SELECT CAST(updated_at AS TEXT) FROM path_rules WHERE rule_id='lb_ts_minute'`, "2026-01-02 03:04:00")
	assertText(`SELECT CAST(created_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_frac'`, "2026-01-02 03:04:05")
	assertText(`SELECT CAST(updated_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_ts_frac'`, "2026-01-02 03:04:05")
	var nullCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_ts_valid' AND updated_at IS NULL`).Scan(&nullCount); err != nil {
		t.Fatal(err)
	}
	if nullCount != 1 {
		t.Errorf("pre-existing NULL updated_at count=%d, want preserved 1", nullCount)
	}
}

func TestRunMigrations_removesLegacyTCPRulePolicyBindings(t *testing.T) {
	// Given 真实旧库数据形态：HTTP 绑定、TCP 惰性绑定、无对应规则的历史绑定。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,cluster_version) VALUES (1,'{}',0);
		INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES
		('lb_bind_http','http-rule','http',8080);
		INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,compress_types) VALUES
		('lb_bind_tcp','tcp-rule','tcp',9000,'');
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_bind_http',7),
		('lb_bind_tcp',7),
		('lb_bind_missing',7)`); err != nil {
		t.Fatalf("seed legacy rules and policy bindings: %v", err)
	}

	// When 启动迁移执行。
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 仅 TCP 规则绑定被清理；HTTP 与无规则绑定原样保留。
	assertBindingRows := func() (httpRows, tcpRows, missingRows int) {
		t.Helper()
		if err := database.QueryRow(`SELECT
			SUM(CASE WHEN rule_caddy_id='lb_bind_http' THEN 1 ELSE 0 END),
			SUM(CASE WHEN rule_caddy_id='lb_bind_tcp' THEN 1 ELSE 0 END),
			SUM(CASE WHEN rule_caddy_id='lb_bind_missing' THEN 1 ELSE 0 END)
			FROM security_policy_bindings`).Scan(&httpRows, &tcpRows, &missingRows); err != nil {
			t.Fatalf("count policy bindings: %v", err)
		}
		return httpRows, tcpRows, missingRows
	}
	httpRows, tcpRows, missingRows := assertBindingRows()
	if httpRows != 1 || tcpRows != 0 || missingRows != 1 {
		t.Fatalf("bindings after migration http/tcp/missing=%d/%d/%d, want 1/0/1", httpRows, tcpRows, missingRows)
	}
	var clusterVersion int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&clusterVersion); err != nil {
		t.Fatalf("read cluster_version: %v", err)
	}
	if clusterVersion != 1 {
		t.Fatalf("cluster_version=%d after TCP binding cleanup, want 1 (same bump path as synced-table migrations)", clusterVersion)
	}

	// And 幂等：重复启动零额外写、不再 bump 版本。
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}
	httpRows, tcpRows, missingRows = assertBindingRows()
	if httpRows != 1 || tcpRows != 0 || missingRows != 1 {
		t.Fatalf("bindings after repeated migration http/tcp/missing=%d/%d/%d, want 1/0/1", httpRows, tcpRows, missingRows)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&clusterVersion); err != nil {
		t.Fatalf("read cluster_version after repeat: %v", err)
	}
	if clusterVersion != 1 {
		t.Fatalf("cluster_version after idempotent rerun=%d, want unchanged 1", clusterVersion)
	}
}

func TestMigrateTCPRuleSecurityPolicyBindings_clusterBumpFailureRollsBack(t *testing.T) {
	// Given 存在待清理 TCP 绑定，且真实 SQLite 触发器阻断 cluster_version bump。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,cluster_version) VALUES (1,'{}',0);
		INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,compress_types) VALUES
		('lb_bind_atomic_http','http-rule','http',8080,'gzip'),
		('lb_bind_atomic_tcp','tcp-rule','tcp',9000,'');
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_bind_atomic_http',7),('lb_bind_atomic_tcp',7);
		CREATE TRIGGER fail_tcp_binding_version_bump
		BEFORE UPDATE OF cluster_version ON global_config
		BEGIN SELECT RAISE(ABORT, 'injected cluster version failure'); END;`); err != nil {
		t.Fatalf("seed bindings and bump failure trigger: %v", err)
	}
	drainSystemAuditBuffer()

	// When
	err := migrateTCPRuleSecurityPolicyBindings()

	// Then 删除与 bump 同事务：bump 失败时 TCP 绑定也必须保留，避免表已改而版本未推进。
	if err == nil || !strings.Contains(err.Error(), "injected cluster version failure") {
		t.Fatalf("migration error=%v, want injected cluster_version failure", err)
	}
	var tcpBindings, httpBindings, version int
	if err := database.QueryRow(`SELECT
		SUM(CASE WHEN rule_caddy_id='lb_bind_atomic_tcp' THEN 1 ELSE 0 END),
		SUM(CASE WHEN rule_caddy_id='lb_bind_atomic_http' THEN 1 ELSE 0 END)
		FROM security_policy_bindings`).Scan(&tcpBindings, &httpBindings); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if tcpBindings != 1 || httpBindings != 1 || version != 0 {
		t.Fatalf("after bump failure tcp/http/version=%d/%d/%d, want 1/1/0", tcpBindings, httpBindings, version)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("回滚后不得留下「已审计但绑定未删」的假留痕: %+v", entries)
	}

	// And 故障解除后重试成功，版本恰好推进一次。
	if _, err := database.Exec(`DROP TRIGGER fail_tcp_binding_version_bump`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if err := migrateTCPRuleSecurityPolicyBindings(); err != nil {
		t.Fatalf("retry binding cleanup: %v", err)
	}
	if err := database.QueryRow(`SELECT
		SUM(CASE WHEN rule_caddy_id='lb_bind_atomic_tcp' THEN 1 ELSE 0 END),
		SUM(CASE WHEN rule_caddy_id='lb_bind_atomic_http' THEN 1 ELSE 0 END)
		FROM security_policy_bindings`).Scan(&tcpBindings, &httpBindings); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if tcpBindings != 0 || httpBindings != 1 || version != 1 {
		t.Fatalf("after retry tcp/http/version=%d/%d/%d, want 0/1/1", tcpBindings, httpBindings, version)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || !strings.Contains(entries[0].detail, "安全策略绑定") {
		t.Fatalf("重试成功应恰留一条聚合审计: %+v", entries)
	}
}

func TestMigrateTCPRuleDeadFields_bumpsNullClusterVersion(t *testing.T) {
	// Given：带外/旧备份形态 cluster_version=NULL，以及一条确需清理的 TCP 行。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,cluster_version) VALUES (1,'{}',NULL);
		INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enable_tls) VALUES ('lb_tcp_null_version','tcp','tcp',9443,1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls) VALUES ('lb_http_null_version','http','http','http.example.test',8443,1)`); err != nil {
		t.Fatalf("seed null version and rules: %v", err)
	}

	// When
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：NULL 必须按 0 参与递增，TCP 清理生效且 HTTP 回归行不受影响。
	var version sql.NullInt64
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !version.Valid || version.Int64 != 1 {
		t.Fatalf("cluster_version=%+v, want 1", version)
	}
	var tcpTLS, httpTLS int
	if err := database.QueryRow(`SELECT enable_tls FROM lb_rules WHERE caddy_id='lb_tcp_null_version'`).Scan(&tcpTLS); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT enable_tls FROM lb_rules WHERE caddy_id='lb_http_null_version'`).Scan(&httpTLS); err != nil {
		t.Fatal(err)
	}
	if tcpTLS != 0 || httpTLS != 1 {
		t.Fatalf("TLS after migration tcp=%d http=%d, want 0/1", tcpTLS, httpTLS)
	}
	// 幂等重跑没有脏行，不再 bump。
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version.Int64 != 1 {
		t.Fatalf("cluster_version after no-op=%d, want unchanged 1", version.Int64)
	}
}

func TestMigrateLegacyAuditLogs_copiesVerifiesAndDropsLegacyTable(t *testing.T) {
	// Given 真实主库/audit 库与两条含 NULL 的历史审计行。
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	if _, err := AuditDB.Exec(`DELETE FROM audit_log`); err != nil {
		t.Fatalf("clear destination audit log: %v", err)
	}
	const legacyAuditDDL = `CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`
	if _, err := DB.Exec(legacyAuditDDL + `;
		INSERT INTO audit_log (id,username,action,resource,detail,ip_address,created_at) VALUES
		(101,NULL,'登录','认证',NULL,'','2026-01-01 00:00:00'),
		(102,'admin','更新','系统配置','legacy detail','127.0.0.1','2026-01-02 00:00:00')`); err != nil {
		t.Fatalf("seed legacy audit rows: %v", err)
	}

	// When
	if err := migrateLegacyAuditLogs(DB, filepath.Join(dir, AuditDBFilename)); err != nil {
		t.Fatalf("migrate legacy audit logs: %v", err)
	}

	// Then 逐列复制成功后主库旧表删除；重复调用按无旧表 no-op。
	var legacyTables, copied int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'`).Scan(&legacyTables); err != nil {
		t.Fatal(err)
	}
	if err := AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE id IN (101,102)`).Scan(&copied); err != nil {
		t.Fatal(err)
	}
	if legacyTables != 0 || copied != 2 {
		t.Fatalf("legacyTables=%d copied=%d, want 0/2", legacyTables, copied)
	}
	var username, detail string
	if err := AuditDB.QueryRow(`SELECT COALESCE(username,'<null>'),COALESCE(detail,'<null>') FROM audit_log WHERE id=101`).Scan(&username, &detail); err != nil {
		t.Fatal(err)
	}
	if username != "<null>" || detail != "<null>" {
		t.Fatalf("NULL fields changed during migration: username=%q detail=%q", username, detail)
	}
	if err := migrateLegacyAuditLogs(DB, filepath.Join(dir, AuditDBFilename)); err != nil {
		t.Fatalf("repeat migration without legacy table: %v", err)
	}

	// And 同 id 不同内容的冲突不得 DROP 源表或覆盖目标行。
	if _, err := DB.Exec(legacyAuditDDL + `;
		INSERT INTO audit_log (id,username,action,resource,detail,ip_address,created_at)
		VALUES (101,'attacker','篡改','冲突','different','','2020-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed conflicting legacy row: %v", err)
	}
	// 冲突改为跳过+保留源表（服务可用优先，冲突留痕见
	// TestMigrateLegacyAuditLogs_conflictKeepsSourceTableAndSkips）——不得
	// DROP 源表或覆盖目标行，也不得硬失败阻断启动。
	if err := migrateLegacyAuditLogs(DB, filepath.Join(dir, AuditDBFilename)); err != nil {
		t.Fatalf("conflict must skip without failing startup: %v", err)
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'`).Scan(&legacyTables); err != nil {
		t.Fatal(err)
	}
	if legacyTables != 1 {
		t.Fatal("legacy audit table dropped after verification conflict")
	}
	var originalAction string
	if err := AuditDB.QueryRow(`SELECT action FROM audit_log WHERE id=101`).Scan(&originalAction); err != nil {
		t.Fatal(err)
	}
	if originalAction != "登录" {
		t.Fatalf("destination conflict row overwritten: action=%q", originalAction)
	}
}

func TestMigrateSyncSwitches_forcesUsersEvenWhenMarkerDone(t *testing.T) {
	// Given 存量 global_config 有 sync_users=0，尚无一次性 marker 列。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`ALTER TABLE global_config ADD COLUMN sync_users BOOLEAN DEFAULT 1;
		INSERT INTO global_config (id,caddy_config,sync_users) VALUES (1,'{}',0)`); err != nil {
		t.Fatalf("seed legacy sync switches: %v", err)
	}

	// When/Then 首轮补 marker 并强制 sync_users=1。
	if err := migrateSyncSwitches(); err != nil {
		t.Fatalf("first sync switch migration: %v", err)
	}
	var syncUsers, marker int
	if err := database.QueryRow(`SELECT sync_users,sync_switches_migrated FROM global_config WHERE id=1`).Scan(&syncUsers, &marker); err != nil {
		t.Fatal(err)
	}
	if syncUsers != 1 || marker != 1 {
		t.Fatalf("first migration sync_users=%d marker=%d, want 1/1", syncUsers, marker)
	}

	// And 带外再次写 0 时，即使 marker=1 也必须再次收敛。
	if _, err := database.Exec(`UPDATE global_config SET sync_users=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSyncSwitches(); err != nil {
		t.Fatalf("second sync switch migration: %v", err)
	}
	if err := database.QueryRow(`SELECT sync_users,sync_switches_migrated FROM global_config WHERE id=1`).Scan(&syncUsers, &marker); err != nil {
		t.Fatal(err)
	}
	if syncUsers != 1 || marker != 1 {
		t.Fatalf("marker-done migration sync_users=%d marker=%d, want 1/1", syncUsers, marker)
	}
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

// legacyLbRulesSchema 描述「PK 重建前」的 lb_rules/upstreams 形态变体
// 此前 6 处测试各自复制同一份 DDL，漂移风险与维护成本
// 双高。每个变体逐列对应原有 DDL（含可选列与 upstreams 两侧历史死列），
// 迁移前置断言所依赖的差异（有无 caddy_id/阶段页列/新健康列、upstreams 死列
// 或 origin_domain）由调用方显式声明。
type legacyLbRulesSchema struct {
	withCaddyID       bool
	withStagePages    bool
	withNewHealthCols bool
	upstreams         string
}

const (
	legacyUpstreamsNone         = ""
	legacyUpstreamsMinimal      = "minimal"       // 仅 origin_domain（无历史死列）
	legacyUpstreamsLegacy       = "legacy"        // 历史死列，无 origin_domain
	legacyUpstreamsLegacyOrigin = "legacy_origin" // 历史死列 + origin_domain
)

// createLegacyLbRulesTables 建出指定变体的旧 schema（lb_rules 以 id 为 PK）。
func createLegacyLbRulesTables(t *testing.T, database *sql.DB, variant legacyLbRulesSchema) {
	t.Helper()
	var schema strings.Builder
	schema.WriteString(`CREATE TABLE lb_rules (
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
		updated_at DATETIME, updated_by INTEGER`)
	if variant.withCaddyID {
		schema.WriteString(`, caddy_id TEXT`)
	}
	if variant.withStagePages {
		schema.WriteString(`,
		block_page_stage1_id INTEGER NOT NULL DEFAULT 0,
		block_page_stage1_status INTEGER NOT NULL DEFAULT 0,
		block_page_stage3_id INTEGER NOT NULL DEFAULT 0,
		block_page_stage3_status INTEGER NOT NULL DEFAULT 0`)
	}
	if variant.withNewHealthCols {
		schema.WriteString(`,
		-- 真实启动序：ensureNewColumns 先于 PK 重建运行，重建只见补列后形态
		health_check_host TEXT NOT NULL DEFAULT '',
		ntlm_compatible INTEGER NOT NULL DEFAULT 0,
		upstream_force_http1 INTEGER NOT NULL DEFAULT 0`)
	}
	schema.WriteString("\n);")
	switch variant.upstreams {
	case legacyUpstreamsMinimal:
		schema.WriteString(`
	CREATE TABLE upstreams (
		id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
		weight INTEGER, dynamic_dns BOOLEAN, enabled BOOLEAN, protocol TEXT, max_connections INTEGER,
		origin_domain TEXT NOT NULL DEFAULT ''
	);`)
	case legacyUpstreamsLegacy:
		schema.WriteString(`
	CREATE TABLE upstreams (
		id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
		weight INTEGER, domain TEXT, dynamic_dns BOOLEAN, enabled BOOLEAN, protocol TEXT, host_header TEXT,
		dns_server TEXT, max_connections INTEGER, proxy_protocol TEXT
	);`)
	case legacyUpstreamsLegacyOrigin:
		schema.WriteString(`
	CREATE TABLE upstreams (
		id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
		weight INTEGER, domain TEXT, dynamic_dns BOOLEAN, enabled BOOLEAN, protocol TEXT, host_header TEXT,
		dns_server TEXT, max_connections INTEGER, proxy_protocol TEXT, origin_domain TEXT NOT NULL DEFAULT ''
	);`)
	}
	if _, err := database.Exec(schema.String()); err != nil {
		t.Fatalf("seed legacy load-balancer schema: %v", err)
	}
}

// cert_jobs 状态枚举单源（db.CertJobStatuses ← fresh CHECK /
// 重建 DDL / 迁移拷贝白名单全部由 strings.Join 生成）。本测试钉住 DDL 与枚举
// 一致，并以真实 INSERT 验证每个枚举值被接受、枚举外值被拒绝。
func TestCertJobStatuses_drivesDDLAndAcceptance(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var tableSQL string
	if err := database.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='cert_jobs'").Scan(&tableSQL); err != nil {
		t.Fatalf("read cert_jobs schema: %v", err)
	}
	if !hasExactStatusConstraint(tableSQL, CertJobStatuses()) {
		t.Fatalf("cert_jobs CHECK constraint does not match CertJobStatuses()")
	}
	for _, status := range CertJobStatuses() {
		if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_status','status.test',?)", status); err != nil {
			t.Fatalf("status %q rejected by DDL: %v", status, err)
		}
	}
	if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_status','status.test','future_unmapped_status')"); err == nil {
		t.Fatal("unlisted status accepted by cert_jobs DDL")
	}
	statuses := CertJobStatuses()
	original := statuses[0]
	statuses[0] = "mutated_by_test"
	if CertJobStatuses()[0] != original {
		t.Fatal("CertJobStatuses leaked mutable global state")
	}
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

func TestRunMigrations_addsGitHubProxyURLColumnWithDefault(t *testing.T) {
	// Given 旧库：global_config 无 github_proxy_url 列且已有存量配置行
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("ALTER TABLE global_config DROP COLUMN github_proxy_url"); err != nil {
		t.Fatalf("drop github_proxy_url to simulate legacy database: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	// When 迁移
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 列被补回，存量行取列默认值（内置 Cloudflare v4 代理）
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='github_proxy_url'").Scan(&count); err != nil {
		t.Fatalf("query global_config schema: %v", err)
	}
	if count != 1 {
		t.Fatalf("global_config.github_proxy_url count=%d, want 1", count)
	}
	var got string
	if err := database.QueryRow("SELECT github_proxy_url FROM global_config WHERE id = 1").Scan(&got); err != nil {
		t.Fatalf("read github_proxy_url: %v", err)
	}
	if got != "https://v4.gh-proxy.org/" {
		t.Fatalf("github_proxy_url=%q, want default https://v4.gh-proxy.org/", got)
	}
}

// 存量库经 newColumns 循环补齐登录锁定列（login_failed_attempts NOT NULL
// DEFAULT 0 / login_locked_until TEXT），幂等，存量行取默认 0。
func TestRunMigrations_addsUserLoginLockoutColumns(t *testing.T) {
	// Given 旧形状 users 表（createTables 的 users 无 login_* 列，模拟前建库）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO users (username,password_hash,role) VALUES ('legacy','hash','admin')"); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	// 与 Initialize 同款单例行（迁移步骤读取 WHERE id=1，缺行即报错——兄弟用例同款种子）
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	// When 迁移两遍（验证幂等）
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then 两列存在、计数列 NOT NULL、存量行取默认 0
	var notNull int
	if err := database.QueryRow(`SELECT "notnull" FROM pragma_table_info('users') WHERE name='login_failed_attempts'`).Scan(&notNull); err != nil {
		t.Fatalf("query login_failed_attempts schema: %v", err)
	}
	if notNull != 1 {
		t.Fatalf("login_failed_attempts notnull=%d, want 1", notNull)
	}
	var lockedUntilCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='login_locked_until'").Scan(&lockedUntilCount); err != nil {
		t.Fatalf("query login_locked_until schema: %v", err)
	}
	if lockedUntilCount != 1 {
		t.Fatalf("login_locked_until count=%d, want 1", lockedUntilCount)
	}
	var attempts int
	if err := database.QueryRow("SELECT login_failed_attempts FROM users WHERE username='legacy'").Scan(&attempts); err != nil {
		t.Fatalf("read migrated user: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("login_failed_attempts=%d, want default 0", attempts)
	}
}

// fresh CREATE 的 DDL 滞后——security_policies 缺
// policy_type/trust_detection、lb_rules 缺 block_page_stage1/3_id/status、
// auto_backups 缺 app_version，四组列此前仅靠 newColumns 启动补列；新库
// 建表即应携带完整形状（newColumns 保留作存量库 ALTER 通道不动）。
func TestCreateTables_freshSchemaCarriesStagedPolicyRuleAndBackupColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	expectColumns := map[string][]struct {
		name string
		dflt string
	}{
		"security_policies": {{"policy_type", "''"}, {"trust_detection", "0"}, {"geoip_crawler_exempt", "0"}, {"geoip_crawler_engines", "'[]'"}},
		"lb_rules":          {{"block_page_stage1_id", "0"}, {"block_page_stage1_status", "0"}, {"block_page_stage3_id", "0"}, {"block_page_stage3_status", "0"}},
		"auto_backups":      {{"app_version", "''"}},
	}
	for table, columns := range expectColumns {
		for _, col := range columns {
			var notNull int
			var dflt string
			if err := database.QueryRow(`SELECT "notnull", COALESCE(dflt_value,'') FROM pragma_table_info('`+table+`') WHERE name=?`, col.name).Scan(&notNull, &dflt); err != nil {
				t.Fatalf("%s.%s missing from fresh schema: %v", table, col.name, err)
			}
			if notNull != 1 {
				t.Fatalf("%s.%s notnull=%d, want 1", table, col.name, notNull)
			}
			if dflt != col.dflt {
				t.Fatalf("%s.%s default=%q, want %q", table, col.name, dflt, col.dflt)
			}
		}
	}
}

func TestCreateTables_freshSchemaCarriesACMEAndTCPProxyColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	for column, wantDefault := range map[string]string{
		"tcp_proxy_protocol": "0",
		"tls_source":         "'manual'",
		"acme_config_id":     "0",
		"ca_provider_id":     "0",
	} {
		var gotDefault string
		if err := database.QueryRow(`SELECT COALESCE(dflt_value,'') FROM pragma_table_info('lb_rules') WHERE name=?`, column).Scan(&gotDefault); err != nil {
			t.Fatalf("lb_rules.%s missing from fresh schema: %v", column, err)
		}
		if gotDefault != wantDefault {
			t.Fatalf("lb_rules.%s default=%q, want %q", column, gotDefault, wantDefault)
		}
	}
}

// migrateSecurityPoliciesNullable 重建 DDL 滞后——
// DDL 未携带 policy_type/trust_detection，窗口期库重建把 newColumns 早前
// 加的两列连同数据一并丢弃：trust_detection 无任何回填路径（显式值永久
// 归零）；policy_type 靠内容重推断「自愈」但显式 stage0 空信任列表行会被
// 误推断为 stage3。重建必须携带两列并保数据。
func TestInitialize_preservesStagedColumnsOnSecurityPoliciesRebuild(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	// 构造窗口期形态：四列 NOT NULL（触发重建）+ 已携带 policy_type/
	// trust_detection（模拟上一轮启动 ensureNewColumns 已加列）与存量行。
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
			waf_check_response INTEGER NOT NULL DEFAULT 0,
			policy_type TEXT NOT NULL DEFAULT '',
			trust_detection BOOLEAN NOT NULL DEFAULT 0,
			geoip_crawler_exempt INTEGER NOT NULL DEFAULT 0,
			geoip_crawler_engines TEXT NOT NULL DEFAULT '[]'
		);
		INSERT INTO security_policies (id,name,geoip_countries,geoip_mode,waf_check_response,block_status_code,enabled,policy_type,trust_detection,geoip_crawler_exempt,geoip_crawler_engines)
		VALUES (1,'window-era','[]','deny',0,0,1,'stage0',1,1,'["googlebot"]');`); err != nil {
		t.Fatalf("seed window-era security_policies: %v", err)
	}

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}

	// Then: 显式 policy_type 与 trust_detection 存活
	var policyType, crawlerEngines string
	var trustDetection, crawlerExempt int
	if err := DB.QueryRow(`SELECT policy_type, trust_detection, geoip_crawler_exempt, geoip_crawler_engines FROM security_policies WHERE id=1`).Scan(&policyType, &trustDetection, &crawlerExempt, &crawlerEngines); err != nil {
		t.Fatalf("read migrated policy staged columns: %v", err)
	}
	if policyType != "stage0" {
		t.Fatalf("policy_type=%q, want stage0 (explicit type must survive rebuild; content re-inference misreads empty-trust stage0 as stage3)", policyType)
	}
	if trustDetection != 1 {
		t.Fatalf("trust_detection=%d, want 1 (explicit value has no backfill path; rebuild must preserve it)", trustDetection)
	}
	if crawlerExempt != 1 || crawlerEngines != `["googlebot"]` {
		t.Fatalf("crawler columns=(%d,%q), want (1,[googlebot]) preserved across rebuild", crawlerExempt, crawlerEngines)
	}
}

// migrateLbRulesPrimaryKey 重建 DDL/拷贝清单滞后——
// 未携带 block_page_stage1/3_id/status 四列，遗留 id-主键库启动重建把阶段
// 拦截页列连同值一并丢弃；且本重建位于二次 ensureNewColumns
// 安全网之后，丢列无同启动自愈（规则保存/读取直接 no such column）。
func TestInitialize_preservesStagePageColumnsOnLbRulesPkRebuild(t *testing.T) {
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	createLegacyLbRulesTables(t, legacy, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, upstreams: legacyUpstreamsLegacy})
	if _, err := legacy.Exec(`
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id, block_page_stage1_id, block_page_stage1_status, block_page_stage3_id, block_page_stage3_status)
		VALUES (7, 'legacy', 'http', 8080, 'lb_stagepages', 5, 2, 7, 1);
	`); err != nil {
		t.Fatalf("seed legacy load-balancer schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	preserveDatabaseHandles(t)

	// When：遗留库启动一次（PK 重建 DROP 并重建 lb_rules）
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then：四列存在且值存活
	for _, col := range []string{"block_page_stage1_id", "block_page_stage1_status", "block_page_stage3_id", "block_page_stage3_status"} {
		var cnt int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name=?`, col).Scan(&cnt); err != nil {
			t.Fatalf("read lb_rules.%s schema: %v", col, err)
		}
		if cnt != 1 {
			t.Fatalf("lb_rules.%s missing after PK rebuild boot (rebuild DDL lag, no same-boot self-heal)", col)
		}
	}
	var s1ID, s1Status, s3ID, s3Status int
	if err := DB.QueryRow(`SELECT block_page_stage1_id, block_page_stage1_status, block_page_stage3_id, block_page_stage3_status
		FROM lb_rules WHERE caddy_id='lb_stagepages'`).Scan(&s1ID, &s1Status, &s3ID, &s3Status); err != nil {
		t.Fatalf("read migrated rule stage pages: %v", err)
	}
	if s1ID != 5 || s1Status != 2 || s3ID != 7 || s3Status != 1 {
		t.Fatalf("stage pages=(%d,%d,%d,%d), want (5,2,7,1)", s1ID, s1Status, s3ID, s3Status)
	}
}

// OIDC 身份三元组唯一索引——JIT 开户并发回调窗口可
// 产生重复 (issuer,subject) 行。partial 索引只约束 oidc 行：本地用户、历史
// 空 subject 行不受影响。
func TestInitialize_createsOidcIdentityUniqueIndex(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	var indexCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('users') WHERE name='u_oidc_identity'`).Scan(&indexCount); err != nil {
		t.Fatalf("inspect users indexes: %v", err)
	}
	if indexCount != 1 {
		t.Fatalf("u_oidc_identity index missing after initialize, want 1")
	}

	seed := func(username, provider, subject, issuer string) error {
		_, err := DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer)
			VALUES (?, 'x', 'user', 1, ?, ?, ?)`, username, provider, subject, issuer)
		return err
	}
	if err := seed("oidc-a", "oidc", "sub-1", "https://idp.example.com"); err != nil {
		t.Fatalf("seed first identity: %v", err)
	}
	if err := seed("oidc-b", "oidc", "sub-1", "https://idp.example.com"); err == nil {
		t.Fatal("duplicate oidc identity insert must violate u_oidc_identity")
	} else if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Fatalf("duplicate identity error = %v, want UNIQUE constraint violation", err)
	}
	// 负控：同 subject 异 issuer、local 同身份、空 subject 两行各自放行
	controls := []struct{ username, provider, subject, issuer string }{
		{"oidc-c", "oidc", "sub-1", "https://other.example.com"},
		{"local-a", "local", "sub-1", "https://idp.example.com"},
		{"oidc-empty-1", "oidc", "", "https://idp.example.com"},
		{"oidc-empty-2", "oidc", "", "https://idp.example.com"},
	}
	for _, tc := range controls {
		if err := seed(tc.username, tc.provider, tc.subject, tc.issuer); err != nil {
			t.Fatalf("seed control %s must pass: %v", tc.username, err)
		}
	}
}

// 安全阀——存量库存在重复 OIDC 身份时跳过建索引并
// 告警，绝不因历史脏数据拖垮启动；重复行原样保留，待人工处置后重启自动建索引。
func TestInitialize_skipsOidcIdentityIndexOnHistoricalDuplicates(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	// 移除索引后播种重复身份（模拟索引诞生前的历史脏数据）
	if _, err := DB.Exec("DROP INDEX IF EXISTS u_oidc_identity"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	for _, username := range []string{"dup-a", "dup-b"} {
		if _, err := DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer)
			VALUES (?, 'x', 'user', 1, 'oidc', 'sub-dup', 'https://idp.example.com')`, username); err != nil {
			t.Fatalf("seed duplicate %s: %v", username, err)
		}
	}

	// When：安全阀启动——不得报错
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize with duplicate oidc identities must not fail: %v", err)
	}

	// Then：索引未建，重复行原样保留
	var indexCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('users') WHERE name='u_oidc_identity'`).Scan(&indexCount); err != nil {
		t.Fatalf("inspect users indexes: %v", err)
	}
	if indexCount != 0 {
		t.Fatalf("u_oidc_identity must be skipped on duplicate identities, found %d", indexCount)
	}
	var dupCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM users WHERE auth_provider='oidc' AND oidc_subject='sub-dup'`).Scan(&dupCount); err != nil {
		t.Fatalf("count duplicates: %v", err)
	}
	if dupCount != 2 {
		t.Fatalf("duplicate rows=%d, want 2 (untouched by safety valve)", dupCount)
	}
}

// 上游 path 改写：path_rules.upstream_path 列（TEXT NOT NULL 且默认空串）由
// fresh DDL 与 newColumns 双通道提供——fresh 初始化后列必须存在且带默认值，
// 存量库由 ensureNewColumns 幂等补列。
func TestInitialize_adds_path_rules_upstream_path_column(t *testing.T) {
	// Given
	dir := t.TempDir()
	preserveDatabaseHandles(t)

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	// Then
	var notNull int
	var columnDefault string
	if err := DB.QueryRow(`SELECT "notnull", COALESCE(dflt_value,'') FROM pragma_table_info('path_rules') WHERE name='upstream_path'`).Scan(&notNull, &columnDefault); err != nil {
		t.Fatalf("read path_rules.upstream_path schema: %v", err)
	}
	// SQLite 将 DEFAULT 空串存为带引号字面量（同 policy_type 断言口径）
	if notNull != 1 || columnDefault != "''" {
		t.Fatalf("path_rules.upstream_path notnull=%d default=%q, want notnull=1 default empty string", notNull, columnDefault)
	}
}

func TestInitialize_customRuleConditionLogicSchemaAndMigration(t *testing.T) {
	t.Run("fresh schema default", func(t *testing.T) {
		dir := t.TempDir()
		preserveDatabaseHandles(t)
		if err := Initialize(dir); err != nil {
			t.Fatalf("initialize database: %v", err)
		}
		var notNull int
		var columnDefault string
		if err := DB.QueryRow(`SELECT "notnull",COALESCE(dflt_value,'') FROM pragma_table_info('security_custom_rules') WHERE name='condition_logic'`).Scan(&notNull, &columnDefault); err != nil {
			t.Fatalf("read condition_logic schema: %v", err)
		}
		if notNull != 1 || columnDefault != "'and'" {
			t.Fatalf("condition_logic notnull=%d default=%q, want 1/'and'", notNull, columnDefault)
		}
		if _, err := DB.Exec(`INSERT INTO security_custom_rules (name,conditions,action,score,enabled) VALUES ('legacy-default','[]','block',5,1)`); err != nil {
			t.Fatal(err)
		}
		var logic string
		if err := DB.QueryRow(`SELECT condition_logic FROM security_custom_rules WHERE name='legacy-default'`).Scan(&logic); err != nil {
			t.Fatal(err)
		}
		if logic != "and" {
			t.Fatalf("旧写入形状 condition_logic=%q, want and", logic)
		}
	})

	t.Run("existing database backfill", func(t *testing.T) {
		database := openMigrationTestDB(t)
		if err := createTables(); err != nil {
			t.Fatalf("create tables: %v", err)
		}
		if _, err := database.Exec(`ALTER TABLE security_custom_rules DROP COLUMN condition_logic`); err != nil {
			t.Fatalf("construct legacy schema: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO security_custom_rules (name,conditions,action,score,enabled) VALUES ('old-row','[]','block',5,1)`); err != nil {
			t.Fatal(err)
		}
		if err := ensureNewColumns(newColumnsRegistry, nil); err != nil {
			t.Fatalf("migrate condition_logic: %v", err)
		}
		var logic string
		if err := database.QueryRow(`SELECT condition_logic FROM security_custom_rules WHERE name='old-row'`).Scan(&logic); err != nil {
			t.Fatal(err)
		}
		if logic != "and" {
			t.Fatalf("存量行 condition_logic=%q, want and", logic)
		}
	})
}

// 存量 TCP 规则的 enable_dns_server/dns_server
// 落库恒无效，迁移按 migrateTCPRuleDeadFields 同口径清空；HTTP 规则同名字段
// （DNS 服务发现合法配置）不受影响。
func TestRunMigrations_clearsTCPRuleStaleDNSServerFields(t *testing.T) {
	// Given 存量行：TCP 规则携带 DNS 字段两形态（开关开+地址/仅地址）、
	// 已干净的 TCP 行、携带同名合法字段的 HTTP 规则（回归形状——不得误清）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		INSERT INTO lb_rules (name,protocol,domain,listen_port,enable_dns_server,dns_server,caddy_id) VALUES
			('tcp-dns-on','tcp','',9090,1,'8.8.8.8:53','lb_tcp_dns_on'),
			('tcp-dns-addr-only','tcp','',9091,0,'1.1.1.1:53','lb_tcp_dns_addr'),
			('tcp-clean','tcp','',9092,0,'','lb_tcp_clean'),
			('http-dns','http','c.example.test',8080,1,'8.8.8.8:53','lb_http_dns');`); err != nil {
		t.Fatalf("seed tcp rules with stale dns fields: %v", err)
	}
	drainSystemAuditBuffer()

	// When migrations run (twice, to prove idempotence)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then 两条携带 DNS 字段的 TCP 行两列清空
	for _, caddyID := range []string{"lb_tcp_dns_on", "lb_tcp_dns_addr"} {
		var enableDNSServer int
		var dnsServer string
		if err := database.QueryRow("SELECT IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,'') FROM lb_rules WHERE caddy_id=?", caddyID).Scan(&enableDNSServer, &dnsServer); err != nil {
			t.Fatalf("read migrated rule %s: %v", caddyID, err)
		}
		if enableDNSServer != 0 || dnsServer != "" {
			t.Fatalf("rule %s enable_dns_server=%d dns_server=%q, want 0/\"\"", caddyID, enableDNSServer, dnsServer)
		}
	}

	// And 受影响规则进入操作日志缓冲，重跑零命中（1 条 stale DNS 聚合 + 1 条
	// TCP 死字段聚合=2 条；聚合行携带命中条数与 caddy_id 清单，逐规则写 N 条
	// 会随存量规模撑爆系统审计缓冲）。
	entries := drainSystemAuditBuffer()
	if len(entries) != 2 {
		t.Fatalf("system audit entries=%d, want 2（1 条 stale DNS 聚合 + 1 条 TCP 死字段聚合；重跑幂等）: %+v", len(entries), entries)
	}
	details := make([]string, 0, len(entries))
	var dnsDetail string
	for _, entry := range entries {
		if entry.action != "启动迁移" {
			t.Fatalf("audit entry action=%q, want 启动迁移", entry.action)
		}
		details = append(details, entry.detail)
		if strings.Contains(entry.detail, "无效 DNS 服务发现配置") {
			dnsDetail = entry.detail
		}
	}
	if dnsDetail == "" {
		t.Fatalf("缺少 stale DNS 聚合审计: %v", details)
	}
	// 聚合行的可追溯性：条数 + 全部命中的 caddy_id 必须在同一行内。
	for _, want := range []string{"2 条", "lb_tcp_dns_on", "lb_tcp_dns_addr"} {
		if !strings.Contains(dnsDetail, want) {
			t.Fatalf("stale DNS 聚合审计缺 %q: %q", want, dnsDetail)
		}
	}
	for _, want := range []string{"lb_tcp_dns_on", "lb_tcp_dns_addr", "TCP 规则 HTTP 专属死字段已清零"} {
		found := false
		for _, detail := range details {
			if strings.Contains(detail, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺少审计条目 %q: %v", want, details)
		}
	}

	// And 干净 TCP 行与 HTTP 行同名字段原样保留（HTTP 的 DNS 配置是合法语义）
	var httpEnable int
	var httpDNS string
	if err := database.QueryRow("SELECT IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,'') FROM lb_rules WHERE caddy_id='lb_http_dns'").Scan(&httpEnable, &httpDNS); err != nil {
		t.Fatalf("read http rule: %v", err)
	}
	if httpEnable != 1 || httpDNS != "8.8.8.8:53" {
		t.Fatalf("HTTP 规则 DNS 字段不得受影响: enable=%d server=%q", httpEnable, httpDNS)
	}
	var cleanEnable int
	var cleanDNS string
	if err := database.QueryRow("SELECT IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,'') FROM lb_rules WHERE caddy_id='lb_tcp_clean'").Scan(&cleanEnable, &cleanDNS); err != nil {
		t.Fatalf("read clean tcp rule: %v", err)
	}
	if cleanEnable != 0 || cleanDNS != "" {
		t.Fatalf("干净 TCP 行被误改: enable=%d server=%q", cleanEnable, cleanDNS)
	}
}

// 逐上游回源域名 + 健康检查域名（2026-10-10）：upstreams.origin_domain 与
// lb_rules.health_check_host 两列——fresh DDL 建表含列，存量库经 ensureNewColumns
// 幂等补列，PK 重建迁移（migrateLbRulesPrimaryKey）DDL 同步携带保值。

// TestInitialize_freshSchemaCarriesUpstreamHostColumns：fresh 安装两表携带新列，
// NOT NULL + 默认空串（同 path_rules.upstream_path 断言口径）。
func TestInitialize_freshSchemaCarriesUpstreamHostColumns(t *testing.T) {
	// Given
	dir := t.TempDir()
	preserveDatabaseHandles(t)

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	// Then
	for _, tc := range []struct{ table, column string }{
		{"upstreams", "origin_domain"},
		{"lb_rules", "health_check_host"},
	} {
		var notNull int
		var columnDefault string
		query := fmt.Sprintf(`SELECT "notnull", COALESCE(dflt_value,'') FROM pragma_table_info('%s') WHERE name='%s'`, tc.table, tc.column)
		if err := DB.QueryRow(query).Scan(&notNull, &columnDefault); err != nil {
			t.Fatalf("read %s.%s schema: %v", tc.table, tc.column, err)
		}
		if notNull != 1 || columnDefault != "''" {
			t.Fatalf("%s.%s notnull=%d default=%q, want notnull=1 default empty string", tc.table, tc.column, notNull, columnDefault)
		}
	}
}

// TestRunMigrations_addsUpstreamHostColumnsToLegacyRows：存量库（无两列）经
// runMigrations 补列，已存在行读回默认空串（SQLite ADD COLUMN 以默认值填充存量行）。
func TestRunMigrations_addsUpstreamHostColumnsToLegacyRows(t *testing.T) {
	// Given 存量库：createTables 后模拟旧版——若新列已存在则先 DROP（RED 期列本不存在，跳过）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		INSERT INTO lb_rules (name,protocol,domain,listen_port,caddy_id) VALUES ('legacy','http','legacy.example.test',8080,'lb_legacyhost');
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_legacyhost','10.0.0.1',9000,1,1,'http');`); err != nil {
		t.Fatalf("seed legacy rows: %v", err)
	}
	for _, tc := range []struct{ table, column string }{
		{"upstreams", "origin_domain"},
		{"lb_rules", "health_check_host"},
	} {
		var cnt int
		if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, tc.table, tc.column).Scan(&cnt); err != nil {
			t.Fatalf("inspect %s.%s: %v", tc.table, tc.column, err)
		}
		if cnt == 1 {
			if _, err := database.Exec(fmt.Sprintf(`ALTER TABLE %s DROP COLUMN %s`, tc.table, tc.column)); err != nil {
				t.Fatalf("simulate legacy %s.%s: %v", tc.table, tc.column, err)
			}
		}
	}

	// When migrations run (twice, to prove idempotence)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then 两列补出且存量行读回空串
	var originDomain string
	if err := database.QueryRow(`SELECT origin_domain FROM upstreams WHERE rule_id='lb_legacyhost'`).Scan(&originDomain); err != nil {
		t.Fatalf("read origin_domain: %v", err)
	}
	if originDomain != "" {
		t.Fatalf("origin_domain=%q, want empty default", originDomain)
	}
	var healthCheckHost string
	if err := database.QueryRow(`SELECT health_check_host FROM lb_rules WHERE caddy_id='lb_legacyhost'`).Scan(&healthCheckHost); err != nil {
		t.Fatalf("read health_check_host: %v", err)
	}
	if healthCheckHost != "" {
		t.Fatalf("health_check_host=%q, want empty default", healthCheckHost)
	}
}

// TestInitialize_carriesUpstreamHostColumnsThroughPkRebuild：遗留库（int PK，
// 触发 migrateLbRulesPrimaryKey 重建）上两列已带真实值——重建 DDL 必须携带，
// 否则重建丢列、值被安全网以默认值回填。
func TestInitialize_carriesUpstreamHostColumnsThroughPkRebuild(t *testing.T) {
	// Given 遗留库：int PK lb_rules/upstreams + 两新列已带值（模拟 ensureNewColumns
	// 已在重建前补列并被写入真实配置的形态）
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	createLegacyLbRulesTables(t, legacy, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsLegacyOrigin})
	if _, err := legacy.Exec(`
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id, health_check_host)
		VALUES (7, 'legacy', 'http', 8080, 'lb_originhost', 'probe.example.test');
		INSERT INTO upstreams (id, rule_id, host, port, enabled, protocol, origin_domain)
		VALUES (3, 7, '10.0.0.1', 9000, 1, 'http', 'origin.example.test');
	`); err != nil {
		t.Fatalf("seed legacy load-balancer schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	preserveDatabaseHandles(t)

	// When：遗留库启动一次（PK 重建 DROP 并重建 lb_rules/upstreams）
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then：两列存在且值存活
	var healthCheckHost string
	if err := DB.QueryRow(`SELECT health_check_host FROM lb_rules WHERE caddy_id='lb_originhost'`).Scan(&healthCheckHost); err != nil {
		t.Fatalf("read migrated rule health_check_host: %v", err)
	}
	if healthCheckHost != "probe.example.test" {
		t.Fatalf("health_check_host=%q after PK rebuild, want probe.example.test（重建丢列）", healthCheckHost)
	}
	var originDomain string
	if err := DB.QueryRow(`SELECT origin_domain FROM upstreams WHERE host='10.0.0.1'`).Scan(&originDomain); err != nil {
		t.Fatalf("read migrated upstream origin_domain: %v", err)
	}
	if originDomain != "origin.example.test" {
		t.Fatalf("origin_domain=%q after PK rebuild, want origin.example.test（重建丢列）", originDomain)
	}
}

// 自定义路由静态响应/301 跳转（2026-10-10 用户裁定）：path_rules 补五列——
// response_mode(”=转发/static/redirect)/response_status/response_body/
// response_content_type/redirect_to。path_rules 不经 migrateLbRulesPrimaryKey
// 重建（仅 lb_rules/upstreams），fresh DDL + ensureNewColumns 双通道即可。
func TestInitialize_freshSchemaCarriesPathRuleResponseColumns(t *testing.T) {
	// Given
	dir := t.TempDir()
	preserveDatabaseHandles(t)

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	// Then
	for _, tc := range []struct{ column, dflt string }{
		{"response_mode", "''"},
		{"response_status", "200"},
		{"response_body", "''"},
		{"response_content_type", "''"},
		{"redirect_to", "''"},
	} {
		var notNull int
		var columnDefault string
		if err := DB.QueryRow(fmt.Sprintf(`SELECT "notnull", COALESCE(dflt_value,'') FROM pragma_table_info('path_rules') WHERE name='%s'`, tc.column)).Scan(&notNull, &columnDefault); err != nil {
			t.Fatalf("read path_rules.%s schema: %v", tc.column, err)
		}
		if notNull != 1 || columnDefault != tc.dflt {
			t.Fatalf("path_rules.%s notnull=%d default=%q, want notnull=1 default %s", tc.column, notNull, columnDefault, tc.dflt)
		}
	}
}

// TestRunMigrations_addsPathRuleResponseColumnsToLegacyRows：存量库补列后
// 旧行五列读回默认值（”=转发/200/空体/空格式/空目标=现状转发语义零漂移）。
func TestRunMigrations_addsPathRuleResponseColumnsToLegacyRows(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		INSERT INTO lb_rules (name,protocol,domain,listen_port,caddy_id) VALUES ('legacy','http','legacy.example.test',8080,'lb_prresp');
		INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_prresp',0,'prefix','/api')`); err != nil {
		t.Fatalf("seed legacy rows: %v", err)
	}
	for _, col := range []string{"response_mode", "response_status", "response_body", "response_content_type", "redirect_to"} {
		var cnt int
		if err := database.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM pragma_table_info('path_rules') WHERE name='%s'`, col)).Scan(&cnt); err != nil {
			t.Fatalf("inspect path_rules.%s: %v", col, err)
		}
		if cnt == 1 {
			if _, err := database.Exec(`ALTER TABLE path_rules DROP COLUMN ` + col); err != nil {
				t.Fatalf("simulate legacy path_rules.%s: %v", col, err)
			}
		}
	}

	// When（重跑证幂等）
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then
	var mode, body, contentType, redirectTo string
	var status int
	if err := database.QueryRow(`SELECT response_mode, response_status, response_body, response_content_type, redirect_to
		FROM path_rules WHERE rule_id='lb_prresp'`).Scan(&mode, &status, &body, &contentType, &redirectTo); err != nil {
		t.Fatalf("read migrated path rule: %v", err)
	}
	if mode != "" || status != 200 || body != "" || contentType != "" || redirectTo != "" {
		t.Fatalf("migrated=(%q,%d,%q,%q,%q), want ('',200,'','','')", mode, status, body, contentType, redirectTo)
	}
}

// 库值唯一真相（批 3，2026-10-14/15 用户裁定）：global_config.cert_expiry_days
// 类型①值型列——写侧 [1,365] 校验+ 导入钳制
// 之外的最后防线：NULL/<=0 随启动幂等回填 30；用户已设有效值（>0）恒不触碰。
func TestInitialize_backfillsCertExpiryDays(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	for _, tc := range []struct {
		name string
		seed string
		want int
	}{
		{"null", `UPDATE global_config SET cert_expiry_days=NULL WHERE id=1`, 30},
		{"zero", `UPDATE global_config SET cert_expiry_days=0 WHERE id=1`, 30},
		{"negative", `UPDATE global_config SET cert_expiry_days=-5 WHERE id=1`, 30},
		{"valid-untouched", `UPDATE global_config SET cert_expiry_days=45 WHERE id=1`, 45},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DB.Exec(tc.seed); err != nil {
				t.Fatalf("seed cert_expiry_days: %v", err)
			}
			if err := Initialize(dir); err != nil {
				t.Fatalf("re-initialize database: %v", err)
			}
			var got int
			if err := DB.QueryRow("SELECT cert_expiry_days FROM global_config WHERE id=1").Scan(&got); err != nil {
				t.Fatalf("read cert_expiry_days: %v", err)
			}
			if got != tc.want {
				t.Fatalf("cert_expiry_days=%d after backfill, want %d (seed %q)", got, tc.want, tc.seed)
			}
		})
	}
}

// 初版 security_crawler_sources 漏 id 主键：存量无 id 库整表重建保留源行，
// 新库（含 id）幂等跳过。
func TestMigrateCrawlerSourcesID_rebuildsLegacyAndPreservesRows(t *testing.T) {
	// Given 存量库：旧形 security_crawler_sources（无 id），一行自定义开关状态
	database := openMigrationTestDB(t)
	createLegacyCrawlerSourcesTable(t, database)
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name,display_name,url,format,update_enabled,entry_count,version)
		VALUES ('googlebot','爬虫机器人 Google','https://example.com/ips.json','json',0,170,'2026.10.16')`); err != nil {
		t.Fatalf("seed legacy crawler sources: %v", err)
	}

	// When
	if err := migrateCrawlerSourcesID(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：id 主键存在且源行/开关状态保留
	var id, enabled, entryCount int
	var version string
	if err := database.QueryRow(`SELECT id,update_enabled,entry_count,version FROM security_crawler_sources WHERE name='googlebot'`).Scan(&id, &enabled, &entryCount, &version); err != nil {
		t.Fatalf("query migrated row: %v", err)
	}
	if id != 1 || enabled != 0 || entryCount != 170 || version != "2026.10.16" {
		t.Errorf("迁移后行内容漂移: id=%d enabled=%d count=%d version=%q", id, enabled, entryCount, version)
	}
	// 幂等：再跑一次不报错、行数不变
	if err := migrateCrawlerSourcesID(); err != nil {
		t.Fatalf("re-run migrate: %v", err)
	}
	var rows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_crawler_sources`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows=%d want 1", rows)
	}
}

func TestMigrateCrawlerSourcesOutOfThreat_preservesStateAndRemovesLegacyRows(t *testing.T) {
	// Given：历史合并形态的爬虫源行（含用户开关与更新状态），新表已有一行待覆盖
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_threat_sources
		(id,name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,consecutive_failures)
		VALUES (1039,'googlebot','Google 官方爬虫 IP','https://example.com/google.json','json',0,170,'2026.10.16','failed','download failed','2026-10-16 01:00:00','2026-10-17 04:00:00',2);
		INSERT INTO security_crawler_sources (name,display_name,url,format)
		VALUES ('googlebot','旧占位名','https://example.com/google.json','json');`); err != nil {
		t.Fatalf("seed merged sources: %v", err)
	}

	// When
	drainSystemAuditBuffer()
	if err := migrateCrawlerSourcesOutOfThreat(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：状态迁入独立源表且不重复，威胁表不再含爬虫地址库源
	var enabled, entryCount, failures int
	var displayName, version, status, nextUpdate string
	if err := database.QueryRow(`SELECT display_name,update_enabled,entry_count,version,update_status,next_update,consecutive_failures
		FROM security_crawler_sources WHERE name='googlebot'`).Scan(&displayName, &enabled, &entryCount, &version, &status, &nextUpdate, &failures); err != nil {
		t.Fatalf("query migrated crawler source: %v", err)
	}
	nextTime, parseErr := time.Parse(time.RFC3339, nextUpdate)
	if displayName != "Google 官方爬虫 IP" || enabled != 0 || entryCount != 170 || version != "2026.10.16" || status != "failed" || parseErr != nil || !nextTime.Equal(time.Date(2026, 10, 17, 4, 0, 0, 0, time.UTC)) || failures != 2 {
		t.Errorf("迁移后状态漂移: name=%q enabled=%d count=%d version=%q status=%q next=%q failures=%d parseErr=%v", displayName, enabled, entryCount, version, status, nextUpdate, failures, parseErr)
	}
	var crawlerRows, legacyRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_crawler_sources WHERE name='googlebot'`).Scan(&crawlerRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_threat_sources WHERE name IN ('googlebot','gptbot','bingbot','so360spider')`).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if crawlerRows != 1 || legacyRows != 0 {
		t.Errorf("迁移行数错误: crawler=%d legacy=%d", crawlerRows, legacyRows)
	}
	// And：跨表搬迁留痕一行（威胁库少了哪些源必须可追溯）。
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || entries[0].resource != "威胁源" || !strings.Contains(entries[0].detail, "已迁入爬虫地址库") || !strings.Contains(entries[0].detail, "1 条") {
		t.Fatalf("搬迁审计=%+v, want 恰一条含条数的威胁源留痕", entries)
	}
	// 回归形状：收敛库（威胁表无爬虫行）重跑零审计。
	if err := migrateCrawlerSourcesOutOfThreat(); err != nil {
		t.Fatalf("re-run migrate: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("收敛库重跑审计=%+v, want 空", entries)
	}
}

// 启动迁移改写用户数据必须留痕：覆盖规则负载策略归一与上游权重无效值归一
// 两条姊妹迁移（此前仅写进程 stdout）。
func TestRunMigrations_recordsStrategyAndWeightNormalization(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		INSERT INTO lb_rules (name,protocol,listen_port,strategy,caddy_id) VALUES ('legacy','http',8080,'round_robin','lb_audit');
		INSERT INTO upstreams (rule_id,host,port,weight) VALUES ('lb_audit','127.0.0.1',8080,NULL), ('lb_audit','127.0.0.2',8080,0);`); err != nil {
		t.Fatalf("seed legacy strategy/weights: %v", err)
	}
	drainSystemAuditBuffer()

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 2 {
		t.Fatalf("audit entries=%d, want 2: %+v", len(entries), entries)
	}
	wants := []string{"round_robin 归一为 weighted_round_robin：1 条", "上游权重无效值（NULL/<1）归 1：2 条"}
	for _, want := range wants {
		found := false
		for _, entry := range entries {
			if entry.action == "启动迁移" && strings.Contains(entry.detail, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("缺少审计 %q: %+v", want, entries)
		}
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("idempotent rerun produced audits: %+v", entries)
	}
}

// 重复 system=1 名单行去重删除整行属用户可见数据改写（重复行可能携带已入库
// 的威胁 IP 条目）：与 cert_jobs 去重/域名归一同口径落「全操作审计」，不能只
// 留进程 stdout（可能随日志轮转丢失）。
func TestMigrateSystemIPListUniqueIndex_recordsAuditForDedupedRows(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	for _, name := range []string{"威胁情报库", "威胁情报库"} {
		if _, err := database.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES (?, '', 'threat', '["1.2.3.4"]', 1)`, name); err != nil {
			t.Fatalf("seed system list %s: %v", name, err)
		}
	}

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
		t.Fatalf("create audit_log: %v", err)
	}
	oldAuditDB := AuditDB
	AuditDB = auditDB
	t.Cleanup(func() { AuditDB = oldAuditDB })
	drainSystemAuditBuffer()

	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate system ip list unique index: %v", err)
	}
	flushSystemAuditLogs()

	var count int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='启动迁移' AND resource='IP 名单' AND detail LIKE '%1 条%'`).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("dedupe audit rows=%d, want 1（删除整行必须留痕）", count)
	}
	var remaining int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND name='威胁情报库'`).Scan(&remaining); err != nil {
		t.Fatalf("count remaining rows: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining system rows=%d, want 1", remaining)
	}
}

// OIDC 唯一索引探测门：索引在位时启动不得再对 users 全表 GROUP BY 查重
// （与 ensureSecurityEventsTransactionIndex / migrateSystemIPListUniqueIndex
// 同款探测门）——每次重启白付一次全表扫描，历史重复身份库还会重复同一条告警；
// 索引被带外删除后必须重新查重并重建（安全阀不被探测门短路）。
func TestInitialize_oidcIdentityIndexProbeSkipsRescan(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	scansBase, skipsBase := oidcIdentityIndexScans.Load(), oidcIdentityIndexSkips.Load()
	if err := Initialize(dir); err != nil {
		t.Fatalf("second initialize: %v", err)
	}
	if got := oidcIdentityIndexScans.Load() - scansBase; got != 0 {
		t.Fatalf("索引在位时仍执行全表查重 %d 次, want 0（启动只做必要工作）", got)
	}
	if got := oidcIdentityIndexSkips.Load() - skipsBase; got != 1 {
		t.Fatalf("探测跳过计数=%d, want 1", got)
	}

	if _, err := DB.Exec("DROP INDEX IF EXISTS u_oidc_identity"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	scansBase = oidcIdentityIndexScans.Load()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize after index drop: %v", err)
	}
	if got := oidcIdentityIndexScans.Load() - scansBase; got != 1 {
		t.Fatalf("索引缺失时查重次数=%d, want 1", got)
	}
	var indexCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('users') WHERE name='u_oidc_identity'`).Scan(&indexCount); err != nil {
		t.Fatalf("inspect users indexes: %v", err)
	}
	if indexCount != 1 {
		t.Fatalf("索引被删后必须重建，实际 count=%d", indexCount)
	}
}

// OIDC 重复身份安全阀的事实必须进「操作日志」（账号面板唯一可见通道），
// 且同一重复集合只留痕一次：该僵持态只能人工合并后重启，每次重启都重写
// 相同审计会让噪声随重启线性增长；指纹变化/冲突解除后自动重报。
func TestMigrateOidcIdentityUniqueIndex_auditConvergesAndNamesDuplicates(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 生产启动序：标记列由 ensureNewColumns 补（fresh DDL 不携带 global_config 标记列）。
	if err := ensureNewColumns(newColumnsRegistry, nil); err != nil {
		t.Fatalf("add new columns: %v", err)
	}
	// 生产启动序：global_config 单行由 Initialize 在迁移前建好（标记列写点在此行）。
	if _, err := DB.Exec(`INSERT INTO global_config (id, caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	seedDuplicate := func(username string) {
		t.Helper()
		if _, err := DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer)
			VALUES (?, 'x', 'user', 1, 'oidc', 'sub-dup', 'https://idp.example.com')`, username); err != nil {
			t.Fatalf("seed duplicate %s: %v", username, err)
		}
	}
	readMarker := func() string {
		t.Helper()
		var marker string
		if err := DB.QueryRow(`SELECT COALESCE(` + oidcDupIdentityMarkerColumn + `,'') FROM global_config WHERE id=1`).Scan(&marker); err != nil {
			t.Fatalf("read marker: %v", err)
		}
		return marker
	}
	readIndexCount := func() int {
		t.Helper()
		var count int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('users') WHERE name='u_oidc_identity'`).Scan(&count); err != nil {
			t.Fatalf("inspect users indexes: %v", err)
		}
		return count
	}
	seedDuplicate("dup-a")
	seedDuplicate("dup-b")
	drainSystemAuditBuffer()

	// 首轮：一条点名 issuer/subject×N 的审计 + marker 置位，索引仍跳过。
	if err := migrateOidcIdentityUniqueIndex(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || entries[0].resource != "用户" || !strings.Contains(entries[0].detail, "https://idp.example.com/sub-dup×2") {
		t.Fatalf("首轮审计=%+v, want 恰一条点名重复身份的留痕", entries)
	}
	if marker := readMarker(); marker == "" {
		t.Fatal("首轮后 marker 必须置位（同一重复集合已告警）")
	}
	if got := readIndexCount(); got != 0 {
		t.Fatalf("重复身份在场时索引数=%d, want 0（安全阀不得建索引）", got)
	}

	// 二次启动（同一重复集合）：零新审计（marker 命中），状态不变。
	if err := migrateOidcIdentityUniqueIndex(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("二次启动审计=%+v, want 空（同一集合不重复留痕）", entries)
	}

	// 人工合并（删除一行）后重启：索引建立、marker 清除。
	if _, err := DB.Exec(`DELETE FROM users WHERE username='dup-b'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateOidcIdentityUniqueIndex(); err != nil {
		t.Fatalf("migrate after manual merge: %v", err)
	}
	if got := readIndexCount(); got != 1 {
		t.Fatalf("合并后索引数=%d, want 1（自动建唯一索引）", got)
	}
	if marker := readMarker(); marker != "" {
		t.Fatalf("冲突解除后 marker=%q, want 空", marker)
	}
}
