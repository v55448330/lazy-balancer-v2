package db

// 唯一索引「探测门 + IF NOT EXISTS」的形状洞：CREATE UNIQUE INDEX IF NOT
// EXISTS 只判名字不判形状——同名非唯一索引存在时「唯一化」会静默 no-op，
// 重复行继续可写而启动日志全绿。三处索引（system 名单名 / OIDC 身份 / 安全
// 事件事务号）必须把形状不符的同名索引重建为唯一。

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateSystemIPListUniqueIndex_rebuildsSameNameNonUniqueIndex(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 带外 DDL 形态：同名非唯一索引已在位（旧工具/手工建索引）。
	if _, err := DB.Exec(`DROP INDEX IF EXISTS u_security_ip_lists_system_name;
		CREATE INDEX u_security_ip_lists_system_name ON security_ip_lists(name) WHERE system=1`); err != nil {
		t.Fatalf("install same-name non-unique index: %v", err)
	}

	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 列必须是 security_ip_lists 的真实列（name/entries/system）：此前用
	// value/type/enabled 三个不存在的列，两条语句都以 "no such column" 失败，
	// 「唯一性未生效才报错」的断言因此恒真通过（假绿）。
	assertUniqueIndexRebuilt(t, DB, "u_security_ip_lists_system_name",
		`INSERT INTO security_ip_lists (name, entries, system) VALUES ('dup-name','["1.1.1.1"]',1);
		 INSERT INTO security_ip_lists (name, entries, system) VALUES ('dup-name','["2.2.2.2"]',1)`)
}

func TestMigrateOidcIdentityUniqueIndex_rebuildsSameNameNonUniqueIndex(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if err := ensureNewColumns(newColumnsRegistry, nil); err != nil {
		t.Fatalf("add new columns: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO global_config (id, caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := DB.Exec(`DROP INDEX IF EXISTS u_oidc_identity;
		CREATE INDEX u_oidc_identity ON users(oidc_issuer, oidc_subject) WHERE auth_provider='oidc' AND oidc_subject<>''`); err != nil {
		t.Fatalf("install same-name non-unique index: %v", err)
	}

	if err := migrateOidcIdentityUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	assertUniqueIndexRebuilt(t, DB, "u_oidc_identity",
		`INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer) VALUES ('a','x','user',1,'oidc','sub','https://idp');
		 INSERT INTO users (username, password_hash, role, is_enabled, auth_provider, oidc_subject, oidc_issuer) VALUES ('b','x','user',1,'oidc','sub','https://idp')`)
}

func TestEnsureSecurityEventsTransactionIndex_rebuildsSameNameNonUniqueIndex(t *testing.T) {
	metrics, err := openAndPingMetricsDB(filepath.Join(t.TempDir(), "metrics-index-shape.db"))
	if err != nil {
		t.Fatalf("open metrics database: %v", err)
	}
	t.Cleanup(func() { _ = metrics.Close() })
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("init metrics schema: %v", err)
	}
	// 初始化已建好唯一索引：换成同名非唯一索引模拟带外 DDL。
	if _, err := metrics.Exec(`DROP INDEX idx_security_events_transaction;
		CREATE INDEX idx_security_events_transaction ON security_events(transaction_id) WHERE transaction_id != ''`); err != nil {
		t.Fatalf("install same-name non-unique index: %v", err)
	}

	if err := ensureSecurityEventsTransactionIndex(metrics); err != nil {
		t.Fatalf("ensure index: %v", err)
	}

	assertUniqueIndexRebuilt(t, metrics, "idx_security_events_transaction",
		`INSERT INTO security_events (transaction_id) VALUES ('tx-dup'); INSERT INTO security_events (transaction_id) VALUES ('tx-dup')`)
}

// assertUniqueIndexRebuilt 断言索引已按目标形状重建（UNIQUE），且重复行写入被拒。
func assertUniqueIndexRebuilt(t *testing.T, database *sql.DB, indexName, duplicateInsert string) {
	t.Helper()
	var indexSQL sql.NullString
	if err := database.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, indexName).Scan(&indexSQL); err != nil {
		t.Fatalf("inspect index %s: %v", indexName, err)
	}
	if !indexSQL.Valid || !strings.Contains(strings.ToUpper(indexSQL.String), "UNIQUE") {
		t.Fatalf("索引 %s 未被重建为唯一：%q（同名非唯一索引让唯一化静默 no-op）", indexName, indexSQL.String)
	}
	if _, err := database.Exec(duplicateInsert); err == nil {
		t.Fatalf("索引 %s 已显示 UNIQUE，但重复行仍可写入", indexName)
	}
}

// 反向形状：形状一致时零 DDL（唯一索引不被无谓重建，启动不白付写事务）。
func TestEnsureUniqueIndex_matchingShapeIsNoOp(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "shape-noop.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(`CREATE TABLE t(a INTEGER, b TEXT)`); err != nil {
		t.Fatal(err)
	}
	const ddl = `CREATE UNIQUE INDEX u_t ON t(a) WHERE b<>''`
	if err := ensureUniqueIndex(database, "u_t", ddl); err != nil {
		t.Fatalf("首次建立: %v", err)
	}
	before := indexRootPage(t, database, "u_t")
	if err := ensureUniqueIndex(database, "u_t", ddl); err != nil {
		t.Fatalf("二次建立: %v", err)
	}
	if after := indexRootPage(t, database, "u_t"); after != before {
		t.Fatalf("形状一致时索引被重建（rootpage %d → %d）", before, after)
	}
}

// indexRootPage 用 rootpage 判定索引对象是否被重建（重建必换 rootpage）。
func indexRootPage(t *testing.T, database *sql.DB, name string) int {
	t.Helper()
	var root int
	if err := database.QueryRow(`SELECT rootpage FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&root); err != nil {
		t.Fatalf("read index rootpage: %v", err)
	}
	return root
}
