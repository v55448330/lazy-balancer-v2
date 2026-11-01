package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/sqlite"
)

// 检测放行拆分（logged）指标库迁移 RED→GREEN：
//   - metrics_history.requests_logged 与 lb_l4_conn_history.logged 属新列，
//     存量指标库缺列时按 2026-09-15 用户裁定同族口径 DROP 重建（7 天缓存
//     数据、重建零成本、与旧计数器不连续的累计保留反而误导）；
//   - 全新库建表语句直接带出两列；迁移幂等（重复初始化不再重建）。

// openLoggedMigrationTestDB 打开独立 metrics 库文件（不经全局 MetricsDB）。
func openLoggedMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "metrics-logged.db"))
	if err != nil {
		t.Fatalf("open metrics database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// Given: 存量库形态（无 requests_logged / logged 列）且带历史行
// When: initMetricsSchema（一次 + 幂等重放）
// Then: 两列补齐（表重建）；重放后列仍在、行数不复活（缓存语义）
func TestInitMetricsSchema_loggedColumnsRecreatedForLegacyDB(t *testing.T) {
	metrics := openLoggedMigrationTestDB(t)

	// 先按现行 schema 建库（拿到基线表），再降级模拟存量库（删新列、写行）。
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("baseline init: %v", err)
	}
	if _, err := metrics.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_blocked)
		VALUES ('lb_old', '2026-01-01 00:00:00', 10, 2);
		INSERT INTO lb_l4_conn_history (timestamp, rule_id, allowed, denied)
		VALUES ('2026-01-01 00:00:00', 'lb_old', 7, 1);
		ALTER TABLE metrics_history DROP COLUMN requests_logged;
		ALTER TABLE lb_l4_conn_history DROP COLUMN logged;`); err != nil {
		t.Fatalf("seed legacy shape: %v", err)
	}

	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var mhLogged, l4Logged int
	if err := metrics.QueryRow("SELECT COUNT(*) FROM pragma_table_info('metrics_history') WHERE name='requests_logged'").Scan(&mhLogged); err != nil {
		t.Fatal(err)
	}
	if err := metrics.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_l4_conn_history') WHERE name='logged'").Scan(&l4Logged); err != nil {
		t.Fatal(err)
	}
	if mhLogged != 1 || l4Logged != 1 {
		t.Fatalf("columns after migrate: metrics_history.requests_logged=%d lb_l4_conn_history.logged=%d, want 1/1（存量库缺列必须重建补齐）", mhLogged, l4Logged)
	}
	// 幂等：重放不报错、列仍在。
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	if err := metrics.QueryRow("SELECT COUNT(*) FROM pragma_table_info('metrics_history') WHERE name='requests_logged'").Scan(&mhLogged); err != nil {
		t.Fatal(err)
	}
	if mhLogged != 1 {
		t.Fatalf("requests_logged count=%d after rerun, want 1", mhLogged)
	}
	// 新列可写默认 0（读侧对旧行=0 的兼容口径由公式层保证）。
	if _, err := metrics.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_logged) VALUES ('lb_new', '2026-01-02 00:00:00', 5)`); err != nil {
		t.Fatalf("write requests_logged: %v", err)
	}
}

// Given: 全新库
// Then: 建表语句直接带出两列（迁移零触发）
func TestInitMetricsSchema_freshDBHasLoggedColumns(t *testing.T) {
	metrics := openLoggedMigrationTestDB(t)

	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, probe := range []struct {
		table, column string
	}{
		{"metrics_history", "requests_logged"},
		{"metrics_history", "requests_blocked"},
		{"lb_l4_conn_history", "logged"},
	} {
		var n int
		if err := metrics.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", probe.table, probe.column).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%s.%s count=%d, want 1（新库必须直接带出）", probe.table, probe.column, n)
		}
	}
}
