package db

// 正常请求日聚合持久化（2026-11）schema RED→GREEN 用例：
//   - metrics_daily_agg（规则级 × 本地日历日 的差分增量聚合）与
//     metrics_counter_checkpoint（采集侧已入账水位）随 initMetricsSchema
//     建出——全新库与存量库同路径（CREATE TABLE IF NOT EXISTS 幂等）；
//   - 日期索引 idx_daily_agg_date 支撑总览读路径按日窗口扫描；
//   - 重复初始化不重建（行不复活、列不丢）。

import (
	"testing"
)

func countMetricsTableRowsDailyAgg(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := MetricsDB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestInitMetricsSchema_createsDailyAggAndCheckpointTables(t *testing.T) {
	path := t.TempDir() + "/daily-agg.db"
	if err := InitializeMetricsDB(path); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() { _ = MetricsDB.Close() })

	for _, table := range []string{"metrics_daily_agg", "metrics_counter_checkpoint"} {
		var n int
		if err := MetricsDB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?)`, table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatalf("表 %s 未随 initMetricsSchema 建出（存量库升级后读/写路径将以 no such table 失败）", table)
		}
	}

	// 列形状（与方案 DDL 一致）：聚合表按 (rule_id, local_date) 主键；checkpoint
	// 三列累计水位。
	wantAggCols := map[string]bool{"rule_id": false, "local_date": false, "requests_delta": false, "blocked_delta": false, "logged_delta": false}
	rows, err := MetricsDB.Query(`SELECT name FROM pragma_table_info('metrics_daily_agg')`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if _, ok := wantAggCols[name]; ok {
			wantAggCols[name] = true
		}
	}
	rows.Close()
	for col, seen := range wantAggCols {
		if !seen {
			t.Fatalf("metrics_daily_agg 缺列 %s", col)
		}
	}
	for _, col := range []string{"rule_id", "requests_total", "requests_blocked", "requests_logged"} {
		var n int
		if err := MetricsDB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('metrics_counter_checkpoint') WHERE name=?`, col).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("metrics_counter_checkpoint 缺列 %s", col)
		}
	}

	// 日窗口扫描索引在位。
	var idx int
	if err := MetricsDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_daily_agg_date'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatal("idx_daily_agg_date 未建出——总览读路径按 local_date 窗口扫描将全表扫描")
	}

	// UPSERT 语义（累加式聚合的写形状）：同主键重复写入走增量相加。
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_daily_agg (rule_id, local_date, requests_delta, blocked_delta, logged_delta)
		VALUES ('lb_a', '2026-11-01', 10, 2, 1)`); err != nil {
		t.Fatalf("insert agg row: %v", err)
	}
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_daily_agg (rule_id, local_date, requests_delta, blocked_delta, logged_delta)
		VALUES ('lb_a', '2026-11-01', 5, 0, 0)
		ON CONFLICT(rule_id, local_date) DO UPDATE SET
		requests_delta = requests_delta + excluded.requests_delta,
		blocked_delta = blocked_delta + excluded.blocked_delta,
		logged_delta = logged_delta + excluded.logged_delta`); err != nil {
		t.Fatalf("upsert agg row: %v", err)
	}
	var total, blocked, logged int
	if err := MetricsDB.QueryRow(`SELECT requests_delta, blocked_delta, logged_delta FROM metrics_daily_agg WHERE rule_id='lb_a' AND local_date='2026-11-01'`).Scan(&total, &blocked, &logged); err != nil {
		t.Fatal(err)
	}
	if total != 15 || blocked != 2 || logged != 1 {
		t.Fatalf("upsert 累加语义 broken: total=%d blocked=%d logged=%d, want 15/2/1", total, blocked, logged)
	}
}

// 幂等：重复初始化不报错、既有数据不复活也不丢失（存量库每次启动都会重放
// initMetricsSchema）。
func TestInitMetricsSchema_dailyAggIdempotent(t *testing.T) {
	path := t.TempDir() + "/daily-agg-idem.db"
	if err := InitializeMetricsDB(path); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_daily_agg (rule_id, local_date, requests_delta) VALUES ('lb_x', '2026-11-01', 7)`); err != nil {
		t.Fatalf("seed agg row: %v", err)
	}
	// 重新走完整初始化（同路径第二次）。
	if err := InitializeMetricsDB(path); err != nil {
		t.Fatalf("re-initialize metrics database: %v", err)
	}
	t.Cleanup(func() { _ = MetricsDB.Close() })
	if got := countMetricsTableRowsDailyAgg(t, "metrics_daily_agg"); got != 1 {
		t.Fatalf("metrics_daily_agg rows=%d after re-init, want 1（重放不得灌回/清空既有行）", got)
	}
}
