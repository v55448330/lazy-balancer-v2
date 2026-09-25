package db

// 第 57 轮追加问题 RED（用户上报：更新 ip2region 定时更新时间报
// 「SQL logic error: no such column: schedule_days」）：
// security_ip2region_version 的 schedule_days/schedule_time 两列在 fresh DDL
// 建表语句中存在，但存量库补列迁移（newColumns）漏登记——升级安装该表缺列，
// SetIP2RegionSchedule 的 UPDATE 必报 no such column，功能自规则库定时调度
// 上线起在全部升级库不可用（CRS 侧同族两列已在 map 中，单侧漏登记）。
// 契约：存量库经 runMigrations 补齐两列（幂等），SetIP2RegionSchedule 可用。

import (
	"testing"
)

func TestRunMigrations_addsMissingIP2RegionScheduleColumns(t *testing.T) {
	// Given：存量库的 security_ip2region_version 缺 schedule 两列
	//（模拟规则库定时调度上线前的 schema：先建表再手工重建为旧形态）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,access_log_format,audit_retention_months) VALUES (1,'{}','{"fields":["ts","status"]}',3);
		DROP TABLE security_ip2region_version;
		CREATE TABLE security_ip2region_version (
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
			finished_at DATETIME,
			consecutive_failures INTEGER DEFAULT 0
		);
		INSERT INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'v3.17.0', TRUE);`); err != nil {
		t.Fatalf("seed legacy ip2region version table: %v", err)
	}

	// When（两次，证明幂等）
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then：两列已补，缺省值正确，行数据存活
	for _, col := range []string{"schedule_days", "schedule_time"} {
		var n int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_ip2region_version') WHERE name=?", col).Scan(&n); err != nil {
			t.Fatalf("query schema: %v", err)
		}
		if n != 1 {
			t.Fatalf("列 %s 未迁移（升级库 ip2region 定时更新不可用根因）", col)
		}
	}
	var days, tm, version string
	if err := database.QueryRow(`SELECT schedule_days, schedule_time, version FROM security_ip2region_version WHERE id=1`).Scan(&days, &tm, &version); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if days != "1,2,3,4,5,6,7" || tm != "04:00" {
		t.Fatalf("defaults=(%q,%q), want (1,2,3,4,5,6,7 / 04:00)", days, tm)
	}
	if version != "v3.17.0" {
		t.Fatalf("version=%q, want 存量行数据存活", version)
	}
}
