package db

import (
	"testing"
)

// S-6/S-7（2026-09-05/06 审计裁定）：global_config 的 metrics_public /
// metrics_origins（零消费死列）与 metrics_retention_days（指标保留期已改用
// audit_retention_months，2026-09-06 裁定）三列迁移删除。契约：①存量库迁移
// 删除且幂等、行数据存活；②新库经 createTables+runMigrations 全流程后不再
// 补建。镜像 TestRunMigrations_dropsDeadSecurityAndAdminTLSColumns 的
// legacy 列残留 → 两次迁移 → 数据存活模式。
func TestRunMigrations_dropsDeadMetricsColumns(t *testing.T) {
	// Given：存量库仍带三列（历史上由建表语句与 newColumns 迁移补建）
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE global_config ADD COLUMN metrics_public BOOLEAN DEFAULT 0;
		ALTER TABLE global_config ADD COLUMN metrics_origins VARCHAR(500);
		ALTER TABLE global_config ADD COLUMN metrics_retention_days INTEGER DEFAULT 7;
		UPDATE global_config SET metrics_public=1, metrics_origins='https://legacy.example.test', metrics_retention_days=30, timezone='Asia/Shanghai' WHERE id=1;`); err != nil {
		t.Fatalf("seed legacy dead columns: %v", err)
	}

	// When（两次，证明幂等）
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}

	// Then：三列已删，其余配置存活
	var deadColumns int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name IN ('metrics_public','metrics_origins','metrics_retention_days')").Scan(&deadColumns); err != nil {
		t.Fatalf("query global_config schema: %v", err)
	}
	if deadColumns != 0 {
		t.Fatalf("dead metrics columns count=%d, want 0", deadColumns)
	}
	var timezone string
	if err := database.QueryRow("SELECT COALESCE(timezone,'') FROM global_config WHERE id=1").Scan(&timezone); err != nil {
		t.Fatalf("read surviving config: %v", err)
	}
	if timezone != "Asia/Shanghai" {
		t.Fatalf("timezone=%q, want preserved Asia/Shanghai", timezone)
	}
}

// 新库不补建：createTables + runMigrations 全流程后三列不存在。
func TestRunMigrations_doesNotRecreateDeadMetricsColumns(t *testing.T) {
	// Given：全新库
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
	var deadColumns int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name IN ('metrics_public','metrics_origins','metrics_retention_days')").Scan(&deadColumns); err != nil {
		t.Fatalf("query global_config schema: %v", err)
	}
	if deadColumns != 0 {
		t.Fatalf("dead metrics columns count=%d, want 0（新库不得补建死列）", deadColumns)
	}
}
