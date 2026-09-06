package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupMetricsHistory_deletes_expired_global_and_rule_rows(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp) VALUES
		(NULL, datetime('now','-8 days')),
		('lb_old', datetime('now','-8 days')),
		(NULL, datetime('now')),
		('lb_fresh', datetime('now'))`); err != nil {
		t.Fatalf("seed metrics history: %v", err)
	}

	// When
	if err := CleanupMetricsHistory(7); err != nil {
		t.Fatalf("cleanup metrics history: %v", err)
	}

	// Then
	var oldRows, freshRows int
	if err := MetricsDB.QueryRow(`SELECT
		SUM(CASE WHEN timestamp < datetime('now','-7 days') THEN 1 ELSE 0 END),
		SUM(CASE WHEN timestamp >= datetime('now','-7 days') THEN 1 ELSE 0 END)
		FROM metrics_history`).Scan(&oldRows, &freshRows); err != nil {
		t.Fatalf("count metrics history: %v", err)
	}
	if oldRows != 0 || freshRows != 2 {
		t.Fatalf("history rows old=%d fresh=%d", oldRows, freshRows)
	}
}

// D3-F1 回归：过期历史清理必须分批执行（默认批 5000 下 12000 行过期数据
// 需 3 批），全部清理且保留保鲜行，重跑幂等零删除。
func TestCleanupMetricsHistory_batchesLargeDeletes(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp)
		WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 12000)
		SELECT 'lb_old', datetime('now','-8 days') FROM cnt`); err != nil {
		t.Fatalf("seed expired metrics history: %v", err)
	}
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp) VALUES
		(NULL, datetime('now')),
		('lb_fresh', datetime('now'))`); err != nil {
		t.Fatalf("seed fresh metrics history: %v", err)
	}

	// When
	if err := CleanupMetricsHistory(7); err != nil {
		t.Fatalf("cleanup metrics history: %v", err)
	}

	// Then
	var remaining int
	if err := MetricsDB.QueryRow("SELECT COUNT(*) FROM metrics_history").Scan(&remaining); err != nil {
		t.Fatalf("count metrics history: %v", err)
	}
	if remaining != 2 {
		t.Fatalf("remaining rows=%d, want 2 fresh rows only", remaining)
	}
	// 幂等：再次清理零删除、无错误、行数不变
	if err := CleanupMetricsHistory(7); err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
	if err := MetricsDB.QueryRow("SELECT COUNT(*) FROM metrics_history").Scan(&remaining); err != nil {
		t.Fatalf("recount metrics history: %v", err)
	}
	if remaining != 2 {
		t.Fatalf("idempotent re-run changed rows: %d", remaining)
	}
}

// D3-F1：用测试钩子收缩批次（30 行 / 批 7 = 5 批 4 次批间停顿，每次至少
// 10ms）证明清理确实跨批推进——单语句 DELETE 实现不感知批次变量，耗时
// 趋近 0，据此判红。
func TestCleanupMetricsHistory_loopsAcrossBatches(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	oldBatch := cleanupMetricsHistoryBatch
	cleanupMetricsHistoryBatch = 7
	t.Cleanup(func() { cleanupMetricsHistoryBatch = oldBatch })
	if _, err := MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp)
		WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 30)
		SELECT 'lb_old', datetime('now','-8 days') FROM cnt`); err != nil {
		t.Fatalf("seed expired metrics history: %v", err)
	}

	// When
	start := time.Now()
	if err := CleanupMetricsHistory(7); err != nil {
		t.Fatalf("cleanup metrics history: %v", err)
	}
	elapsed := time.Since(start)

	// Then
	var remaining int
	if err := MetricsDB.QueryRow("SELECT COUNT(*) FROM metrics_history").Scan(&remaining); err != nil {
		t.Fatalf("count metrics history: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining rows=%d, want 0 — cleanup must loop until all expired rows are gone", remaining)
	}
	// time.Sleep 保证至少停顿指定时长（单调时钟下界断言安全）：4 次批间
	// 停顿 ⇒ 至少 40ms；单语句实现无停顿会被此处捕获。
	if elapsed < 4*10*time.Millisecond {
		t.Fatalf("cleanup finished in %v, want >=40ms (4 inter-batch yields) — batching not in effect", elapsed)
	}
}

func TestInitialize_omitsMetricsRetentionColumnAndAddsCompositeIndexes(t *testing.T) {
	// S-7（2026-09-06 裁定）：指标保留期改用 audit_retention_months，
	// metrics_retention_days 死列不再建（随迁移删除）；复合索引契约保留。
	// Given
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	var retentionColumn int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='metrics_retention_days'").Scan(&retentionColumn); err != nil {
		t.Fatalf("inspect global_config schema: %v", err)
	}

	// Then
	if retentionColumn != 0 {
		t.Fatalf("metrics_retention_days column count=%d, want 0（死列不得再建）", retentionColumn)
	}
	for _, index := range []struct {
		database *sql.DB
		name     string
	}{
		{database: DB, name: "idx_cert_jobs_status_ca_available"},
		{database: DB, name: "idx_cert_jobs_status_expires"},
		{database: MetricsDB, name: "idx_metrics_rule_timestamp"},
	} {
		var count int
		if err := index.database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index.name).Scan(&count); err != nil {
			t.Fatalf("query index %s: %v", index.name, err)
		}
		if count != 1 {
			t.Fatalf("index %s count=%d, want 1", index.name, count)
		}
	}
}

func TestInitializeMetricsDB_preserves_global_when_schema_creation_fails(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "lazy-balancer-metrics.db")
	conflictingDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open conflicting metrics database: %v", err)
	}
	if _, err := conflictingDB.Exec("CREATE VIEW metrics_history AS SELECT 1 AS id"); err != nil {
		closeErr := conflictingDB.Close()
		t.Fatalf("create conflicting metrics schema: %v; close database: %v", err, closeErr)
	}
	if err := conflictingDB.Close(); err != nil {
		t.Fatalf("close conflicting metrics database: %v", err)
	}
	oldMetricsDB := MetricsDB
	sentinelDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sentinel metrics database: %v", err)
	}
	MetricsDB = sentinelDB
	t.Cleanup(func() {
		if err := sentinelDB.Close(); err != nil {
			t.Errorf("close sentinel metrics database: %v", err)
		}
		MetricsDB = oldMetricsDB
	})

	// When
	err = InitializeMetricsDB(dataDir)

	// Then
	if err == nil {
		t.Fatal("initialize metrics database succeeded, want schema error")
	}
	if MetricsDB != sentinelDB {
		t.Fatal("failed initialization replaced global metrics database")
	}
}
