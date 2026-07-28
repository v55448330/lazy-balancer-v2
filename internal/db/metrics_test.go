package db

import (
	"database/sql"
	"testing"
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

func TestInitialize_adds_metrics_retention_and_composite_indexes(t *testing.T) {
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
	var retentionDays int
	if err := DB.QueryRow("SELECT metrics_retention_days FROM global_config WHERE id=1").Scan(&retentionDays); err != nil {
		t.Fatalf("read metrics retention: %v", err)
	}

	// Then
	if retentionDays != 7 {
		t.Fatalf("metrics retention days=%d, want 7", retentionDays)
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
