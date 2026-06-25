package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
)

func InitializeMetricsDB(dataDir string) error {
	dbPath := filepath.Join(dataDir, "lazy-balancer-metrics.db")

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=30000&_synchronous=NORMAL")
	if err != nil {
		return fmt.Errorf("failed to open metrics database: %w", err)
	}

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping metrics database: %w", err)
	}

	MetricsDB = db

	schema := `
	CREATE TABLE IF NOT EXISTS metrics_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20),
		timestamp DATETIME NOT NULL,
		requests_total INTEGER DEFAULT 0,
		requests_2xx INTEGER DEFAULT 0,
		requests_3xx INTEGER DEFAULT 0,
		requests_4xx INTEGER DEFAULT 0,
		requests_5xx INTEGER DEFAULT 0,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		latency_p50 INTEGER DEFAULT 0,
		latency_p95 INTEGER DEFAULT 0,
		latency_p99 INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_rule ON metrics_history(rule_id);
	`

	_, err = MetricsDB.Exec(schema)
	return err
}
