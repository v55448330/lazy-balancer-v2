package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestInitializeMigratesAPIKeyMCPColumns(t *testing.T) {
	dataDir := t.TempDir()
	database, err := sql.Open("sqlite", filepath.Join(dataDir, "lazy-balancer.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE api_keys (
		id INTEGER PRIMARY KEY, name TEXT, key_hash TEXT, key_prefix TEXT, created_by INTEGER,
		last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN DEFAULT TRUE, created_at DATETIME
	)`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	if err := Initialize(dataDir); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	for _, column := range []string{"mcp_enabled", "read_only", "mcp_ip_whitelist"} {
		var count int
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name=?", column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("column %s count=%d, want 1", column, count)
		}
	}
}
