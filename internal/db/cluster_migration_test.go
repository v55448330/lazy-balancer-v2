package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestInitialize_migrates_cluster_columns_and_token_table(t *testing.T) {
	// Given
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, caddy_config TEXT, is_master BOOLEAN DEFAULT 1);
		INSERT INTO global_config VALUES (1, '{}', 1);
		CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT NOT NULL, mode TEXT, ip_address TEXT, port INTEGER, master_id INTEGER, is_approved BOOLEAN, sync_enabled BOOLEAN, sync_interval INTEGER, sync_scope TEXT, status TEXT, last_seen DATETIME, created_at DATETIME);`); err != nil {
		t.Fatalf("seed legacy database: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize migrated database: %v", err)
	}

	// Then
	var clusterVersion int
	var syncCaddy bool
	if err := DB.QueryRow("SELECT cluster_version, sync_caddy_config FROM global_config WHERE id=1").Scan(&clusterVersion, &syncCaddy); err != nil {
		t.Fatalf("read cluster defaults: %v", err)
	}
	if clusterVersion != 0 || syncCaddy {
		t.Fatalf("cluster defaults version=%d sync_caddy=%v", clusterVersion, syncCaddy)
	}
	var tokenTable int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cluster_register_tokens'").Scan(&tokenTable); err != nil {
		t.Fatalf("query token table: %v", err)
	}
	if tokenTable != 1 {
		t.Fatalf("cluster_register_tokens count=%d, want 1", tokenTable)
	}
	var usedTicketTable int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='used_login_tickets'").Scan(&usedTicketTable); err != nil {
		t.Fatalf("query used ticket table: %v", err)
	}
	if usedTicketTable != 1 {
		t.Fatalf("used_login_tickets count=%d, want 1", usedTicketTable)
	}
	for _, column := range []string{"cluster_token_hash", "registration_secret", "reported_version", "health_json", "last_sync_at", "last_sync_error", "access_url"} {
		var count int
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name=?", column).Scan(&count); err != nil {
			t.Fatalf("query nodes column %s: %v", column, err)
		}
		if count != 1 {
			t.Fatalf("nodes column %s count=%d, want 1", column, count)
		}
	}
}
