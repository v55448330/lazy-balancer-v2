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
	if err := DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&clusterVersion); err != nil {
		t.Fatalf("read cluster defaults: %v", err)
	}
	if clusterVersion != 0 {
		t.Fatalf("cluster version=%d, want 0", clusterVersion)
	}
	var syncCaddyColumn int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='sync_caddy_config'").Scan(&syncCaddyColumn); err != nil {
		t.Fatalf("query sync_caddy_config column: %v", err)
	}
	if syncCaddyColumn != 0 {
		t.Fatalf("sync_caddy_config column still present (count=%d), want dropped", syncCaddyColumn)
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
	var revokedJTITable int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='revoked_jti'").Scan(&revokedJTITable); err != nil {
		t.Fatalf("query revoked JWT table: %v", err)
	}
	if revokedJTITable != 1 {
		t.Fatalf("revoked_jti count=%d, want 1", revokedJTITable)
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
