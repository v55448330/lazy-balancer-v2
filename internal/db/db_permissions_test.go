package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialize_tightens_database_directory_and_files(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0755); err != nil {
		t.Fatalf("create permissive data directory: %v", err)
	}
	for _, name := range []string{"lazy-balancer.db", "lazy-balancer-audit.db", "lazy-balancer-metrics.db"} {
		path := filepath.Join(dataDir, name)
		if err := os.WriteFile(path, nil, 0644); err != nil {
			t.Fatalf("create permissive database %s: %v", name, err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatalf("set permissive database mode %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When
	if err := Initialize(dataDir); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	type liveWAL struct {
		tx   *sql.Tx
		conn *sql.Conn
	}
	var liveWALs []liveWAL
	for _, write := range []struct {
		database       *sql.DB
		readStatement  string
		writeStatement string
	}{
		{database: DB, readStatement: "SELECT COUNT(*) FROM global_config", writeStatement: "UPDATE global_config SET updated_at=CURRENT_TIMESTAMP WHERE id=1"},
		{database: AuditDB, readStatement: "SELECT COUNT(*) FROM audit_log", writeStatement: "INSERT INTO audit_log (action) VALUES ('permission-test')"},
		{database: MetricsDB, readStatement: "SELECT COUNT(*) FROM metrics_history", writeStatement: "INSERT INTO metrics_history (timestamp) VALUES (CURRENT_TIMESTAMP)"},
	} {
		tx, conn := holdSQLiteWAL(t, write.database, write.readStatement, write.writeStatement)
		liveWALs = append(liveWALs, liveWAL{tx: tx, conn: conn})
	}
	t.Cleanup(func() {
		for _, wal := range liveWALs {
			_ = wal.tx.Rollback()
			_ = wal.conn.Close()
		}
	})

	// Then
	requirePathMode(t, dataDir, 0700)
	for _, name := range []string{"lazy-balancer.db", "lazy-balancer-audit.db", "lazy-balancer-metrics.db"} {
		path := filepath.Join(dataDir, name)
		requirePathMode(t, path, 0600)
		requirePathMode(t, path+"-wal", 0600)
		requireOptionalPathMode(t, path+"-shm", 0600)
	}
}

func TestInitialize_preserves_permissions_when_WAL_is_rebuilt(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	dataDir := filepath.Join(t.TempDir(), "data")
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dataDir); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	path := filepath.Join(dataDir, "lazy-balancer.db")
	tx, conn := holdSQLiteWAL(t, DB, "SELECT COUNT(*) FROM global_config", "UPDATE global_config SET updated_at=CURRENT_TIMESTAMP WHERE id=1")
	requirePathMode(t, path+"-wal", 0600)
	if err := tx.Rollback(); err != nil {
		t.Fatalf("release WAL reader: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close WAL reader connection: %v", err)
	}
	if _, err := DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint WAL: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close checkpointed databases: %v", err)
	}

	// When
	if err := Initialize(dataDir); err != nil {
		t.Fatalf("reinitialize databases: %v", err)
	}
	tx, conn = holdSQLiteWAL(t, DB, "SELECT COUNT(*) FROM global_config", "UPDATE global_config SET updated_at=CURRENT_TIMESTAMP WHERE id=1")
	t.Cleanup(func() {
		_ = tx.Rollback()
		_ = conn.Close()
	})

	// Then
	requirePathMode(t, path+"-wal", 0600)
}

func holdSQLiteWAL(t *testing.T, database *sql.DB, readStatement, writeStatement string) (*sql.Tx, *sql.Conn) {
	t.Helper()
	ctx := context.Background()
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire SQLite connection: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		_ = conn.Close()
		t.Fatalf("enable WAL mode: %v", err)
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("begin WAL reader: %v", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, readStatement).Scan(&count); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("establish WAL reader snapshot: %v", err)
	}
	if _, err := database.ExecContext(ctx, writeStatement); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("create WAL sidecar: %v", err)
	}
	return tx, conn
}

func TestSecureSQLiteArtifacts_tightens_existing_sidecars(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "database.db")
	for _, artifact := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.WriteFile(artifact, nil, 0644); err != nil {
			t.Fatalf("create permissive artifact: %v", err)
		}
		if err := os.Chmod(artifact, 0644); err != nil {
			t.Fatalf("set permissive artifact mode: %v", err)
		}
	}

	// When
	if err := secureSQLiteArtifacts(path); err != nil {
		t.Fatalf("secure SQLite artifacts: %v", err)
	}

	// Then
	for _, artifact := range []string{path, path + "-wal", path + "-shm"} {
		requirePathMode(t, artifact, 0600)
	}
}

func requirePathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s=%04o, want %04o", path, got, want)
	}
}

func requireOptionalPathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s=%04o, want %04o", path, got, want)
	}
}
