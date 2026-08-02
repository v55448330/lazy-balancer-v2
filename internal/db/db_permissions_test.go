package db

import (
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
	for _, write := range []struct {
		database interface {
			Exec(string, ...any) (sql.Result, error)
		}
		statement string
	}{
		{database: DB, statement: "UPDATE global_config SET updated_at=CURRENT_TIMESTAMP WHERE id=1"},
		{database: AuditDB, statement: "INSERT INTO audit_log (action) VALUES ('permission-test')"},
		{database: MetricsDB, statement: "INSERT INTO metrics_history (timestamp) VALUES (CURRENT_TIMESTAMP)"},
	} {
		if _, err := write.database.Exec(write.statement); err != nil {
			t.Fatalf("create WAL sidecars: %v", err)
		}
	}

	// Then
	requirePathMode(t, dataDir, 0700)
	for _, name := range []string{"lazy-balancer.db", "lazy-balancer-audit.db", "lazy-balancer-metrics.db"} {
		path := filepath.Join(dataDir, name)
		requirePathMode(t, path, 0600)
		requireOptionalPathMode(t, path+"-wal", 0600)
		requireOptionalPathMode(t, path+"-shm", 0600)
	}
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
