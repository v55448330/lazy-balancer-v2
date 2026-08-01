package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestFlushAPIKeyLastUsedBatchesDirtyKeys(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE api_keys (id INTEGER PRIMARY KEY, last_used DATETIME);
		INSERT INTO api_keys (id) VALUES (1),(2);`); err != nil {
		t.Fatal(err)
	}
	SetDB(database)
	MarkAPIKeyUsed(1)
	MarkAPIKeyUsed(1)
	MarkAPIKeyUsed(2)

	// When
	if err := FlushAPIKeyLastUsed(); err != nil {
		t.Fatal(err)
	}

	// Then
	for _, id := range []int{1, 2} {
		var lastUsed sql.NullTime
		if err := database.QueryRow("SELECT last_used FROM api_keys WHERE id=?", id).Scan(&lastUsed); err != nil {
			t.Fatal(err)
		}
		if !lastUsed.Valid {
			t.Fatalf("api key %d last_used is NULL", id)
		}
	}
}

func TestCloseFlushesDirtyAPIKeyUsage(t *testing.T) {
	// Given
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() { DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB })
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec("INSERT INTO users (id,username,password_hash) VALUES (1,'close-user','hash')"); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec("INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by) VALUES (9,'close-key','hash','prefix',1)"); err != nil {
		t.Fatal(err)
	}
	MarkAPIKeyUsed(9)

	// When
	if err := Close(); err != nil {
		t.Fatal(err)
	}

	// Then
	database, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var lastUsed sql.NullTime
	if err := database.QueryRow("SELECT last_used FROM api_keys WHERE id=9").Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if !lastUsed.Valid {
		t.Fatal("last_used is NULL after Close")
	}
}
