package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestCleanupExpiredRegistrationSecretsClearsDeliveredSecretAfterWindow(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, registration_secret TEXT, registration_secret_expires_at DATETIME);
		INSERT INTO nodes VALUES (1,'expired',datetime('now','-1 second'));
		INSERT INTO nodes VALUES (2,'active',datetime('now','+1 hour'));`); err != nil {
		t.Fatal(err)
	}

	// When
	err := cleanupExpiredRegistrationSecrets(context.Background(), database)

	// Then
	if err != nil {
		t.Fatal(err)
	}
	var expired, active sql.NullString
	if err := database.QueryRow("SELECT registration_secret FROM nodes WHERE id=1").Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT registration_secret FROM nodes WHERE id=2").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if expired.Valid || !active.Valid || active.String != "active" {
		t.Fatalf("expired=%#v active=%#v", expired, active)
	}
}

// U12-F13（第 78 轮）：Close 关闭三句柄后必须清空包级句柄与 currentDB——
// 残留的已关闭 *sql.DB 会让后续 GetDB() 返回不可用句柄且在测试间泄漏；
// 重复 Close 必须幂等（nil 句柄跳过）。
func TestClose_clearsHandlesAndIsIdempotent(t *testing.T) {
	// Given
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	oldCurrent := GetDB()
	t.Cleanup(func() {
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
		SetDB(oldCurrent)
	})
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}

	// When
	if err := Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Then：句柄全部清空，重复 Close 幂等
	if DB != nil || MetricsDB != nil || AuditDB != nil {
		t.Fatalf("handles after Close: DB=%v MetricsDB=%v AuditDB=%v, want all nil", DB, MetricsDB, AuditDB)
	}
	if got := GetDB(); got != nil {
		t.Fatalf("GetDB() after Close=%v, want nil", got)
	}
	if err := Close(); err != nil {
		t.Fatalf("second Close must be idempotent: %v", err)
	}
}

func TestFlushAPIKeyLastUsedBatchesDirtyKeys(t *testing.T) {
	// Given
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE api_keys (id INTEGER PRIMARY KEY, last_used DATETIME);
		INSERT INTO api_keys (id) VALUES (1),(2);`); err != nil {
		t.Fatal(err)
	}
	SetDB(database)
	// U12-F12（第 78 轮）：currentDB 是包级全局，测试结束必须复位，否则后续
	// 测试的 GetDB()/flush 会落到本测试的已关闭临时库。
	oldCurrent := GetDB()
	t.Cleanup(func() { SetDB(oldCurrent) })
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
	oldCurrent := GetDB()
	t.Cleanup(func() {
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
		SetDB(oldCurrent)
	})
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
