package db

import (
	"database/sql"
	"testing"
)

// R-sqlite-pragmas：DSN 中的 _journal_mode/_busy_timeout/_synchronous 会被 glebarez
// 驱动静默忽略（仅 _pragma/_txlock/_time_format 生效，且驱动无条件 busy_timeout=5000），
// 三个库必须在 open 后显式落 PRAGMA——否则主库常年跑 delete+5s，任何长写事务都会
// 把 BEGIN IMMEDIATE 的读写全线拖垮（v2.2.0 生产 SQLITE_BUSY 级联的根因之一）。
func TestInitialize_appliesSQLiteRuntimePragmas(t *testing.T) {
	// Given 全新数据目录初始化
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize databases: %v", err)
	}
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// When/Then 三库的 journal_mode 必须为 wal、busy_timeout 必须为 30000、synchronous 为 NORMAL
	assert := func(label string, handle *sql.DB, pragma, want string) {
		t.Helper()
		var got string
		if err := handle.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatalf("%s: read %s: %v", label, pragma, err)
		}
		if got != want {
			t.Fatalf("%s: %s=%s, want %s", label, pragma, got, want)
		}
	}
	for label, handle := range map[string]*sql.DB{"main": DB, "metrics": MetricsDB, "audit": AuditDB} {
		assert(label, handle, "journal_mode", "wal")
		assert(label, handle, "busy_timeout", "30000")
		assert(label, handle, "synchronous", "1") // NORMAL=1
	}
}
