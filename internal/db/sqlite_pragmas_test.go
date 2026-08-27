package db

import (
	"database/sql"
	"path/filepath"
	"strings"
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

// R-sqlite-pragmas-mask：busy_timeout/synchronous 的连接级生效通道是 DSN _pragma（驱动
// 对每条新连接执行）。若驱动 _pragma 处理回退（274f3028 修复的静默忽略同类回归），
// 守卫必须在专用连接上只读回读并报错——不能先在采样连接上 Exec 修复再自证通过，
// 否则其余连接仍跑驱动默认值（busy_timeout=5000 / synchronous=FULL）而守卫放行。
func TestApplySQLiteRuntimePragmas_rejectsWeakenedDSN(t *testing.T) {
	// Given 一个缺失 busy_timeout/synchronous _pragma 的弱化 DSN 打开的句柄
	path := filepath.Join(t.TempDir(), "weak.db")
	handle, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open weakened dsn: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	if err := handle.Ping(); err != nil {
		t.Fatalf("ping weakened handle: %v", err)
	}

	// When 运行期守卫检查该句柄
	err = applySQLiteRuntimePragmas(handle)

	// Then 必须报错并点名失配项（驱动默认 busy_timeout=5000、synchronous=FULL(2)）
	if err == nil {
		t.Fatal("expected error for DSN missing busy_timeout/synchronous _pragma, got nil")
	}
	if !strings.Contains(err.Error(), "busy_timeout") && !strings.Contains(err.Error(), "synchronous") {
		t.Fatalf("error should name the mismatched pragma, got: %v", err)
	}
}

// R-sqlite-pragmas-migrate：journal_mode=WAL 的显式 apply 必须保留——它是旧 delete 模式
// 库文件的迁移路径（文件级、幂等、不受连接遮蔽影响），删掉它旧库永远停在 delete。
func TestApplySQLiteRuntimePragmas_migratesDeleteModeFile(t *testing.T) {
	// Given 一个以 delete 模式创建的库文件（DSN 不带任何 _pragma）
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy dsn: %v", err)
	}
	if _, err := legacy.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatalf("force delete mode: %v", err)
	}
	if _, err := legacy.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	var mode string
	if err := legacy.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read legacy journal_mode: %v", err)
	}
	if mode != "delete" {
		t.Fatalf("legacy file journal_mode=%s, want delete", mode)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy handle: %v", err)
	}

	// When 以生产 DSN 重新打开并跑守卫
	handle, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		t.Fatalf("open production dsn: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	if err := handle.Ping(); err != nil {
		t.Fatalf("ping production handle: %v", err)
	}
	if err := applySQLiteRuntimePragmas(handle); err != nil {
		t.Fatalf("apply pragmas on migrated file: %v", err)
	}

	// Then 文件已迁移到 wal
	if err := handle.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read migrated journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode=%s, want wal", mode)
	}
}
