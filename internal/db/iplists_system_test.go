package db

import (
	"testing"
)

// 威胁情报库名单化（v2.3.2 重构）：security_ip_lists 增 system 列，
// 三个内置只读名单随迁移种子（name 稳定、条目空、由更新任务独占写）。
func TestIPListsSystemColumn_seededThreatLists(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	rows, err := database.Query(`SELECT name, category, system, entries FROM security_ip_lists WHERE system=1 ORDER BY id`)
	if err != nil {
		t.Fatalf("query system lists: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name, category, entries string
		var system bool
		if err := rows.Scan(&name, &category, &system, &entries); err != nil {
			t.Fatal(err)
		}
		if !system || entries != "[]" {
			t.Fatalf("system list %q: system=%v entries=%q, want system=1 且空名单", name, system, entries)
		}
		got = append(got, name)
	}
	if len(got) != 3 {
		t.Fatalf("system lists=%d %v, want 3", len(got), got)
	}

	// 幂等：二次迁移不重复种子
	if err := runMigrations(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count=%d after re-seed, want 3", count)
	}
}

// 存量库迁移：无 system 列的旧表经 newColumns 补列后三行种子落位。
func TestIPListsSystemColumn_legacyMigration(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE security_ip_lists (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '',
		category TEXT DEFAULT '', entries TEXT DEFAULT '[]',
		created_by INTEGER DEFAULT 0, created_at TEXT DEFAULT '', updated_by INTEGER DEFAULT 0, updated_at TEXT DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	if err := createTables(); err != nil {
		t.Fatalf("createTables on legacy schema: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatal(err)
	}
	// newColumns 在 runMigrations——模拟生产迁移顺序
	if err := runMigrations(); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1`).Scan(&count); err != nil {
		t.Fatalf("system column missing after migration: %v", err)
	}
	if count != 3 {
		t.Fatalf("migrated system lists=%d, want 3", count)
	}
}
