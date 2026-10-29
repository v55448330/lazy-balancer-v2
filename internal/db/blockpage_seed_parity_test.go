package db

import (
	"database/sql"
	"testing"
)

// 内置备选页的清单即事实源：播种循环逐条生成 SQL（builtinBlockPageSeeds），
// 探测（builtinBlockPageCount）与播种消费同一清单——逐字段断言 seed 与库内
// 行一致（名字/描述/内容/is_default/is_builtin 任一分叉即红）。新增第三页
// 只加清单条目，无需改任何 SQL。
func TestRunMigrations_builtinBlockPageSeedsMatchRows(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	originalSeeds := builtinBlockPageSeeds
	customSeeds := []builtinBlockPageSeed{
		{ID: 19001, Name: "限流拦截页面", Description: "系统内置 429 限流拦截页面（备选，手动选用后生效）", Content: "<!DOCTYPE html><html><title>Too Many Requests</title></html>", IsBuiltin: true},
		{ID: 19002, Name: "系统维护页面", Description: "系统内置维护页面（备选，手动选用后生效）", Content: "<!DOCTYPE html><html><title>Under Maintenance</title></html>", IsBuiltin: true},
	}
	builtinBlockPageSeeds = customSeeds
	t.Cleanup(func() { builtinBlockPageSeeds = originalSeeds })

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	assertBuiltinBlockPageRowsMatch(t, database, customSeeds)

	// 追加第三条 seed：单测绿且无需改 SQL（清单即事实源的结构性验收）。
	third := builtinBlockPageSeed{ID: 19003, Name: "维护预告页", Description: "系统内置维护预告页面（备选，手动选用后生效）", Content: "<!DOCTYPE html><html><title>Scheduled Maintenance</title></html>", IsBuiltin: true}
	builtinBlockPageSeeds = append(customSeeds, third)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations with third seed: %v", err)
	}
	assertBuiltinBlockPageRowsMatch(t, database, builtinBlockPageSeeds)

	count, err := builtinBlockPageCount()
	if err != nil {
		t.Fatalf("count builtin pages: %v", err)
	}
	if count != len(builtinBlockPageSeeds) {
		t.Fatalf("builtin page count=%d, want %d（探测未消费同一清单）", count, len(builtinBlockPageSeeds))
	}
}

// assertBuiltinBlockPageRowsMatch 逐字段比对清单与库内行。
func assertBuiltinBlockPageRowsMatch(t *testing.T, database *sql.DB, seeds []builtinBlockPageSeed) {
	t.Helper()
	for _, seed := range seeds {
		var name, description, content string
		var isDefault, isBuiltin int
		if err := database.QueryRow(`SELECT name, description, content, is_default, is_builtin
			FROM security_block_pages WHERE id=?`, seed.ID).Scan(&name, &description, &content, &isDefault, &isBuiltin); err != nil {
			t.Fatalf("builtin page id %d: %v（播种未落行）", seed.ID, err)
		}
		if name != seed.Name {
			t.Errorf("page %d name=%q, want %q", seed.ID, name, seed.Name)
		}
		if description != seed.Description {
			t.Errorf("page %d description=%q, want %q", seed.ID, description, seed.Description)
		}
		if content != seed.Content {
			t.Errorf("page %d content 分叉（len=%d, want %d）", seed.ID, len(content), len(seed.Content))
		}
		if isDefault != 0 {
			t.Errorf("page %d is_default=%d, want 0（备选页不自动绑定）", seed.ID, isDefault)
		}
		if isBuiltin != 1 {
			t.Errorf("page %d is_builtin=%d, want 1", seed.ID, isBuiltin)
		}
	}
}
