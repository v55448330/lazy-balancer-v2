package db

import (
	"strings"
	"testing"
)

// 内置备选页的探测与播种必须共用同一组 ID。只改切片而漏改任何一处 SQL
// 都会在本用例中表现为自定义 ID 未播种或探测计数不符。
func TestRunMigrations_builtinBlockPageIDsSingleSource(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	originalIDs := builtinBlockPageIDs
	builtinBlockPageIDs = []int{19001, 19002}
	t.Cleanup(func() { builtinBlockPageIDs = originalIDs })

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	for _, id := range builtinBlockPageIDs {
		var present int
		if err := database.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id=?`, id).Scan(&present); err != nil {
			t.Fatalf("inspect seeded page %d: %v", id, err)
		}
		if present != 1 {
			t.Errorf("builtin page id %d present=%d, want 1（播种 SQL 未消费统一切片）", id, present)
		}
	}
	count, err := builtinBlockPageCount()
	if err != nil {
		t.Fatalf("count builtin pages: %v", err)
	}
	if count != len(builtinBlockPageIDs) {
		t.Fatalf("builtin page count=%d, want %d（探测 SQL 未消费统一切片）", count, len(builtinBlockPageIDs))
	}

	// 畸形形态：清单增加 ID 但没有对应种子行时必须显性失败，不能静默只播两行。
	builtinBlockPageIDs = append(builtinBlockPageIDs, 19003)
	if err := runMigrations(); err == nil || !strings.Contains(err.Error(), "seed parity") {
		t.Fatalf("id 清单与种子行数量不一致时 err=%v, want seed parity 错误", err)
	}
}
