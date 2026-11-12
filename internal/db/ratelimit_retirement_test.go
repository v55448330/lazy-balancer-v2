package db

import "testing"

// 配额限流下线迁移：legacy 库的 rate_limit_* 列必须被物理删除且幂等；
// 阶段 2 拦截页/状态码保留（直接封禁沿用）。
func TestRetireRateLimitQuota_dropsLegacyColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	for _, column := range []string{
		"rate_limit_enabled BOOLEAN DEFAULT FALSE",
		"rate_limit_rps INTEGER DEFAULT 0",
		"rate_limit_burst INTEGER DEFAULT 0",
	} {
		if _, err := database.Exec("ALTER TABLE security_policies ADD COLUMN " + column); err != nil {
			t.Fatalf("seed legacy column %s: %v", column, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,policy_type,human_verify_mode,block_page_id,block_status_code,enabled)
		VALUES ('legacy-cc','stage2','force',9001,429,1)`); err != nil {
		t.Fatalf("seed legacy CC policy: %v", err)
	}

	if err := retireRateLimitQuota(); err != nil {
		t.Fatalf("retire rate-limit quota: %v", err)
	}
	var remaining int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_policies') WHERE name IN ('rate_limit_enabled','rate_limit_rps','rate_limit_burst')`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("rate_limit_* 列仍存在 %d 个，want 0", remaining)
	}
	var pageID, status int
	if err := database.QueryRow(`SELECT block_page_id, block_status_code FROM security_policies WHERE name='legacy-cc'`).Scan(&pageID, &status); err != nil {
		t.Fatal(err)
	}
	if pageID != 9001 || status != 429 {
		t.Fatalf("限流下线不得改写阶段 2 拦截页/状态码: page=%d status=%d", pageID, status)
	}
	// 幂等：列已不存在时再次执行不报错。
	if err := retireRateLimitQuota(); err != nil {
		t.Fatalf("second retire run: %v", err)
	}
}
