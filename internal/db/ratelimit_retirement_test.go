package db

import "testing"

// 配额限流下线迁移：存量 rate_limit_* 必须归零且幂等；列保留用于旧备份/
// 混版本快照兼容，但不再被渲染消费。
func TestRetireRateLimitQuota_zeroesLegacyPolicies(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,rate_limit_enabled,rate_limit_rps,rate_limit_burst,enabled) VALUES ('legacy-rl','off',1,120,40,1)`); err != nil {
		t.Fatalf("seed legacy rate-limit policy: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	var enabled int
	var rps, burst int
	if err := database.QueryRow("SELECT rate_limit_enabled, rate_limit_rps, rate_limit_burst FROM security_policies WHERE name='legacy-rl'").Scan(&enabled, &rps, &burst); err != nil {
		t.Fatalf("read retired columns: %v", err)
	}
	if enabled != 0 || rps != 0 || burst != 0 {
		t.Fatalf("rate_limit_* 未归零: enabled=%d rps=%d burst=%d", enabled, rps, burst)
	}

	// 幂等：再次启动迁移不得报错，也不得复活旧值。
	if err := retireRateLimitQuota(); err != nil {
		t.Fatalf("second retire run: %v", err)
	}
}
