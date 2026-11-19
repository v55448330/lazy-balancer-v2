package db

// 通知投递两新列存量库补列回归（2026-11-19 通知重构）：
// is_test（测试发送标记）/retry_channel_ids（failed_only 重发通道过滤）
// 经 newColumns 统一通道幂等补齐，存量行取默认 0/''（升级零行为漂移）。

import "testing"

func TestRunMigrationsAddsNotificationDeliveryIsTestRetryColumns(t *testing.T) {
	// Given 存量库形态：fresh 建表后删两新列，落一行 legacy 投递
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	for _, col := range []string{"is_test", "retry_channel_ids"} {
		if _, err := database.Exec("ALTER TABLE notification_deliveries DROP COLUMN " + col); err != nil {
			t.Fatalf("simulate legacy deliveries (drop %s): %v", col, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, created_at)
		VALUES (1, 'cert.failed', 'critical', 't', 'b', 'sent', datetime('now'))`); err != nil {
		t.Fatalf("seed legacy delivery: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 两列补齐且存量行取默认（0/''）
	for _, tc := range []struct{ col, want string }{
		{"is_test", "0"},
		{"retry_channel_ids", ""},
	} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('notification_deliveries') WHERE name=?", tc.col).Scan(&count); err != nil {
			t.Fatalf("query %s schema: %v", tc.col, err)
		}
		if count != 1 {
			t.Fatalf("notification_deliveries.%s count=%d, want 1", tc.col, count)
		}
	}
	var isTest int
	var retryIDs string
	if err := database.QueryRow(`SELECT is_test, retry_channel_ids FROM notification_deliveries WHERE title='t'`).Scan(&isTest, &retryIDs); err != nil {
		t.Fatalf("read legacy row: %v", err)
	}
	if isTest != 0 || retryIDs != "" {
		t.Fatalf("legacy 行 is_test=%d retry_channel_ids=%q, want 0/空", isTest, retryIDs)
	}

	// 幂等：二次迁移不重复补列/不报错
	if err := runMigrations(); err != nil {
		t.Fatalf("second run migrations: %v", err)
	}
}
