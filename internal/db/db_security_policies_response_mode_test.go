package db

// security_policies NOT NULL 窗口期重建的 block_response_mode 拷贝契约：
// CREATE 携带该列而 INSERT/SELECT 拷贝清单漏列时，重建把显式 json/html 值
// 静默重置为默认 auto——拦截响应形态在升级后无声改变。重建必须保值，
// NULL（带外/restoreTable 残留）按 DDL DEFAULT 归一 auto。

import (
	"database/sql"
	"testing"
)

// seedWindowEraSecurityPolicies 建出「fresh 全列 + 四列 NOT NULL」窗口期形态
// 并种两行：显式 block_response_mode='json' 与 NULL（可空列带外残留）。
func seedWindowEraSecurityPolicies(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`DROP TABLE IF EXISTS security_policies;
	CREATE TABLE security_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		mode TEXT DEFAULT 'off',
		anomaly_threshold INTEGER DEFAULT 5,
		ip_acl_mode TEXT DEFAULT '',
		ip_acl_list TEXT DEFAULT '[]',
		ip_acl_enabled BOOLEAN DEFAULT FALSE,
		ip_whitelist TEXT DEFAULT '[]',
		ip_blacklist TEXT DEFAULT '[]',
		crs_rule_groups TEXT DEFAULT '[]',
		crs_excluded_rules TEXT DEFAULT '[]',
		custom_rules TEXT DEFAULT '[]',
		block_page_id INTEGER DEFAULT 0,
		block_status_code INTEGER NOT NULL DEFAULT 0,
		block_response_mode TEXT DEFAULT 'auto',
		enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now')),
		ip_whitelist_enabled INTEGER DEFAULT 1,
		geoip_countries TEXT NOT NULL DEFAULT '[]',
		geoip_mode TEXT NOT NULL DEFAULT 'deny',
		waf_check_response INTEGER NOT NULL DEFAULT 0,
		log_request_body INTEGER DEFAULT 0,
		ip_acl_list_refs TEXT DEFAULT '[]',
		ip_whitelist_refs TEXT DEFAULT '[]',
		policy_type TEXT NOT NULL DEFAULT '',
		trust_detection BOOLEAN NOT NULL DEFAULT 0,
		geoip_crawler_exempt INTEGER NOT NULL DEFAULT 0,
		geoip_crawler_engines TEXT NOT NULL DEFAULT '[]',
		human_verify_mode TEXT NOT NULL DEFAULT 'off',
		human_verify_type TEXT NOT NULL DEFAULT 'slider',
		human_verify_ttl INTEGER NOT NULL DEFAULT 30,
		human_exempt_paths TEXT NOT NULL DEFAULT '[]',
		cc_detect_enabled INTEGER NOT NULL DEFAULT 0,
		cc_rps_limit INTEGER NOT NULL DEFAULT 40,
		cc_rps_window INTEGER NOT NULL DEFAULT 10,
		cc_4xx_ratio INTEGER NOT NULL DEFAULT 70,
		cc_session_anomaly INTEGER NOT NULL DEFAULT 0,
		cc_session_ua_threshold INTEGER NOT NULL DEFAULT 5
	);
	INSERT INTO security_policies (id,name,block_response_mode) VALUES (1,'json-mode','json');
	INSERT INTO security_policies (id,name,block_response_mode) VALUES (2,'null-mode',NULL);`); err != nil {
		t.Fatalf("seed window-era security_policies: %v", err)
	}
}

// Given 窗口期库携带显式 json 与 NULL 两种 block_response_mode。
// When NOT NULL 收敛重建。Then json 值原样保留、NULL 归一 auto。
func TestSecurityPoliciesNullableRebuild_preservesBlockResponseMode(t *testing.T) {
	database := openMigrationTestDB(t)
	seedWindowEraSecurityPolicies(t, database)

	// When
	if err := migrateSecurityPoliciesNullable(); err != nil {
		t.Fatalf("rebuild security_policies: %v", err)
	}

	// Then
	for _, tc := range []struct {
		id   int
		want string
	}{
		{1, "json"},
		{2, "auto"},
	} {
		var got string
		if err := database.QueryRow(`SELECT COALESCE(block_response_mode,'<null>') FROM security_policies WHERE id=?`, tc.id).Scan(&got); err != nil {
			t.Fatalf("read rebuilt block_response_mode(id=%d): %v", tc.id, err)
		}
		if got != tc.want {
			t.Fatalf("block_response_mode(id=%d)=%q, want %q（重建拷贝漏列会把显式值静默重置 auto）", tc.id, got, tc.want)
		}
	}
}
