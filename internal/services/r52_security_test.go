package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// setupSecurityEnumTestDB 初始化隔离测试库并恢复全局句柄（同 cluster_test.go 惯例）。
func setupSecurityEnumTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
}

func insertLegacyPolicyRow(t *testing.T, name, mode, ipACLMode, geoipMode string) {
	t.Helper()
	if _, err := db.DB.Exec(
		"INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode) VALUES (?, ?, ?, ?)",
		name, mode, ipACLMode, geoipMode,
	); err != nil {
		t.Fatalf("insert policy %s: %v", name, err)
	}
}

func clusterVersion(t *testing.T) int64 {
	t.Helper()
	var v int64
	if err := db.DB.QueryRow("SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
		t.Fatalf("read cluster_version: %v", err)
	}
	return v
}

// TestNormalizeLegacySecurityPolicyEnums_normalizesAndBumps_whenLegacyRowsExist
// 验证 R52 发现1：遗留枚举空串行在启动时被归一到 Create 侧默认值
// （ip_acl_mode→deny、mode→off、geoip_mode→deny），合法行不受影响；实际变更
// >0 且为主节点时集群版本 +1，让从节点随下次同步收敛。
func TestNormalizeLegacySecurityPolicyEnums_normalizesAndBumps_whenLegacyRowsExist(t *testing.T) {
	// Given 主节点（fresh 库 is_master 默认 TRUE），两条遗留空串行 + 一条合法行
	setupSecurityEnumTestDB(t)
	insertLegacyPolicyRow(t, "legacy-acl", "detection", "", "deny")
	insertLegacyPolicyRow(t, "legacy-all", "", "", "")
	insertLegacyPolicyRow(t, "valid", "blocking", "allow", "allow")
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 空串全部归一，合法行原值保留
	rows, err := db.DB.Query("SELECT name, mode, ip_acl_mode, geoip_mode FROM security_policies ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string][3]string{}
	for rows.Next() {
		var name, mode, ipACLMode, geoipMode string
		if err := rows.Scan(&name, &mode, &ipACLMode, &geoipMode); err != nil {
			t.Fatal(err)
		}
		got[name] = [3]string{mode, ipACLMode, geoipMode}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string][3]string{
		"legacy-acl": {"detection", "deny", "deny"},
		"legacy-all": {"off", "deny", "deny"},
		"valid":      {"blocking", "allow", "allow"},
	}
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("policy %s = %v, want %v", name, got[name], w)
		}
	}
	// 集群版本仅 +1（三条 UPDATE 合并为一次 bump）
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want %d (bumped exactly once)", v, before+1)
	}
}

// TestNormalizeLegacySecurityPolicyEnums_noBump_whenNoLegacyRows 验证无遗留
// 行时归一是纯 no-op：不 bump 集群版本（避免每次启动版本空转）。
func TestNormalizeLegacySecurityPolicyEnums_noBump_whenNoLegacyRows(t *testing.T) {
	// Given 主节点，全部行枚举合法
	setupSecurityEnumTestDB(t)
	insertLegacyPolicyRow(t, "valid", "blocking", "allow", "allow")
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 行不变、版本不 bump
	var mode, ipACLMode, geoipMode string
	if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE name='valid'").
		Scan(&mode, &ipACLMode, &geoipMode); err != nil {
		t.Fatal(err)
	}
	if mode != "blocking" || ipACLMode != "allow" || geoipMode != "allow" {
		t.Fatalf("valid row mutated: (%q,%q,%q)", mode, ipACLMode, geoipMode)
	}
	if v := clusterVersion(t); v != before {
		t.Fatalf("cluster_version=%d, want unchanged %d", v, before)
	}
}

// TestNormalizeLegacySecurityPolicyEnums_noBump_onSlave 验证从节点本地归一
// 但不 bump——集群版本只能由主节点推进，从节点收敛靠下次快照。
func TestNormalizeLegacySecurityPolicyEnums_noBump_onSlave(t *testing.T) {
	// Given 从节点 + 一条遗留空串行
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertLegacyPolicyRow(t, "legacy-all", "", "", "")
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 行被归一，但版本不 bump
	var mode, ipACLMode, geoipMode string
	if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE name='legacy-all'").
		Scan(&mode, &ipACLMode, &geoipMode); err != nil {
		t.Fatal(err)
	}
	if mode != "off" || ipACLMode != "deny" || geoipMode != "deny" {
		t.Fatalf("legacy row not normalized on slave: (%q,%q,%q)", mode, ipACLMode, geoipMode)
	}
	if v := clusterVersion(t); v != before {
		t.Fatalf("slave must not bump cluster_version: %d, want %d", v, before)
	}
}
