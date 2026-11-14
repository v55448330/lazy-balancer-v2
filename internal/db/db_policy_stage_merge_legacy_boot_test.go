package db

import (
	"database/sql"
	"testing"
)

// 阶段合并迁移的旧库直跳升级启动契约：policy_type 列由统一 ensureNewColumns
// 通道补齐，阶段合并（migratePolicyStagesV1/repairPolicyStageMergeV2）的候选
// 查询消费该列——二者顺序颠倒时，2026-09-20 实体单职化之前建库、此后从未启动
// 过新版本的存量库（无 policy_type 列）直跳升级会在启动迁移报
// 「no such column: policy_type」，进程起不来。本文件以真实旧形态库走完整
// Initialize 启动链钉住「启动成功」，不依赖迁移内部顺序的实现细节。

// legacyPolicyStageDDL 是实体单职化（policy_type 引入）之前的 security_policies
// 形态：无 policy_type/人机/CC 各列，geoip 四列 NOT NULL（窗口期建库形态，
// 同时触发 migrateSecurityPoliciesNullable 重建）。
const legacyPolicyStageDDL = `CREATE TABLE security_policies (
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
	enabled BOOLEAN DEFAULT TRUE,
	updated_by INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT (datetime('now')),
	updated_at DATETIME DEFAULT (datetime('now')),
	geoip_countries TEXT NOT NULL DEFAULT '[]',
	geoip_mode TEXT NOT NULL DEFAULT 'deny',
	waf_check_response INTEGER NOT NULL DEFAULT 0
)`

// seedLegacyPolicyStageDB 在 dir 里造「fresh 建表后把 security_policies 换成
// 旧形态」的库文件（模拟旧版本进程建库后停机），返回时句柄已关闭。
func seedLegacyPolicyStageDB(t *testing.T, dir string, seedSQL string) {
	t.Helper()
	preserveDatabaseHandles(t)
	reopenDatabaseForTest(t, dir)
	if _, err := DB.Exec(`DROP TABLE security_policies; ` + legacyPolicyStageDDL + `; ` + seedSQL); err != nil {
		t.Fatalf("seed legacy security_policies: %v", err)
	}
	// 旧库从未跑过阶段合并：一次性门列也不存在（fresh 建库会置位门，
	// 留着会让迁移走「已完成」短路，测不到候选查询的补列顺序）。
	for _, marker := range []string{"policy_stage_merge_v1", "policy_stage_merge_v2"} {
		if _, err := dropColumnIfExists("global_config", marker); err != nil {
			t.Fatalf("drop legacy merge marker %s: %v", marker, err)
		}
	}
	for _, handle := range []*sql.DB{DB, MetricsDB, AuditDB} {
		if handle != nil {
			_ = handle.Close()
		}
	}
	reopenHandlesForTest = nil
}

// Given 无 policy_type 列的旧库（WAF 行 mode=blocking）。
// When 直跳升级启动（完整 Initialize）。
// Then 启动成功，WAF 行经内容推断归位 stage3，数据保留。
func TestInitialize_legacyPolicyStageBootSucceeds(t *testing.T) {
	dir := t.TempDir()
	seedLegacyPolicyStageDB(t, dir, `INSERT INTO security_policies (id,name,mode,crs_rule_groups)
		VALUES (1,'legacy-waf','blocking','["42"]')`)

	// When：旧库直跳升级——阶段合并候选查询不得先于 policy_type 补列。
	if err := Initialize(dir); err != nil {
		t.Fatalf("legacy boot must succeed, got: %v", err)
	}

	// Then：WAF 行存活且归位 stage3（内容推断），CRS 配置保留。
	var typ, mode, crs string
	if err := DB.QueryRow(`SELECT policy_type, mode, crs_rule_groups FROM security_policies WHERE id=1`).Scan(&typ, &mode, &crs); err != nil {
		t.Fatalf("legacy WAF row must survive boot: %v", err)
	}
	if typ != "stage3" || mode != "blocking" || crs != `["42"]` {
		t.Fatalf("legacy WAF row=(%q,%q,%q), want (stage3,blocking,[\"42\"])", typ, mode, crs)
	}
	// 幂等：再次启动零改写。
	reopenDatabaseForTest(t, dir)
	if err := DB.QueryRow(`SELECT policy_type FROM security_policies WHERE id=1`).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	if typ != "stage3" {
		t.Fatalf("reboot changed legacy WAF type to %q", typ)
	}
}

// Given 无 policy_type 列的旧库（空策略行，零能力）。
// When 直跳升级启动。Then 启动成功（零能力行按默认归 stage3，不得炸启动）。
func TestInitialize_legacyPolicyStageBootEmptyPolicy(t *testing.T) {
	dir := t.TempDir()
	seedLegacyPolicyStageDB(t, dir, `INSERT INTO security_policies (id,name) VALUES (2,'legacy-empty')`)
	if err := Initialize(dir); err != nil {
		t.Fatalf("legacy boot with empty policy must succeed, got: %v", err)
	}
	var typ string
	if err := DB.QueryRow(`SELECT policy_type FROM security_policies WHERE id=2`).Scan(&typ); err != nil {
		t.Fatalf("empty policy row must survive boot: %v", err)
	}
	if typ != "stage3" {
		t.Fatalf("empty policy type=%q, want stage3 (zero-capability default)", typ)
	}
}
