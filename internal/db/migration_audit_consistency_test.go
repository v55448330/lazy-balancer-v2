package db

import (
	"database/sql"
	"strings"
	"testing"
)

// 一次性迁移的审计口径必须统一为「提交后按实际变更计数、一行聚合」：
//   - 探测计数会重复计数（同一行命中多条子查询）且并发修正后与实际变更脱节，
//     不能直接当「已清零处数」；
//   - 逐规则一条审计在存量 N 条时写 N 条，受 systemAuditBufferCap 截断且噪音大。
func TestMigrateRuleTLSModeResidue_skipsAuditWhenNothingChanged(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, tls_source, tls_cert, tls_key)
		VALUES (1, 'lb_residue_noop', 'residue-noop', 'http', 'residue.example.test', 443, 'acme_dns', 'CERT', 'KEY')`); err != nil {
		t.Fatalf("seed residue rule: %v", err)
	}
	// 探测命中但 UPDATE 全部被跳过（等价：探测到加锁/执行之间行已被并发修正）。
	if _, err := database.Exec(`CREATE TRIGGER skip_tls_residue BEFORE UPDATE ON lb_rules
		BEGIN SELECT RAISE(IGNORE); END;`); err != nil {
		t.Fatalf("create skip trigger: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateRuleTLSModeResidue(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("实际变更 0 行时不得写审计（探测计数不得冒充变更数）: %+v", entries)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("cluster_version=%d, want 0（无实际变更不得 bump）", version)
	}
}

// 逐规则审计改一行聚合 + 计数（caddy_id 清单上限 20）：存量 N 条不再写 N 条。
func TestMigrateTCPRuleStaleDNSServer_aggregatesAudit(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_dns_server, dns_server)
		VALUES ('lb_tcp_dns_a','tcp-dns-a','tcp','',19001,1,'8.8.8.8:53'),
		       ('lb_tcp_dns_b','tcp-dns-b','tcp','',19002,1,'1.1.1.1:53')`); err != nil {
		t.Fatalf("seed stale dns rules: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateTCPRuleStaleDNSServer(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1（按批聚合，避免截断与噪音）: %+v", len(entries), entries)
	}
	for _, fragment := range []string{"2", "lb_tcp_dns_a", "lb_tcp_dns_b"} {
		if !strings.Contains(entries[0].detail, fragment) {
			t.Fatalf("audit detail=%q, want 含 %q", entries[0].detail, fragment)
		}
	}
}

// 遗留记账行被删除时若目标列已非空（搬运 UPDATE 的谓词不成立），遗留哈希/版本
// 会被整体丢弃——一次性记账丢失不可恢复，必须留痕说明丢弃了什么。
func TestMigrateDropMergedSyncSwitchColumns_recordsDiscardedLegacyBookkeeping(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 目标记账列由 runMigrations 的 newColumns 通道补齐（本用例直调迁移，
	// 需显式补列以复现升级后形态）。
	if err := ensureNewColumns(map[string]string{
		"global_config.applied_waf_ref_hash":    "TEXT DEFAULT ''",
		"global_config.applied_waf_ref_version": "INTEGER DEFAULT 0",
	}, nil); err != nil {
		t.Fatalf("add bookkeeping columns: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id, caddy_config, applied_waf_ref_hash, applied_waf_ref_version)
		VALUES (1,'{}','target-hash',9)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE cluster_applied_sections (
		section TEXT PRIMARY KEY,
		hash TEXT DEFAULT '',
		applied_version INTEGER DEFAULT 0,
		applied_at DATETIME
	)`); err != nil {
		t.Fatalf("create legacy applied sections table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at)
		VALUES ('waf_files','legacy-hash',3,datetime('now'))`); err != nil {
		t.Fatalf("seed legacy bookkeeping: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateDropMergedSyncSwitchColumns(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var legacyRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections WHERE section='waf_files'`).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 0 {
		t.Fatalf("legacy rows=%d, want 0", legacyRows)
	}
	var hash string
	var version int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''), COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&hash, &version); err != nil {
		t.Fatal(err)
	}
	if hash != "target-hash" || version != 9 {
		t.Fatalf("target bookkeeping=(%q,%d), want (target-hash,9)（已非空的目标列不得被遗留值覆盖）", hash, version)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1（丢弃遗留记账必须留痕）: %+v", len(entries), entries)
	}
	for _, fragment := range []string{"legacy-hash", "target-hash"} {
		if !strings.Contains(entries[0].detail, fragment) {
			t.Fatalf("audit detail=%q, want 含 %q", entries[0].detail, fragment)
		}
	}
}

// 正常搬移与新旧同值都没有丢弃任何记账，不得留下“丢弃遗留”假审计；
// 真实异值丢弃由上一条用例覆盖，重跑迁移不得新增审计。
func TestMigrateDropMergedSyncSwitchColumns_skipsAuditForMovedOrIdenticalBookkeeping(t *testing.T) {
	cases := []struct {
		name          string
		targetHash    string
		targetVersion int
		legacyHash    string
		legacyVersion int
	}{
		{name: "empty target moves legacy", targetHash: "", targetVersion: 0, legacyHash: "legacy-hash", legacyVersion: 3},
		{name: "identical target retains legacy", targetHash: "same-hash", targetVersion: 7, legacyHash: "same-hash", legacyVersion: 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := openMigrationTestDB(t)
			if err := createTables(); err != nil {
				t.Fatalf("create tables: %v", err)
			}
			if err := ensureNewColumns(map[string]string{
				"global_config.applied_waf_ref_hash":    "TEXT DEFAULT ''",
				"global_config.applied_waf_ref_version": "INTEGER DEFAULT 0",
			}, nil); err != nil {
				t.Fatalf("add bookkeeping columns: %v", err)
			}
			if _, err := database.Exec(`INSERT INTO global_config (id, caddy_config, applied_waf_ref_hash, applied_waf_ref_version)
				VALUES (1,'{}',?,?)`, tc.targetHash, tc.targetVersion); err != nil {
				t.Fatalf("seed global config: %v", err)
			}
			if _, err := database.Exec(`CREATE TABLE cluster_applied_sections (
				section TEXT PRIMARY KEY,
				hash TEXT DEFAULT '',
				applied_version INTEGER DEFAULT 0,
				applied_at DATETIME
			)`); err != nil {
				t.Fatalf("create legacy applied sections table: %v", err)
			}
			if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at)
				VALUES ('waf_files',?,?,datetime('now'))`, tc.legacyHash, tc.legacyVersion); err != nil {
				t.Fatalf("seed legacy bookkeeping: %v", err)
			}
			drainSystemAuditBuffer()

			if err := migrateDropMergedSyncSwitchColumns(); err != nil {
				t.Fatalf("migrate: %v", err)
			}

			var hash string
			var version int
			if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''), COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&hash, &version); err != nil {
				t.Fatal(err)
			}
			if hash != tc.legacyHash || version != tc.legacyVersion {
				t.Fatalf("bookkeeping=(%q,%d), want (%q,%d)", hash, version, tc.legacyHash, tc.legacyVersion)
			}
			if entries := drainSystemAuditBuffer(); len(entries) != 0 {
				t.Fatalf("无值丢弃时审计数=%d, want 0: %+v", len(entries), entries)
			}
			if err := migrateDropMergedSyncSwitchColumns(); err != nil {
				t.Fatalf("re-migrate: %v", err)
			}
			if entries := drainSystemAuditBuffer(); len(entries) != 0 {
				t.Fatalf("幂等重跑新增审计=%d, want 0: %+v", len(entries), entries)
			}
		})
	}
}

// seedWAFModeMigrationDB 建表并播种 global_config 行（一次性门列由迁移自身
// 补列）+ 四条覆盖迁移判据两面的策略行。
func seedWAFModeMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name, mode, custom_rules) VALUES
		('off-启用-a','off','[{"id":1,"enabled":true,"action":"block","score":5}]'),
		('off-启用-b','off','[{"id":2,"enabled":true,"action":"block","score":5}]'),
		('off-仅禁用','off','[{"id":3,"enabled":false,"action":"block","score":5}]'),
		('blocking-启用','blocking','[{"id":4,"enabled":true,"action":"block","score":5}]')`); err != nil {
		t.Fatalf("seed security policies: %v", err)
	}
	return database
}

func securityPolicyMode(t *testing.T, database *sql.DB, name string) string {
	t.Helper()
	var mode string
	if err := database.QueryRow(`SELECT mode FROM security_policies WHERE name=?`, name).Scan(&mode); err != nil {
		t.Fatalf("read mode of %s: %v", name, err)
	}
	return mode
}

// WAF 模式四态化迁移改写用户策略必须进操作审计：提交后按事务内实际变更
// 计数写一行聚合（存量 N 条不再写 N 条）；一次性门置位后重跑零新增。
func TestMigrateSecurityPolicyCustomOnlyMode_aggregatesAudit(t *testing.T) {
	seedWAFModeMigrationDB(t)
	drainSystemAuditBuffer()

	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1（聚合一行）: %+v", len(entries), entries)
	}
	if entries[0].action != "启动迁移" || entries[0].resource != "安全策略" {
		t.Fatalf("audit action/resource=(%q,%q), want (启动迁移,安全策略)", entries[0].action, entries[0].resource)
	}
	if !strings.Contains(entries[0].detail, "2") || !strings.Contains(entries[0].detail, "custom_only") {
		t.Fatalf("audit detail=%q, want 含实际变更计数 2 与目标模式", entries[0].detail)
	}

	// 一次性门已置位：重跑零变更、零新增审计。
	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("repeat migrate: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("重复启动不得重复留痕: %+v", entries)
	}
}

// 零实际变更不写审计（探测/无命中行时不得造留痕）。
func TestMigrateSecurityPolicyCustomOnlyMode_skipsAuditWhenNothingChanged(t *testing.T) {
	database := seedWAFModeMigrationDB(t)
	// 只留不满足迁移判据的行：off 仅挂禁用规则、blocking 挂启用规则。
	if _, err := database.Exec(`DELETE FROM security_policies WHERE name LIKE 'off-启用-%'`); err != nil {
		t.Fatalf("trim policies: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("零变更不得写审计: %+v", entries)
	}
	if mode := securityPolicyMode(t, database, "off-仅禁用"); mode != "off" {
		t.Fatalf("off-仅禁用 mode=%q, want off", mode)
	}
	if mode := securityPolicyMode(t, database, "blocking-启用"); mode != "blocking" {
		t.Fatalf("blocking-启用 mode=%q, want blocking", mode)
	}
}

// 一次性门写失败必须整体回滚：数据保持原状且不得留下「已审计但未落库」的
// 假留痕；故障解除后重试成功只留一条。
func TestMigrateSecurityPolicyCustomOnlyMode_rollbackLeavesNoAudit(t *testing.T) {
	database := seedWAFModeMigrationDB(t)
	if _, err := database.Exec(`CREATE TRIGGER block_waf_mode_marker BEFORE UPDATE OF waf_mode4_migrated ON global_config
		BEGIN SELECT RAISE(ABORT, 'marker blocked'); END;`); err != nil {
		t.Fatalf("create blocking trigger: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateSecurityPolicyCustomOnlyMode(); err == nil {
		t.Fatal("门写失败必须向上返回错误")
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("回滚后不得留痕: %+v", entries)
	}
	if mode := securityPolicyMode(t, database, "off-启用-a"); mode != "off" {
		t.Fatalf("回滚后 mode=%q, want off（归一与一次性门同事务）", mode)
	}

	if _, err := database.Exec(`DROP TRIGGER block_waf_mode_marker`); err != nil {
		t.Fatalf("drop blocking trigger: %v", err)
	}
	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		t.Fatalf("retry migrate: %v", err)
	}
	if mode := securityPolicyMode(t, database, "off-启用-a"); mode != "custom_only" {
		t.Fatalf("retry mode=%q, want custom_only", mode)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 1 || !strings.Contains(entries[0].detail, "2") {
		t.Fatalf("重试成功应恰留一条聚合审计: %+v", entries)
	}
}

// seedTCPBindingMigrationDB 播种两条 TCP 规则绑定 + 一条 HTTP 绑定（HTTP 与
// 无对应规则的历史行必须保留）。
func seedTCPBindingMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,cluster_version) VALUES (1,'{}',0);
		INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,compress_types) VALUES
		('lb_audit_http','http-rule','http',8080,'gzip'),
		('lb_audit_tcp_a','tcp-a','tcp',9001,''),
		('lb_audit_tcp_b','tcp-b','tcp',9002,'');
		INSERT INTO security_policies (id,name,mode) VALUES (7,'audit-blocking','blocking');
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_audit_http',7),('lb_audit_tcp_a',7),('lb_audit_tcp_b',7);`); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}
	return database
}

// TCP 绑定清理删除用户策略绑定必须进操作审计（聚合一行 + 实际变更计数），
// 重复启动零新增。
func TestMigrateTCPRuleSecurityPolicyBindings_aggregatesAudit(t *testing.T) {
	seedTCPBindingMigrationDB(t)
	drainSystemAuditBuffer()

	if err := migrateTCPRuleSecurityPolicyBindings(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1（聚合一行）: %+v", len(entries), entries)
	}
	if entries[0].action != "启动迁移" || entries[0].resource != "安全策略" {
		t.Fatalf("audit action/resource=(%q,%q), want (启动迁移,安全策略)", entries[0].action, entries[0].resource)
	}
	if !strings.Contains(entries[0].detail, "2") {
		t.Fatalf("audit detail=%q, want 含实际变更计数 2", entries[0].detail)
	}

	if err := migrateTCPRuleSecurityPolicyBindings(); err != nil {
		t.Fatalf("repeat migrate: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("无待清理行时不得重复留痕: %+v", entries)
	}
}

// 无 TCP 绑定（只有 HTTP/历史行）时零写、零版本扰动、零审计。
func TestMigrateTCPRuleSecurityPolicyBindings_skipsAuditWhenNothingChanged(t *testing.T) {
	database := seedTCPBindingMigrationDB(t)
	if _, err := database.Exec(`DELETE FROM security_policy_bindings WHERE rule_caddy_id LIKE 'lb_audit_tcp_%'`); err != nil {
		t.Fatalf("trim tcp bindings: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateTCPRuleSecurityPolicyBindings(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("零变更不得写审计: %+v", entries)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("cluster_version=%d, want 0（无变更不得 bump）", version)
	}
}
