package db

// 启动一次性写入迁移的二次启动零写门：
//   - 存量自定义规则清理（判据在 JSON 内容里，无法索引探测）→ 指纹 marker；
//   - TCP 死字段清零（此前每次启动无条件开写事务）→ 计数探测门；
//   - TCP 协议绑定/失效 DNS/TLS-only https → 探测门（命中才开写事务）。
// 二次启动（等价重启）必须零写事务、零整表扫描，且数据终态不变。
//
// 计数口径边界（本门只断言「探测门 + 写事务骨架」这两族）：
//   - 覆盖：startupMigrationWriteStatements（execMigrationWriteIfNeeded 登记的
//     零命中可判定的 DML）与 startupMigrationWriteTx（withWriteTx / 各探测门后
//     打开的迁移事务）。
//   - 未覆盖：createTables 的 DDL 整包（CREATE TABLE/INDEX IF NOT EXISTS、1 号
//     拦截页种子）与散落的 DROP ... IF EXISTS / CREATE INDEX IF NOT EXISTS——
//     schema 收敛 DDL 无法探测，每启动各取一次主库写锁（WAL 下不写帧）。该族
//     不在「零写」口号范围内，不得据本门断言其为零写。

import (
	"testing"
)

func TestStartupLegacyMigrations_secondStartWriteFree(t *testing.T) {
	_ = openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := DB.Exec(query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	mustExec(`INSERT INTO global_config (id, caddy_config) VALUES (1,'{}')`)
	// 存量自定义规则：尾部反斜杠 pattern（迁移目标）。
	mustExec(`INSERT INTO security_custom_rules (name, conditions, enabled) VALUES ('legacy-rule', ?, 1)`,
		`[{"target":"ARGS","operator":"@rx","pattern":"abc\\"}]`)
	// 存量 TCP 规则：携带 HTTP 专属死字段 + 失效 DNS 服务发现。
	mustExec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, host_header, enable_dns_server, dns_server)
		VALUES ('lb_tcp_1','tcp 规则','tcp', 9000, 'dead.example', 1, '1.1.1.1')`)
	// 存量 https 协议规则（TLS-only 旧形态）。
	mustExec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_https_1','https 规则','https', 8443)`)
	// 存量 TCP 策略绑定（旧版本 HTTP→TCP 切换遗留）：策略需携带 G2/G3 特征
	// 才在新语义（L4 阶段 0/1）下被启动迁移清理。
	mustExec(`INSERT INTO security_policies (id, name, mode) VALUES (1, 'legacy policy', 'blocking')`)
	mustExec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_tcp_1', 1)`)

	// Given 首轮启动迁移（存量数据命中全部四条迁移）。
	writeBase, scanBase := startupMigrationWriteTx.Load(), startupLegacySanitizeMigrations.Load()
	if err := runMigrations(); err != nil {
		t.Fatalf("first migrations: %v", err)
	}
	if got := startupMigrationWriteTx.Load() - writeBase; got < 4 {
		t.Fatalf("首轮启动写事务=%d, want >=4（四条清理各一次）", got)
	}
	if got := startupLegacySanitizeMigrations.Load() - scanBase; got != 1 {
		t.Fatalf("首轮自定义规则扫描=%d, want 1", got)
	}
	var enabled int
	if err := DB.QueryRow(`SELECT enabled FROM security_custom_rules WHERE name='legacy-rule'`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("legacy-rule enabled=%d, want 0（尾部反斜杠必须禁用）", enabled)
	}
	var marker string
	if err := DB.QueryRow(`SELECT COALESCE(legacy_custom_rule_sanitize_fp,'') FROM global_config WHERE id=1`).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != legacyCustomRuleSanitizeFingerprint {
		t.Fatalf("marker=%q, want %q", marker, legacyCustomRuleSanitizeFingerprint)
	}

	// When 二次启动（等价重启，数据已是收敛态）。
	writeBase, scanBase = startupMigrationWriteTx.Load(), startupLegacySanitizeMigrations.Load()
	stmtBase := startupMigrationWriteStatements.Load()
	if err := runMigrations(); err != nil {
		t.Fatalf("second migrations: %v", err)
	}

	// Then 四条迁移零写事务、自定义规则零扫描（marker 命中）。
	if got := startupMigrationWriteTx.Load() - writeBase; got != 0 {
		t.Fatalf("二次启动写事务=%d, want 0（探测门/标记门失效）", got)
	}
	if got := startupLegacySanitizeMigrations.Load() - scanBase; got != 0 {
		t.Fatalf("二次启动自定义规则整表扫描=%d, want 0（指纹 marker 未生效）", got)
	}
	// 无条件写语句族（默认回填/时间戳归一/权重与 NTLM 归一/孤儿清理）在
	// 收敛库上探测门零命中——二次启动连写语句都不执行（不写锁）。
	if got := startupMigrationWriteStatements.Load() - stmtBase; got != 0 {
		t.Fatalf("二次启动写语句=%d, want 0（无条件写语句探测门失效）", got)
	}

	// And 终态幂等：TCP 死字段仍清零、https 已归一、绑定已删。
	var hostHeader, dnsServer string
	var enableDNS, tlsEnabled int
	if err := DB.QueryRow(`SELECT COALESCE(host_header,''), COALESCE(dns_server,''), COALESCE(enable_dns_server,0), COALESCE(enable_tls,0)
		FROM lb_rules WHERE caddy_id='lb_tcp_1'`).Scan(&hostHeader, &dnsServer, &enableDNS, &tlsEnabled); err != nil {
		t.Fatal(err)
	}
	if hostHeader != "" || dnsServer != "" || enableDNS != 0 || tlsEnabled != 0 {
		t.Fatalf("TCP 规则终态 host_header=%q dns=%q enable_dns=%d tls=%d, want 全零", hostHeader, dnsServer, enableDNS, tlsEnabled)
	}
	var protocol string
	if err := DB.QueryRow(`SELECT protocol FROM lb_rules WHERE caddy_id='lb_https_1'`).Scan(&protocol); err != nil {
		t.Fatal(err)
	}
	if protocol != "http" {
		t.Fatalf("https 规则 protocol=%q, want http", protocol)
	}
	var bindings int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_tcp_1'`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 {
		t.Fatalf("TCP 绑定残留=%d, want 0", bindings)
	}
}
