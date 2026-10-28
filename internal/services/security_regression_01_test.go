package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// setupSecurityEnumTestDB 初始化隔离测试库并恢复全部全局句柄。
func setupSecurityEnumTestDB(t *testing.T) {
	t.Helper()
	setupIsolatedDB(t)
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
// 验证：遗留枚举空串行在启动时被归一到 Create 侧默认值
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

// 非空非法枚举（带外直写/跨版本快照绕过写侧白名单落库）同样随启动归一
// 收敛——渲染端对枚举外值零产出规则/落入错误分支，与遗留空串同型。
func TestNormalizeLegacySecurityPolicyEnums_normalizesNonEnumValues(t *testing.T) {
	setupSecurityEnumTestDB(t)
	insertLegacyPolicyRow(t, "dirty-mode", "BLOCKING", "deny", "off")
	insertLegacyPolicyRow(t, "dirty-acl", "off", "DENY", "off")
	insertLegacyPolicyRow(t, "dirty-geo", "off", "deny", "banana")
	insertLegacyPolicyRow(t, "valid", "blocking", "allow", "allow")
	before := clusterVersion(t)

	NormalizeLegacySecurityPolicyEnums(context.Background())

	rows := map[string][3]string{}
	for _, name := range []string{"dirty-mode", "dirty-acl", "dirty-geo", "valid"} {
		var mode, aclMode, geoMode string
		if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE name=?", name).Scan(&mode, &aclMode, &geoMode); err != nil {
			t.Fatal(err)
		}
		rows[name] = [3]string{mode, aclMode, geoMode}
	}
	want := map[string][3]string{
		"dirty-mode": {"off", "deny", "off"},
		"dirty-acl":  {"off", "deny", "off"},
		"dirty-geo":  {"off", "deny", "deny"},
		"valid":      {"blocking", "allow", "allow"},
	}
	for name, w := range want {
		if rows[name] != w {
			t.Fatalf("policy %s = %v, want %v", name, rows[name], w)
		}
	}
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want +1", v)
	}
}

// 首尾空白脏值（带外直写/旧快照）必须写回归一值：归一谓词按 TRIM 判定
// 白名单，若不写回，' blocking ' 这类「合法但带空白」的行永远跳过归一；而
// 渲染与事件归属按原始值精确比较——策略零发射、UI 下拉匹配不上、事件也不
// 认领。本用例同时给出未 trim 的反证（归属谓词为 false）。
func TestNormalizeLegacySecurityPolicyEnums_trimsWhitespaceDirtyValues(t *testing.T) {
	setupSecurityEnumTestDB(t)
	insertLegacyPolicyRow(t, "padded-mode", " blocking ", "deny", "off")
	insertLegacyPolicyRow(t, "padded-geo", "off", "deny", "  banana  ")
	before := clusterVersion(t)

	// 反证：带空白的 mode 不认领 CRS 事件（精确比较）——证明夹具形态有效。
	if securityEventsPolicyContainsRule(&models.SecurityPolicy{Mode: " blocking ", CRSRuleGroups: json.RawMessage(`[]`)}, "942100", "") {
		t.Fatal("未 trim 的 mode 不应认领 CRS 事件（反证失效）")
	}

	NormalizeLegacySecurityPolicyEnums(context.Background())

	var mode, acl, geo string
	if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE name='padded-mode'").Scan(&mode, &acl, &geo); err != nil {
		t.Fatal(err)
	}
	if mode != "blocking" || acl != "deny" || geo != "off" {
		t.Fatalf("padded-mode=(%q,%q,%q), want (blocking,deny,off)", mode, acl, geo)
	}
	if !securityEventsPolicyContainsRule(&models.SecurityPolicy{Mode: mode, CRSRuleGroups: json.RawMessage(`[]`)}, "942100", "") {
		t.Fatal("归一后 mode=blocking 必须认领 CRS 事件（渲染/归属面恢复）")
	}
	if err := db.DB.QueryRow("SELECT geoip_mode FROM security_policies WHERE name='padded-geo'").Scan(&geo); err != nil {
		t.Fatal(err)
	}
	if geo != "deny" {
		t.Fatalf("padded-geo geoip_mode=%q, want deny（trim 后仍非法→枚举外默认值族）", geo)
	}
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want %d（归一变更必须 bump 一次）", v, before+1)
	}
}

// TestNormalizeLegacySecurityPolicyEnums_disablesRateLimitWithInvalidRPS
// （enabled=1 & rps<1，修复前 Update 缺陷可落库）绑定启用规则时整份配置
// 生成失败（render fail-visible）。启动归一关停业务开关（enabled=0，rps 库值
// 保持原样不造假），与其他遗留行同事务归一+bump。
func TestNormalizeLegacySecurityPolicyEnums_disablesRateLimitWithInvalidRPS(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, rate_limit_enabled, rate_limit_rps) VALUES
		('dirty-rps', 'off', 1, 0), ('dirty-null-rps', 'off', 1, NULL), ('dirty-neg-rps', 'off', 1, -5), ('valid-rps', 'off', 1, 100), ('off-clean', 'off', 0, 0)`); err != nil {
		t.Fatalf("seed rows: %v", err)
	}
	before := clusterVersion(t)

	NormalizeLegacySecurityPolicyEnums(context.Background())

	var dirty, dirtyNull, dirtyNeg, valid, offClean int
	for _, tc := range []struct {
		name string
		dest *int
	}{{"dirty-rps", &dirty}, {"dirty-null-rps", &dirtyNull}, {"dirty-neg-rps", &dirtyNeg}, {"valid-rps", &valid}, {"off-clean", &offClean}} {
		if err := db.DB.QueryRow("SELECT rate_limit_enabled FROM security_policies WHERE name=?", tc.name).Scan(tc.dest); err != nil {
			t.Fatalf("read %s: %v", tc.name, err)
		}
	}
	if dirty != 0 || dirtyNull != 0 || dirtyNeg != 0 {
		t.Fatalf("脏行必须启动归一关停（enabled=0）: rps0=%d null=%d neg=%d", dirty, dirtyNull, dirtyNeg)
	}
	if valid != 1 || offClean != 0 {
		t.Fatalf("合法行不受影响: valid=%d offClean=%d", valid, offClean)
	}
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want +1（归一随既有机制 bump）", v)
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

// sync_security=1（默认）格：从节点不做本地归一——其职责是镜像主节点快照；若
// 主节点为无归一修复的旧版本，本地归一会与旧主快照互相覆盖（归一翻转 ACL 发射
// → 首次 Pull 全量重拉 → 快照恢复遗留空串行），每重启一次行为翻转。保留遗留
// 空串行是旧主集群的一致状态，升级主节点后快照自然携带归一后行。
func TestNormalizeLegacySecurityPolicyEnums_slaveSkipsNormalize(t *testing.T) {
	// Given 从节点 + sync_security=1（快照权威下发）+ 一条遗留空串行
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0, sync_security=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertLegacyPolicyRow(t, "legacy-all", "", "", "")
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 行保持原样（等主节点快照权威下发），版本不 bump
	var mode, ipACLMode, geoipMode string
	if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE name='legacy-all'").
		Scan(&mode, &ipACLMode, &geoipMode); err != nil {
		t.Fatal(err)
	}
	if mode != "" || ipACLMode != "" || geoipMode != "" {
		t.Fatalf("slave must not normalize locally, rows must stay as mirrored: (%q,%q,%q)", mode, ipACLMode, geoipMode)
	}
	if v := clusterVersion(t); v != before {
		t.Fatalf("slave must not bump cluster_version: %d, want %d", v, before)
	}
}

// TestNormalizeLegacySecurityPolicyEnums_backfillsZeroAnomalyThreshold 验证
// 之前落库的 anomaly_threshold=0 行随启动归一为 5（UI 显示 0
// 而发射端 >0 判断跳过阈值 SecAction、CRS 回落默认 5 的展示/行为漂移闭合）。
func TestNormalizeLegacySecurityPolicyEnums_backfillsZeroAnomalyThreshold(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(
		"INSERT INTO security_policies (name, mode, anomaly_threshold) VALUES ('zero-threshold', 'blocking', 0), ('valid-threshold', 'blocking', 10)"); err != nil {
		t.Fatalf("insert policies: %v", err)
	}
	before := clusterVersion(t)

	NormalizeLegacySecurityPolicyEnums(context.Background())

	var zero, valid int
	if err := db.DB.QueryRow("SELECT anomaly_threshold FROM security_policies WHERE name='zero-threshold'").Scan(&zero); err != nil {
		t.Fatalf("read zero-threshold: %v", err)
	}
	if err := db.DB.QueryRow("SELECT anomaly_threshold FROM security_policies WHERE name='valid-threshold'").Scan(&valid); err != nil {
		t.Fatalf("read valid-threshold: %v", err)
	}
	if zero != 5 || valid != 10 {
		t.Fatalf("anomaly_threshold zero-row=%d valid-row=%d, want 5/10（合法值不受影响）", zero, valid)
	}
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want %d（一次启动归一净增 1）", v, before+1)
	}
}

// 批 3 扩展：负值行同归一——回填口径从 `=0` 扩为 `<=0`
// （写侧 max1(x,5)/枚举白名单恒产生正值，负值只能是带外直写）。
func TestNormalizeLegacySecurityPolicyEnums_backfillsNegativeAnomalyThreshold(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(
		"INSERT INTO security_policies (name, mode, anomaly_threshold) VALUES ('neg-threshold', 'blocking', -3), ('valid-threshold', 'blocking', 10)"); err != nil {
		t.Fatalf("insert policies: %v", err)
	}

	NormalizeLegacySecurityPolicyEnums(context.Background())

	var neg, valid int
	if err := db.DB.QueryRow("SELECT anomaly_threshold FROM security_policies WHERE name='neg-threshold'").Scan(&neg); err != nil {
		t.Fatalf("read neg-threshold: %v", err)
	}
	if err := db.DB.QueryRow("SELECT anomaly_threshold FROM security_policies WHERE name='valid-threshold'").Scan(&valid); err != nil {
		t.Fatalf("read valid-threshold: %v", err)
	}
	if neg != 5 || valid != 10 {
		t.Fatalf("anomaly_threshold neg-row=%d valid-row=%d, want 5/10（负值归一、合法值不受影响）", neg, valid)
	}
}

// 态——写侧白名单仅 400/401/403/404/503）随启动归一为默认 403；合法枚举
// （含 0=未设置类型②省略型）不受影响。
func TestNormalizeLegacySecurityPolicyEnums_backfillsInvalidBlockStatusCode(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, block_status_code) VALUES
		('invalid-418', 'blocking', 418),
		('off-enum-451', 'blocking', 451),
		('legacy-429', 'blocking', 429),
		('valid-503', 'blocking', 503),
		('unset-zero', 'blocking', 0)`); err != nil {
		t.Fatalf("insert policies: %v", err)
	}

	NormalizeLegacySecurityPolicyEnums(context.Background())

	readStatus := func(name string) int {
		t.Helper()
		var status int
		if err := db.DB.QueryRow("SELECT block_status_code FROM security_policies WHERE name=?", name).Scan(&status); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return status
	}
	if got := readStatus("invalid-418"); got != 403 {
		t.Fatalf("invalid-418 block_status_code=%d, want 403（枚举外归一默认）", got)
	}
	if got := readStatus("off-enum-451"); got != 403 {
		t.Fatalf("off-enum-451 block_status_code=%d, want 403（451 非写侧白名单值，SQL 直写形态归一）", got)
	}
	if got := readStatus("legacy-429"); got != 403 {
		t.Fatalf("legacy-429 block_status_code=%d, want 403（历史修复 既有归一保持）", got)
	}
	if got := readStatus("valid-503"); got != 503 {
		t.Fatalf("valid-503 block_status_code=%d, want 503（合法值不受影响）", got)
	}
	if got := readStatus("unset-zero"); got != 0 {
		t.Fatalf("unset-zero block_status_code=%d, want 0（类型②省略型合法值不受影响）", got)
	}
}

// 归一是保护语义变更（mode 非法→off 停发该策略全部规则，限流 1→0
// 关闭保护），必须可选定位到策略：逐字段 warn 留痕并对两种收窄方向
// 各落一条系统审计；合法限流行不得产生关停审计。
func TestNormalizeLegacySecurityPolicyEnums_leavesPerPolicyTrace(t *testing.T) {
	setupSecurityEnumTestDB(t)
	insertLegacyPolicyRow(t, "legacy-blocking-typo", "BLOCKING", "deny", "deny")
	insertLegacyPolicyRow(t, "legacy-acl-empty", "blocking", "", "deny")
	insertLegacyPolicyRow(t, "legacy-rate-limit", "off", "deny", "deny")
	insertLegacyPolicyRow(t, "valid-rate-limit", "off", "deny", "deny")
	if _, err := db.DB.Exec(`UPDATE security_policies SET rate_limit_enabled=1, rate_limit_rps=CASE name
		WHEN 'legacy-rate-limit' THEN 0 ELSE 100 END WHERE name IN ('legacy-rate-limit','valid-rate-limit')`); err != nil {
		t.Fatalf("seed rate limit rows: %v", err)
	}
	buf := captureLogf(t)

	NormalizeLegacySecurityPolicyEnums(context.Background())

	logText := buf.String()
	if !strings.Contains(logText, "legacy-blocking-typo") || !strings.Contains(logText, `"BLOCKING" 归一为 "off"`) {
		t.Fatalf("日志缺少策略名与旧值→新值: %s", logText)
	}
	if !strings.Contains(logText, "legacy-acl-empty") || !strings.Contains(logText, `ip_acl_mode 由 "" 归一为 "deny"`) {
		t.Fatalf("日志缺少 ip_acl_mode 变更: %s", logText)
	}
	// mode 收窄（BLOCKING→off = 规则停止发射）必须写系统审计。
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='修改状态' AND detail LIKE '%legacy-blocking-typo%'`).Scan(&auditCount); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("mode 收窄审计行=%d, want 1", auditCount)
	}
	// 限流 1→0 同样逐策略留审计；全表按关停短语取证，合法行多写/脏行漏写
	// 都会改变精确行集。
	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='修改状态' AND detail LIKE '%限流被启动归一关停%' ORDER BY id`)
	if err != nil {
		t.Fatalf("query rate limit audit: %v", err)
	}
	var rateLimitAudits []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			rows.Close()
			t.Fatalf("scan rate limit audit: %v", err)
		}
		rateLimitAudits = append(rateLimitAudits, detail)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("iterate rate limit audit: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close rate limit audit rows: %v", err)
	}
	if len(rateLimitAudits) != 1 || !strings.Contains(rateLimitAudits[0], "legacy-rate-limit") {
		t.Fatalf("限流关停审计=%v, want 仅 legacy-rate-limit 一行", rateLimitAudits)
	}
	// ip_acl_mode 的归一方向是「开始拦截」而非停发规则，不写 mode 收窄审计。
	var aclAudit int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='修改状态' AND detail LIKE '%legacy-acl-empty%'`).Scan(&aclAudit); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if aclAudit != 0 {
		t.Fatalf("ip_acl_mode 归一不应写 mode 收窄审计: %d", aclAudit)
	}
}
