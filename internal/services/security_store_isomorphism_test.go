package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A-I1（v2.2.0 多策略 · in-tx WAF 自定义规则读取）：
// BuildCorazaDirectives → resolvePolicyCustomRules 必须与
// loadSecurityPolicyContext 走同一 caddyConfigStore——v2 导入事务在 tx 内
// delete+重插 security_custom_rules 后渲染，若自定义规则读已提交 db.DB，
// 新导入规则会从发射的 coraza 指令中静默丢失（WAF 削弱），直到下次全量重生成。
//
// A-I2（v2.2.0 多策略 · 批量预载与单查路径同构）：
// loadSecurityPolicyContext 的批量 SELECT 必须与 scanSecurityPolicyByID
// 的单查 SELECT 字段级一致——geoip_countries / geoip_mode /
// waf_check_response 三列在 schema 上可空（无 NOT NULL），带外编辑或
// restoreTable 携带 JSON null 时，批量路径必须经 COALESCE 归一化，
// 否则一行 NULL 即让整配置生成 scan 失败（旧配置已保留），而单规则生成
// 仍能成功。

// seedCustomRuleInTx 在事务内插入一条 enabled 自定义规则并返回其 id；
// 该规则在事务外的已提交 db.DB 视角中不存在——正是 A-I1 复现所需。
func seedCustomRuleInTx(t *testing.T, tx *sql.Tx, name string) int {
	t.Helper()
	conditions := `[{"target":"uri","operator":"contains","pattern":"/tx-only"}]`
	result, err := tx.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled)
		VALUES (?, ?, 'block', 5, 1)`, name, conditions)
	if err != nil {
		t.Fatalf("seed custom rule in tx: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read custom rule id: %v", err)
	}
	return int(id)
}

// TestGenerateCaddyConfigFromStore_readsUncommittedCustomRuleThroughTx 锁定
// A-I1 修复：在 tx 内播种自定义规则+绑定策略+绑定规则，从 tx 渲染时
// 发射的 WAF 指令必须包含该规则的 id 与 msg——修复前
// resolvePolicyCustomRules 走全局 db.DB 看不到未提交行，规则静默丢失。
func TestGenerateCaddyConfigFromStore_readsUncommittedCustomRuleThroughTx(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_tx_custom_rule", false)

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	ruleID := seedCustomRuleInTx(t, tx, "tx-only-rule")
	policyResult, err := tx.Exec(`INSERT INTO security_policies (name, mode, enabled, custom_rules)
		VALUES ('tx-policy', 'blocking', 1, ?)`, fmt.Sprintf("[%d]", ruleID))
	if err != nil {
		t.Fatalf("seed policy in tx: %v", err)
	}
	policyID, err := policyResult.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
		VALUES ('lb_tx_custom_rule', ?)`, policyID); err != nil {
		t.Fatalf("bind policy in tx: %v", err)
	}

	// When：事务内渲染（ApplyConfigFromTx 同通道）
	generated := generateCaddyConfigFromStore(tx)

	// Then：自定义规则的 SecRule id（10000+ruleID）与 msg 必须出现在 WAF 指令中
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_8080")
	route := findRouteByID(t, routes, "lb_tx_custom_rule")
	if route == nil {
		t.Fatalf("规则主路由缺失: %#v", routes)
	}
	waf := findChainHandler(t, route, "waf")
	if waf == nil {
		t.Fatalf("事务内生成必须包含 WAF 处理器: %#v", route)
	}
	directives, ok := waf["directives"].(string)
	if !ok {
		t.Fatalf("waf directives 类型错误: %T", waf["directives"])
	}
	wantID := fmt.Sprintf("id:%d", ruleID+10000)
	if !strings.Contains(directives, wantID) {
		t.Fatalf("事务内生成必须发射自定义规则 id %s（A-I1：规则仅存在于 tx）:\n%s", wantID, directives)
	}
	if !strings.Contains(directives, "tx-only-rule") {
		t.Fatalf("事务内生成必须携带自定义规则名 tx-only-rule:\n%s", directives)
	}
}

// TestLoadSecurityPolicyContext_toleratesNullGeoIPColumns 锁定 A-I2 修复：
// 显式插入 geoip_countries=NULL 的策略行，批量预载必须成功并返回该策略
// （与 scanSecurityPolicyByID 单查路径同构，COALESCE 归一化）；
// 修复前批量 scan 直接报错 → 整配置生成失败（旧配置已保留）。
func TestLoadSecurityPolicyContext_toleratesNullGeoIPColumns(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	// 显式 NULL：模拟带外编辑或 restoreTable 携带 JSON null 的脏数据。
	result, err := database.Exec(`INSERT INTO security_policies
		(name, mode, enabled, geoip_countries, geoip_mode, waf_check_response)
		VALUES ('null-geoip', 'blocking', 1, NULL, NULL, NULL)`)
	if err != nil {
		t.Fatalf("seed null-geoip policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
		VALUES ('lb_null_geoip', ?)`, policyID); err != nil {
		t.Fatalf("bind null-geoip policy: %v", err)
	}

	// When：批量预载（与 generateCaddyConfigFromStore 同通道）
	ctx, err := loadSecurityPolicyContext(database)

	// Then：不得 scan 失败；策略按 id 可见且字段归一化到 COALESCE 默认值
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext 不得因 NULL 列报错（A-I2）: %v", err)
	}
	policies := ctx.policyByRule["lb_null_geoip"]
	if len(policies) != 1 {
		t.Fatalf("want 1 policy for lb_null_geoip, got %d", len(policies))
	}
	p := policies[0]
	if p.ID != int(policyID) {
		t.Fatalf("policy id = %d, want %d", p.ID, policyID)
	}
	if p.GeoIPMode != "off" {
		t.Fatalf("GeoIPMode = %q, want COALESCE 归一化后的 %q（与单查路径同构）", p.GeoIPMode, "off")
	}
	if string(p.GeoIPCountries) != "[]" {
		t.Fatalf("GeoIPCountries = %q, want COALESCE 归一化后的 %q", string(p.GeoIPCountries), "[]")
	}
	if p.WAFCheckResponse {
		t.Fatalf("WAFCheckResponse = true, want COALESCE 归一化后的 false")
	}
}

// TestLoadSecurityPolicyContext_toleratesNullCoreColumns 锁定 A-I2 硬化扩展：
// 除 geoip 三列外，fresh-install schema 下其余扫描列同样可空（仅 name/PK
// NOT NULL）——带外编辑、restoreTable 透传 JSON null、集群快照继承均可产生
// NULL。批量预载必须对全部可空列 COALESCE 归一化（与单查路径表达式级同构），
// 否则一行 NULL 即让整配置生成 scan 失败（旧配置已保留），形成自锁。
func TestLoadSecurityPolicyContext_toleratesNullCoreColumns(t *testing.T) {
	// Given：显式 NULL 的核心列（mode/custom_rules/ip_whitelist/block_page_id）
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO security_policies
		(name, enabled, mode, custom_rules, ip_whitelist, block_page_id)
		VALUES ('null-core', 1, NULL, NULL, NULL, NULL)`)
	if err != nil {
		t.Fatalf("seed null-core policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
		VALUES ('lb_null_core', ?)`, policyID); err != nil {
		t.Fatalf("bind null-core policy: %v", err)
	}

	// When：批量预载（与 generateCaddyConfigFromStore 同通道）
	ctx, err := loadSecurityPolicyContext(database)

	// Then：不得 scan 失败；字段归一化到 COALESCE 默认值
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext 不得因 NULL 核心列报错（A-I2 硬化）: %v", err)
	}
	policies := ctx.policyByRule["lb_null_core"]
	if len(policies) != 1 {
		t.Fatalf("want 1 policy for lb_null_core, got %d", len(policies))
	}
	p := policies[0]
	if p.Mode != "off" {
		t.Fatalf("Mode = %q, want COALESCE 归一化后的 %q（schema 默认）", p.Mode, "off")
	}
	if string(p.CustomRules) != "[]" {
		t.Fatalf("CustomRules = %q, want COALESCE 归一化后的 %q", string(p.CustomRules), "[]")
	}
	if string(p.IPWhitelist) != "[]" {
		t.Fatalf("IPWhitelist = %q, want COALESCE 归一化后的 %q", string(p.IPWhitelist), "[]")
	}
	if p.BlockPageID != 0 {
		t.Fatalf("BlockPageID = %d, want COALESCE 归一化后的 0", p.BlockPageID)
	}
}

// TestSnapshotSecurityPolicies_coalescesNullJSONColumns 锁定 A-I2 集群传播
// 硬化：主节点 dump（snapshotSecurityPolicies）必须对可空列 COALESCE——否则
// 主节点一行 NULL 经快照原样透传（dumpTableAsJSON 把 NULL  marshals 成
// JSON null），从节点 apply 时 snapshotJSONText(nil) 重新落 NULL，脏数据
// 跨集群复制。键名必须保持裸列名（COALESCE 需 AS 别名），否则从节点
// apply 按 p["custom_rules"] 取值会读到 nil。
func TestSnapshotSecurityPolicies_coalescesNullJSONColumns(t *testing.T) {
	// Given：一条 custom_rules/crs_rule_groups 为 NULL 的策略
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies
		(name, enabled, custom_rules, crs_rule_groups)
		VALUES ('null-dump', 1, NULL, NULL)`); err != nil {
		t.Fatalf("seed null-dump policy: %v", err)
	}

	// When：主节点快照 dump
	payload, err := service.snapshotSecurityPolicies(context.Background(), database)

	// Then：payload 中两列必须是 "[]" 而非 null，且键名为裸列名
	if err != nil {
		t.Fatalf("snapshotSecurityPolicies: %v", err)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(payload, &rows); err != nil {
		t.Fatalf("parse dump payload %s: %v", string(payload), err)
	}
	if len(rows) != 1 {
		t.Fatalf("dump rows=%d, want 1: %s", len(rows), string(payload))
	}
	row := rows[0]
	customRules, ok := row["custom_rules"]
	if !ok {
		t.Fatalf("dump 缺少 custom_rules 键（COALESCE 必须 AS 裸列名）: %s", string(payload))
	}
	if customRules != "[]" {
		t.Fatalf("custom_rules = %#v, want %q（不得为 nil/null）", customRules, "[]")
	}
	crsGroups, ok := row["crs_rule_groups"]
	if !ok {
		t.Fatalf("dump 缺少 crs_rule_groups 键（COALESCE 必须 AS 裸列名）: %s", string(payload))
	}
	if crsGroups != "[]" {
		t.Fatalf("crs_rule_groups = %#v, want %q（不得为 nil/null）", crsGroups, "[]")
	}
}
