package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// （v2.2.0 多策略绑定）：GetSecurityPoliciesForRule 返回规则绑定的
// 全部 enabled 策略，按绑定 rank ASC（policy_id ASC 兜序）有序；disabled
// 排除；空结果返回 nil（非空切片）；单绑定时与 GetSecurityPolicyForRule
// 返回同一策略。

// mpInitDB 初始化一个独立的临时 SQLite 库并接管全局 db.DB（与
// security_wafcheck_test.go 同款模式，测试间互不串扰）。保存/恢复三库句柄
// ——裸 Close+nil 丢弃旧句柄会让后续用例读到已删除临时目录。
func mpInitDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dir); err != nil {
		t.Fatalf("init db: %v", err)
	}
}

// mpSeedPolicy 插入一条最小安全策略（blocking 模式）并返回其 id；
// enabled 取 1/0。
func mpSeedPolicy(t *testing.T, name string, enabled int) int {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled) VALUES (?, 'blocking', ?)`, name, enabled)
	if err != nil {
		t.Fatalf("seed policy %s: %v", name, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("seed policy %s: last insert id: %v", name, err)
	}
	return int(id)
}

// mpBindRule 记录规则与策略的绑定（rank 缺省 0，排序走 policy_id 兜序）。
func mpBindRule(t *testing.T, ruleCaddyID string, policyID int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind policy %d to %s: %v", policyID, ruleCaddyID, err)
	}
}

// mpBindRuleRank 记录规则与策略的绑定并写入显式 rank（绑定执行序）。
func mpBindRuleRank(t *testing.T, ruleCaddyID string, policyID, rank int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id, rank) VALUES (?, ?, ?)`, ruleCaddyID, policyID, rank); err != nil {
		t.Fatalf("bind policy %d to %s with rank %d: %v", policyID, ruleCaddyID, rank, err)
	}
}

// rank 显式种子 B=1,C=2,A=3（插入序 C,A,B）→ 返回必须为 [B,C,A]：
// 与 policy_id ASC（[A,B,C]）和插入序（[C,A,B]）都不重合，断言只能被
// 生产 ORDER BY rank ASC, policy_id ASC 的 rank 主序满足。
func TestGetSecurityPoliciesForRule_ASCOrder(t *testing.T) {
	mpInitDB(t)
	// 新库 AUTOINCREMENT 从 1 起：三条策略 id 恒为 1,2,3。
	idA := mpSeedPolicy(t, "policy-a", 1)
	idB := mpSeedPolicy(t, "policy-b", 1)
	idC := mpSeedPolicy(t, "policy-c", 1)
	if !(idA == 1 && idB == 2 && idC == 3) {
		t.Fatalf("unexpected seed ids: %d %d %d, want 1 2 3", idA, idB, idC)
	}
	mpBindRuleRank(t, "lb_mp_asc", idC, 2)
	mpBindRuleRank(t, "lb_mp_asc", idA, 3)
	mpBindRuleRank(t, "lb_mp_asc", idB, 1)

	policies := GetSecurityPoliciesForRule("lb_mp_asc")
	if len(policies) != 3 {
		t.Fatalf("want 3 policies, got %d", len(policies))
	}
	want := []int{idB, idC, idA}
	for i, p := range policies {
		if p.ID != want[i] {
			t.Fatalf("position %d = policy id %d, want %d（必须按绑定 rank ASC 排序）", i, p.ID, want[i])
		}
	}
}

// enabled + disabled 混绑 → 只返回 enabled，且相对顺序保持 ASC。
func TestGetSecurityPoliciesForRule_ExcludesDisabled(t *testing.T) {
	mpInitDB(t)
	idA := mpSeedPolicy(t, "policy-enabled-1", 1)
	idB := mpSeedPolicy(t, "policy-disabled-2", 0)
	idC := mpSeedPolicy(t, "policy-enabled-3", 1)
	mpBindRule(t, "lb_mp_disabled", idA)
	mpBindRule(t, "lb_mp_disabled", idB)
	mpBindRule(t, "lb_mp_disabled", idC)

	policies := GetSecurityPoliciesForRule("lb_mp_disabled")
	if len(policies) != 2 {
		t.Fatalf("want 2 enabled policies, got %d（disabled 策略必须被排除）", len(policies))
	}
	if policies[0].ID != idA || policies[1].ID != idC {
		t.Fatalf("got ids [%d %d], want [%d %d]", policies[0].ID, policies[1].ID, idA, idC)
	}
}

// 空绑定返回 nil（不是空切片）；绑定全部为 disabled 时同样返回 nil。
func TestGetSecurityPoliciesForRule_NilWhenEmpty(t *testing.T) {
	mpInitDB(t)
	mpSeedPolicy(t, "policy-never-bound", 1)
	idDisabled := mpSeedPolicy(t, "policy-disabled-only", 0)
	mpBindRule(t, "lb_mp_all_disabled", idDisabled)

	if policies := GetSecurityPoliciesForRule("lb_no_bindings"); policies != nil {
		t.Fatalf("无绑定时 want nil, got non-nil slice of length %d", len(policies))
	}
	if policies := GetSecurityPoliciesForRule("lb_mp_all_disabled"); policies != nil {
		t.Fatalf("绑定全为 disabled 时 want nil, got non-nil slice of length %d", len(policies))
	}
}

// 单绑定时与 GetSecurityPolicyForRule 返回同一策略（向后兼容）。
func TestGetSecurityPoliciesForRule_SingleBindingMatchesLegacy(t *testing.T) {
	mpInitDB(t)
	id := mpSeedPolicy(t, "policy-single", 1)
	mpBindRule(t, "lb_mp_single", id)

	policies := GetSecurityPoliciesForRule("lb_mp_single")
	if len(policies) != 1 {
		t.Fatalf("want 1 policy, got %d", len(policies))
	}
	legacy := GetSecurityPolicyForRule("lb_mp_single")
	if legacy == nil {
		t.Fatal("legacy GetSecurityPolicyForRule returned nil for a single enabled binding")
	}
	first := policies[0]
	if first.ID != legacy.ID || first.Name != legacy.Name || first.Mode != legacy.Mode ||
		first.AnomalyThreshold != legacy.AnomalyThreshold || first.Enabled != legacy.Enabled ||
		first.BlockStatusCode != legacy.BlockStatusCode {
		t.Fatalf("single-binding mismatch: list[0] = {id:%d name:%q mode:%q}, legacy = {id:%d name:%q mode:%q}",
			first.ID, first.Name, first.Mode, legacy.ID, legacy.Name, legacy.Mode)
	}
}

// GetSecurityPoliciesForRule 不得在 rows 未关闭时
// 嵌套查询（scanSecurityPolicyByID/resolvePolicyIPListRefs）——连接池耗尽即
// 永久阻塞（无 context 超时）。单连接池（SetMaxOpenConns(1)）下旧实现必然
// 自锁；修复后先收集 policy_id、关闭 rows、再逐条加载，单连接即可跑通。
func TestGetSecurityPoliciesForRule_singleConnectionPool(t *testing.T) {
	mpInitDB(t)
	idA := mpSeedPolicy(t, "policy-pool-a", 1)
	idB := mpSeedPolicy(t, "policy-pool-b", 1)
	mpBindRule(t, "lb_mp_pool", idB)
	mpBindRule(t, "lb_mp_pool", idA)

	db.DB.SetMaxOpenConns(1)

	type result struct {
		count int
	}
	done := make(chan result, 1)
	go func() {
		policies := GetSecurityPoliciesForRule("lb_mp_pool")
		done <- result{count: len(policies)}
	}()
	select {
	case r := <-done:
		if r.count != 2 {
			t.Fatalf("want 2 policies, got %d", r.count)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("连接池=1 下调用挂死：rows 打开期间的嵌套查询在等待第二个连接（连接池死锁形态）")
	}
}
