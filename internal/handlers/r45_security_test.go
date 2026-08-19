package handlers

import (
	"net/http"
	"strconv"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestBindRuleToPolicy_ruleCheckDBErrorReturns500 验证 R45 F2-B：规则存在性
// COUNT 查询的 DB 故障（此处以表重命名模拟「no such table」瞬时故障）必须返回
// 500 而非 400「规则不存在」——合并 err||count 的旧实现会把可重试故障误报为
// 客户端错误，与 R44 F2 修复的策略校验口径一致。
func TestBindRuleToPolicy_ruleCheckDBErrorReturns500(t *testing.T) {
	// Given 一个存在的策略与一张被重命名的 lb_rules 表（COUNT 查询必然报错）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	policyID := createTestPolicy(t, router, map[string]any{"name": "故障策略", "mode": "blocking", "enabled": true})
	if _, err := db.DB.Exec("ALTER TABLE lb_rules RENAME TO lb_rules_broken"); err != nil {
		t.Fatalf("rename lb_rules: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("ALTER TABLE lb_rules_broken RENAME TO lb_rules") })

	// When 发起绑定请求
	recorder := postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bind", map[string]any{"rule_caddy_id": "lb_any"})

	// Then 返回 500（DB 故障），且无任何绑定写入
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("bind status=%d body=%s, want 500（DB 故障不得误报 400）", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_any'").Scan(&count); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if count != 0 {
		t.Fatal("no binding should be written when rule existence check fails")
	}
}
