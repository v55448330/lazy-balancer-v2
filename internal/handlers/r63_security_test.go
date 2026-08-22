package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestUpdateSecurityPolicy_partialEnableRejectsDanglingReferences 验证 R63 B-N1：
// 仅含 {enabled:true} 的部分更新（REST 文档明示「只提交需要修改的字段」）不得
// 让禁用期间被删除的自定义规则/拦截页引用随重启用静默激活——此前 deref 零值
// 使引用校验整体短路，悬空引用激活后发射端仅 warn 跳过（WAF 规则静默丢失、
// 拦截页退回 Caddy 默认错误页）。
func TestUpdateSecurityPolicy_partialEnableRejectsDanglingReferences(t *testing.T) {
	// Given 禁用策略引用一个自定义规则，随后该规则被删除（删除门只拦 enabled=1）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('悬空规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	id := createTestPolicy(t, router, map[string]any{"name": "悬空引用策略"})
	if _, err := db.DB.Exec(`UPDATE security_policies SET enabled=0, custom_rules=? WHERE id=?`, fmt.Sprintf("[%d]", ruleID), id); err != nil {
		t.Fatalf("bind reference: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM security_custom_rules WHERE id=?`, ruleID); err != nil {
		t.Fatalf("delete custom rule: %v", err)
	}

	// When 仅提交 {enabled:true} 的部分更新
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"enabled": true})

	// Then 400 拒绝（按「显式值 ?? 存量值」的有效形态重校验引用）
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("partial enable status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}

	// And 显式清空引用后的启用可通过（自助修复路径不受阻）
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"enabled": true, "custom_rules": "[]"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("clean enable status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow("SELECT enabled FROM security_policies WHERE id=?", id).Scan(&enabled); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("enabled=%d, want 1", enabled)
	}
}
