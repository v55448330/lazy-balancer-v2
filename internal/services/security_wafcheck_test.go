package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 回归锁定（R12-H1；SEC-B-GAP-R1 第 69 轮头注改写为现行链路口径）：DB
// waf_check_response 列必须经 scanSecurityPolicyByID（生产等价路径
// GetSecurityPoliciesForRule 同用的 SQL 扫描）加载并传导至
// BuildCorazaDirectives——否则「检查响应体」开关在 Caddy 渲染层被静默关闭。
// GetSecurityPolicyForRule 已经 SEC41-1 退役为测试专用 helper（生产面零调用），
// 本测试的独立价值=「DB 列→渲染」端到端形状钉。
func TestGetSecurityPolicyForRule_LoadsWafCheckResponse(t *testing.T) {
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { db.DB.Close(); db.DB = nil })

	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, waf_check_response, enabled) VALUES ('resp-off', 'blocking', 0, 1)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, waf_check_response, enabled) VALUES ('resp-on', 'blocking', 1, 1)`); err != nil {
		t.Fatalf("seed policy2: %v", err)
	}
	db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_resp_check','r','http',8080,1)`)
	db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) SELECT 'lb_resp_check', id FROM security_policies WHERE name='resp-on'`)
	db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) SELECT 'lb_resp_check', id FROM security_policies WHERE name='resp-off'`)

	p := GetSecurityPolicyForRule("lb_resp_check")
	if p == nil {
		t.Fatal("policy not found")
	}
	if !p.WAFCheckResponse {
		t.Fatalf("WAFCheckResponse=false, want true (DB path must load the column)")
	}
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0))
	if !strings.Contains(directives, "SecResponseBodyAccess On") {
		t.Fatalf("directives missing SecResponseBodyAccess On:\n%s", directives)
	}
	if !strings.Contains(directives, "Include /app/waf/crs/rules/*.conf") {
		t.Fatalf("check-response on with no groups must include response-capable glob:\n%s", directives)
	}

	// 关闭开关的对照：仅保留 resp-off 绑定
	if _, err := db.DB.Exec(`DELETE FROM security_policy_bindings WHERE rule_caddy_id='lb_resp_check'`); err != nil {
		t.Fatal(err)
	}
	db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) SELECT 'lb_resp_check', id FROM security_policies WHERE name='resp-off'`)
	p2 := GetSecurityPolicyForRule("lb_resp_check")
	if p2 == nil || p2.WAFCheckResponse {
		t.Fatalf("p2=%v want WAFCheckResponse=false", p2)
	}
	if d2 := mustDirectives(BuildCorazaDirectives(p2, nil, "", false, 0)); !strings.Contains(d2, "SecResponseBodyAccess Off") {
		t.Fatalf("directives missing Off:\n%s", d2)
	}
}
