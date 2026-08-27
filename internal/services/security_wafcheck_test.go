package services

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 回归锁定（R12-H1）：GetSecurityPolicyForRule 必须加载 waf_check_response，
// 否则 buildWafHandlerWithPolicy→BuildCorazaDirectives 看到恒 false，
// 「检查响应体」开关在 Caddy 渲染层被静默关闭。
func TestGetSecurityPolicyForRule_LoadsWafCheckResponse(t *testing.T) {
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { db.DB.Close(); db.DB = nil })

	crs := filepath.Join(dir, "waf", "crs")
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
	directives := BuildCorazaDirectives(p, nil)
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
	if d2 := BuildCorazaDirectives(p2, nil); !strings.Contains(d2, "SecResponseBodyAccess Off") {
		t.Fatalf("directives missing Off:\n%s", d2)
	}
	_ = crs
	_ = context.Background
}
