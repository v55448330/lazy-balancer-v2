package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestBuildCorazaDirectives_allowEmptyEmitsDenyAll(t *testing.T) {
	p := &models.SecurityPolicy{
		Name: "allow-empty", Mode: "blocking", AnomalyThreshold: 5,
		IPACLEnabled: true, IPACLMode: "allow", IPACLList: "[]",
	}
	directives, err := BuildCorazaDirectives(p, nil, "", false, 0, "lb_allow_empty")
	if err != nil {
		t.Fatalf("allow empty must render fail-closed deny-all, got %v", err)
	}
	// fail-closed 语义的关键在投影文件内容为空（空合并集 ⇒ !@ipListFast 恒真 ⇒
	// 拒绝所有 IP）——只断言算子/规则 id 时，若实现改为「空集不重写文件」，
	// id 复用的残留名单会让这些 IP 被放行而用例仍绿。
	if got := readRenderedIPList(t, directives, "-acl"); got != "" {
		t.Fatalf("allow-empty 投影文件必须为空（残留内容会让 fail-closed 反转）: %q", got)
	}
	wantLine := `SecRule REMOTE_ADDR "!@ipListFast `
	if !strings.Contains(directives, wantLine) ||
		!strings.Contains(directives, `" "id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END"`) {
		t.Fatalf("allow empty must emit complete negated ipListFast deny rule:\n%s", directives)
	}
}

func TestBuildIPPrecheckDirectives_allowEmptyEmitsDenyAll(t *testing.T) {
	p := &models.SecurityPolicy{
		Name: "allow-empty", Mode: "blocking", AnomalyThreshold: 5,
		IPACLEnabled: true, IPACLMode: "allow", IPACLList: "[]",
	}
	directives, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, "lb_allow_empty")
	if err != nil {
		t.Fatalf("precheck allow empty must render fail-closed deny-all, got %v", err)
	}
	if !strings.Contains(directives, "id:7,") || !strings.Contains(directives, "@rx .*") {
		t.Fatalf("precheck allow empty must emit unconditional deny rule:\n%s", directives)
	}
}
