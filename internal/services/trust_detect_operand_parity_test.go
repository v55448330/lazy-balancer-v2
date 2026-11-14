package services

// 信任保留检测路由的 matcher 与引擎 operand 必须消费同一差集（保留检测 −
// 直通）：matcher 用差集而 operand 用全并集时，重叠形态下引擎 operand 宽于
// matcher（内容面超集）——路由命中面虽由 matcher 决定，两份名单分叉会让
// 后续维护者误判检测事务的覆盖范围。此处钉「两份名单逐字一致」。

import (
	"os"
	"strings"
	"testing"
)

func TestTrustedDetection_handlerOperandMatchesDiffSet(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdov", "tdov.example.test", 8080)
	// 保留检测集 {10.0.0.9, 10.0.0.10}，直通集 {10.0.0.9}：差集={10.0.0.10}。
	seedStage0Policy(t, database, "lb_tdov", `["10.0.0.9","10.0.0.10"]`, true)
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_whitelist,ip_whitelist_enabled,policy_type,trust_detection,enabled)
		VALUES ('stage0-pt-ov','off','["10.0.0.9"]',1,'stage0',0,1)`); err != nil {
		t.Fatal(err)
	}
	var ptID int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='stage0-pt-ov'`).Scan(&ptID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_tdov',?)`, ptID); err != nil {
		t.Fatal(err)
	}
	mpGenBindPolicy(t, database, "lb_tdov", "tdov-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdov", "tdov.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.trustIdx < 0 || shape.trustHandler == nil {
		t.Fatalf("重叠形态必须渲染信任检测路由: %v", handlerNames(t, mainRoute))
	}
	trustMatcher := innerMatcherJSON(t, shape.trustRoute)
	if strings.Contains(trustMatcher, "10.0.0.9/") || strings.Contains(trustMatcher, `"10.0.0.9"`) {
		t.Fatalf("matcher 必须是差集（不含直通吸收的 10.0.0.9）: %s", trustMatcher)
	}
	directives, _ := shape.trustHandler["directives"].(string)
	if directives == "" {
		t.Fatalf("信任检测 handler 缺 directives: %#v", shape.trustHandler)
	}
	// operand 是 @ipListFast 投影文件——读回文件内容比对名单（文本协议逐行）。
	idx := strings.Index(directives, "@ipListFast ")
	if idx < 0 {
		t.Fatalf("信任检测 operand 必须是 @ipListFast 投影:\n%s", directives)
	}
	rest := directives[idx+len("@ipListFast "):]
	end := strings.IndexAny(rest, "\" \t\n")
	if end < 0 {
		end = len(rest)
	}
	raw, err := os.ReadFile(rest[:end])
	if err != nil {
		t.Fatalf("读回信任检测投影: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "10.0.0.9") {
		t.Fatalf("引擎 operand 必须与 matcher 同为差集（不得含直通吸收的 10.0.0.9）:\n%s", content)
	}
	if !strings.Contains(content, "10.0.0.10") {
		t.Fatalf("差集成员 10.0.0.10 必须在 operand 内:\n%s", content)
	}
}
