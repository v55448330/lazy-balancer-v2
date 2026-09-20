package services

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 阶段 0 信任名单执行语义（2026-09-20 用户裁定）：
//   trust_detection=0（默认，直通）：信任 IP 在路由层被「not remote_ip」
//     subroute 跳过全部安全阶段（预检/限流/WAF），直达上游——保留路径分流
//     形态，零安全事件（无任何 coraza 事务产生）。
//   trust_detection=1（保留检测记录）：信任 IP 经 id:12 的
//     ctl:ruleEngine=DetectionOnly 在预检与每个策略引擎全评估全记录不拦
//     （事件动作=检测）——与 mixed 策略存量信任（id:3/5）同族但 id 独立。

// seedStage0Policy 播种 stage0 信任策略并绑定到规则。
func seedStage0Policy(t *testing.T, database *sql.DB, ruleCaddyID, whitelist string, trustDetection bool) int {
	t.Helper()
	res, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_whitelist,ip_whitelist_enabled,policy_type,trust_detection,enabled)
		VALUES (?, 'off', ?, 1, 'stage0', ?, 1)`, "stage0-"+ruleCaddyID, whitelist, trustDetection)
	if err != nil {
		t.Fatalf("seed stage0 policy: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, ruleCaddyID, id); err != nil {
		t.Fatal(err)
	}
	return int(id)
}

func TestTrustedPassthrough_subrouteSkipsAllSecurityStages(t *testing.T) {
	// Given：规则绑定 stage0 直通策略（信任 10.0.0.9）+ stage3 WAF 策略
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_trust", "trust.example.test", 8080)
	seedStage0Policy(t, database, "lb_trust", `["10.0.0.9"]`, false)
	mpGenBindPolicy(t, database, "lb_trust", "trust-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_trust", "trust.example.test"))

	// Then：安全阶段被「not remote_ip ∈ 信任集」的 subroute 包裹——信任 IP
	// 流程 headers→metrics→counter→(subroute 跳过)→reverse_proxy，零安全事件。
	handlers, _ := mainRoute["handle"].([]interface{})
	var subroute map[string]interface{}
	var subIdx, proxyIdx = -1, -1
	for i, hv := range handlers {
		h := mustMap(t, hv, "handler")
		switch h["handler"] {
		case "subroute":
			if _, hasRoutes := h["routes"]; hasRoutes && subIdx < 0 {
				subroute = h
				subIdx = i
			}
		case "reverse_proxy":
			proxyIdx = i
		}
	}
	if subIdx < 0 {
		t.Fatalf("main chain must wrap security stages in a subroute when stage0 passthrough bound: %v", handlerNames(t, mainRoute))
	}
	if proxyIdx < 0 || proxyIdx < subIdx {
		t.Fatalf("reverse_proxy must stay outside (after) the security subroute: %v", handlerNames(t, mainRoute))
	}
	// matcher 在 subroute 内层路由上：not remote_ip ∈ {10.0.0.9}
	innerRoutes, _ := subroute["routes"].([]interface{})
	if len(innerRoutes) == 0 {
		t.Fatalf("subroute must carry inner routes: %#v", subroute)
	}
	inner := mustMap(t, innerRoutes[0], "inner route")
	subMatchers, _ := inner["match"].([]interface{})
	if len(subMatchers) == 0 {
		t.Fatalf("inner route must carry a matcher: %#v", inner)
	}
	raw, err := json.Marshal(subMatchers[0])
	if err != nil {
		t.Fatalf("marshal matcher: %v", err)
	}
	matcherJSON := string(raw)
	if !strings.Contains(matcherJSON, `"not"`) || !strings.Contains(matcherJSON, `"remote_ip"`) || !strings.Contains(matcherJSON, "10.0.0.9") {
		t.Fatalf("subroute matcher must be not-remote_ip in trust set: %s", matcherJSON)
	}
	// 安全段在 subroute 内（precheck/rate_limit/waf 均不在主链裸层）
	innerNames := map[string]bool{}
	for _, hv := range inner["handle"].([]interface{}) {
		innerNames[mustMap(t, hv, "inner handler")["handler"].(string)] = true
	}
	if !innerNames["waf"] {
		t.Fatalf("waf engines must live inside the subroute: %v", innerNames)
	}
	for _, hv := range handlers {
		h := mustMap(t, hv, "handler")
		if h["handler"] == "waf" || h["handler"] == "rate_limit" {
			t.Fatalf("security handlers must not remain on the main chain when passthrough wraps them: %v", handlerNames(t, mainRoute))
		}
	}
	// 直通形态下预检不再信任并集直通集的 DetectionOnly——预检 id:3 并集仅
	// 含保留检测语义（本用例无 detection 策略，id:3/12 均不应出现直通集）。
	for _, hv := range handlers {
		d, _ := mustMap(t, hv, "handler")["directives"].(string)
		if strings.Contains(d, "10.0.0.9") && strings.Contains(d, "id:3,") {
			t.Fatalf("passthrough trust set must not be emitted as precheck DetectionOnly:\n%s", d)
		}
	}
}

func TestTrustedDetection_id12InPrecheckAndEngines(t *testing.T) {
	// Given：规则绑定 stage0 保留检测策略（信任 10.0.0.9）+ stage3 WAF 策略
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_td", "td.example.test", 8080)
	seedStage0Policy(t, database, "lb_td", `["10.0.0.9"]`, true)
	mpGenBindPolicy(t, database, "lb_td", "td-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_td", "td.example.test"))

	// Then：无直通 subroute（保留检测=全评估）；预检与策略引擎均含 id:12
	// DetectionOnly（信任 10.0.0.9）。
	for _, hv := range mainRoute["handle"].([]interface{}) {
		if mustMap(t, hv, "handler")["handler"] == "subroute" {
			t.Fatalf("detection mode must not wrap security stages in a passthrough subroute: %v", handlerNames(t, mainRoute))
		}
	}
	joined := strings.Join(wafDirectives(t, mainRoute), "\n")
	wantRule := `SecRule REMOTE_ADDR "@ipMatch 10.0.0.9" "id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(joined, wantRule) {
		t.Fatalf("precheck must carry id:12 DetectionOnly for detection trust set:\n%s", joined)
	}
	// 策略引擎同样含 id:12（各自 coraza 事务的 DetectionOnly 独立生效）
	engineCount := strings.Count(joined, "id:12,")
	if engineCount < 2 {
		t.Fatalf("id:12 must appear in precheck AND every policy engine (got %d):\n%s", engineCount, joined)
	}
}

// BuildCorazaDirectives 的 stage0DetectionTrust 变参（第 6 参）：引擎内 id:12
// 由渲染链按规则绑定的 stage0 保留检测策略并集透传。
func TestBuildCorazaDirectives_stage0DetectionTrustEmitsId12(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "blocking"}
	directives := BuildCorazaDirectives(policy, nil, "", false, 0, []string{"10.0.0.9", "192.168.1.0/24"})
	want := `SecRule REMOTE_ADDR "@ipMatch 10.0.0.9,192.168.1.0/24" "id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(directives, want) {
		t.Fatalf("engine must emit id:12 for stage0 detection trust union:\n%s", directives)
	}
	// 缺省（无第 6 参）零发射——存量调用形状不漂移。
	plain := BuildCorazaDirectives(policy, nil, "", false, 0)
	if strings.Contains(plain, "id:12,") {
		t.Fatalf("engine without stage0 trust must not emit id:12:\n%s", plain)
	}
	// 引擎门禁（R-10）：新形状必须被 coraza 编译接受。
	compileForEngineGate(t, directives)
}
