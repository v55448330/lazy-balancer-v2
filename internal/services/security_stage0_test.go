package services

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 阶段 0 信任名单执行语义（2026-11-04 用户裁定，推翻 2026-09-20 原语义）：
//   trust_detection=0（默认，直通）：信任 IP 在路由层被「not client_ip」
//     subroute 跳过全部安全阶段（预检/限流/WAF），直达上游——保留路径分流
//     形态，零安全事件（无任何 coraza 事务产生）。
//   trust_detection=1（保留检测记录）：信任 IP 同样跳过全部安全阶段（跳过
//     并集=直通∪保留检测），唯一事件=独立最小 coraza 引擎（仅 id:12，
//     nolog,auditlog）写入的 logged 检测记录（归因信任策略）；主链预检/
//     引擎内的 id:12（nolog）保留为防御性发射（信任 IP 已被路由层短路，
//     永不匹配，字节零变化）。

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
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
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
	// v2.3.x：matcher 改 client_ip（受信代理启用时=真实 IP；未启用与 remote_ip 同值）。
	if !strings.Contains(matcherJSON, `"not"`) || !strings.Contains(matcherJSON, `"client_ip"`) || !strings.Contains(matcherJSON, "10.0.0.9") {
		t.Fatalf("subroute matcher must be not-client_ip in trust set: %s", matcherJSON)
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
	// 直通形态下预检不再信任并集直通集的 DetectionOnly——必须检查
	// subroute 内真实预检/策略引擎，主链裸层没有 waf，读主链会得到假绿。
	for _, d := range wafDirectives(t, inner) {
		if strings.Contains(d, "10.0.0.9") && strings.Contains(d, "ctl:ruleEngine=DetectionOnly") &&
			(strings.Contains(d, "id:3,") || strings.Contains(d, "id:12,")) {
			t.Fatalf("passthrough trust set must not be emitted as precheck DetectionOnly:\n%s", d)
		}
	}
}

func TestTrustedDetection_wrapsChainWithDefensiveID12AndMinimalEngine(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
	// Given：规则绑定 stage0 保留检测策略（信任 10.0.0.9）+ stage3 WAF 策略
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_td", "td.example.test", 8080)
	seedStage0Policy(t, database, "lb_td", `["10.0.0.9"]`, true)
	mpGenBindPolicy(t, database, "lb_td", "td-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_td", "td.example.test"))

	// Then：安全链被「not client_ip ∈ 信任并集」subroute 包裹（信任 IP 跳过
	// 全部阶段）；包裹内预检与策略引擎的 id:12（nolog）防御性发射字节不变；
	// 信任检测路由挂仅含 id:12（nolog,auditlog）的最小检测事务。
	handlers, _ := mainRoute["handle"].([]interface{})
	var wrap, trust map[string]interface{}
	for _, hv := range handlers {
		h := mustMap(t, hv, "handler")
		if h["handler"] != "subroute" {
			continue
		}
		inner := mustMap(t, h["routes"].([]interface{})[0], "inner route")
		matcher := mustJSON(t, inner["match"].([]interface{})[0])
		if strings.Contains(matcher, `"not"`) && wrap == nil {
			wrap = h
		}
		if !strings.Contains(matcher, `"not"`) && trust == nil {
			trust = h
		}
	}
	if wrap == nil || trust == nil {
		t.Fatalf("保留检测必须同时渲染安全链包裹与信任检测路由: %v", handlerNames(t, mainRoute))
	}
	wrapInner := mustMap(t, wrap["routes"].([]interface{})[0], "wrap inner")
	wrapMatcher := mustJSON(t, wrapInner["match"].([]interface{})[0])
	if !strings.Contains(wrapMatcher, `"client_ip"`) || !strings.Contains(wrapMatcher, "10.0.0.9") {
		t.Fatalf("跳过并集必须含保留检测信任集（10.0.0.9）: %s", wrapMatcher)
	}
	joined := strings.Join(wafDirectives(t, wrapInner), "\n")
	wantRule := `"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(joined, wantRule) {
		t.Fatalf("precheck must carry defensive id:12 DetectionOnly for detection trust set:\n%s", joined)
	}
	if got := readRenderedIPList(t, joined, "u-trust12"); got != "10.0.0.9/32\n" {
		t.Fatalf("id:12 信任名单文件=%q, want 仅 10.0.0.9/32", got)
	}
	// 策略引擎同样含 id:12（各自 coraza 事务的 DetectionOnly 独立生效）
	engineCount := strings.Count(joined, "id:12,")
	if engineCount < 2 {
		t.Fatalf("id:12 must appear in precheck AND every policy engine (got %d):\n%s", engineCount, joined)
	}
	// 信任检测路由：最小检测事务（仅 id:12，nolog,auditlog）。
	trustInner := mustMap(t, trust["routes"].([]interface{})[0], "trust inner")
	trustMatcher := mustJSON(t, trustInner["match"].([]interface{})[0])
	if strings.Contains(trustMatcher, `"not"`) || !strings.Contains(trustMatcher, "10.0.0.9") {
		t.Fatalf("信任检测路由必须正向匹配保留检测并集: %s", trustMatcher)
	}
	trustHandle := trustInner["handle"].([]interface{})
	if len(trustHandle) != 1 || mustMap(t, trustHandle[0], "trust handler")["handler"] != "waf" {
		t.Fatalf("信任检测路由必须挂且仅挂一个 waf handler: %#v", trustHandle)
	}
	trustDirectives, _ := mustMap(t, trustHandle[0], "trust handler")["directives"].(string)
	if !strings.Contains(trustDirectives, `"id:12,phase:1,pass,nolog,auditlog,ctl:ruleEngine=DetectionOnly"`) {
		t.Fatalf("信任检测引擎必须发射 nolog,auditlog 形态的 id:12:\n%s", trustDirectives)
	}
}

// BuildCorazaDirectives 的 stage0DetectionTrust 变参（第 6 参）：引擎内 id:12
// 由渲染链按规则绑定的 stage0 保留检测策略并集透传。
func TestBuildCorazaDirectives_stage0DetectionTrustEmitsId12(t *testing.T) {
	policy := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test", []string{"10.0.0.9", "192.168.1.0/24"}))
	want := `"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(directives, want) || !strings.Contains(directives, "@ipListFast ") {
		t.Fatalf("engine must emit id:12 for stage0 detection trust union:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-trust12"); got != "10.0.0.9/32\n192.168.1.0/24\n" {
		t.Fatalf("id:12 名单文件=%q, want 两条聚合排序条目", got)
	}
	// 缺省（无第 6 参）零发射——存量调用形状不漂移。
	plain := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if strings.Contains(plain, "id:12,") {
		t.Fatalf("engine without stage0 trust must not emit id:12:\n%s", plain)
	}
	// 引擎门禁：新形状必须被 coraza 编译接受。
	compileForEngineGate(t, directives)
}
