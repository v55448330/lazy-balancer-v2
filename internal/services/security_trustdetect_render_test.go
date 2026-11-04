package services

// 阶段 0 信任保留检测语义变更（2026-11-04 用户裁定，推翻 2026-09-20 原语义）：
//   trust_detection=1 的信任 IP 不再进入任何安全阶段（预检/IP ACL/限流/WAF
//   引擎全部包进「not client_ip ∈ 信任并集」的 subroute），直达上游；唯一
//   事件 = 独立最小 coraza 引擎（仅 id:12）写入的 logged 检测记录（归因信任
//   策略）。非信任 IP 全链评估零变化；直通（trust_detection=0）零变化。
//
// 验证分层（R-10）：形状钉测（本文件渲染断言）之外，信任检测事务必须经
// 真实 coraza 引擎（NewWAF 同版 v3.8.1）跑事务级行为实证——信任 IP 产
// id:12 审计行（logged、不中断、200 响应也记录）、非信任 IP 零审计行，
// 并经真实摄取解析（securityEventsParseTransaction）落事件契约。

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// trustDetectRenderShape 汇集一次渲染中与本语义相关的链位。
type trustDetectRenderShape struct {
	securityWrap    map[string]interface{} // not client_ip ∈ 跳过并集 的 subroute（安全链包裹）
	securityWrapIdx int
	trustRoute      map[string]interface{} // 信任检测 subroute 的内层路由
	trustIdx        int
	proxyIdx        int
	trustHandler    map[string]interface{} // 信任检测 waf handler
}

// findTrustDetectShape 在主链 handlers 上定位安全链包裹 subroute 与信任检测
// subroute。securityWrap=首个带 not+client_ip 匹配的 subroute；trustRoute=
// 带 client_ip 正向匹配且 handle 恰含一个 waf 的 subroute。
func findTrustDetectShape(t *testing.T, mainRoute map[string]interface{}) trustDetectRenderShape {
	t.Helper()
	handlers, ok := mainRoute["handle"].([]interface{})
	if !ok {
		t.Fatalf("main route missing handle chain: %#v", mainRoute)
	}
	var shape trustDetectRenderShape
	shape.securityWrapIdx, shape.trustIdx, shape.proxyIdx = -1, -1, -1
	for i, hv := range handlers {
		h := mustMap(t, hv, "handler")
		switch h["handler"] {
		case "subroute":
			routes, _ := h["routes"].([]interface{})
			if len(routes) == 0 {
				continue
			}
			inner := mustMap(t, routes[0], "inner route")
			matchers, _ := inner["match"].([]interface{})
			if len(matchers) == 0 {
				continue
			}
			matcherJSON := mustJSON(t, matchers[0])
			innerHandle, _ := inner["handle"].([]interface{})
			if strings.Contains(matcherJSON, `"not"`) && strings.Contains(matcherJSON, `"client_ip"`) {
				if shape.securityWrapIdx < 0 {
					shape.securityWrap = h
					shape.securityWrapIdx = i
				}
				continue
			}
			if strings.Contains(matcherJSON, `"client_ip"`) && len(innerHandle) == 1 {
				trustHandler := mustMap(t, innerHandle[0], "trust handler")
				if trustHandler["handler"] == "waf" && shape.trustIdx < 0 {
					shape.trustRoute = inner
					shape.trustIdx = i
					shape.trustHandler = trustHandler
				}
			}
		case "reverse_proxy":
			shape.proxyIdx = i
		}
	}
	return shape
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// innerMatcherJSON 取 subroute 内层路由首个 matcher 的 JSON 文本。
func innerMatcherJSON(t *testing.T, route map[string]interface{}) string {
	t.Helper()
	matchers, ok := route["match"].([]interface{})
	if !ok || len(matchers) == 0 {
		t.Fatalf("inner route missing matcher: %#v", route)
	}
	return mustJSON(t, matchers[0])
}

// TestTrustedDetection_wrapsChainAndRendersMinimalTrustEngine 保留检测渲染形状：
// ①安全链被「not client_ip ∈ 信任并集」subroute 包裹（信任 IP 跳过预检/ACL/
// 限流/WAF 全部阶段）；②信任路径挂仅含 id:12 的最小检测事务；③顺序
// headers→…→安全包裹→信任检测→reverse_proxy。
func TestTrustedDetection_wrapsChainAndRendersMinimalTrustEngine(t *testing.T) {
	stubSecurityLibsAvailable(t)
	// Given：规则绑定 stage0 保留检测策略（信任 10.0.0.9）+ stage3 WAF + 限流策略
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_td", "td.example.test", 8080)
	seedStage0Policy(t, database, "lb_td", `["10.0.0.9"]`, true)
	mpGenBindPolicy(t, database, "lb_td", "td-waf", mpGenPolicySpec{mode: "blocking", enabled: true})
	mpGenBindPolicy(t, database, "lb_td", "td-rl", mpGenPolicySpec{mode: "blocking", enabled: true, rateLimit: true, rps: 10, burst: 20})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_td", "td.example.test"))
	shape := findTrustDetectShape(t, mainRoute)

	// Then①：安全链包裹存在且覆盖保留检测并集。
	if shape.securityWrapIdx < 0 {
		t.Fatalf("保留检测必须把安全链包进 not-client_ip subroute（信任 IP 跳过全部阶段）: %v", handlerNames(t, mainRoute))
	}
	wrapMatcher := innerMatcherJSON(t, mustMap(t, shape.securityWrap["routes"].([]interface{})[0], "wrap route"))
	if !strings.Contains(wrapMatcher, "10.0.0.9") {
		t.Fatalf("安全链包裹的跳过并集必须含保留检测信任 IP 10.0.0.9: %s", wrapMatcher)
	}
	// 包裹内仍是完整安全链（预检+限流+WAF 引擎逐字节不变——id:12 防御性发射保留）。
	wrapHandle := shape.securityWrap["routes"].([]interface{})[0].(map[string]interface{})["handle"].([]interface{})
	wrapNames := map[string]bool{}
	for _, hv := range wrapHandle {
		wrapNames[mustMap(t, hv, "wrap handler")["handler"].(string)] = true
	}
	for _, want := range []string{"waf", "rate_limit", "lb_security_timing_pre", "lb_security_timing_end", "request_body"} {
		if !wrapNames[want] {
			t.Fatalf("安全链包裹内必须保留 %s（非信任路径零漂移）: %v", want, wrapNames)
		}
	}
	wrapDirectives := ""
	for _, hv := range wrapHandle {
		h := mustMap(t, hv, "wrap handler")
		if h["handler"] == "waf" {
			if d, _ := h["directives"].(string); strings.Contains(d, "id:12,") {
				wrapDirectives = d
			}
		}
	}
	if wrapDirectives == "" {
		t.Fatalf("包裹内预检/引擎必须保留防御性 id:12 发射（字节不变）")
	}
	if got := readRenderedIPList(t, wrapDirectives, "u-trust12"); got != "10.0.0.9/32\n" {
		t.Fatalf("id:12 信任并集文件=%q, want 仅 10.0.0.9/32", got)
	}

	// Then②：信任路径存在且是最小检测事务。
	if shape.trustIdx < 0 {
		t.Fatalf("保留检测必须渲染独立最小信任检测路由: %v", handlerNames(t, mainRoute))
	}
	if shape.proxyIdx < 0 || shape.trustIdx < shape.securityWrapIdx || shape.proxyIdx < shape.trustIdx {
		t.Fatalf("链序必须为 安全包裹(%d)→信任检测(%d)→reverse_proxy(%d): %v",
			shape.securityWrapIdx, shape.trustIdx, shape.proxyIdx, handlerNames(t, mainRoute))
	}
	trustMatcher := innerMatcherJSON(t, shape.trustRoute)
	if strings.Contains(trustMatcher, `"not"`) {
		t.Fatalf("信任检测路由必须是正向 client_ip 匹配: %s", trustMatcher)
	}
	if !strings.Contains(trustMatcher, "10.0.0.9") {
		t.Fatalf("信任检测路由必须匹配保留检测并集（10.0.0.9）: %s", trustMatcher)
	}
	directives, _ := shape.trustHandler["directives"].(string)
	if directives == "" {
		t.Fatalf("信任检测 handler 缺 directives: %#v", shape.trustHandler)
	}
	assertTrustDetectDirectivesShape(t, directives, "10.0.0.9/32\n")
}

// assertTrustDetectDirectivesShape 钉最小检测事务的形状：单条 id:12
// nolog,auditlog 规则 + 审计配置 + marker；零 CRS/ACL/GeoIP/自定义/黑名单。
func assertTrustDetectDirectivesShape(t *testing.T, directives, wantFile string) {
	t.Helper()
	if !strings.Contains(directives, `"id:12,phase:1,pass,nolog,auditlog,ctl:ruleEngine=DetectionOnly"`) {
		t.Fatalf("信任检测引擎必须发射 nolog,auditlog 形态的 id:12（RelevantOnly 下 auditlog 命中即落审计行，与上游状态无关）:\n%s", directives)
	}
	for _, want := range []string{"SecRuleEngine On", "SecRequestBodyAccess Off", "SecResponseBodyAccess Off",
		"SecAuditEngine RelevantOnly", "SecAuditLogType lbfile", "SecAuditLogFormat JSON",
		"SecAuditLogParts ABIJDEFHKZ", "SecMarker SECURITY_RULES_END"} {
		if !strings.Contains(directives, want) {
			t.Fatalf("信任检测引擎缺 %s:\n%s", want, directives)
		}
	}
	if strings.Count(directives, "SecRule ") != 1 {
		t.Fatalf("信任检测引擎必须只含一条 SecRule（id:12）:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-trust12"); got != wantFile {
		t.Fatalf("信任检测并集文件=%q, want %q", got, wantFile)
	}
	for _, banned := range []string{"Include ", "deny", "id:2,", "id:4,", "id:7,", "id:8,", "id:13,", "id:14,", "1500000", "1510000", "8000", "allow"} {
		if strings.Contains(directives, banned) {
			t.Fatalf("信任检测引擎不得包含完整引擎面（命中禁词 %q）:\n%s", banned, directives)
		}
	}
}

// TestTrustedDetection_mixedTrustSets_skipsUnionCoversBoth 保留检测+直通混合绑定：
// 跳过并集=两者之并（信任 IP 全部绕开安全链），信任检测路由只匹配保留检测集。
func TestTrustedDetection_mixedTrustSets_skipsUnionCoversBoth(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdmix", "tdmix.example.test", 8080)
	seedStage0Policy(t, database, "lb_tdmix", `["10.0.0.9"]`, true)
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_whitelist,ip_whitelist_enabled,policy_type,trust_detection,enabled)
		VALUES ('stage0-pt','off','["192.168.1.5"]',1,'stage0',0,1)`); err != nil {
		t.Fatal(err)
	}
	var ptID int64
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='stage0-pt'`).Scan(&ptID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_tdmix',?)`, ptID); err != nil {
		t.Fatal(err)
	}
	mpGenBindPolicy(t, database, "lb_tdmix", "tdmix-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdmix", "tdmix.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.securityWrapIdx < 0 || shape.trustIdx < 0 {
		t.Fatalf("混合绑定必须同时渲染安全链包裹与信任检测路由: %v", handlerNames(t, mainRoute))
	}
	wrapMatcher := innerMatcherJSON(t, mustMap(t, shape.securityWrap["routes"].([]interface{})[0], "wrap route"))
	for _, want := range []string{"10.0.0.9", "192.168.1.5"} {
		if !strings.Contains(wrapMatcher, want) {
			t.Fatalf("跳过并集必须含 %s（保留检测∪直通）: %s", want, wrapMatcher)
		}
	}
	trustMatcher := innerMatcherJSON(t, shape.trustRoute)
	if !strings.Contains(trustMatcher, "10.0.0.9") || strings.Contains(trustMatcher, "192.168.1.5") {
		t.Fatalf("信任检测路由必须只匹配保留检测集（不得含直通 IP）: %s", trustMatcher)
	}
}

// TestTrustedPassthrough_renderZeroTrustRoute 直通形态零变化：仅一个 subroute
// （not client_ip ∈ 直通并集），无信任检测路由。
func TestTrustedPassthrough_renderZeroTrustRoute(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tpt", "tpt.example.test", 8080)
	seedStage0Policy(t, database, "lb_tpt", `["10.0.0.9"]`, false)
	mpGenBindPolicy(t, database, "lb_tpt", "tpt-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tpt", "tpt.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.securityWrapIdx < 0 {
		t.Fatalf("直通形态必须保留安全链包裹 subroute: %v", handlerNames(t, mainRoute))
	}
	if shape.trustIdx >= 0 {
		t.Fatalf("直通形态不得渲染信任检测路由（trust_detection=0 零事件）: %v", handlerNames(t, mainRoute))
	}
	// 主链其余位置不得出现第二个 subroute。
	subrouteCount := 0
	for _, hv := range mainRoute["handle"].([]interface{}) {
		if mustMap(t, hv, "handler")["handler"] == "subroute" {
			subrouteCount++
		}
	}
	if subrouteCount != 1 {
		t.Fatalf("直通形态主链必须恰好一个 subroute（got %d）: %v", subrouteCount, handlerNames(t, mainRoute))
	}
}

// TestTrustDetectDirectives_engineGate 最小检测事务逐字送 coraza v3.8.1 编译
// （引擎门禁：形状合法性只能经编译证明）。空并集恒发射（空文件算子永不命中）。
func TestTrustDetectDirectives_engineGate(t *testing.T) {
	t.Run("nonempty-union", func(t *testing.T) {
		directives, err := buildTrustDetectDirectives("lb_eg", []string{"10.0.0.9", "192.168.1.0/24"})
		if err != nil {
			t.Fatalf("buildTrustDetectDirectives: %v", err)
		}
		compileForEngineGate(t, directives)
		if got := readRenderedIPList(t, directives, "u-trust12-lb_eg"); got != "10.0.0.9/32\n192.168.1.0/24\n" {
			t.Fatalf("并集文件=%q, want 聚合排序两条", got)
		}
	})
	t.Run("empty-union-always-emits", func(t *testing.T) {
		directives, err := buildTrustDetectDirectives("lb_eg_empty", []string{})
		if err != nil {
			t.Fatalf("空并集必须恒发射（发射面 flag 语义）: %v", err)
		}
		compileForEngineGate(t, directives)
		assertTrustDetectDirectivesShape(t, directives, "")
	})
	t.Run("nil-union-fails-loud", func(t *testing.T) {
		if _, err := buildTrustDetectDirectives("lb_eg_nil", nil); err == nil {
			t.Fatal("nil 并集必须显性报错（无保留检测策略不得渲染信任检测引擎）")
		}
	})
	t.Run("missing-rule-identity-fails-loud", func(t *testing.T) {
		if _, err := buildTrustDetectDirectives("", []string{"10.0.0.9"}); err == nil {
			t.Fatal("缺规则身份必须显性报错（投影 scope 必须编入规则身份）")
		}
	})
}

// newTrustDetectBehaviorWAF 用真实渲染产物构建 coraza WAF：仅替换审计日志
// 路径与写插件（lbfile 只在 xcaddy 构建的 Caddy 二进制内注册；行为语义
// RelevantOnly/JSON/parts 原样保留），审计落盘走 coraza 内建 Serial 写器。
func newTrustDetectBehaviorWAF(t *testing.T, directives, auditPath string) coraza.WAF {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "SecAuditLog "):
			kept = append(kept, "SecAuditLog "+auditPath)
		case strings.HasPrefix(trimmed, "SecAuditLogType "):
			kept = append(kept, "SecAuditLogType Serial")
		default:
			kept = append(kept, line)
		}
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n")))
	if err != nil {
		t.Fatalf("coraza 拒绝信任检测引擎指令:\n%v\n--- directives ---\n%s", err, strings.Join(kept, "\n"))
	}
	return waf
}

// runTrustDetectTransaction 以真实事务跑完整请求生命周期（含响应阶段与
// ProcessLogging），返回中断（nil=未中断=放行）。ruleCaddyID 经 X-LB-Rule-ID
// 头注入（与生产链首 headers handler 同形，摄取归因消费）。
func runTrustDetectTransaction(waf coraza.WAF, clientIP, ruleCaddyID string, status int) any {
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessConnection(clientIP, 12345, "127.0.0.1", 443)
	tx.ProcessURI("/app?q=1", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "td.example.test")
	tx.AddRequestHeader("X-LB-Rule-ID", ruleCaddyID)
	it := tx.ProcessRequestHeaders()
	if it != nil {
		return it
	}
	if rint := tx.ProcessResponseHeaders(status, "HTTP/1.1"); rint != nil {
		return rint
	}
	tx.ProcessLogging()
	return nil
}

// countAuditDocs 按摄取侧同构方式解析审计文件文档数。
func countAuditDocs(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	n := 0
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			return n
		}
		n++
	}
}

// TestEngineBehavior_trustDetectOnlyEmitsID12Audit R-10 行为实证：
// ①信任 IP（上游 200）→ 恰一条审计行：id:12、未中断、动作=logged；
// ②非信任 IP → 零审计行；③上游 5xx 同样只记 id:12（与状态无关）。
func TestEngineBehavior_trustDetectOnlyEmitsID12Audit(t *testing.T) {
	directives, err := buildTrustDetectDirectives("lb_td", []string{"203.0.113.9"})
	if err != nil {
		t.Fatalf("buildTrustDetectDirectives: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	waf := newTrustDetectBehaviorWAF(t, directives, auditPath)

	// ①信任 IP：200 响应仍必落审计行（auditlog 命中即 relevant，RelevantOnly
	// 的状态门放行）。
	if it := runTrustDetectTransaction(waf, "203.0.113.9", "lb_td", 200); it != nil {
		t.Fatalf("信任 IP 必须放行（无中断），got %#v", it)
	}
	if docs := countAuditDocs(t, auditPath); docs != 1 {
		t.Fatalf("信任 IP 请求必须落恰一条审计行, got %d", docs)
	}

	// ②非信任 IP：零审计行（引擎空转不产事件）。
	if it := runTrustDetectTransaction(waf, "198.51.100.7", "lb_td", 200); it != nil {
		t.Fatalf("非信任 IP 经信任检测引擎必须放行, got %#v", it)
	}
	if docs := countAuditDocs(t, auditPath); docs != 1 {
		t.Fatalf("非信任 IP 不得产生审计行, got %d", docs)
	}

	// ③上游 5xx：依然恰一条（唯一事件=id:12，与上游状态无关）。
	if it := runTrustDetectTransaction(waf, "203.0.113.9", "lb_td", 503); it != nil {
		t.Fatalf("信任 IP 503 场景必须放行（检测引擎不拦）, got %#v", it)
	}
	if docs := countAuditDocs(t, auditPath); docs != 2 {
		t.Fatalf("5xx 后审计行应为 2（信任请求各自一条）, got %d", docs)
	}
}

// TestEngineBehavior_trustDetectAuditRowIngestsAsLoggedID12 审计行 → 事件契约：
// 真实引擎产出的审计 JSON 经摄取解析（securityEventsParseTransaction）必须
// 得到 RuleTriggered=12、action=logged、归因头透传（x-lb-rule-id）。
func TestEngineBehavior_trustDetectAuditRowIngestsAsLoggedID12(t *testing.T) {
	directives, err := buildTrustDetectDirectives("lb_td", []string{"203.0.113.9"})
	if err != nil {
		t.Fatalf("buildTrustDetectDirectives: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	waf := newTrustDetectBehaviorWAF(t, directives, auditPath)
	if it := runTrustDetectTransaction(waf, "203.0.113.9", "lb_td", 200); it != nil {
		t.Fatalf("信任 IP 必须放行, got %#v", it)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	rec, perr := securityEventsParseTransaction(data)
	if perr != nil {
		t.Fatalf("摄取解析失败: %v\n%s", perr, data)
	}
	if rec.RuleTriggered != "12" || rec.Action != "logged" {
		t.Fatalf("事件=(rule=%s action=%s), want (12,logged)", rec.RuleTriggered, rec.Action)
	}
	if rec.ClientIP != "203.0.113.9" {
		t.Fatalf("client_ip=%q, want 203.0.113.9", rec.ClientIP)
	}
	if rec.AttributionRuleID != "lb_td" {
		t.Fatalf("归因头未透传: AttributionRuleID=%q, want lb_td", rec.AttributionRuleID)
	}
	if rec.AnomalyScore != 12 {
		t.Fatalf("保留检测事件语义分=12（预检族）, got %d", rec.AnomalyScore)
	}
}

// TestSecurityEventsAttribution_trustDetectOwnsID12 id:12 归因：logged 归信任
// 保留检测策略（成员命中优先）；直通策略不得认领；blocked 恒不可产；名单
// 发射后漂移由 fallback 认领（摄取必有归属）。
func TestSecurityEventsAttribution_trustDetectOwnsID12(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_whitelist,ip_whitelist_enabled,policy_type,trust_detection,enabled)
		VALUES ('p-td-owner','off','["198.51.100.9"]',1,'stage0',1,1),
		       ('p-pt-other','off','["198.51.100.8"]',1,'stage0',0,1)`); err != nil {
		t.Fatal(err)
	}
	var tdID, ptID int
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='p-td-owner'`).Scan(&tdID); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='p-pt-other'`).Scan(&ptID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_td_attr',?), ('lb_td_attr',?), ('lb_td_only',?), ('lb_pt_only',?)`,
		tdID, ptID, tdID, ptID); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}

	pid, pname := securityEventsAttributePolicy("lb_td_attr", "12", "logged", "198.51.100.9", policyByID, bindings)
	if pid != tdID || pname != "p-td-owner" {
		t.Fatalf("attribution=(%d,%q), want (%d,p-td-owner) — id:12 logged 必须归因信任保留检测策略", pid, pname, tdID)
	}
	pid, _ = securityEventsAttributePolicy("lb_td_attr", "12", "blocked", "198.51.100.9", policyByID, bindings)
	if pid != tdID {
		t.Fatalf("id:12 的发射面唯一属主是保留检测策略（blocked+12 生产不可达——pass 恒不中断，防御性归因仍应归 td）, got %d", pid)
	}
	pid, _ = securityEventsAttributePolicy("lb_pt_only", "12", "logged", "198.51.100.8", policyByID, bindings)
	if pid != 0 {
		t.Fatalf("直通策略物理上不产 id:12，不得认领, got %d", pid)
	}
	// 名单发射后漂移：contains 全部落空 → fallback 仍归保留检测策略（绝不归零）。
	pid, pname = securityEventsAttributePolicy("lb_td_only", "12", "logged", "203.0.113.99", policyByID, bindings)
	if pid != tdID || pname != "p-td-owner" {
		t.Fatalf("漂移 fallback attribution=(%d,%q), want (%d,p-td-owner)", pid, pname, tdID)
	}
}

// TestSecurityEventsPipeline_trustDetectAuditRowEndToEnd 真实审计行 → 入库行：
// 用真实引擎审计 JSON 走摄取归因，事件行 policy_id/策略名/规则列齐全。
func TestSecurityEventsPipeline_trustDetectAuditRowEndToEnd(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_td_e2e", "tde2e.example.test", 8080)
	seedStage0Policy(t, database, "lb_td_e2e", `["203.0.113.9"]`, true)
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	directives, err := buildTrustDetectDirectives("lb_td_e2e", []string{"203.0.113.9"})
	if err != nil {
		t.Fatalf("buildTrustDetectDirectives: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	waf := newTrustDetectBehaviorWAF(t, directives, auditPath)
	if it := runTrustDetectTransaction(waf, "203.0.113.9", "lb_td_e2e", 200); it != nil {
		t.Fatalf("信任 IP 必须放行, got %#v", it)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	rec, perr := securityEventsParseTransaction(data)
	if perr != nil {
		t.Fatalf("摄取解析失败: %v", perr)
	}
	pid, pname := securityEventsAttributePolicy(rec.AttributionRuleID, rec.RuleTriggered, rec.Action, rec.ClientIP, policyByID, bindings)
	wantID := tdPolicyIDForTest(t, database)
	if pid == 0 || pname == "" {
		t.Fatalf("id:12 logged 事件必须归因到保留检测策略, got (%d,%q)", pid, pname)
	}
	if pid != wantID {
		t.Fatalf("attribution policy=%d, want stage0 保留检测策略 %d", pid, wantID)
	}
}

// tdPolicyIDForTest 读回本用例播种的 stage0 保留检测策略 id。
func tdPolicyIDForTest(t *testing.T, database *sql.DB) int {
	t.Helper()
	var id int
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE policy_type='stage0' AND trust_detection=1`).Scan(&id); err != nil {
		t.Fatalf("read stage0 policy: %v", err)
	}
	return id
}
