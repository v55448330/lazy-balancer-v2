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
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"

	"lazy-balancer-v2/wafiplist"
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
// 得到 RuleTriggered=12、action=trust（信任记录，2026-11-12 四结果语义）、归因头透传（x-lb-rule-id）。
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
	if rec.RuleTriggered != "12" || rec.Action != "trust" {
		t.Fatalf("事件=(rule=%s action=%s), want (12,trust)", rec.RuleTriggered, rec.Action)
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

// clientIPRangesOfMatcher 读取一个 matcher 的 client_ip.ranges（渲染产物保持
// []string 形态，未经 JSON 往返）。
func clientIPRangesOfMatcher(t *testing.T, matcherValue interface{}, name string) []string {
	t.Helper()
	matcher := mustMap(t, matcherValue, name)
	clientIP, ok := matcher["client_ip"].(map[string]interface{})
	if !ok {
		t.Fatalf("%s 缺 client_ip matcher: %#v", name, matcher)
	}
	ranges, ok := clientIP["ranges"].([]string)
	if !ok {
		t.Fatalf("%s client_ip.ranges 类型=%T，want []string", name, clientIP["ranges"])
	}
	return ranges
}

// trustRouteRanges 取信任检测路由的正向 client_ip ranges。
func trustRouteRanges(t *testing.T, shape trustDetectRenderShape) []string {
	t.Helper()
	matchers, ok := shape.trustRoute["match"].([]interface{})
	if !ok || len(matchers) == 0 {
		t.Fatalf("信任检测路由缺 matcher: %#v", shape.trustRoute)
	}
	return clientIPRangesOfMatcher(t, matchers[0], "信任检测路由 matcher")
}

// wrapSkipUnionRanges 取安全链包裹 not-client_ip 的跳过并集 ranges。
func wrapSkipUnionRanges(t *testing.T, shape trustDetectRenderShape) []string {
	t.Helper()
	routes, ok := shape.securityWrap["routes"].([]interface{})
	if !ok || len(routes) == 0 {
		t.Fatalf("安全包裹缺内层路由: %#v", shape.securityWrap)
	}
	inner := mustMap(t, routes[0], "wrap route")
	matchers, _ := inner["match"].([]interface{})
	if len(matchers) == 0 {
		t.Fatalf("安全包裹内层路由缺 matcher: %#v", inner)
	}
	outer := mustMap(t, matchers[0], "wrap matcher")
	nots, ok := outer["not"].([]interface{})
	if !ok || len(nots) == 0 {
		t.Fatalf("安全包裹缺 not matcher: %#v", outer)
	}
	return clientIPRangesOfMatcher(t, nots[0], "安全包裹 not matcher")
}

// clientIPInRanges 按 Caddy client_ip 字面 ranges 语义（前缀包含）判定——渲染
// 产物只含字面 ranges（无反向/特殊语义），本 helper 即路由 gate 的行为等价物。
func clientIPInRanges(t *testing.T, ranges []string, ip string) bool {
	t.Helper()
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("parse probe ip %q: %v", ip, err)
	}
	for _, entry := range ranges {
		prefix, perr := wafiplist.ParseIPEntry(entry)
		if perr != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// countSubroutes 统计主链 handles 中的 subroute 数量。
func countSubroutes(t *testing.T, mainRoute map[string]interface{}) int {
	t.Helper()
	handlers, ok := mainRoute["handle"].([]interface{})
	if !ok {
		t.Fatalf("main route missing handle chain: %#v", mainRoute)
	}
	count := 0
	for _, hv := range handlers {
		if mustMap(t, hv, "handler")["handler"] == "subroute" {
			count++
		}
	}
	return count
}

// TestTrustedDetection_overlappingIPExcludedFromTrustRoute 直通∩保留检测重叠 IP：
// 直通优先（与 TCP 路由序「直通 → 保留检测」同语义）——重叠 IP 不进信任检测
// 路由（零 id:12 事件），仅保留检测集 IP 照常进；跳过并集仍是两者之并（热路径
// 字节语义不变），最小检测事务的并集文件保持全量（引擎/预检字节不变）。
func TestTrustedDetection_overlappingIPExcludedFromTrustRoute(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdover", "tdover.example.test", 8080)
	seedStage0Policy(t, database, "lb_tdover", `["10.0.0.9","203.0.113.9"]`, true)
	seedStage0Policy(t, database, "lb_tdover", `["10.0.0.9","192.168.1.5"]`, false)
	mpGenBindPolicy(t, database, "lb_tdover", "tdover-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdover", "tdover.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.securityWrapIdx < 0 || shape.trustIdx < 0 {
		t.Fatalf("混合绑定必须渲染安全链包裹与信任检测路由: %v", handlerNames(t, mainRoute))
	}

	// 跳过并集=直通∪保留检测（热路径判定面不变：重叠 IP 同样绕开全部安全阶段）。
	wantSkip := []string{"10.0.0.9/32", "192.168.1.5/32", "203.0.113.9/32"}
	if got := wrapSkipUnionRanges(t, shape); !reflect.DeepEqual(got, wantSkip) {
		t.Fatalf("跳过并集=%v, want %v（直通∪保留检测，字节语义不变）", got, wantSkip)
	}

	// 信任路由=差集（保留检测 − 直通）：重叠 10.0.0.9 归直通，仅 203.0.113.9 进。
	ranges := trustRouteRanges(t, shape)
	if !reflect.DeepEqual(ranges, []string{"203.0.113.9/32"}) {
		t.Fatalf("信任路由 ranges=%v, want 仅 [203.0.113.9/32]（重叠 IP 直通优先=零 id:12）", ranges)
	}
	if clientIPInRanges(t, ranges, "10.0.0.9") {
		t.Fatal("重叠 IP 不得命中信任检测路由 gate")
	}
	if !clientIPInRanges(t, ranges, "203.0.113.9") {
		t.Fatal("仅检测集 IP 必须命中信任检测路由 gate")
	}

	// 最小检测事务并集文件与防御性 id:12 保持全量并集（引擎面零变化）。
	directives, _ := shape.trustHandler["directives"].(string)
	assertTrustDetectDirectivesShape(t, directives, "10.0.0.9/32\n203.0.113.9/32\n")
}

// TestTrustedDetection_nestedOverlapSplitsTrustRouteRanges 嵌套重叠（保留检测
// 宽段 ∩ 直通子段）按真实 CIDR 差集拆分信任路由 ranges——字符串相等剔除会
// 把整个宽段留在信任路由里，与 TCP 侧直通优先行为分叉。
func TestTrustedDetection_nestedOverlapSplitsTrustRouteRanges(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdnest", "tdnest.example.test", 8080)
	seedStage0Policy(t, database, "lb_tdnest", `["10.0.0.0/24"]`, true)
	seedStage0Policy(t, database, "lb_tdnest", `["10.0.0.128/25"]`, false)
	mpGenBindPolicy(t, database, "lb_tdnest", "tdnest-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdnest", "tdnest.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.trustIdx < 0 {
		t.Fatalf("保留检测宽段减去直通子段后仍非空，必须渲染信任检测路由: %v", handlerNames(t, mainRoute))
	}
	ranges := trustRouteRanges(t, shape)
	if !reflect.DeepEqual(ranges, []string{"10.0.0.0/25"}) {
		t.Fatalf("信任路由 ranges=%v, want [10.0.0.0/25]（仅直通子段被扣除）", ranges)
	}
	if !clientIPInRanges(t, ranges, "10.0.0.9") {
		t.Fatal("宽段内直通子段外的 IP 必须照常命中信任检测路由")
	}
	if clientIPInRanges(t, ranges, "10.0.0.200") {
		t.Fatal("直通子段内 IP（重叠）不得命中信任检测路由")
	}
}

// TestTrustedDetection_fullOverlapSkipsTrustRoute 差异集空（保留检测集全被
// 直通吸收）：不产事件即不发射——不渲染信任检测路由（此前的空 ranges
// 恒发射形态退役）。
func TestTrustedDetection_fullOverlapSkipsTrustRoute(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdfull", "tdfull.example.test", 8080)
	seedStage0Policy(t, database, "lb_tdfull", `["10.0.0.9"]`, true)
	seedStage0Policy(t, database, "lb_tdfull", `["10.0.0.0/24"]`, false)
	mpGenBindPolicy(t, database, "lb_tdfull", "tdfull-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdfull", "tdfull.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.securityWrapIdx < 0 {
		t.Fatalf("重叠信任 IP 仍在跳过并集内，安全链包裹必须保留: %v", handlerNames(t, mainRoute))
	}
	if shape.trustIdx >= 0 {
		t.Fatalf("差异集空不得渲染信任检测路由（直通优先，零 id:12）: %v", handlerNames(t, mainRoute))
	}
	// 包裹内防御性 id:12 与并集文件仍在（引擎/预检发射面不受路由门控影响）。
	wrapHandle := shape.securityWrap["routes"].([]interface{})[0].(map[string]interface{})["handle"].([]interface{})
	wrapRoute := map[string]interface{}{"handle": wrapHandle}
	joined := strings.Join(wafDirectives(t, wrapRoute), "\n")
	if !strings.Contains(joined, `"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`) {
		t.Fatalf("包裹内预检必须保留防御性 id:12: \n%s", joined)
	}
	if got := readRenderedIPList(t, joined, "u-trust12"); got != "10.0.0.9/32\n" {
		t.Fatalf("id:12 信任并集文件=%q, want 全量保留检测集 [10.0.0.9/32]", got)
	}
}

// TestTrustedDetection_emptyUnionSkipsTrustRoute 保留检测策略在但并集空：
// 不产事件即不发射——不渲染信任检测路由（不再以空 client_ip 集恒发射）；
// 防御性 id:12 与空投影文件照常（预检/引擎发射面与路由门控解耦）。
func TestTrustedDetection_emptyUnionSkipsTrustRoute(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdempty", "tdempty.example.test", 8080)
	seedStage0Policy(t, database, "lb_tdempty", `[]`, true)
	mpGenBindPolicy(t, database, "lb_tdempty", "tdempty-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdempty", "tdempty.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.trustIdx >= 0 {
		t.Fatalf("空并集不得渲染信任检测路由（空差集=不产事件即不发射）: %v", handlerNames(t, mainRoute))
	}
	// 跳过并集空 → 安全链平坦（无包裹）。
	if count := countSubroutes(t, mainRoute); count != 0 {
		t.Fatalf("空并集安全链必须平坦（got %d 个 subroute）: %v", count, handlerNames(t, mainRoute))
	}
	joined := strings.Join(wafDirectives(t, mainRoute), "\n")
	if !strings.Contains(joined, `"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`) {
		t.Fatalf("预检必须保留防御性 id:12（发射面与路由门控解耦）: \n%s", joined)
	}
	if got := readRenderedIPList(t, joined, "u-trust12"); got != "" {
		t.Fatalf("空并集投影文件=%q, want 空", got)
	}
}

// TestEngineBehavior_overlapIPRouteGateYieldsZeroID12Audit R-10 引擎级实证：
// 生产渲染产物组合下（信任路由 gate + 真实 coraza 最小检测事务）——
// ①重叠 IP（直通优先）不满足 gate → 零 id:12 审计行；②仅检测集 IP 恰 1 条
// id:12 logged（未中断、归因头透传）；③直通独有与名单外 IP 仍零新增。
// gate 判定用渲染出的 client_ip 字面 ranges（Caddy matcher 语义等价物），
// 事务经 coraza v3.8.1 真实引擎与审计文件计数（沿用本文件既有行为实证手法）。
func TestEngineBehavior_overlapIPRouteGateYieldsZeroID12Audit(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tdgate", "tdgate.example.test", 8080)
	seedStage0Policy(t, database, "lb_tdgate", `["10.0.0.9","203.0.113.9"]`, true)
	seedStage0Policy(t, database, "lb_tdgate", `["10.0.0.9","192.168.1.5"]`, false)
	mpGenBindPolicy(t, database, "lb_tdgate", "tdgate-waf", mpGenPolicySpec{mode: "blocking", enabled: true})

	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_tdgate", "tdgate.example.test"))
	shape := findTrustDetectShape(t, mainRoute)
	if shape.securityWrapIdx < 0 || shape.trustIdx < 0 {
		t.Fatalf("混合绑定必须渲染安全链包裹与信任检测路由: %v", handlerNames(t, mainRoute))
	}
	ranges := trustRouteRanges(t, shape)
	skipUnion := wrapSkipUnionRanges(t, shape)
	directives, _ := shape.trustHandler["directives"].(string)
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	waf := newTrustDetectBehaviorWAF(t, directives, auditPath)

	// 生产等价管线：跳过并集命中的请求不进安全链；信任检测路由 gate 命中的
	// 请求才进入最小检测事务；其余直达上游（零 coraza 事务）。
	run := func(ip string) any {
		if clientIPInRanges(t, skipUnion, ip) {
			if clientIPInRanges(t, ranges, ip) {
				return runTrustDetectTransaction(waf, ip, "lb_tdgate", 200)
			}
			return nil
		}
		// 非信任 IP 走完整安全链（不在本用例断言面）——不进入最小检测事务。
		return nil
	}

	// ① 重叠 IP：直通优先——不进事务，零 id:12 审计行。
	if it := run("10.0.0.9"); it != nil {
		t.Fatalf("重叠 IP 必须零中断直通, got %#v", it)
	}
	if docs := countAuditDocs(t, auditPath); docs != 0 {
		t.Fatalf("重叠 IP 必须零 id:12 审计行, got %d", docs)
	}

	// ② 仅检测集 IP：恰 1 条审计行，id:12 logged，客户端 IP/归因头正确。
	if it := run("203.0.113.9"); it != nil {
		t.Fatalf("仅检测集 IP 必须放行（检测不拦）, got %#v", it)
	}
	if docs := countAuditDocs(t, auditPath); docs != 1 {
		t.Fatalf("仅检测集 IP 必须恰 1 条 id:12 审计行, got %d", docs)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	rec, perr := securityEventsParseTransaction(data)
	if perr != nil {
		t.Fatalf("摄取解析失败: %v\n%s", perr, data)
	}
	if rec.RuleTriggered != "12" || rec.Action != "trust" {
		t.Fatalf("事件=(rule=%s action=%s), want (12,trust)", rec.RuleTriggered, rec.Action)
	}
	if rec.ClientIP != "203.0.113.9" || rec.AttributionRuleID != "lb_tdgate" {
		t.Fatalf("事件归因=(ip %q rule %q), want (203.0.113.9, lb_tdgate)", rec.ClientIP, rec.AttributionRuleID)
	}

	// ③ 直通独有 IP 与名单外 IP：零新增审计行（不进入任何 coraza 事务）。
	if it := run("192.168.1.5"); it != nil {
		t.Fatalf("直通独有 IP 必须零中断直通, got %#v", it)
	}
	if it := run("198.51.100.7"); it != nil {
		t.Fatalf("名单外 IP 不得被最小检测事务中断, got %#v", it)
	}
	if docs := countAuditDocs(t, auditPath); docs != 1 {
		t.Fatalf("直通独有/名单外 IP 不得新增审计行, got %d", docs)
	}
}
