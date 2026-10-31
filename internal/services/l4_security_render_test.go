package services

// L4（TCP 规则）阶段 0/1 安全渲染 RED 测试（契约 C2，见 .omp/local/l4-stage01-contract.md）：
//   - 绑定启用策略集的 TCP 规则渲染 routes 短路链：信任直通 → deny → 独立黑名单 →
//     allow 交集外 → 逐策略 GeoIP → 兜底采样+proxy；
//   - 模块 ID 固定 layer4.handlers.lb_l4_sec / layer4.matchers.lb_geoip / layer4.matchers.lb_ipfile（与 caddyl4sec
//     模块对账，另见 l4sec_module_contract_test.go）；
//   - securityLibsOK 同款降级门（缺库安全段整体不渲染）；
//   - 投影 scope=l4-<kind>-<caddyID>（不得复用 HTTP u-* 粒度），文件进 GC 白名单与
//     渲染引用集；
//   - 无绑定 → 与既有单 proxy 路由逐字段一致（现状回归形状）。
import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func l4SecTestRule(caddyID string) SingleRuleConfig {
	return SingleRuleConfig{
		CaddyID:                       caddyID,
		Protocol:                      "tcp",
		ListenPort:                    9000,
		Strategy:                      "weighted_round_robin",
		HealthCheckInterval:           10,
		HealthCheckUnhealthyThreshold: 3,
		Upstreams: []UpstreamConfig{
			{Host: "127.0.0.1", Port: 8080, Weight: 1, Protocol: "tcp", Enabled: true},
		},
	}
}

// l4SecAllFeaturePolicies 覆盖全部安全段形态：stage0 直通信任 / stage0 保留
// 检测信任 / deny ACL / 独立黑名单 / allow ACL / GeoIP deny。
func l4SecAllFeaturePolicies() []*models.SecurityPolicy {
	return []*models.SecurityPolicy{
		{ID: 11, Name: "l4-trust", PolicyType: "stage0", IPWhitelistEnabled: true, TrustDetection: false, IPWhitelist: []byte(`["10.0.0.1/32"]`)},
		{ID: 16, Name: "l4-trust-detect", PolicyType: "stage0", IPWhitelistEnabled: true, TrustDetection: true, IPWhitelist: []byte(`["10.0.0.2/32"]`)},
		{ID: 12, Name: "l4-deny", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.5/32","10.0.0.6/32"]`},
		{ID: 13, Name: "l4-bl", PolicyType: "stage1", IPBlacklist: []byte(`["9.9.9.9/32"]`)},
		{ID: 14, Name: "l4-allow", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["10.0.0.7/32"]`},
		{ID: 15, Name: "l4-geoip", PolicyType: "stage1", GeoIPMode: "deny", GeoIPCountries: []byte(`["北京市","海外"]`)},
	}
}

func l4SecRouteMatchers(t *testing.T, route interface{}) []map[string]interface{} {
	t.Helper()
	m, ok := route.(map[string]interface{})
	if !ok {
		t.Fatalf("route not a map: %T", route)
	}
	rawMatchers, ok := m["match"].([]interface{})
	if !ok {
		t.Fatalf("route %#v has no match slice", m)
	}
	out := make([]map[string]interface{}, 0, len(rawMatchers))
	for _, raw := range rawMatchers {
		set, ok := raw.(map[string]interface{})
		if !ok {
			t.Fatalf("matcher set not a map: %T", raw)
		}
		out = append(out, set)
	}
	return out
}

func l4SecRouteHandlers(t *testing.T, route interface{}) []map[string]interface{} {
	t.Helper()
	m, ok := route.(map[string]interface{})
	if !ok {
		t.Fatalf("route not a map: %T", route)
	}
	raw, ok := m["handle"].([]interface{})
	if !ok {
		t.Fatalf("route %#v has no handle slice", m)
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		h, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("handler not a map: %T", item)
		}
		out = append(out, h)
	}
	return out
}

func TestBuildTCPServer_tcpWithStage01Policies_rendersShortCircuitChain(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_full"
	rule := l4SecTestRule(cid)
	server, err := buildTCPServer(rule, &tcpSecurityRenderInput{policies: l4SecAllFeaturePolicies()})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// 信任直通/信任检测/deny/bl/allow/geoip/兜底 = 7 条。
	if len(rawRoutes) != 7 {
		t.Fatalf("routes=%d, want 7（trust→trust_detect→deny→bl→allow→geoip→sample+proxy）: %s", len(rawRoutes), dumpJSON(t, server))
	}

	// ① 信任直通：文件匹配 + [（proxy_protocol）→] proxy 透传（零事件零开销；
	// TCPProxyProtocol=false 形态不发射 proxy_protocol——SEC-P2-1 对称性由
	// TestBuildTCPServer_tcpProxyProtocol_trustRoutesPrefixed 钉）。
	trustMatchers := l4SecRouteMatchers(t, rawRoutes[0])
	if len(trustMatchers) != 1 {
		t.Fatalf("trust matcher sets=%d, want 1", len(trustMatchers))
	}
	trustFiles := l4SecMatcherFiles(t, trustMatchers[0], "lb_ipfile")
	wantTrust := filepath.Join(IPListDataDir, "l4-trust-"+cid+".txt")
	if len(trustFiles) != 1 || trustFiles[0] != wantTrust {
		t.Fatalf("trust files=%v, want [%s]", trustFiles, wantTrust)
	}
	trustHandlers := l4SecRouteHandlers(t, rawRoutes[0])
	if len(trustHandlers) != 1 || trustHandlers[0]["handler"] != "proxy" {
		t.Fatalf("trust handlers=%#v, want 单个 proxy handler（零事件零开销）", trustHandlers)
	}

	// ①b 信任检测（trust_detection=1）：logged 事件上报后直通 proxy——路由序
	// 短路其后全部拦截路由（HTTP id:12 DetectionOnly 的 L4 等价物），无 close。
	detectMatchers := l4SecRouteMatchers(t, rawRoutes[1])
	if len(detectMatchers) != 1 {
		t.Fatalf("trust_detect matcher sets=%d, want 1", len(detectMatchers))
	}
	detectFiles := l4SecMatcherFiles(t, detectMatchers[0], "lb_ipfile")
	wantDetect := filepath.Join(IPListDataDir, "l4-trust12-"+cid+".txt")
	if len(detectFiles) != 1 || detectFiles[0] != wantDetect {
		t.Fatalf("trust_detect files=%v, want [%s]", detectFiles, wantDetect)
	}
	detectHandlers := l4SecRouteHandlers(t, rawRoutes[1])
	if len(detectHandlers) != 2 {
		t.Fatalf("trust_detect handlers=%d, want 2（lb_l4_sec + proxy，无 close=不拦截）", len(detectHandlers))
	}
	assertL4SecEventHandler(t, detectHandlers[0], "trust_detect", 0)
	if detectHandlers[1]["handler"] != "proxy" {
		t.Fatalf("trust_detect 透传 handler=%#v, want proxy", detectHandlers[1])
	}

	// ② deny 拒绝：lb_l4_sec(reason=deny,policy_id=0 合并段) + close。
	assertL4SecCloseRoute(t, rawRoutes[2], "lb_ipfile", "l4-deny-"+cid+".txt", "deny", 0, false)

	// ③ 独立黑名单：reason=blacklist。
	assertL4SecCloseRoute(t, rawRoutes[3], "lb_ipfile", "l4-bl-"+cid+".txt", "blacklist", 0, false)

	// ④ allow 交集外：not 包裹 + reason=allow。
	assertL4SecCloseRoute(t, rawRoutes[4], "lb_ipfile", "l4-allow-"+cid+".txt", "allow", 0, true)

	// ⑤ GeoIP：lb_geoip matcher + policy_id 精确归因。
	geoipMatchers := l4SecRouteMatchers(t, rawRoutes[5])
	if len(geoipMatchers) != 1 {
		t.Fatalf("geoip matcher sets=%d, want 1", len(geoipMatchers))
	}
	geoipRaw, ok := geoipMatchers[0]["lb_geoip"].(map[string]interface{})
	if !ok {
		t.Fatalf("geoip matcher missing lb_geoip set: %#v", geoipMatchers[0])
	}
	countries, ok := geoipRaw["countries"].([]string)
	if !ok || len(countries) != 2 {
		t.Fatalf("geoip countries=%#v, want 2 条策略名单原文", geoipRaw["countries"])
	}
	geoipHandlers := l4SecRouteHandlers(t, rawRoutes[5])
	if len(geoipHandlers) != 2 {
		t.Fatalf("geoip handlers=%d, want 2（lb_l4_sec + close）", len(geoipHandlers))
	}
	assertL4SecEventHandler(t, geoipHandlers[0], "geoip", 15)
	if geoipHandlers[1]["handler"] != "close" {
		t.Fatalf("geoip 断连 handler=%#v, want close", geoipHandlers[1])
	}

	// ⑥ 兜底：lb_l4_sec 采样 + proxy；@id 保持在兜底路由（与现状同位）。
	fbHandlers := l4SecRouteHandlers(t, rawRoutes[6])
	if len(fbHandlers) != 2 {
		t.Fatalf("fallback handlers=%d, want 2（allow_sample + proxy）", len(fbHandlers))
	}
	sample := fbHandlers[0]
	if sample["handler"] != "lb_l4_sec" || sample["mode"] != "allow_sample" || sample["rule_caddy_id"] != cid {
		t.Fatalf("fallback sample handler=%#v, want lb_l4_sec allow_sample", sample)
	}
	if _, hasReason := sample["reason"]; hasReason {
		t.Fatalf("fallback sample 不得携带 reason: %#v", sample)
	}
	if fbHandlers[1]["handler"] != "proxy" {
		t.Fatalf("fallback proxy handler=%#v", fbHandlers[1])
	}
	if got := rawRoutes[6].(map[string]interface{})["@id"]; got != cid {
		t.Fatalf("fallback @id=%v, want %s", got, cid)
	}

	// 投影文件落盘 + GC 白名单 + 渲染引用集（发射面一致性口径）。
	for _, scope := range []string{"l4-trust-" + cid, "l4-trust12-" + cid, "l4-deny-" + cid, "l4-bl-" + cid, "l4-allow-" + cid} {
		content, err := os.ReadFile(filepath.Join(IPListDataDir, scope+".txt"))
		if err != nil {
			t.Fatalf("read projection %s: %v", scope, err)
		}
		if !ipListProjectedFileName.MatchString(scope + ".txt") {
			t.Fatalf("GC 白名单不认 L4 投影 %s.txt（孤儿永不回收）", scope)
		}
		if strings.Contains(string(content), "\r") {
			t.Fatalf("projection %s 含回车符: %q", scope, content)
		}
	}
	trustContent, err := os.ReadFile(filepath.Join(IPListDataDir, "l4-trust-"+cid+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trustContent), "10.0.0.1") {
		t.Fatalf("trust projection=%q, want 含 10.0.0.1", trustContent)
	}
	detectContent, err := os.ReadFile(filepath.Join(IPListDataDir, "l4-trust12-"+cid+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(detectContent), "10.0.0.2") {
		t.Fatalf("trust_detect projection=%q, want 含 10.0.0.2（detection 集不再丢弃）", detectContent)
	}
	denyContent, err := os.ReadFile(filepath.Join(IPListDataDir, "l4-deny-"+cid+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"10.0.0.5", "10.0.0.6"} {
		if !strings.Contains(string(denyContent), want) {
			t.Fatalf("deny projection=%q, want 含 %s", denyContent, want)
		}
	}
}

func l4SecMatcherFiles(t *testing.T, set map[string]interface{}, matcher string) []string {
	t.Helper()
	raw, ok := set[matcher].(map[string]interface{})
	if !ok {
		t.Fatalf("matcher set %#v missing %s", set, matcher)
	}
	// lb_ipfile 仓内模块形状：单实例单文件键 file（多文件=match 数组多 set OR）。
	file, ok := raw["file"].(string)
	if !ok {
		t.Fatalf("%s matcher missing file: %#v", matcher, raw)
	}
	return []string{file}
}

// assertL4SecCloseRoute 校验 deny/blacklist/allow 三族的统一形状：
// 文件匹配（allow 为 not 包裹）→ [lb_l4_sec 事件上报, close]。
func assertL4SecCloseRoute(t *testing.T, route interface{}, matcher, file, reason string, policyID int, negated bool) {
	t.Helper()
	sets := l4SecRouteMatchers(t, route)
	if len(sets) != 1 {
		t.Fatalf("%s route matcher sets=%d, want 1", reason, len(sets))
	}
	if negated {
		notRaw, ok := sets[0]["not"].([]interface{})
		if !ok || len(notRaw) != 1 {
			t.Fatalf("%s route 缺 not 包裹: %#v", reason, sets[0])
		}
		inner, ok := notRaw[0].(map[string]interface{})
		if !ok {
			t.Fatalf("%s not 内容非 matcher set: %T", reason, notRaw[0])
		}
		sets[0] = inner
	}
	files := l4SecMatcherFiles(t, sets[0], matcher)
	want := filepath.Join(IPListDataDir, file)
	if len(files) != 1 || files[0] != want {
		t.Fatalf("%s files=%v, want [%s]", reason, files, want)
	}
	handlers := l4SecRouteHandlers(t, route)
	if len(handlers) != 2 {
		t.Fatalf("%s handlers=%d, want 2（lb_l4_sec + close）", reason, len(handlers))
	}
	assertL4SecEventHandler(t, handlers[0], reason, policyID)
	if handlers[1]["handler"] != "close" {
		t.Fatalf("%s 断连 handler=%#v, want close", reason, handlers[1])
	}
}

func assertL4SecEventHandler(t *testing.T, h map[string]interface{}, reason string, policyID int) {
	t.Helper()
	if h["handler"] != "lb_l4_sec" {
		t.Fatalf("event handler=%#v, want lb_l4_sec", h)
	}
	if h["reason"] != reason {
		t.Fatalf("reason=%v, want %s", h["reason"], reason)
	}
	if id, ok := h["policy_id"].(int); !ok || id != policyID {
		t.Fatalf("policy_id=%#v, want %d", h["policy_id"], policyID)
	}
	if h["mode"] != nil {
		t.Fatalf("事件上报 handler 不得携带 mode: %#v", h)
	}
}

func dumpJSON(t *testing.T, v interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// 无绑定（nil 输入）→ 与既有形状逐字段一致：单 proxy 路由 + @id（现状回归形状）。
func TestBuildTCPServer_tcpWithoutSecurity_singleProxyRouteRegression(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input *tcpSecurityRenderInput
	}{
		{name: "nil input", input: nil},
		{name: "no bound policies", input: &tcpSecurityRenderInput{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cid := "lb_l4sec_plain"
			var secInput []*tcpSecurityRenderInput
			if tc.input != nil {
				secInput = append(secInput, tc.input)
			}
			server, err := buildTCPServer(l4SecTestRule(cid), secInput...)
			if err != nil {
				t.Fatalf("buildTCPServer: %v", err)
			}
			routes, ok := server["routes"].([]interface{})
			if !ok || len(routes) != 1 {
				t.Fatalf("routes=%#v, want 单路由", server["routes"])
			}
			route, ok := routes[0].(map[string]interface{})
			if !ok {
				t.Fatalf("route not map: %T", routes[0])
			}
			handlers := l4SecRouteHandlers(t, route)
			if len(handlers) != 1 || handlers[0]["handler"] != "proxy" {
				t.Fatalf("handlers=%#v, want 单 proxy", handlers)
			}
			if route["@id"] != cid {
				t.Fatalf("@id=%v, want %s", route["@id"], cid)
			}
			if _, has := route["match"]; has {
				t.Fatalf("无绑定路由不得携带 match: %#v", route)
			}
			// 与独立 buildTCPProxyRoute 产物同构（单源回归）。
			want, err := buildTCPProxyRoute(l4SecTestRule(cid))
			if err != nil {
				t.Fatal(err)
			}
			if dumpJSON(t, want) != dumpJSON(t, route) {
				t.Fatalf("无绑定形状漂移:\nwant %s\ngot  %s", dumpJSON(t, want), dumpJSON(t, route))
			}
		})
	}
}

// 缺库降级门（securityLibsOK 同款）：CRS/IP2Region 缺失 → 安全段整体不渲染
// （连 trust/deny 文件路由一并缺席），且不留投影副作用。
func TestBuildTCPServer_tcpDegradedLibs_securitySectionAbsent(t *testing.T) {
	// 不调 stubSecurityLibsAvailable：默认探测形态即缺库（crsDirectivesDir 指向不存在目录）。
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_degraded"
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: l4SecAllFeaturePolicies()})
	if err != nil {
		t.Fatalf("缺库必须降级而非失败: %v", err)
	}
	routes, ok := server["routes"].([]interface{})
	if !ok || len(routes) != 1 {
		t.Fatalf("缺库 routes=%d, want 单 proxy 路由", len(routes))
	}
	entries, err := os.ReadDir(IPListDataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("缺库降级不得写投影: %d 个文件", len(entries))
	}
}

// G2（限流）/G3（WAF）特征策略对 L4 渲染零贡献：安全段只消费
// 信任/ACL/黑名单/GeoIP 特征（绑定写侧 400 拒 G2/G3，渲染侧对带外存量忽略）。
func TestBuildTCPServer_tcpG23FeaturesIgnoredInRender(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	policies := []*models.SecurityPolicy{
		{ID: 21, Name: "l4-rate", PolicyType: "stage2", RateLimitEnabled: true, RateLimitRPS: 100},
		{ID: 22, Name: "l4-waf", PolicyType: "stage3", Mode: "blocking"},
	}
	server, err := buildTCPServer(l4SecTestRule("lb_l4sec_g23"), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	routes, ok := server["routes"].([]interface{})
	if !ok || len(routes) != 1 {
		t.Fatalf("纯 G2/G3 绑定的 TCP 渲染 routes=%d, want 单 proxy 路由（限流/WAF 不进 L4 链）", len(routes))
	}
}

// GeoIP allow 模式：lb_geoip 匹配需 not 包裹（名单外地区断连）。
func TestBuildTCPServer_tcpGeoipAllowMode_negatedMatcher(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	policies := []*models.SecurityPolicy{
		{ID: 31, Name: "l4-geo-allow", PolicyType: "stage1", GeoIPMode: "allow", GeoIPCountries: []byte(`["中国"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule("lb_l4sec_geoallow"), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	routes, ok := server["routes"].([]interface{})
	if !ok || len(routes) != 2 {
		t.Fatalf("routes=%d, want 2（geoip allow + 兜底）", len(routes))
	}
	sets := l4SecRouteMatchers(t, routes[0])
	if len(sets) != 1 {
		t.Fatalf("matcher sets=%d, want 1", len(sets))
	}
	notRaw, ok := sets[0]["not"].([]interface{})
	if !ok || len(notRaw) != 1 {
		t.Fatalf("geoip allow 路由缺 not 包裹: %#v", sets[0])
	}
	inner, ok := notRaw[0].(map[string]interface{})
	if !ok {
		t.Fatalf("not 内容非 set: %T", notRaw[0])
	}
	geoipRaw, ok := inner["lb_geoip"].(map[string]interface{})
	if !ok {
		t.Fatalf("not 内缺 lb_geoip: %#v", inner)
	}
	countries, ok := geoipRaw["countries"].([]string)
	if !ok || len(countries) != 1 || countries[0] != "中国" {
		t.Fatalf("countries=%#v, want [中国]", geoipRaw["countries"])
	}
}

// 信任检测路由序 + 形状（SEC-P1-1）：trust_detect 置于直通之后、deny 之前——
// 保留检测信任命中在一切拦截路由前短路（产 logged 事件后直通上游，HTTP
// id:12 DetectionOnly 的 L4 等价物）。仅 stage0 保留检测 + deny 两策略：
// 三路由（trust_detect → deny → 兜底）。
func TestBuildTCPServer_tcpTrustDetection_routeOrderAndShape(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_tdetect"
	policies := []*models.SecurityPolicy{
		{ID: 41, Name: "td", PolicyType: "stage0", IPWhitelistEnabled: true, TrustDetection: true, IPWhitelist: []byte(`["203.0.113.10/32","203.0.113.99/32"]`)},
		{ID: 42, Name: "deny", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["203.0.113.10/32"]`},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok || len(rawRoutes) != 3 {
		t.Fatalf("routes=%d, want 3（trust_detect→deny→兜底）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	// 保留检测信任命中不得落 deny 路由语义：首路由是 trust_detect（lb_l4_sec+
	// proxy），deny（close）在其后，兜底采样在最后。
	detectHandlers := l4SecRouteHandlers(t, rawRoutes[0])
	if len(detectHandlers) != 2 || detectHandlers[0]["handler"] != "lb_l4_sec" || detectHandlers[1]["handler"] != "proxy" {
		t.Fatalf("trust_detect handlers=%#v, want [lb_l4_sec trust_detect, proxy]（无 close=不拦截）", detectHandlers)
	}
	assertL4SecEventHandler(t, detectHandlers[0], "trust_detect", 0)
	if got := detectHandlers[0]["mode"]; got != nil {
		t.Fatalf("trust_detect 不得携带 mode: %#v", detectHandlers[0])
	}
	assertL4SecCloseRoute(t, rawRoutes[1], "lb_ipfile", "l4-deny-"+cid+".txt", "deny", 0, false)
	fbHandlers := l4SecRouteHandlers(t, rawRoutes[2])
	if len(fbHandlers) != 2 || fbHandlers[0]["mode"] != "allow_sample" {
		t.Fatalf("fallback handlers=%#v, want [allow_sample, proxy]", fbHandlers)
	}
	// detection 集投影文件：两策略条目聚合落盘（stage0TrustSets detection 不再丢弃）。
	content, err := os.ReadFile(filepath.Join(IPListDataDir, "l4-trust12-"+cid+".txt"))
	if err != nil {
		t.Fatalf("trust12 projection missing: %v", err)
	}
	for _, want := range []string{"203.0.113.10", "203.0.113.99"} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("trust12 projection=%q, want 含 %s", content, want)
		}
	}
	if !ipListProjectedFileName.MatchString("l4-trust12-" + cid + ".txt") {
		t.Fatalf("GC 白名单不认 l4-trust12 投影（孤儿永不回收）")
	}
}

// 空集不发射：保留检测策略存在但信任并集为空（空名单/条目全失效）→ 不渲染
// trust_detect 路由（L4 渲染器内容门控口径，与直通包裹同族）。
func TestBuildTCPServer_tcpTrustDetect_emptyUnion_notEmitted(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	server, err := buildTCPServer(l4SecTestRule("lb_l4sec_tdempty"), &tcpSecurityRenderInput{policies: []*models.SecurityPolicy{
		{ID: 43, Name: "td-empty", PolicyType: "stage0", IPWhitelistEnabled: true, TrustDetection: true, IPWhitelist: []byte(`[]`)},
	}})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok || len(rawRoutes) != 1 {
		t.Fatalf("routes=%d, want 1（仅兜底，trust_detect 空集不发射）: %s", len(rawRoutes), dumpJSON(t, server))
	}
}

// SEC-P2-1：规则开 TCPProxyProtocol 时信任族两路由与 deny/兜底路由对称前置
// proxy_protocol——直通/检测路由的 lb_l4_sec 归因与上游 PROXY 头都按改写后
// 对端，客户端伪造 PROXY 头不再原样透传上游。
func TestBuildTCPServer_tcpProxyProtocol_trustRoutesPrefixed(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	rule := l4SecTestRule("lb_l4sec_pp")
	rule.TCPProxyProtocol = true
	server, err := buildTCPServer(rule, &tcpSecurityRenderInput{policies: l4SecAllFeaturePolicies()})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok || len(rawRoutes) != 7 {
		t.Fatalf("routes=%d, want 7: %s", len(rawRoutes), dumpJSON(t, server))
	}
	assertHandlerSeq := func(route interface{}, want ...string) {
		t.Helper()
		var got []string
		for _, h := range l4SecRouteHandlers(t, route) {
			name, _ := h["handler"].(string)
			got = append(got, name)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("handler 序=%v, want %v", got, want)
		}
	}
	// ① 直通：proxy_protocol → proxy（SEC-P2-1 修复点：原来裸 proxy 透传）。
	assertHandlerSeq(rawRoutes[0], "proxy_protocol", "proxy")
	// ①b 信任检测：proxy_protocol → lb_l4_sec(trust_detect) → proxy。
	assertHandlerSeq(rawRoutes[1], "proxy_protocol", "lb_l4_sec", "proxy")
	assertL4SecEventHandler(t, l4SecRouteHandlers(t, rawRoutes[1])[1], "trust_detect", 0)
	// ② deny：proxy_protocol → lb_l4_sec → close（既有对称基准）。
	assertHandlerSeq(rawRoutes[2], "proxy_protocol", "lb_l4_sec", "close")
	// ⑥ 兜底：proxy_protocol → allow_sample → proxy（既有对称基准）。
	assertHandlerSeq(rawRoutes[6], "proxy_protocol", "lb_l4_sec", "proxy")
}

// 引擎级实证（R-10 类）：绑定 stage0/1 策略的 TCP 渲染产物必须通过真实
// `caddy validate --adapter json`——与 caddy_engine_acceptance_test.go 同门槛：
// PATH 无 caddy 二进制 / 二进制未编入 lb_l4_sec 模块时显式 SKIP（结构断言
// 由上方各形状用例承担），有引擎时配置被拒即 FAIL。
func TestL4SecConfig_caddyEngineAcceptance(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Skipf("真实 Caddy 引擎不可用：PATH 中未找到 caddy（需要项目定制二进制的 layer4/lb_l4_sec/lb_geoip 模块）: %v", err)
	}
	if out, merr := exec.Command(binary, "list-modules").CombinedOutput(); merr != nil ||
		!strings.Contains(string(out), "lb_l4_sec") || !strings.Contains(string(out), "lb_geoip") ||
		!strings.Contains(string(out), "lb_ipfile") {
		t.Skipf("caddy 二进制未编入 caddyl4sec 模块（list-modules=%s）: %v", strings.TrimSpace(string(out)), merr)
	}

	cid := "lb_l4sec_accept"
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: l4SecAllFeaturePolicies()})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	conf := map[string]interface{}{
		"admin": map[string]interface{}{"listen": CaddyAdminListenAddr},
		"apps": map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{fmt.Sprintf("tcp_%d", l4SecTestRule(cid).ListenPort): server},
			},
		},
	}
	rendered, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "l4sec-acceptance.json")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	out, verr := exec.Command(binary, "validate", "--adapter", "json", "--config", path).CombinedOutput()
	t.Logf("caddy validate --adapter json --config %s\n%s", path, strings.TrimSpace(string(out)))
	if verr != nil {
		t.Fatalf("真实 Caddy 引擎拒绝了 L4 安全路由渲染产物: %v", verr)
	}
}
