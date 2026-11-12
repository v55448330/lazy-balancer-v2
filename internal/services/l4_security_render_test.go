package services

// L4（TCP 规则）阶段 0/1 安全渲染 RED 测试（契约 C2，见 .omp/local/l4-stage01-contract.md）：
//   - 绑定启用策略集的 TCP 规则渲染 routes 短路链：信任直通 → deny → 独立黑名单 →
//     allow 交集外 → allow 交集豁免直通 → 逐策略 GeoIP → 兜底采样+proxy；
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
	"time"

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
	// 信任直通/信任检测/deny/bl/allow/豁免直通/geoip/兜底 = 8 条。
	if len(rawRoutes) != 8 {
		t.Fatalf("routes=%d, want 8（trust→trust_detect→deny→bl→allow→豁免直通→geoip→sample+proxy）: %s", len(rawRoutes), dumpJSON(t, server))
	}

	// ① 信任直通：文件匹配 + [（proxy_protocol）→] proxy 透传（零事件零开销；
	// TCPProxyProtocol=false 形态不发射 proxy_protocol——对称性由
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

	// ④b 豁免直通（allow 交集成员豁免 GeoIP，HTTP id:13 路由序等价物）：
	// 同一交集投影文件正向匹配 → 单 proxy（零事件零 close，nolog 语义），
	// GeoIP close 路由在其后。
	allowNotRaw, ok := l4SecRouteMatchers(t, rawRoutes[4])[0]["not"].([]interface{})
	if !ok || len(allowNotRaw) != 1 {
		t.Fatalf("④ allow 路由缺 not 包裹: %#v", l4SecRouteMatchers(t, rawRoutes[4])[0])
	}
	wantAllowFile := allowNotRaw[0].(map[string]interface{})["lb_ipfile"].(map[string]interface{})["file"].(string)
	exemptSets := l4SecRouteMatchers(t, rawRoutes[5])
	if len(exemptSets) != 1 {
		t.Fatalf("豁免直通 matcher sets=%d, want 1", len(exemptSets))
	}
	if _, hasNot := exemptSets[0]["not"]; hasNot {
		t.Fatalf("豁免直通必须正向匹配（交集成员命中）: %#v", exemptSets[0])
	}
	if got := l4SecMatcherFiles(t, exemptSets[0], "lb_ipfile"); len(got) != 1 || got[0] != wantAllowFile {
		t.Fatalf("豁免直通 files=%v, want 与 ④ 同一交集投影 %s", got, wantAllowFile)
	}
	exemptHandlers := l4SecRouteHandlers(t, rawRoutes[5])
	if len(exemptHandlers) != 1 || exemptHandlers[0]["handler"] != "proxy" {
		t.Fatalf("豁免直通 handlers=%#v, want 单 proxy（零事件零 close）", exemptHandlers)
	}

	// ⑤ GeoIP：lb_geoip matcher + policy_id 精确归因。
	geoipMatchers := l4SecRouteMatchers(t, rawRoutes[6])
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
	geoipHandlers := l4SecRouteHandlers(t, rawRoutes[6])
	if len(geoipHandlers) != 2 {
		t.Fatalf("geoip handlers=%d, want 2（lb_l4_sec + close）", len(geoipHandlers))
	}
	assertL4SecEventHandler(t, geoipHandlers[0], "geoip", 15)
	if geoipHandlers[1]["handler"] != "close" {
		t.Fatalf("geoip 断连 handler=%#v, want close", geoipHandlers[1])
	}

	// ⑥ 兜底：lb_l4_sec 采样 + proxy；@id 保持在兜底路由（与现状同位）。
	fbHandlers := l4SecRouteHandlers(t, rawRoutes[7])
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
	if got := rawRoutes[7].(map[string]interface{})["@id"]; got != cid {
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
		{ID: 21, Name: "l4-cc", PolicyType: "stage2", HumanVerifyMode: "force"},
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

// GeoIP allow 模式：lb_geoip 匹配直接编码阻断方向（mode:allow，名单外
// 地区断连；无 not 包裹——不可判定由 matcher fail-open 放行）。
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
	if _, hasNot := sets[0]["not"]; hasNot {
		t.Fatalf("geoip allow 路由不得再经 not 包裹: %#v", sets[0])
	}
	geoipRaw, ok := sets[0]["lb_geoip"].(map[string]interface{})
	if !ok {
		t.Fatalf("缺 lb_geoip 匹配: %#v", sets[0])
	}
	countries, ok := geoipRaw["countries"].([]string)
	if !ok || len(countries) != 1 || countries[0] != "中国" {
		t.Fatalf("countries=%#v, want [中国]", geoipRaw["countries"])
	}
	if mode, _ := geoipRaw["mode"].(string); mode != "allow" {
		t.Fatalf("mode=%v, want allow", geoipRaw["mode"])
	}
}

// 信任检测路由序 + 形状（：trust_detect 置于直通之后、deny 之前——
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

// 规则开 TCPProxyProtocol 时信任族两路由、deny 族与豁免直通/兜底路由对称前置
// proxy_protocol——直通/检测/豁免路由的 lb_l4_sec 归因与上游 PROXY 头都按改写后
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
	if !ok || len(rawRoutes) != 8 {
		t.Fatalf("routes=%d, want 8: %s", len(rawRoutes), dumpJSON(t, server))
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
	// ① 直通：proxy_protocol → proxy（修复点：原来裸 proxy 透传）。
	assertHandlerSeq(rawRoutes[0], "lb_l4_pp", "proxy")
	// ①b 信任检测：proxy_protocol → lb_l4_sec(trust_detect) → proxy。
	assertHandlerSeq(rawRoutes[1], "lb_l4_pp", "lb_l4_sec", "proxy")
	assertL4SecEventHandler(t, l4SecRouteHandlers(t, rawRoutes[1])[1], "trust_detect", 0)
	// ② deny：proxy_protocol → lb_l4_sec → close（既有对称基准）。
	assertHandlerSeq(rawRoutes[2], "lb_l4_pp", "lb_l4_sec", "close")
	// ④b 豁免直通：proxy_protocol → proxy（与信任直通对称，零事件零 close）。
	assertHandlerSeq(rawRoutes[5], "lb_l4_pp", "proxy")
	// ⑥ 兜底：proxy_protocol → allow_sample → proxy（既有对称基准）。
	assertHandlerSeq(rawRoutes[7], "lb_l4_pp", "lb_l4_sec", "proxy")
}

// TCP PROXY 入站解析信任门控：每个 lb_l4_pp handler（信任直通/信任检测/deny 族/
// 兜底采样共用单源）都必须携带 allow（受信代理网段白名单）——PROXY 头仅来自
// 受信网段内的来源时采信（引擎侧按声明源改写对端），其余来源的头被消费但不
// 采信、按直连地址处理，与 HTTP 侧「仅受信网段采信」纪律对齐；受信网段为空时
// allow 空数组仍发射（全部来源按直连地址处理）；关闭 TCPProxyProtocol 零发射
// 回归不变（配置字节不含 lb_l4_pp）。策略语义由仓内模块 lb_l4_pp 显式设置
// （上游 proxy_protocol 在 go-proxyproto v0.15 下 NewConn 恒施加 REQUIRE 且
// allow/fallback 字段不进 NewConn，属死配置）。
func TestBuildTCPServer_tcpProxyProtocol_inboundAllowGating(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	buildRoutes := func(proxyProtocol bool, trustedAllow []string) []interface{} {
		t.Helper()
		rule := l4SecTestRule("lb_l4sec_pp_allow")
		rule.TCPProxyProtocol = proxyProtocol
		server, err := buildTCPServer(rule, &tcpSecurityRenderInput{
			policies:          l4SecAllFeaturePolicies(),
			trustedProxyAllow: trustedAllow,
		})
		if err != nil {
			t.Fatalf("buildTCPServer: %v", err)
		}
		rawRoutes, ok := server["routes"].([]interface{})
		if !ok {
			t.Fatalf("routes missing: %s", dumpJSON(t, server))
		}
		return rawRoutes
	}

	assertAllowGating := func(routes []interface{}, wantAllow []string) {
		t.Helper()
		seen := 0
		for _, route := range routes {
			for _, h := range l4SecRouteHandlers(t, route) {
				if name, _ := h["handler"].(string); name != "lb_l4_pp" {
					continue
				}
				seen++
				rawAllow, ok := h["allow"].([]interface{})
				if !ok {
					t.Fatalf("lb_l4_pp handler 缺 allow（受信网段来源采信白名单）: %s", dumpJSON(t, h))
				}
				var gotAllow []string
				for _, v := range rawAllow {
					s, _ := v.(string)
					gotAllow = append(gotAllow, s)
				}
				if strings.Join(gotAllow, ",") != strings.Join(wantAllow, ",") {
					t.Fatalf("allow=%v, want %v", gotAllow, wantAllow)
				}
			}
		}
		if seen == 0 {
			t.Fatalf("lb_l4_pp handler 零发射: %s", dumpJSON(t, routes))
		}
	}

	// 开启：allow=受信网段展开（桩值顺序保留），必须在每个 lb_l4_pp handler
	// （信任直通/信任检测/deny 族/兜底采样）上。
	assertAllowGating(buildRoutes(true, []string{"203.0.113.0/24", "198.51.100.7/32"}),
		[]string{"203.0.113.0/24", "198.51.100.7/32"})
	// 受信网段为空（未启用/零有效网段/读取失败）：allow 空数组仍发射——全部
	// 来源按直连地址处理（严格但与 HTTP 口径一致）。
	assertAllowGating(buildRoutes(true, nil), nil)
	// 关闭：零发射（受信网段在场也不得发射——配置字节不变回归）。
	for _, route := range buildRoutes(false, []string{"203.0.113.0/24"}) {
		for _, h := range l4SecRouteHandlers(t, route) {
			if name, _ := h["handler"].(string); name == "lb_l4_pp" {
				t.Fatalf("TCPProxyProtocol 关闭时不得发射 lb_l4_pp: %s", dumpJSON(t, h))
			}
		}
	}
}

// TestBuildTCPServer_tcpGeoipPolicyIDOverflowSegment_softSkips 逐策略 GeoIP 的
// policy_id 段界软跳过契约：policy_id 越出普通 GeoIP 段 [1,9999] 时，模块侧
// lb_l4_sec Provision 显性拒绝（handler_test「geoip policy overflows segment」
// 钉住）会打死整份 L4 配置——渲染侧必须与 HTTP 预检链同口径（段界由
// encodeGeoIPPrecheckRuleID 单一裁决）：软跳过该策略 GeoIP 路由 + 告警，
// 其余安全段照常渲染，单策略越界不得波及负载均衡。
func TestBuildTCPServer_tcpGeoipPolicyIDOverflowSegment_softSkips(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	policies := []*models.SecurityPolicy{
		{ID: 12, Name: "l4-deny", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.5/32"]`},
		{ID: 10000, Name: "l4-geoip-overflow", PolicyType: "stage1", GeoIPMode: "deny", GeoIPCountries: []byte(`["海外"]`)},
		{ID: 15, Name: "l4-geoip", PolicyType: "stage1", GeoIPMode: "deny", GeoIPCountries: []byte(`["北京市"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule("lb_l4sec_overflow"), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// deny + 段内 geoip(15) + 兜底 = 3 条；越界 geoip(10000) 软跳过不渲染。
	if len(rawRoutes) != 3 {
		t.Fatalf("routes=%d, want 3（deny→geoip(15)→sample+proxy，越界 geoip 跳过）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	geoipHandlers := l4SecRouteHandlers(t, rawRoutes[1])
	if len(geoipHandlers) != 2 {
		t.Fatalf("geoip handlers=%d, want 2（lb_l4_sec + close）", len(geoipHandlers))
	}
	assertL4SecEventHandler(t, geoipHandlers[0], "geoip", 15)
	if geoipHandlers[1]["handler"] != "close" {
		t.Fatalf("geoip 断连 handler=%#v, want close", geoipHandlers[1])
	}
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
		!strings.Contains(string(out), "lb_ipfile") || !strings.Contains(string(out), "lb_l4_pp") {
		t.Skipf("caddy 二进制未编入 caddyl4sec 模块（list-modules=%s）: %v", strings.TrimSpace(string(out)), merr)
	}

	cid := "lb_l4sec_accept"
	acceptRule := l4SecTestRule(cid)
	// PROXY 入站信任门控形态一并过真实引擎（allow CIDR 形状由仓内 lb_l4_pp
	// 模块 Unmarshal/Provision 裁决）。
	acceptRule.TCPProxyProtocol = true
	server, err := buildTCPServer(acceptRule, &tcpSecurityRenderInput{
		policies:          l4SecAllFeaturePolicies(),
		trustedProxyAllow: []string{"203.0.113.0/24", "198.51.100.7/32"},
	})
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

// allow 模式 ACL 名单为空：仍参与交集（空集→交集空→空投影=恒命中=全拒），
// 与 HTTP 预检同语义——不得经内容门剔除而静默 fail-open。
func TestBuildTCPServer_tcpAclAllowEmptyList_stillContributes(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_allowempty"
	policies := []*models.SecurityPolicy{
		{ID: 51, Name: "l4-allow-empty", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// allow 路由 + 兜底 = 2 条。
	if len(rawRoutes) != 2 {
		t.Fatalf("routes=%d, want 2（allow 空名单仍参与交集→恒拒路由+兜底）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	assertL4SecCloseRoute(t, rawRoutes[0], "lb_ipfile", "l4-allow-"+cid+".txt", "allow", 0, true)
}

// 信任路由的 proxy 实例不挂 health_checks——主动/被动健康检查只由兜底 proxy
// 实例承担（Caddy 按出现次数实例化 proxy，多实例各挂一份会把上游探测频次按
// 实例数放大）。
func TestBuildTCPServer_tcpTrustRoutesProxyNoHealthChecks(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_hc"
	policies := []*models.SecurityPolicy{
		{ID: 61, Name: "l4-trust-p", PolicyType: "stage0", TrustDetection: false, IPWhitelistEnabled: true, IPWhitelist: []byte(`["127.0.0.1"]`)},
		{ID: 62, Name: "l4-trust-d", PolicyType: "stage0", TrustDetection: true, IPWhitelistEnabled: true, IPWhitelist: []byte(`["127.0.0.2"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// trust 直通 + trust_detect + 兜底 = 3 条。
	if len(rawRoutes) != 3 {
		t.Fatalf("routes=%d, want 3: %s", len(rawRoutes), dumpJSON(t, server))
	}
	for i, label := range []string{"trust 直通", "trust_detect"} {
		for _, h := range l4SecRouteHandlers(t, rawRoutes[i]) {
			if h["handler"] != "proxy" {
				continue
			}
			if _, has := h["health_checks"]; has {
				t.Fatalf("%s 路由 proxy 不得挂 health_checks: %#v", label, h)
			}
		}
	}
	// 兜底 proxy 保留 health_checks（健康检查唯一实例）。
	var found bool
	for _, h := range l4SecRouteHandlers(t, rawRoutes[2]) {
		if h["handler"] == "proxy" {
			found = true
			if _, has := h["health_checks"]; !has {
				t.Fatalf("兜底 proxy 缺 health_checks: %#v", h)
			}
		}
	}
	if !found {
		t.Fatal("兜底路由缺 proxy handler")
	}
}

// resetL4GeoipEmptyListWarnForTest 清空空名单脏行告警的限频状态（同策略 ID
// 跨用例串号会把第二次渲染的留痕误判为节流命中）。
func resetL4GeoipEmptyListWarnForTest() {
	l4GeoipEmptyListWarnMu.Lock()
	l4GeoipEmptyListWarnSeen = map[int]time.Time{}
	l4GeoipEmptyListWarnMu.Unlock()
}

// 兜底采样 handler 的 xdb_path 与 geoipMatcherSet 同口径：派生值≠插件默认时
// 显式发射——allow_sample 的归属采样读模块侧 sampleXdbPath，渲染侧不发射时
// 自定义 data_dir 部署会落容器默认 /app/data/ip2region.xdb，采样归属与面板
// GeoIP 静默分叉。默认路径形态字节不变（对照断言钉住）。
func TestL4SecSampleHandler_emitsDerivedXdbPath(t *testing.T) {
	stubSecurityLibsAvailable(t)
	cid := "lb_l4sec_xdb"
	if ip2regionLivePath == defaultIP2RegionLivePath {
		t.Fatalf("setup: 桩路径 %q 不得等于插件默认", ip2regionLivePath)
	}
	// 纯函数形态：非默认路径显式携带派生 xdb_path。
	h := l4SecSampleHandler(cid)
	if got := h["xdb_path"]; got != ip2regionLivePath {
		t.Fatalf("xdb_path=%v, want %s（未发射则自定义 data_dir 部署采样读错库）", got, ip2regionLivePath)
	}
	// 兜底路由装配处同口径（不只纯函数，渲染面一致）。
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: l4SecAllFeaturePolicies()})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	fbHandlers := l4SecRouteHandlers(t, rawRoutes[len(rawRoutes)-1])
	if len(fbHandlers) < 1 || fbHandlers[0]["mode"] != "allow_sample" {
		t.Fatalf("兜底首 handler=%#v, want allow_sample 采样", fbHandlers)
	}
	if got := fbHandlers[0]["xdb_path"]; got != ip2regionLivePath {
		t.Fatalf("兜底采样 xdb_path=%v, want %s", got, ip2regionLivePath)
	}
}

// 对照：默认路径（=插件 Provision 兜底默认）必须省略 xdb_path——渲染字节
// 稳定裁定（loadConfig 同字节短路不变量依赖之）。
func TestL4SecSampleHandler_defaultPathOmitted(t *testing.T) {
	old := ip2regionLivePath
	ip2regionLivePath = defaultIP2RegionLivePath
	t.Cleanup(func() { ip2regionLivePath = old })
	h := l4SecSampleHandler("lb_l4sec_xdb")
	if _, ok := h["xdb_path"]; ok {
		t.Fatalf("默认形态必须省略 xdb_path（字节稳定裁定），got %#v", h)
	}
	if h["handler"] != "lb_l4_sec" || h["mode"] != "allow_sample" || h["rule_caddy_id"] != "lb_l4sec_xdb" {
		t.Fatalf("默认三键形态漂移: %#v", h)
	}
}

// GeoIP 开启（mode≠off）但名单为空 = 带外脏行（写侧启用与名单校验双 400
// 在前，正常写路径不可达）：渲染跳过该策略 GeoIP 路由（allow 模式跳过=静默
// 放行），必须限流留痕而非静默；同策略重复渲染窗口内只告警一次；off 为正常
// 停用态（名单保留不清空），不告警。
func TestBuildTCPServer_tcpGeoipEmptyList_warnsThrottled(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)
	resetL4GeoipEmptyListWarnForTest()
	t.Cleanup(resetL4GeoipEmptyListWarnForTest)

	dirty := &models.SecurityPolicy{ID: 21, Name: "l4-geoip-empty", PolicyType: "stage1", GeoIPMode: "allow", GeoIPCountries: []byte(`[]`)}
	rule := l4SecTestRule("lb_l4sec_geoip_empty")

	buf := captureLogf(t)
	server, err := buildTCPServer(rule, &tcpSecurityRenderInput{policies: []*models.SecurityPolicy{dirty}})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	// 脏行跳过发射：geoip 路由缺席，只有兜底。
	rawRoutes := server["routes"].([]interface{})
	if len(rawRoutes) != 1 {
		t.Fatalf("routes=%d, want 1（空名单 GeoIP 跳过发射）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	if n := strings.Count(buf.String(), "geoip_countries 为空"); n != 1 {
		t.Fatalf("空名单脏行留痕=%d, want 1: %s", n, buf.String())
	}

	// 同策略第二次渲染：窗口内限流，不再刷屏。
	buf.Reset()
	if _, err := buildTCPServer(rule, &tcpSecurityRenderInput{policies: []*models.SecurityPolicy{dirty}}); err != nil {
		t.Fatalf("second buildTCPServer: %v", err)
	}
	if n := strings.Count(buf.String(), "geoip_countries 为空"); n != 0 {
		t.Fatalf("同策略窗口内重复留痕=%d, want 0（限流）: %s", n, buf.String())
	}

	// 对照：mode=off（正常停用态，名单保留不清空）不得告警。
	resetL4GeoipEmptyListWarnForTest()
	off := &models.SecurityPolicy{ID: 22, Name: "l4-geoip-off", PolicyType: "stage1", GeoIPMode: "off", GeoIPCountries: []byte(`["北京市"]`)}
	buf.Reset()
	if _, err := buildTCPServer(rule, &tcpSecurityRenderInput{policies: []*models.SecurityPolicy{off}}); err != nil {
		t.Fatalf("off buildTCPServer: %v", err)
	}
	if strings.Contains(buf.String(), "geoip_countries 为空") {
		t.Fatalf("mode=off 正常停用态不得告警: %s", buf.String())
	}
}

// 直通∩保留检测重叠 IP 的跨协议对齐钉测：TCP 路由序 ① 直通在 ①b 保留检测
// 之前——重叠 IP 命中直通路由即短路（零事件、不进 lb_l4_sec 上报），与 HTTP
// 侧信任路由取「保留检测 − 直通」差集的语义一致（同一 IP 在两种协议下都不产
// 检测事件）。保留检测投影文件保持全量并集（引擎面不因差集门控缩水）。
func TestBuildTCPServer_tcpTrustOverlapPrefersPassthrough(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4overlap"
	policies := []*models.SecurityPolicy{
		{ID: 71, Name: "l4-td-overlap", PolicyType: "stage0", TrustDetection: true, IPWhitelistEnabled: true, IPWhitelist: []byte(`["10.0.0.9","203.0.113.9"]`)},
		{ID: 72, Name: "l4-pt-overlap", PolicyType: "stage0", TrustDetection: false, IPWhitelistEnabled: true, IPWhitelist: []byte(`["10.0.0.9"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// 直通路由在前、保留检测路由在后，再兜底 = 3 条（直通优先=重叠 IP 零事件）。
	if len(rawRoutes) != 3 {
		t.Fatalf("routes=%d, want 3（trust 直通 → trust_detect → 兜底）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	passFiles := l4SecMatcherFiles(t, l4SecRouteMatchers(t, rawRoutes[0])[0], "lb_ipfile")
	if passFiles[0] != filepath.Join(IPListDataDir, "l4-trust-"+cid+".txt") {
		t.Fatalf("首条必须是信任直通路由（重叠 IP 短路于此后一切上报）: %v", passFiles)
	}
	passContent, err := os.ReadFile(passFiles[0])
	if err != nil {
		t.Fatalf("read trust passthrough projection: %v", err)
	}
	if !strings.Contains(string(passContent), "10.0.0.9") {
		t.Fatalf("直通投影=%q, want 含重叠 IP 10.0.0.9（直通优先判定面）", passContent)
	}
	detectFiles := l4SecMatcherFiles(t, l4SecRouteMatchers(t, rawRoutes[1])[0], "lb_ipfile")
	if detectFiles[0] != filepath.Join(IPListDataDir, "l4-trust12-"+cid+".txt") {
		t.Fatalf("第二条必须是保留检测路由: %v", detectFiles)
	}
	detectContent, err := os.ReadFile(detectFiles[0])
	if err != nil {
		t.Fatalf("read trust detection projection: %v", err)
	}
	for _, want := range []string{"10.0.0.9", "203.0.113.9"} {
		if !strings.Contains(string(detectContent), want) {
			t.Fatalf("保留检测投影=%q, want 含 %s（引擎文件保持全量并集）", detectContent, want)
		}
	}
	assertL4SecEventHandler(t, l4SecRouteHandlers(t, rawRoutes[1])[0], "trust_detect", 0)
}

// allow 交集成员豁免逐策略 GeoIP：④ allow 交集外拒绝与 ⑤ 逐策略 GeoIP 之间
// 发射豁免直通路由（HTTP id:13 pass+nolog+skipAfter 的路由序等价物）——交集
// 投影文件正向匹配 → [proxy] 直通（无 lb_l4_sec 事件=nolog 语义，无 close，
// 透传 proxy 不挂 health_checks），GeoIP close 路由在其后（交集成员不再被
// 地域断连）；显式 deny 路由仍在豁免之前（白名单不豁免显式黑名单）。
func TestBuildTCPServer_tcpAllowIntersectionExemptPassthrough(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_exempt"
	policies := []*models.SecurityPolicy{
		{ID: 81, Name: "l4-deny", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.5/32"]`},
		{ID: 82, Name: "l4-allow", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["10.0.0.7/32"]`},
		{ID: 83, Name: "l4-geoip", PolicyType: "stage1", GeoIPMode: "deny", GeoIPCountries: []byte(`["北京市","海外"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// ② deny → ④ allow 交集外 → ④b 豁免直通 → ⑤ geoip → ⑥ 兜底 = 5 条。
	if len(rawRoutes) != 5 {
		t.Fatalf("routes=%d, want 5（deny→allow→豁免直通→geoip→兜底）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	assertL4SecCloseRoute(t, rawRoutes[0], "lb_ipfile", "l4-deny-"+cid+".txt", "deny", 0, false)
	assertL4SecCloseRoute(t, rawRoutes[1], "lb_ipfile", "l4-allow-"+cid+".txt", "allow", 0, true)

	// ④b 豁免直通：与 ④ 同一交集投影文件的正向匹配（无 not 包裹），handle
	// =[proxy] 单 handler——无 lb_l4_sec 事件（nolog 语义）、无 close、无
	// lb_l4_pp（TCPProxyProtocol 关闭形态）、proxy 不挂 health_checks（健康
	// 检查唯一实例仍归兜底 proxy）。
	allowNotRaw, ok := l4SecRouteMatchers(t, rawRoutes[1])[0]["not"].([]interface{})
	if !ok || len(allowNotRaw) != 1 {
		t.Fatalf("④ allow 路由缺 not 包裹: %#v", l4SecRouteMatchers(t, rawRoutes[1])[0])
	}
	allowInner := allowNotRaw[0].(map[string]interface{})
	wantFile := allowInner["lb_ipfile"].(map[string]interface{})["file"].(string)
	exemptSets := l4SecRouteMatchers(t, rawRoutes[2])
	if len(exemptSets) != 1 {
		t.Fatalf("豁免路由 matcher sets=%d, want 1", len(exemptSets))
	}
	if _, hasNot := exemptSets[0]["not"]; hasNot {
		t.Fatalf("豁免路由必须正向匹配（交集成员命中）: %#v", exemptSets[0])
	}
	if got := l4SecMatcherFiles(t, exemptSets[0], "lb_ipfile"); len(got) != 1 || got[0] != wantFile {
		t.Fatalf("豁免路由 files=%v, want 与 ④ 同一交集投影 %s", got, wantFile)
	}
	exemptHandlers := l4SecRouteHandlers(t, rawRoutes[2])
	if len(exemptHandlers) != 1 || exemptHandlers[0]["handler"] != "proxy" {
		t.Fatalf("豁免路由 handlers=%#v, want 单 proxy（nolog 语义，零事件零 close）", exemptHandlers)
	}
	if _, has := exemptHandlers[0]["health_checks"]; has {
		t.Fatalf("豁免路由 proxy 不得挂 health_checks: %#v", exemptHandlers[0])
	}

	// ⑤ geoip 在豁免之后：交集成员不再被地域断连。
	geoipHandlers := l4SecRouteHandlers(t, rawRoutes[3])
	if len(geoipHandlers) != 2 || geoipHandlers[1]["handler"] != "close" {
		t.Fatalf("geoip handlers=%#v, want [lb_l4_sec, close]", geoipHandlers)
	}
	assertL4SecEventHandler(t, geoipHandlers[0], "geoip", 83)

	// 交集投影内容含成员（正向匹配的匹配面）。
	content, err := os.ReadFile(wantFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "10.0.0.7") {
		t.Fatalf("allow 交集投影=%q, want 含 10.0.0.7", content)
	}
}

// 豁免直通发射门镜像 HTTP id:13：无 GeoIP 策略时不发射——交集成员本就经
// 兜底 proxy 透传，此时发射属纯字节变化（回归形状钉住）。
func TestBuildTCPServer_tcpAllowIntersectionExempt_requiresGeoipRoute(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_exempt_nogeo"
	policies := []*models.SecurityPolicy{
		{ID: 84, Name: "l4-allow", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["10.0.0.7/32"]`},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// 无 GeoIP：allow 交集外拒绝 + 兜底 = 2 条，无豁免直通路由。
	if len(rawRoutes) != 2 {
		t.Fatalf("routes=%d, want 2（allow→兜底，无 GeoIP 不发射豁免路由）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	assertL4SecCloseRoute(t, rawRoutes[0], "lb_ipfile", "l4-allow-"+cid+".txt", "allow", 0, true)
	if got := l4SecRouteHandlers(t, rawRoutes[1]); len(got) != 2 || got[0]["mode"] != "allow_sample" {
		t.Fatalf("兜底 handlers=%#v, want [allow_sample, proxy]", got)
	}
}

// 无 allow 名单时不发射豁免直通（避免恒真直通路由绕过其后一切拦截路由，
// 与 HTTP id:13「无 allow 名单不发射」同口径）；GeoIP 照常发射。
func TestBuildTCPServer_tcpAllowIntersectionExempt_noAllowListNotEmitted(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_exempt_noallow"
	policies := []*models.SecurityPolicy{
		{ID: 85, Name: "l4-geoip", PolicyType: "stage1", GeoIPMode: "deny", GeoIPCountries: []byte(`["海外"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// 无 allow：geoip + 兜底 = 2 条。
	if len(rawRoutes) != 2 {
		t.Fatalf("routes=%d, want 2（geoip→兜底，无 allow 不发射豁免路由）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	geoipHandlers := l4SecRouteHandlers(t, rawRoutes[0])
	if len(geoipHandlers) != 2 || geoipHandlers[1]["handler"] != "close" {
		t.Fatalf("geoip handlers=%#v, want [lb_l4_sec, close]", geoipHandlers)
	}
	assertL4SecEventHandler(t, geoipHandlers[0], "geoip", 85)
}

// 交集为空（多条 allow 名单互不相交=恒拒形态）无成员可豁免，不发射豁免
// 直通（与 HTTP id:13「交集为空恒拒形态不发射」同口径）。
func TestBuildTCPServer_tcpAllowIntersectionExempt_emptyIntersectionNotEmitted(t *testing.T) {
	stubSecurityLibsAvailable(t)
	oldDir := IPListDataDir
	IPListDataDir = t.TempDir()
	t.Cleanup(func() { IPListDataDir = oldDir })
	ResetIPListProjectionStateForTest()
	t.Cleanup(ResetIPListProjectionStateForTest)

	cid := "lb_l4sec_exempt_emptyix"
	policies := []*models.SecurityPolicy{
		{ID: 86, Name: "l4-allow-a", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["10.0.0.7/32"]`},
		{ID: 87, Name: "l4-allow-b", PolicyType: "stage1", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["10.0.0.8/32"]`},
		{ID: 88, Name: "l4-geoip", PolicyType: "stage1", GeoIPMode: "deny", GeoIPCountries: []byte(`["海外"]`)},
	}
	server, err := buildTCPServer(l4SecTestRule(cid), &tcpSecurityRenderInput{policies: policies})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	rawRoutes, ok := server["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes missing: %#v", server)
	}
	// 恒拒形态：allow 交集外拒绝 + geoip + 兜底 = 3 条，无豁免直通。
	if len(rawRoutes) != 3 {
		t.Fatalf("routes=%d, want 3（allow 恒拒→geoip→兜底，空交集不发射豁免路由）: %s", len(rawRoutes), dumpJSON(t, server))
	}
	assertL4SecCloseRoute(t, rawRoutes[0], "lb_ipfile", "l4-allow-"+cid+".txt", "allow", 0, true)
	geoipHandlers := l4SecRouteHandlers(t, rawRoutes[1])
	if len(geoipHandlers) != 2 || geoipHandlers[1]["handler"] != "close" {
		t.Fatalf("geoip handlers=%#v, want [lb_l4_sec, close]", geoipHandlers)
	}
	assertL4SecEventHandler(t, geoipHandlers[0], "geoip", 88)
}
