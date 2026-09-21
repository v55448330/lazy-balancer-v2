package services

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// SC-GEN-01..05（v2.2.0 多策略绑定 · Caddy 生成路径）：一条 LB 规则可绑定至多
// maxBindingsPerRule=8 条安全策略，评估顺序 = policy_id ASC；每策略的 [rate_limit?, waf?] 处理器组
// 按序编入规则主路由。geoip pass 路由至多一条（任一启用策略带 geoip 即存在，
// 为下游 coraza 的 GeoIP SecRule 设置 X-GeoIP-* headers；地域拦截在各自策略的
// waf directives 内评估，无 Caddy 原生 block 路由）；错误路由取首绑定（最低
// policy_id）启用策略的拦截页，匹配表达式只含统一 403 interruption 子句；
// disabled 策略在生成中零贡献。

// mpGenPolicySpec 描述一条待播种策略的生成相关字段（未列字段走表默认值）。
type mpGenPolicySpec struct {
	mode            string // off/detection/blocking（空 → off）
	enabled         bool
	rateLimit       bool
	rps             int
	burst           int
	geoCountries    string // geoip_countries JSON（空 → '[]'）
	geoMode         string // deny/allow（空 → deny）
	blockPageID     int
	blockStatusCode int
	ipACLEnabled    bool
	ipACLMode       string // allow/deny/bypass（空 → 不设置）
	ipACLList       string // ip_acl_list JSON（空 → '[]'）
	ipBlacklist     string // ip_blacklist JSON（空 → '[]'）
}

// mpGenBindPolicy 播种一条策略并绑定到规则，返回 policy_id。
func mpGenBindPolicy(t *testing.T, database *sql.DB, ruleCaddyID, name string, spec mpGenPolicySpec) int {
	t.Helper()
	mode := spec.mode
	if mode == "" {
		mode = "off"
	}
	enabled := 0
	if spec.enabled {
		enabled = 1
	}
	rateLimit := 0
	if spec.rateLimit {
		rateLimit = 1
	}
	countries := spec.geoCountries
	if countries == "" {
		countries = "[]"
	}
	geoMode := spec.geoMode
	if geoMode == "" {
		geoMode = "deny"
	}
	ipACLEnabled := 0
	if spec.ipACLEnabled {
		ipACLEnabled = 1
	}
	ipACLList := spec.ipACLList
	if ipACLList == "" {
		ipACLList = "[]"
	}
	ipBlacklist := spec.ipBlacklist
	if ipBlacklist == "" {
		ipBlacklist = "[]"
	}
	result, err := database.Exec(`INSERT INTO security_policies
		(name, mode, enabled, rate_limit_enabled, rate_limit_rps, rate_limit_burst, geoip_countries, geoip_mode, block_page_id, block_status_code,
		 ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_blacklist)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		name, mode, enabled, rateLimit, spec.rps, spec.burst, countries, geoMode, spec.blockPageID, spec.blockStatusCode,
		ipACLEnabled, spec.ipACLMode, ipACLList, ipBlacklist)
	if err != nil {
		t.Fatalf("seed policy %s: %v", name, err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy %s id: %v", name, err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?,?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind policy %s to %s: %v", name, ruleCaddyID, err)
	}
	return int(policyID)
}

// mpGenHTTPRule 构造一条内存 SingleRuleConfig（与播种的规则行同 CaddyID/域名）。
func mpGenHTTPRule(caddyID, domain string) SingleRuleConfig {
	return SingleRuleConfig{
		CaddyID:    caddyID,
		Protocol:   "http",
		Domain:     domain,
		ListenPort: 8080,
		Strategy:   "weighted_round_robin",
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.10", Port: 8080, Weight: 1, Protocol: "http", Enabled: true},
		},
	}
}

// mpGenRoutes 经批量预载上下文生成规则路由（与全量渲染同通道）。
func mpGenRoutes(t *testing.T, database *sql.DB, rule SingleRuleConfig) ([]map[string]interface{}, map[string]interface{}) {
	t.Helper()
	ctx, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext: %v", err)
	}
	routes, mainRoute, err := generateHTTPRouteObjects(rule, ctx)
	if err != nil {
		t.Fatalf("generateHTTPRouteObjects: %v", err)
	}
	return routes, mainRoute
}

// mpCountGeoipPassRoutes 统计携带 geoip2region 直通处理器的路由条数。
func mpCountGeoipPassRoutes(t *testing.T, routes []map[string]interface{}) int {
	t.Helper()
	count := 0
	for _, route := range routes {
		names := handlerNames(t, route)
		if len(names) == 1 && names[0] == "geoip2region" {
			count++
		}
	}
	return count
}

// SC-GEN-01：路由顺序 = geoipPass(≤1) → pathRoutes → main；主路由处理器链按
// 阶段化执行模型编排——阶段 1 合并预检（IP ACL+GeoIP，单/多策略同构）→ 阶段 2
// 限流（全部策略 rate_limit 集中）→ 阶段 3 每策略独立 WAF 引擎（policy_id ASC）。
// 纯 GeoIP 策略（p1 off+geoip）不再贡献策略 waf，GeoIP 链由预检 800000+ 段承接。
func TestMultiPolicy_RouteComposition_OrderAndHandlerGroups(t *testing.T) {
	// Given 一条规则绑定三条启用策略（绑定顺序故意打乱，验证按 policy_id ASC）：
	// p1(off+geoip) < p2(blocking+限流) < p3(detection+geoip)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen1", "gen1.example.test", 8080)
	p1 := mpGenBindPolicy(t, database, "lb_gen1", "gen1-p1", mpGenPolicySpec{
		mode: "off", enabled: true, geoCountries: `["海外"]`, blockStatusCode: 451,
	})
	p2 := mpGenBindPolicy(t, database, "lb_gen1", "gen1-p2", mpGenPolicySpec{
		mode: "blocking", enabled: true, rateLimit: true, rps: 100, burst: 50,
	})
	p3 := mpGenBindPolicy(t, database, "lb_gen1", "gen1-p3", mpGenPolicySpec{
		mode: "detection", enabled: true, geoCountries: `["江苏"]`,
	})
	if !(p1 < p2 && p2 < p3) {
		t.Fatalf("seed ids not ascending: %d %d %d", p1, p2, p3)
	}
	rule := mpGenHTTPRule("lb_gen1", "gen1.example.test")
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{{SortOrder: 1, MatchType: "prefix", Path: "/api/"}}

	// When
	routes, mainRoute := mpGenRoutes(t, database, rule)

	// Then 顺序：pass → path → main（地域拦截改走 coraza，无逐策略 block 路由）
	if len(routes) != 3 {
		t.Fatalf("want 3 routes (pass+path+main), got %d: %#v", len(routes), routes)
	}
	if names := handlerNames(t, routes[0]); len(names) != 1 || names[0] != "geoip2region" {
		t.Fatalf("routes[0] handlers=%v, want geoip pass route", names)
	}
	for _, route := range routes {
		for _, name := range handlerNames(t, route) {
			if name == "error" {
				t.Fatalf("native geoip block route must not be emitted: %#v", route)
			}
		}
	}
	// routes[1] = path 路由，routes[2] = 主路由
	if _, hasPath := routeMatcher(t, routes[1])["path"]; !hasPath {
		t.Fatalf("routes[1] must be the path route: %#v", routes[1])
	}
	if _, hasPath := routeMatcher(t, routes[2])["path"]; hasPath {
		t.Fatalf("routes[2] must be the main route (no path matcher): %#v", routes[2])
	}

	// 主路由处理器链（阶段化模型）：headers(X-LB-Rule-ID 注入，F3) →
	// lb_rule_metrics → lb_security_blocked_counter → 阶段 1 预检 waf（p1/p3
	// GeoIP 链）→ request_body → 阶段 2 rate_limit(p2) → 阶段 3 waf(p2
	// blocking) → waf(p3 detection，不含 GeoIP) → reverse_proxy。
	names := handlerNames(t, mainRoute)
	if len(names) != 9 || names[0] != "headers" || names[1] != "lb_rule_metrics" || names[2] != "lb_security_blocked_counter" || names[3] != "waf" || names[4] != "request_body" || names[5] != "rate_limit" || names[6] != "waf" || names[7] != "waf" {
		t.Fatalf("main chain=%v, want [headers(X-LB-Rule-ID), lb_rule_metrics, lb_security_blocked_counter, waf(precheck), request_body, rate_limit(p2), waf(p2), waf(p3), reverse_proxy]", names)
	}
	if names[len(names)-1] != "reverse_proxy" {
		t.Fatalf("main chain last handler=%v, want reverse_proxy", names)
	}
	wafs := wafHandlers(t, mainRoute)
	if len(wafs) != 3 {
		t.Fatalf("waf handlers=%d, want 3 (precheck/p2/p3): %v", len(wafs), names)
	}
	precheck := wafs[0]["directives"].(string)
	p2Waf := wafs[1]["directives"].(string)
	p3Waf := wafs[2]["directives"].(string)
	// 预检：p1(海外) 与 p3(江苏) 的 GeoIP 链按策略序在 800000+ 段，无 CRS Include
	if !strings.Contains(precheck, "SecRuleEngine On") || strings.Contains(precheck, "Include ") {
		t.Fatalf("precheck must be geoip-only directives, got: %.200s", precheck)
	}
	if !strings.Contains(precheck, fmt.Sprintf("id:%d,", 800000+p1)) || !strings.Contains(precheck, `@rx ^(?:海外)$`) {
		t.Fatalf("precheck must carry p1 overseas geoip chain (id %d):\n%s", 800000+p1, precheck)
	}
	if !strings.Contains(precheck, fmt.Sprintf("id:%d,", 800000+p3)) || !strings.Contains(precheck, `江苏(?:/.*)?`) {
		t.Fatalf("precheck must carry p3 Jiangsu geoip chain (id %d):\n%s", 800000+p3, precheck)
	}
	if strings.Index(precheck, fmt.Sprintf("id:%d,", 800000+p1)) > strings.Index(precheck, fmt.Sprintf("id:%d,", 800000+p3)) {
		t.Fatalf("precheck geoip chains must follow policy order p1 < p3:\n%s", precheck)
	}
	if !strings.Contains(p2Waf, "SecRuleEngine On") || strings.Contains(p2Waf, "DetectionOnly") {
		t.Fatalf("p2 waf must be blocking directives, got: %.200s", p2Waf)
	}
	// p3：检测模式；GeoIP 已迁预检，策略引擎零 GeoIP 段
	if !strings.Contains(p3Waf, "DetectionOnly") {
		t.Fatalf("p3 waf must be detection directives, got: %.200s", p3Waf)
	}
	if strings.Contains(p3Waf, `msg:'GeoIP 区域拦截'`) {
		t.Fatalf("p3 waf must not carry geoip rules (moved to precheck):\n%s", p3Waf)
	}
	// geoip 处理器只能出现在 pass 路由，主链不得重复
	for _, name := range names {
		if name == "geoip2region" {
			t.Fatalf("main chain must not contain geoip2region: %v", names)
		}
	}
}

// SC-GEN-02：两条策略同时开启限流 → 2 个 rate_limit 处理器，zone 键互不相同且
// 嵌入 policy_id（{ruleID}-p{policyID}-sec / -min；burst=0 时 {ruleID}-p{policyID}）。
func TestMultiPolicy_RateLimitZoneKeys_EmbedPolicyID(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen2", "gen2.example.test", 8080)
	pA := mpGenBindPolicy(t, database, "lb_gen2", "gen2-pA", mpGenPolicySpec{
		mode: "off", enabled: true, rateLimit: true, rps: 100, burst: 50,
	})
	pB := mpGenBindPolicy(t, database, "lb_gen2", "gen2-pB", mpGenPolicySpec{
		mode: "off", enabled: true, rateLimit: true, rps: 20, burst: 0,
	})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen2", "gen2.example.test"))

	// Then 两个 rate_limit 处理器（策略 ASC 顺序）
	handlers, _ := mainRoute["handle"].([]interface{})
	var rateLimits []map[string]interface{}
	for _, handlerValue := range handlers {
		handler := mustMap(t, handlerValue, "handler")
		if handler["handler"] == "rate_limit" {
			rateLimits = append(rateLimits, handler)
		}
	}
	if len(rateLimits) != 2 {
		t.Fatalf("want 2 rate_limit handlers (one per policy), got %d", len(rateLimits))
	}
	zonesA := mustMap(t, rateLimits[0]["rate_limits"], "policy A zones")
	wantSecA := fmt.Sprintf("lb_gen2-p%d-sec", pA)
	wantMinA := fmt.Sprintf("lb_gen2-p%d-min", pA)
	if len(zonesA) != 2 || zonesA[wantSecA] == nil || zonesA[wantMinA] == nil {
		t.Fatalf("policy A zone keys=%v, want [%s %s]", mapKeys(zonesA), wantSecA, wantMinA)
	}
	zonesB := mustMap(t, rateLimits[1]["rate_limits"], "policy B zones")
	wantB := fmt.Sprintf("lb_gen2-p%d", pB)
	if len(zonesB) != 1 || zonesB[wantB] == nil {
		t.Fatalf("policy B zone keys=%v, want [%s]", mapKeys(zonesB), wantB)
	}
	// 两个处理器的 zone 键集合必须互不相交（否则 UsagePool 按名共享计数器）
	for key := range zonesA {
		if zonesB[key] != nil {
			t.Fatalf("zone key %q shared between policies — counters would silently merge", key)
		}
	}
	// 限流额度仍来自各自策略
	secZone := mustMap(t, zonesA[wantSecA], "policy A sec zone")
	assertEqual(t, secZone["max_events"], 150)
	zoneB := mustMap(t, zonesB[wantB], "policy B zone")
	assertEqual(t, zoneB["max_events"], 20)
}

// SC-GEN-06：阶段化执行模型——阶段 2（限流）集中在全部 WAF 引擎（阶段 3）
// 之前：双策略各开限流时主路由 handle 链中两个 rate_limit 的索引均小于全部
// 策略 waf 的索引（单/多策略链形状同构：阶段 1 预检 → 阶段 2 限流 → 阶段 3
// WAF；限流恒 429，被前位 WAF 拦的请求也消耗后位策略配额为已裁定口径）。
func TestMultiPolicy_RateLimitStagePrecedesAllWafEngines(t *testing.T) {
	// Given 一条规则绑定两条 blocking+限流策略（无 IP 控制/GeoIP → 无预检段）：
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_stage", "stage.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_stage", "stage-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, rateLimit: true, rps: 100, burst: 50,
	})
	mpGenBindPolicy(t, database, "lb_stage", "stage-p2", mpGenPolicySpec{
		mode: "blocking", enabled: true, rateLimit: true, rps: 20, burst: 0,
	})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_stage", "stage.example.test"))

	// Then 两个 rate_limit 索引均小于全部策略 waf 索引（阶段 2 先于阶段 3）
	names := handlerNames(t, mainRoute)
	var rateLimitIdx, wafIdx []int
	for i, name := range names {
		switch name {
		case "rate_limit":
			rateLimitIdx = append(rateLimitIdx, i)
		case "waf":
			wafIdx = append(wafIdx, i)
		}
	}
	if len(rateLimitIdx) != 2 || len(wafIdx) != 2 {
		t.Fatalf("chain=%v, want 2 rate_limit + 2 policy waf handlers", names)
	}
	for _, rl := range rateLimitIdx {
		for _, wf := range wafIdx {
			if rl > wf {
				t.Fatalf("stage order violated: rate_limit idx %d after waf idx %d, chain=%v", rl, wf, names)
			}
		}
	}
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// SC-GEN-03：geoip pass 路由存在 ⟺ 至少一条绑定启用策略带 geoip；多条 geoip
// 策略时 pass 路由仍至多一条（地域拦截改走各自策略的 coraza directives）。
func TestMultiPolicy_GeoipPassRoute_ExistsIffAnyEnabledPolicyHasGeoIP(t *testing.T) {
	// Given 情形 A：唯一绑定启用策略无 geoip → 无 pass 路由
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen3a", "gen3a.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_gen3a", "gen3a-plain", mpGenPolicySpec{mode: "blocking", enabled: true})

	// When
	routesA, _ := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen3a", "gen3a.example.test"))

	// Then 仅主路由
	if len(routesA) != 1 {
		t.Fatalf("no-geoip rule: want 1 route (main only), got %d: %#v", len(routesA), routesA)
	}
	if count := mpCountGeoipPassRoutes(t, routesA); count != 0 {
		t.Fatalf("no-geoip rule: pass routes=%d, want 0", count)
	}

	// Given 情形 B：两条启用策略都带 geoip → 恰好一条 pass 路由（无 block 路由）
	seedHTTPRuleForGeneration(t, database, "lb_gen3b", "gen3b.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_gen3b", "gen3b-p1", mpGenPolicySpec{
		mode: "off", enabled: true, geoCountries: `["海外"]`,
	})
	mpGenBindPolicy(t, database, "lb_gen3b", "gen3b-p2", mpGenPolicySpec{
		mode: "off", enabled: true, geoCountries: `["江苏"]`,
	})

	// When
	routesB, _ := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen3b", "gen3b.example.test"))

	// Then
	if count := mpCountGeoipPassRoutes(t, routesB); count != 1 {
		t.Fatalf("two geoip policies: pass routes=%d, want exactly 1", count)
	}
	for _, route := range routesB {
		for _, name := range handlerNames(t, route) {
			if name == "error" {
				t.Fatalf("native geoip block route must not be emitted: %#v", route)
			}
		}
	}
}

// SC-GEN-04：错误路由 = 每规则 403 兜底（host 限定，首绑定策略页，承接预检
// 合并中断与无页策略中断）+ 每有页策略 1 条合成码归因路由（无 host，渲染
// 各自拦截页与状态码）+ 限流 429（首绑定策略页，恒 429）。
func TestMultiPolicy_ErrorRoutes_FirstBoundBlockPageAndUnionMatcher(t *testing.T) {
	// Given p1(geoip 451+page7) < p2(geoip 503+page8+限流)
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen4", "gen4.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>first-block</html>")
	seedSecurityBlockPage(t, database, 8, "<html>second-block</html>")
	p1 := mpGenBindPolicy(t, database, "lb_gen4", "gen4-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, geoCountries: `["海外"]`, blockPageID: 7, blockStatusCode: 451,
	})
	p2 := mpGenBindPolicy(t, database, "lb_gen4", "gen4-p2", mpGenPolicySpec{
		mode: "off", enabled: true, rateLimit: true, rps: 100, geoCountries: `["江苏"]`, blockPageID: 8, blockStatusCode: 503,
	})
	if !(p1 < p2) {
		t.Fatalf("seed ids not ascending: %d %d", p1, p2)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	if len(errorRoutes) != 4 {
		t.Fatalf("want 4 error routes (fallback + 2 attribution + rate limit), got %#v", errorRoutes)
	}
	var blockPageRoute, rateLimitRoute map[string]interface{}
	bySynthetic := make(map[string]map[string]interface{}, 2)
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, route)["expression"].(string)
		switch {
		case expr == "{http.error.status_code} == 429":
			rateLimitRoute = route
		case strings.Contains(expr, "== 403"):
			blockPageRoute = route
		case strings.Contains(expr, "== 483 &&"):
			bySynthetic["483"] = route
		case strings.Contains(expr, "== 484 &&"):
			bySynthetic["484"] = route
		}
	}
	if blockPageRoute == nil || rateLimitRoute == nil || bySynthetic["483"] == nil || bySynthetic["484"] == nil {
		t.Fatalf("missing error route kind: fallback=%v rateLimit=%v attr483=%v attr484=%v",
			blockPageRoute != nil, rateLimitRoute != nil, bySynthetic["483"] != nil, bySynthetic["484"] != nil)
	}
	// 兜底路由：host 限定，首绑定策略（p1）的页面与状态码，统一 403 interruption
	// 子句（"GeoIP blocked" 子句已消亡——预检合并中断与无页策略中断走此）
	handler := firstHandler(t, blockPageRoute)
	assertEqual(t, handler["body"], "<html>first-block</html>")
	assertEqual(t, handler["status_code"], 451)
	wantExpr := "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')"
	assertEqual(t, routeMatcher(t, blockPageRoute)["expression"], wantExpr)
	// 归因路由：逐策略渲染各自拦截页与状态码（483=p1/451，484=p2/503），无 host
	for code, wantBodyStatus := range map[string][2]interface{}{"483": {"<html>first-block</html>", 451}, "484": {"<html>second-block</html>", 503}} {
		route := bySynthetic[code]
		if _, hasHost := routeMatcher(t, route)["host"]; hasHost {
			t.Fatalf("attribution route %s must not carry host matcher: %#v", code, routeMatcher(t, route))
		}
		h := firstHandler(t, route)
		assertEqual(t, h["body"], wantBodyStatus[0])
		assertEqual(t, h["status_code"], wantBodyStatus[1])
	}
	// 限流错误路由同样使用首绑定策略的拦截页，但状态码恒 429（语义正确+
	// 使 code=429 指标可计量），不再取策略 BlockStatusCode
	rlHandler := firstHandler(t, rateLimitRoute)
	assertEqual(t, rlHandler["body"], "<html>first-block</html>")
	assertEqual(t, rlHandler["status_code"], 429)
	assertEqual(t, rlHandler["headers"].(map[string]interface{})["Retry-After"], []string{"1"})
}

// SC-GEN-05：disabled 策略在生成中零贡献（无处理器/路由/错误路由），同规则的
// enabled 兄弟策略照常贡献。
func TestMultiPolicy_DisabledPolicyContributesNothing(t *testing.T) {
	// Given p1(enabled, blocking) < p2(DISABLED, 限流+geoip+拦截页)——旧 MAX 语义
	// 取最高绑定会命中 disabled 而整规则无策略，新语义必须只看见 p1。
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen5", "gen5.example.test", 8080)
	seedSecurityBlockPage(t, database, 9, "<html>disabled-block</html>")
	p1 := mpGenBindPolicy(t, database, "lb_gen5", "gen5-p1", mpGenPolicySpec{mode: "blocking", enabled: true})
	p2 := mpGenBindPolicy(t, database, "lb_gen5", "gen5-p2", mpGenPolicySpec{
		mode: "blocking", enabled: false, rateLimit: true, rps: 100, burst: 50,
		geoCountries: `["海外"]`, blockPageID: 9, blockStatusCode: 503,
	})
	if !(p1 < p2) {
		t.Fatalf("seed ids not ascending: %d %d", p1, p2)
	}

	// When
	routes, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen5", "gen5.example.test"))

	// Then 无 geoip 路由（disabled 策略的 geoip 不生效）
	if len(routes) != 1 {
		t.Fatalf("want 1 route (main only), got %d: %#v", len(routes), routes)
	}
	// 主链：enabled p1 的 waf 存在；disabled p2 的 rate_limit 不存在
	names := handlerNames(t, mainRoute)
	if indexOfHandler(names, "waf") < 0 {
		t.Fatalf("enabled policy's waf missing from chain %v", names)
	}
	if indexOfHandler(names, "rate_limit") >= 0 {
		t.Fatalf("disabled policy's rate_limit present in chain %v", names)
	}

	// And 全量渲染不产生任何错误路由（disabled 策略的拦截页不生效）
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	_, server := serverErrorRoutes(t, generated, "http_8080")
	if _, exists := server["errors"]; exists {
		t.Fatalf("server errors config present though only disabled policy has a block page: %#v", server["errors"])
	}
}

// SC-GEN-06（多策略 IP ACL 优先 · IP 预检）：多策略绑定时，任一绑定策略的
// deny 侧 IP 控制（deny 模式 ACL / allow 模式 ACL / 遗留黑名单）合并为一个
// 极简 coraza 预检 WAF，置于处理器链最前（先于全部 rate_limit/waf）——被拒
// IP 在任何策略的 CRS/自定义规则评估前即中断，不再产生前置策略的检测事件；
// 预检仍是 coraza 拒绝（audit log 留痕、403 interruption → 拦截页错误路由）。
// 单策略同构亦走预检（见 caddy.go:3180-3194）：ACL 并集与引擎 id:2/4 幂等重复无害——预检先拦，引擎内不再命中。
func TestMultiPolicy_IPPrecheckHandlerPrecedesAllSecurityHandlers(t *testing.T) {
	// Given：p1(detection CRS) < p2(deny ACL 203.0.113.5)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen6", "gen6.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_gen6", "gen6-p1", mpGenPolicySpec{mode: "detection", enabled: true})
	mpGenBindPolicy(t, database, "lb_gen6", "gen6-p2", mpGenPolicySpec{
		enabled: true, ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.5"]`,
	})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen6", "gen6.example.test"))

	// Then：链首是 X-LB-Rule-ID 注入（F3），其次 IP 预检 waf、p1 的 CRS waf、p2 的 ACL waf
	handlers, _ := mainRoute["handle"].([]interface{})
	if len(handlers) < 4 {
		t.Fatalf("main chain too short: %#v", handlers)
	}
	names := handlerNames(t, mainRoute)
	// 方案 B(2026-09-15):counter 在 headers 之后、precheck 之前——包 precheck
	// +全部策略 waf(IP 预检的 IP ACL/GeoIP 中断也计入)。
	// D40-2-1:request_body 恒发射,位于 precheck waf 之后、策略 waf 之前。
	if names[0] != "headers" || names[1] != "lb_rule_metrics" || names[2] != "lb_security_blocked_counter" || names[3] != "waf" || names[4] != "request_body" || names[5] != "waf" || names[6] != "waf" {
		t.Fatalf("main chain=%v, want [headers(X-LB-Rule-ID), lb_security_blocked_counter, waf(precheck), request_body, waf, waf, ...]", names)
	}
	// 注入头值=规则 caddy id 且覆盖客户端伪造（F3 归因信号本身的断言）
	inject := mustMap(t, handlers[0], "X-LB-Rule-ID inject handler")
	setHeaders := mustMap(t, inject["request"], "inject request")["set"].(map[string]interface{})
	assertEqual(t, setHeaders["X-LB-Rule-ID"], []string{"lb_gen6"})
	wafs := wafHandlers(t, mainRoute)
	precheck := wafs[0]["directives"].(string)
	// 预检含 p2 的拒绝 IP（deny 并集、id:2、audit 留痕）
	if !strings.Contains(precheck, `@ipMatch 203.0.113.5" "id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END`) {
		t.Fatalf("precheck must deny p2's ACL union with id:2:\n%s", precheck)
	}
	// 预检不得包含任何 CRS Include / DetectionOnly / 自定义规则——仅 IP 控制
	for _, unwanted := range []string{"Include ", "DetectionOnly", "SecRuleRemoveById"} {
		if strings.Contains(precheck, unwanted) {
			t.Fatalf("precheck must stay minimal (no %q):\n%s", unwanted, precheck)
		}
	}
	// 预检的 skipAfter 终点标记成对存在（coraza 编译约束）
	if !strings.Contains(precheck, "SecMarker SECURITY_RULES_END") {
		t.Fatalf("precheck must emit the SecMarker terminal:\n%s", precheck)
	}
	// 后续策略 waf 保持原样：p1 的 CRS 指令仍在（预检不取代逐策略 WAF）
	p1Directives := wafs[1]["directives"].(string)
	if !strings.Contains(p1Directives, "Include /app/waf/crs/rules/REQUEST-*.conf") {
		t.Fatalf("p1 CRS directives must remain after the precheck:\n%s", p1Directives)
	}
}

// SC-GEN-07：IP 预检发射门——阶段化模型单/多策略同构：单策略绑定且存在 deny
// 侧 IP 控制时同样发射预检（阶段 1 统一承接；ACL 并集与策略引擎 id:2/4 幂等
// 重复无害——预检先拦，引擎内不再命中）；无 deny 侧 IP 控制且无 GeoIP 时
// 主链形状不变（不新增预检 waf）。
func TestMultiPolicy_IPPrecheckEmissionGate(t *testing.T) {
	// Given A：单策略 + deny ACL → 预检同构发射（阶段 1）+ 策略引擎各一
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen7a", "gen7a.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_gen7a", "gen7a-solo", mpGenPolicySpec{
		mode: "detection", enabled: true, ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.5"]`,
	})
	_, mainA := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen7a", "gen7a.example.test"))
	namesA := handlerNames(t, mainA)
	wafCountA := 0
	for _, name := range namesA {
		if name == "waf" {
			wafCountA++
		}
	}
	if wafCountA != 2 {
		t.Fatalf("single policy with deny ACL: waf handlers=%d, want 2 (precheck + policy engine): %v", wafCountA, namesA)
	}
	// 预检在前、策略引擎在后；预检携带 deny 并集（id:2）
	wafsA := wafHandlers(t, mainA)
	precheckA := wafsA[0]["directives"].(string)
	if !strings.Contains(precheckA, `@ipMatch 203.0.113.5" "id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("single-policy precheck must carry the deny union:\n%s", precheckA)
	}

	// Given B：多策略但无任何 deny 侧 IP 控制（信任名单不算 deny 侧）→ 无预检
	seedHTTPRuleForGeneration(t, database, "lb_gen7b", "gen7b.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_gen7b", "gen7b-p1", mpGenPolicySpec{mode: "detection", enabled: true})
	mpGenBindPolicy(t, database, "lb_gen7b", "gen7b-p2", mpGenPolicySpec{enabled: true, ipACLMode: "bypass", ipACLList: `["198.51.100.9"]`})
	_, mainB := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen7b", "gen7b.example.test"))
	namesB := handlerNames(t, mainB)
	wafCountB := 0
	for _, name := range namesB {
		if name == "waf" {
			wafCountB++
		}
	}
	if wafCountB != 1 {
		t.Fatalf("no deny-side control: waf handlers=%d, want 1 (no precheck): %v", wafCountB, namesB)
	}
}

// SC-GEN-08：allow 模式白名单并入预检——多条 allow 模式策略取交集，仅交集内
// IP 通过预检；交集为空（互斥名单）时拒绝一切（与逐策略顺序评估等价）。
func TestMultiPolicy_IPPrecheckAllowModeIntersection(t *testing.T) {
	// Given：p1(detection) < p2(allow 203.0.113.0/24,10.0.0.1) < p3(allow 10.0.0.1)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_gen8", "gen8.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_gen8", "gen8-p1", mpGenPolicySpec{mode: "detection", enabled: true})
	mpGenBindPolicy(t, database, "lb_gen8", "gen8-p2", mpGenPolicySpec{
		enabled: true, ipACLEnabled: true, ipACLMode: "allow", ipACLList: `["203.0.113.0/24","10.0.0.1"]`,
	})
	mpGenBindPolicy(t, database, "lb_gen8", "gen8-p3", mpGenPolicySpec{
		enabled: true, ipACLEnabled: true, ipACLMode: "allow", ipACLList: `["10.0.0.1"]`,
	})

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen8", "gen8.example.test"))

	// Then：预检 allow 规则否定匹配交集（10.0.0.1），deny 模式并集规则不出现
	wafs := wafHandlers(t, mainRoute)
	if len(wafs) == 0 {
		t.Fatalf("no waf handler (expect the IP precheck): %v", handlerNames(t, mainRoute))
	}
	precheck := wafs[0]["directives"].(string)
	if !strings.Contains(precheck, `"!@ipMatch 10.0.0.1" "id:7,phase:1,deny,status:403`) {
		t.Fatalf("precheck allow rule must negate-match the intersection with id:7:\n%s", precheck)
	}
	if strings.Contains(precheck, "203.0.113.0/24") || strings.Contains(precheck, "id:2,") {
		t.Fatalf("precheck must not carry non-intersection entries or a deny-union rule:\n%s", precheck)
	}
}

// R1(2026-09-10 审计):规则级压缩(encode)必须位于全部 waf 处理器之外侧
// (链序在 waf 之前)——coraza 响应拦截器包在 coraza handler 外层,encode 若在
// waf 内侧,响应体规则扫描的是压缩后字节(≥512B 可压缩响应恒不匹配,静默失明)。
func TestMultiPolicy_EncodeHandlerPrecedesWafForResponseBodyInspection(t *testing.T) {
	_, database := newClusterTestService(t)
	rule := mpGenHTTPRule("mp-encode-r", "encode.test")
	rule.EnableCompress = true
	rule.CompressTypes = "gzip"
	mpGenBindPolicy(t, database, "mp-encode-r", "p-blocking", mpGenPolicySpec{mode: "blocking", enabled: true})
	// WAFCheckResponse 需要直接播策略行携带(waf_check_response 列)——用 SQL 补
	if _, err := database.Exec(`UPDATE security_policies SET waf_check_response=1 WHERE name='p-blocking'`); err != nil {
		t.Fatalf("seed waf_check_response: %v", err)
	}
	_, mainRoute := mpGenRoutes(t, database, rule)
	names := handlerNames(t, mainRoute)
	encodeIdx, firstWafIdx := -1, -1
	for i, n := range names {
		if n == "encode" && encodeIdx < 0 {
			encodeIdx = i
		}
		if n == "waf" && firstWafIdx < 0 {
			firstWafIdx = i
		}
	}
	if encodeIdx < 0 || firstWafIdx < 0 {
		t.Fatalf("chain missing encode/waf: %v", names)
	}
	if encodeIdx > firstWafIdx {
		t.Fatalf("encode(%d) 必须先于首个 waf(%d)——响应体规则需扫未压缩字节: %v", encodeIdx, firstWafIdx, names)
	}
}

// R4-Render-1/2(第 4 轮审计):coraza 默认 RequestBodyLimit=128MiB,
// 用户限额>128MiB 时 WAF 活跃规则 body 在 128MiB 处被拦;413 语义被压平。
// 修复:按规则有效限额发射 SecRequestBodyLimit(min(用户值,1GiB))。
func TestMultiPolicy_RequestBodyLimitInWafDirectives(t *testing.T) {
	_, database := newClusterTestService(t)
	rule := mpGenHTTPRule("mp-bodylimit-r", "bodylimit.test")
	rule.RequestBodyMaxSizeMB = 50
	mpGenBindPolicy(t, database, "mp-bodylimit-r", "p-bl", mpGenPolicySpec{mode: "blocking", enabled: true})
	_, mainRoute := mpGenRoutes(t, database, rule)
	// 从 waf handler 提取 directives
	handlers := handlerNames(t, mainRoute)
	wafIdx := -1
	for i, h := range handlers {
		if h == "waf" {
			wafIdx = i
			break
		}
	}
	if wafIdx < 0 {
		t.Fatalf("no waf handler in chain: %v", handlers)
	}
	// 提取 directives 字段
	chain := mainRoute["handle"].([]interface{})
	wafMap := chain[wafIdx].(map[string]interface{})
	directives, _ := wafMap["directives"].(string)
	if directives == "" {
		t.Fatal("waf handler has no directives")
	}
	// 验证 SecRequestBodyLimit 50MB=52428800
	want := "SecRequestBodyLimit 52428800"
	if !strings.Contains(directives, want) {
		t.Fatalf("directives missing %q:\n%s", want, directives)
	}
}

// 预检信任 DetectionOnly(2026-09-15 用户裁定):信任最高优先——预检层
// 信任规则 ctl:ruleEngine=DetectionOnly 先行,deny/黑名单/GeoIP/CRS 全评估
// 不拦但全记录(取代 S1 的「并入 allow 放行集」——并入会使信任 IP 不触发
// 规则=无检测事件,与「可见放行」冲突)。
func TestMultiPolicy_PrecheckTrustDetectionOnly(t *testing.T) {
	// Given:两策略,P1 allow 模式+信任 198.51.100.9,P2 deny 模式(198.51.100.9 在 deny 名单)
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_whitelist_enabled, ip_whitelist) VALUES
		('p1-allow','blocking',1,1,'allow','["10.0.0.1"]',1,'["198.51.100.9"]'),
		('p2-deny','blocking',1,1,'deny','["198.51.100.9"]',0,'[]')`); err != nil {
		t.Fatal(err)
	}
	var p1ID, p2ID int
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='p1-allow'`).Scan(&p1ID); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT id FROM security_policies WHERE name='p2-deny'`).Scan(&p2ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_gen_trust',?), ('lb_gen_trust',?)`, p1ID, p2ID); err != nil {
		t.Fatal(err)
	}
	seedHTTPRuleForGeneration(t, database, "lb_gen_trust", "trust.example.test", 8080)

	// When
	_, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_gen_trust", "trust.example.test"))

	// Then:预检含信任 DetectionOnly 先行(在 allow/deny 规则之前)
	wafs := wafHandlers(t, mainRoute)
	if len(wafs) == 0 {
		t.Fatalf("no waf handler: %v", handlerNames(t, mainRoute))
	}
	precheck := wafs[0]["directives"].(string)
	trustRule := `SecRule REMOTE_ADDR "@ipMatch 198.51.100.9" "id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(precheck, trustRule) {
		t.Fatalf("precheck missing trust DetectionOnly rule:\n%s", precheck)
	}
	trustIdx := strings.Index(precheck, trustRule)
	// deny 规则(id:2)在信任之后,且信任 IP 也在 deny 名单——DetectionOnly 使其
	// 评估不拦但记录(信任最高优先,不再被 403)
	denyIdx := strings.Index(precheck, `"@ipMatch 198.51.100.9" "id:2,phase:1,deny`)
	if denyIdx < 0 {
		t.Fatalf("precheck missing deny rule for trusted IP (must log as detection):\n%s", precheck)
	}
	if trustIdx > denyIdx {
		t.Fatalf("trust DetectionOnly (offset %d) must precede deny rules (offset %d):\n%s", trustIdx, denyIdx, precheck)
	}
	// 信任不再并入 allow intersection(并入会使信任 IP 不触发规则=无检测事件)
	if strings.Contains(precheck, `"!@ipMatch 10.0.0.1,198.51.100.9"`) {
		t.Fatalf("trust must NOT be merged into allow intersection (merge = no detection event):\n%s", precheck)
	}
}
