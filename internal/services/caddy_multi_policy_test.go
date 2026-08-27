package services

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// SC-GEN-01..05（v2.2.0 多策略绑定 · Caddy 生成路径）：一条 LB 规则可绑定至多
// 5 条安全策略，评估顺序 = policy_id ASC；每策略的 [rate_limit?, waf?] 处理器组
// 按序编入规则主路由。geoip pass 路由至多一条（任一启用策略带 geoip 即存在），
// geoip block 路由每带 geoip 的启用策略一条（ASC）；错误路由取首绑定（最低
// policy_id）启用策略的拦截页，匹配表达式覆盖 403 WAF 中断与全部绑定启用策略的
// geoip 拦截状态码并集；disabled 策略在生成中零贡献。

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
	result, err := database.Exec(`INSERT INTO security_policies
		(name, mode, enabled, rate_limit_enabled, rate_limit_rps, rate_limit_burst, geoip_countries, geoip_mode, block_page_id, block_status_code)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		name, mode, enabled, rateLimit, spec.rps, spec.burst, countries, geoMode, spec.blockPageID, spec.blockStatusCode)
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

// mpGeoipBlockRoutes 收集 geoip block 路由（唯一处理器为 error）。
func mpGeoipBlockRoutes(t *testing.T, routes []map[string]interface{}) []map[string]interface{} {
	t.Helper()
	var blocks []map[string]interface{}
	for _, route := range routes {
		names := handlerNames(t, route)
		if len(names) == 1 && names[0] == "error" {
			blocks = append(blocks, route)
		}
	}
	return blocks
}

// SC-GEN-01：路由顺序 = geoipPass(≤1) → geoipBlock×k（policy_id ASC）→ pathRoutes
// → main；主路由处理器链按绑定启用策略 ASC 依次编入各策略的 [rate_limit?, waf?]。
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

	// Then 顺序：pass → block(p1) → block(p3) → path → main
	if len(routes) != 5 {
		t.Fatalf("want 5 routes (pass+2 geoip blocks+path+main), got %d: %#v", len(routes), routes)
	}
	if names := handlerNames(t, routes[0]); len(names) != 1 || names[0] != "geoip2region" {
		t.Fatalf("routes[0] handlers=%v, want geoip pass route", names)
	}
	blocks := mpGeoipBlockRoutes(t, routes)
	if len(blocks) != 2 {
		t.Fatalf("want 2 geoip block routes (one per geoip policy), got %d", len(blocks))
	}
	expr1 := routeMatcher(t, blocks[0])["expression"]
	expr3 := routeMatcher(t, blocks[1])["expression"]
	if expr1 != `{http.vars.geoip.country_name} != "中国"` {
		t.Fatalf("first block route expression=%v, want p1 海外（policy_id ASC 在前）", expr1)
	}
	if expr3 != `{http.vars.geoip.province} == "江苏"` {
		t.Fatalf("second block route expression=%v, want p3 江苏", expr3)
	}
	// block 路由必须紧邻 pass 路由之后（在 path 路由之前）
	if routes[1]["handle"] == nil || handlerNames(t, routes[1])[0] != "error" || handlerNames(t, routes[2])[0] != "error" {
		t.Fatalf("routes[1..2] must be the geoip block routes: %#v", routes)
	}
	// routes[3] = path 路由，routes[4] = 主路由
	if _, hasPath := routeMatcher(t, routes[3])["path"]; !hasPath {
		t.Fatalf("routes[3] must be the path route: %#v", routes[3])
	}
	if _, hasPath := routeMatcher(t, routes[4])["path"]; hasPath {
		t.Fatalf("routes[4] must be the main route (no path matcher): %#v", routes[4])
	}

	// 主路由处理器链：p1(off) 无贡献；p2 → rate_limit + waf(blocking)；
	// p3 → waf(detection)；随后 reverse_proxy。
	names := handlerNames(t, mainRoute)
	if len(names) < 4 || names[0] != "rate_limit" || names[1] != "waf" || names[2] != "waf" {
		t.Fatalf("main chain=%v, want [rate_limit, waf, waf, ..., reverse_proxy]", names)
	}
	if names[len(names)-1] != "reverse_proxy" {
		t.Fatalf("main chain last handler=%v, want reverse_proxy", names)
	}
	handlers, _ := mainRoute["handle"].([]interface{})
	firstWaf := mustMap(t, handlers[1], "first waf handler")["directives"].(string)
	secondWaf := mustMap(t, handlers[2], "second waf handler")["directives"].(string)
	if !strings.Contains(firstWaf, "SecRuleEngine On") || strings.Contains(firstWaf, "DetectionOnly") {
		t.Fatalf("first waf must be p2 blocking directives, got: %.200s", firstWaf)
	}
	if !strings.Contains(secondWaf, "DetectionOnly") {
		t.Fatalf("second waf must be p3 detection directives, got: %.200s", secondWaf)
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

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// SC-GEN-03：geoip pass 路由存在 ⟺ 至少一条绑定启用策略带 geoip；多条 geoip
// 策略时 pass 路由仍至多一条。
func TestMultiPolicy_GeoipPassRoute_ExistsIffAnyEnabledPolicyHasGeoIP(t *testing.T) {
	// Given 情形 A：唯一绑定启用策略无 geoip → 无 pass/block 路由
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

	// Given 情形 B：两条启用策略都带 geoip → 恰好一条 pass 路由 + 两条 block 路由
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
	if blocks := mpGeoipBlockRoutes(t, routesB); len(blocks) != 2 {
		t.Fatalf("two geoip policies: block routes=%d, want 2", len(blocks))
	}
}

// SC-GEN-04：错误路由使用首绑定（最低 policy_id）启用策略的拦截页；匹配表达式
// 覆盖 403 WAF 中断 + 全部绑定启用策略的 geoip 拦截状态码并集。
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
	if len(errorRoutes) != 2 {
		t.Fatalf("want 2 error routes (block page + rate limit), got %#v", errorRoutes)
	}
	var blockPageRoute, rateLimitRoute map[string]interface{}
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, route)["expression"].(string)
		if expr == "{http.error.status_code} == 429" {
			rateLimitRoute = route
		} else {
			blockPageRoute = route
		}
	}
	if blockPageRoute == nil || rateLimitRoute == nil {
		t.Fatalf("missing error route kind: block=%v rateLimit=%v", blockPageRoute != nil, rateLimitRoute != nil)
	}
	// 拦截页错误路由：首绑定策略（p1）的页面与状态码
	handler := firstHandler(t, blockPageRoute)
	assertEqual(t, handler["body"], "<html>first-block</html>")
	assertEqual(t, handler["status_code"], 451)
	// 匹配表达式：403 WAF 中断 + p1(451) 与 p2(503) 的 geoip 状态码并集（ASC 顺序）
	wantExpr := "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')" +
		" || ({http.error.status_code} == 451 && {http.error.message} == 'GeoIP blocked')" +
		" || ({http.error.status_code} == 503 && {http.error.message} == 'GeoIP blocked')"
	assertEqual(t, routeMatcher(t, blockPageRoute)["expression"], wantExpr)
	// 限流错误路由同样使用首绑定策略的拦截页
	rlHandler := firstHandler(t, rateLimitRoute)
	assertEqual(t, rlHandler["body"], "<html>first-block</html>")
	assertEqual(t, rlHandler["status_code"], 451)
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
