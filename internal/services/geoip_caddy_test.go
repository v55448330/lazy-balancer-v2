package services

import (
	"database/sql"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func setupGeoipConfigTestDB(t *testing.T) {
	t.Helper()
	oldDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = oldDB
	})
}

func seedGeoipPolicy(t *testing.T, ruleCaddyID, countries, mode string) {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, geoip_countries, geoip_mode)
		VALUES ('geoip-test', 'off', 1, ?, ?)`, countries, mode)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := db.DB.Exec("INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, policyID); err != nil {
		t.Fatal(err)
	}
}

func seedGeoipPolicyWithBlockPage(t *testing.T, ruleCaddyID, countries, mode string, blockPageID, blockStatusCode int) {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, geoip_countries, geoip_mode, block_page_id, block_status_code)
		VALUES ('geoip-test', 'off', 1, ?, ?, ?, ?)`, countries, mode, blockPageID, blockStatusCode)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := db.DB.Exec("INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, policyID); err != nil {
		t.Fatal(err)
	}
}

func handlerNames(t *testing.T, routeValue interface{}) []string {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("handle has type %T", route["handle"])
	}
	names := make([]string, 0, len(handlers))
	for _, handlerValue := range handlers {
		handler := mustMap(t, handlerValue, "handler")
		name, _ := handler["handler"].(string)
		names = append(names, name)
	}
	return names
}

func handlerNamesAsString(t *testing.T, routeValue interface{}) string {
	t.Helper()
	return strings.Join(handlerNames(t, routeValue), ",")
}

// geoipRuleLine 从 BuildCorazaDirectives 产物中取出 GeoIP 链首规则行（id:8）。
func geoipRuleLine(t *testing.T, directives string) string {
	t.Helper()
	for _, line := range strings.Split(directives, "\n") {
		if strings.Contains(line, "msg:'GeoIP 区域拦截'") {
			return line
		}
	}
	t.Fatalf("no GeoIP rule line in directives:\n%s", directives)
	return ""
}

// TestBuildCorazaDirectives_geoip_emitsSecRuleChain：地域拦截改走 coraza 后，
// deny 模式海外策略发射链式 SecRule——链首内网放行（!@ipMatch 全量私网段 +
// id:8 + deny 不带 status + skipAfter 终点），子规则锚定正则匹配 X-GeoIP-Loc。
func TestBuildCorazaDirectives_geoip_emitsSecRuleChain(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if directives == "" {
		t.Fatal("geoip-enabled policy must emit directives even with WAF mode off")
	}
	starter := geoipRuleLine(t, directives)
	if !strings.Contains(starter, `"id:8,phase:1,deny,log,msg:'GeoIP 区域拦截',skipAfter:SECURITY_RULES_END,chain"`) {
		t.Fatalf("starter actions must be unified deny (no status) with chain:\n%s", starter)
	}
	if !strings.Contains(starter, `"!@ipMatch `+strings.Join(geoipPrivateRanges, ",")+`"`) {
		t.Fatalf("starter must exempt all private ranges:\n%s", starter)
	}
	// deny 不带 status：coraza 默认 403 → errors.routes 403 子句 → 拦截页按
	// block_status_code 渲染（与自定义规则拦截统一口径）。
	if strings.Contains(starter, "status:") {
		t.Fatalf("geoip deny must not carry a status action (unified block page path):\n%s", starter)
	}
	if !strings.Contains(directives, ` SecRule REQUEST_HEADERS:X-GeoIP-Loc "@rx ^(?:海外)$" "t:none"`) {
		t.Fatalf("child rule missing anchored overseas match:\n%s", directives)
	}
}

// TestBuildCorazaDirectives_geoipProvinces_joinedAlternation：纯省条目附加
// (?:/.*)?——省内城市段（省/市 形态的 X-GeoIP-Loc）同样命中（整省语义）。
func TestBuildCorazaDirectives_geoipProvinces_joinedAlternation(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["广东省","北京市"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	want := `@rx ^(?:广东省(?:/.*)?|北京市(?:/.*)?)$`
	if !strings.Contains(directives, want) {
		t.Fatalf("directives missing province alternation %q:\n%s", want, directives)
	}
}

// TestBuildCorazaDirectives_geoipDetectionMode_rulePrecedesDetectionOnly：
// 检测模式下 GeoIP 规则先于 DetectionOnly 切换发出——地域拦截仍强制阻断
// （与 IP 控制/自定义拦截规则同阵营）。
func TestBuildCorazaDirectives_geoipDetectionMode_rulePrecedesDetectionOnly(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:           "detection",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	geoIdx := strings.Index(directives, "msg:'GeoIP 区域拦截'")
	switchIdx := strings.Index(directives, "DetectionOnly")
	if geoIdx < 0 || switchIdx < 0 || geoIdx > switchIdx {
		t.Fatalf("geoip rule must precede the DetectionOnly switch:\n%s", directives)
	}
}

// TestGenerateHTTPRouteObjects_geoip_passRouteOnlyNoBlockRoutes：路由层只剩
// pass 路由（设置 X-GeoIP-* headers 供下游 coraza），不再有 Caddy 原生 block
// 路由；地域拦截在主路由的 coraza 处理器内评估。
func TestGenerateHTTPRouteObjects_geoip_passRouteOnlyNoBlockRoutes(t *testing.T) {
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `["海外"]`, "deny")

	routes, mainRoute, err := generateHTTPRouteObjects(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}

	// pass 路由：首条、仅 geoip2region、非 terminal（后续路由继续评估）
	first := mustMap(t, routes[0], "first route")
	if got := handlerNames(t, routes[0]); len(got) != 1 || got[0] != "geoip2region" {
		t.Fatalf("routes[0] handlers=%v, want pass-through geoip2region", got)
	}
	if first["terminal"] == true {
		t.Fatal("geoip pass route must not be terminal")
	}
	// 无 Caddy 原生 block 路由（error 处理器只属于 server 级 errors 路由）
	for _, route := range routes {
		for _, name := range handlerNames(t, route) {
			if name == "error" {
				t.Fatalf("native geoip block route must not be emitted: %#v", route)
			}
		}
	}
	// 主路由链内含 waf 处理器（GeoIP SecRule 在其 directives 中），geoip2region
	// 只出现在 pass 路由
	mainNames := handlerNames(t, mainRoute)
	hasWaf := false
	for _, n := range mainNames {
		if n == "waf" {
			hasWaf = true
		}
		if n == "geoip2region" {
			t.Fatalf("main route should not contain geoip2region (handled by pass route), handlers=%v", mainNames)
		}
	}
	if !hasWaf {
		t.Fatalf("main route must carry the coraza waf handler for geoip evaluation, handlers=%v", mainNames)
	}
	handlers, _ := mainRoute["handle"].([]interface{})
	directives, _ := mustMap(t, handlers[0], "first handler")["directives"].(string)
	found := false
	for _, h := range handlers {
		if d, _ := mustMap(t, h, "handler")["directives"].(string); strings.Contains(d, "msg:'GeoIP 区域拦截'") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no waf handler carries the geoip rule, directives=%.200s", directives)
	}
}

// TestGenerateHTTPRouteObjects_geoipDisabled_noRoutesOrDirectives：无 geoip
// 条目的策略不产生 pass 路由，mode=off 且无其他控制时也不发射 waf 处理器。
func TestGenerateHTTPRouteObjects_geoipDisabled_noRoutesOrDirectives(t *testing.T) {
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `[]`, "deny")

	routes, mainRoute, err := generateHTTPRouteObjects(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("want 1 route (main only), got %d: %#v", len(routes), routes)
	}
	for _, routeValue := range routes {
		if strings.Contains(handlerNamesAsString(t, routeValue), "geoip2region") {
			t.Fatalf("unexpected geoip handler in %#v", routeValue)
		}
	}
	if strings.Contains(handlerNamesAsString(t, mainRoute), "waf") {
		t.Fatal("mode=off policy without geoip/IP control/custom rules must not emit a waf handler")
	}
}

// TestGenerateSingleRuleCaddyConfig_geoip_previewIncludesPassRoute：预览路径
// 同样只发射 pass 路由（无 block 路由）。
func TestGenerateSingleRuleCaddyConfig_geoip_previewIncludesPassRoute(t *testing.T) {
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `["海外"]`, "deny")

	config := GenerateSingleRuleCaddyConfig(baseHTTPRule())
	routes := renderedHTTPRoutes(t, config)
	if len(routes) == 0 {
		t.Fatal("no routes rendered")
	}
	if got := handlerNames(t, routes[0]); len(got) != 1 || got[0] != "geoip2region" {
		t.Fatalf("routes[0] handlers=%v, want geoip pass route", got)
	}
	for _, routeValue := range routes {
		if strings.Contains(handlerNamesAsString(t, routeValue), "error") {
			t.Fatalf("native geoip block route must not be emitted in preview: %#v", routeValue)
		}
	}
}

// TestGenerateCaddyConfig_geoip_blockPageServesConfiguredStatus：coraza deny
// 默认 403 → errors 路由 403 interruption 子句 → 拦截页按 block_status_code 渲染
// （原 Caddy 原生 block 路由的 honorsBlockStatusCode 保证迁移到统一路径）。
func TestGenerateCaddyConfig_geoip_blockPageServesConfiguredStatus(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_geoip", "geoip.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>geoip-block</html>")
	seedGeoipPolicyBound(t, database, "lb_geoip", `["海外"]`, "deny", 7, 451)

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	if len(errorRoutes) != 1 {
		t.Fatalf("want exactly one error route, got %#v", errorRoutes)
	}
	route := mustMap(t, errorRoutes[0], "error route")
	// 匹配表达式只剩统一 403 interruption 子句（"GeoIP blocked" 形态已消亡）
	assertEqual(t, routeMatcher(t, route)["expression"],
		"({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')")
	handler := firstHandler(t, route)
	assertEqual(t, handler["status_code"], 451)
	assertEqual(t, handler["body"], "<html>geoip-block</html>")
}

// seedGeoipPolicyBound 在 cluster 测试库上播种带 geoip + 拦截页的策略并绑定。
func seedGeoipPolicyBound(t *testing.T, database *sql.DB, ruleCaddyID, countries, mode string, blockPageID, blockStatusCode int) {
	t.Helper()
	result, err := database.Exec(`INSERT INTO security_policies (name, mode, enabled, geoip_countries, geoip_mode, block_page_id, block_status_code)
		VALUES ('geoip-bound', 'off', 1, ?, ?, ?, ?)`, countries, mode, blockPageID, blockStatusCode)
	if err != nil {
		t.Fatalf("seed geoip policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read seeded policy id: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind geoip policy: %v", err)
	}
}

// TestGeoipLocOperator_forms：算子编译的形态覆盖——海外字面、纯省附加
// (?:/.*)?、省/市精确联值、allow 取反、QuoteMeta 防注入。
func TestGeoipLocOperator_forms(t *testing.T) {
	deny := geoipLocOperator([]string{"福建省", "广东省/深圳市", "海外"}, false)
	if !strings.Contains(deny, `福建省(?:/.*)?`) || !strings.Contains(deny, `广东省/深圳市`) || !strings.Contains(deny, `海外`) {
		t.Fatalf("operator missing entry forms: %s", deny)
	}
	if !strings.HasPrefix(deny, "@rx ^(?:") || !strings.HasSuffix(deny, ")$") {
		t.Fatalf("operator must be anchored full-value match: %s", deny)
	}
	allow := geoipLocOperator([]string{"广东省"}, true)
	if allow != "!@rx ^(?:广东省(?:/.*)?)$" {
		t.Fatalf("allow mode must negate the whole match: %s", allow)
	}
	// 集群同步/历史行可携带绕过校验的元字符——QuoteMeta 中和（ReDoS/越权匹配）
	evil := geoipLocOperator([]string{`EVIL(.*)`}, false)
	if !strings.Contains(evil, `EVIL\(\.\*\)`) {
		t.Fatalf("metacharacters must be quoted: %s", evil)
	}
}

// TestGeoipLocOperator_regexEquivalence：把算子正则按 coraza 语义编译
// （单行值下 (?sm) 与默认等价），锁定与既有 CEL 语义的逐案等价：
// 海外哨兵（含不可解析/IPv6）、省整省覆盖省内城市、省/市精确联值、
// 空串（国内段省份不可解析）deny 不命中 / allow 反向命中（fail-closed）。
func TestGeoipLocOperator_regexEquivalence(t *testing.T) {
	compile := func(t *testing.T, countries []string, allowMode bool) *regexp.Regexp {
		t.Helper()
		op := geoipLocOperator(countries, allowMode)
		re, err := regexp.Compile(strings.TrimPrefix(strings.TrimPrefix(op, "!"), "@rx "))
		if err != nil {
			t.Fatalf("compile %q: %v", op, err)
		}
		return re
	}
	denyRe := compile(t, []string{"海外", "广东省", "福建省/厦门市"}, false)
	cases := []struct {
		loc  string
		want bool
	}{
		{"海外", true},       // 海外客户端（含 IPv6/不可解析哨兵）
		{"广东省", true},      // 纯省
		{"广东省/深圳市", true},  // 省内城市段命中整省条目
		{"福建省/厦门市", true},  // 省/市精确联值
		{"福建省/福州市", false}, // 同省异市不命中联值条目
		{"北京市", false},     // 未列省份
		{"", false},        // 国内段省份不可解析：deny 不误伤
		{"海外省", false},     // 前缀串不得命中（锚定全值）
		{"中国", false},      // 国家名不得命中省份条目
	}
	for _, tc := range cases {
		if got := denyRe.MatchString(tc.loc); got != tc.want {
			t.Fatalf("deny-mode match(%q) = %v, want %v", tc.loc, got, tc.want)
		}
	}
	// allow 模式（!@rx）：算子取反——原始正则命中 = 条目命中 = 放行。此处编译
	// 剥离 "!" 后的原始正则：列表外（含空串、外省）不得命中（→ 算子反向命中
	// → 拦截，fail-closed），列表内（含省内城市段）必须命中（→ 放行）。
	allowRe := compile(t, []string{"海外", "广东省"}, true)
	for _, blocked := range []string{"北京市", "", "福建省/厦门市"} {
		if allowRe.MatchString(blocked) {
			t.Fatalf("allow-mode raw regex must not match (operator negates → block) %q", blocked)
		}
	}
	for _, allowed := range []string{"海外", "广东省", "广东省/深圳市"} {
		if !allowRe.MatchString(allowed) {
			t.Fatalf("allow-mode raw regex must match (operator negates → allow) %q", allowed)
		}
	}
}

// TestGeoipPrivateRanges_excludesPublicMappedIPv4 verifies the fail-open fix:
// a public IPv4-mapped address (::ffff:8.8.8.8) must NOT match any private
// range, while mapped private (::ffff:192.168.1.1) and plain private
// (192.168.1.1) addresses must. The prior ::ffff:0:0/96 entry matched the whole
// mapped space and would have let public mapped clients bypass GeoIP blocking.
func TestGeoipPrivateRanges_excludesPublicMappedIPv4(t *testing.T) {
	prefixes := make([]netip.Prefix, 0, len(geoipPrivateRanges))
	for _, cidr := range geoipPrivateRanges {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	containsAny := func(addr netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}

	if containsAny(netip.MustParseAddr("::ffff:8.8.8.8")) {
		t.Fatal("public mapped address ::ffff:8.8.8.8 must not match any private range")
	}
	if !containsAny(netip.MustParseAddr("::ffff:192.168.1.1")) {
		t.Fatal("mapped private address ::ffff:192.168.1.1 should match a private range")
	}
	if !containsAny(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("plain private address 192.168.1.1 should match a private range")
	}
}

// TestBuildCorazaDirectives_geoipModeOff_noEmission：geoip_mode='off' 是区域
// 控制的关闭态（与 ip_acl_enabled=false 同语义）——即使 geoip_countries 名单
// 非空（保留语义不清单）也不得发射 id:8 拦截链。
func TestBuildCorazaDirectives_geoipModeOff_noEmission(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:           "off",
		GeoIPMode:      "off",
		GeoIPCountries: json.RawMessage(`["海外","广东省"]`),
	}
	directives := BuildCorazaDirectives(policy, nil)
	if strings.Contains(directives, "GeoIP 区域拦截") || strings.Contains(directives, "id:8") {
		t.Fatalf("geoip_mode=off must not emit geoip rules, got:\n%s", directives)
	}
}

// TestPolicyHasGeoIP_modeGate：活跃判定 = mode!='off' 且名单非空。mode 门失效
// 会使 caddygeoip handler 在开关关闭后照常注入（X-GeoIP-* 头继续被打到请求上）。
func TestPolicyHasGeoIP_modeGate(t *testing.T) {
	countries := json.RawMessage(`["海外"]`)
	if PolicyHasGeoIP(&models.SecurityPolicy{GeoIPMode: "off", GeoIPCountries: countries}) {
		t.Fatal("mode=off with retained countries must be inactive")
	}
	if !PolicyHasGeoIP(&models.SecurityPolicy{GeoIPMode: "deny", GeoIPCountries: countries}) {
		t.Fatal("mode=deny with countries must be active")
	}
	if PolicyHasGeoIP(&models.SecurityPolicy{GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`[]`)}) {
		t.Fatal("empty countries must be inactive regardless of mode")
	}
}

// TestBuildHTTPHandleChain_stripsGeoIPHeadersBeforeUpstream：X-GeoIP-* 是
// caddygeoip→coraza 的进程内控制头，绝不允许透传上游后端。reverse_proxy 必须在
// headers.request.delete 中剥离全部 6 个头；无条件剥离（不依赖安全策略绑定），
// 同时拦截 geoip 关闭时客户端伪造同名头直达后端。与 HostHeader set 并存。
func TestBuildHTTPHandleChain_stripsGeoIPHeadersBeforeUpstream(t *testing.T) {
	wantStrip := []string{
		"X-GeoIP-Country", "X-GeoIP-Country-Code", "X-GeoIP-Region",
		"X-GeoIP-Province", "X-GeoIP-City", "X-GeoIP-Loc",
	}
	upstreams := []UpstreamConfig{{Host: "127.0.0.1", Port: 8080, Weight: 1, Enabled: true}}

	for _, tc := range []struct {
		name       string
		hostHeader string
	}{
		{name: "no host header override", hostHeader: ""},
		{name: "with host header override", hostHeader: "api.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := SingleRuleConfig{CaddyID: "lb_strip", Protocol: "http", ListenPort: 80, HostHeader: tc.hostHeader}
			chain, err := buildHTTPHandleChain(rule, upstreams)
			if err != nil {
				t.Fatalf("buildHTTPHandleChain: %v", err)
			}
			if len(chain) == 0 {
				t.Fatal("chain must not be empty")
			}
			last, ok := chain[len(chain)-1].(map[string]interface{})
			if !ok || last["handler"] != "reverse_proxy" {
				t.Fatalf("last handler must be reverse_proxy, got %#v", chain[len(chain)-1])
			}
			headers, ok := last["headers"].(map[string]interface{})
			if !ok {
				t.Fatalf("reverse_proxy must carry headers, got %#v", last["headers"])
			}
			request, ok := headers["request"].(map[string]interface{})
			if !ok {
				t.Fatalf("headers.request missing: %#v", headers)
			}
			del, ok := request["delete"].([]string)
			if !ok {
				t.Fatalf("headers.request.delete must be []string, got %#v", request["delete"])
			}
			have := make(map[string]bool, len(del))
			for _, h := range del {
				have[h] = true
			}
			for _, h := range wantStrip {
				if !have[h] {
					t.Fatalf("headers.request.delete must contain %s, got %v", h, del)
				}
			}
			if tc.hostHeader != "" {
				set, ok := request["set"].(map[string]interface{})
				if !ok || set["Host"] == nil {
					t.Fatalf("host header set must coexist with geoip strip, got %#v", request)
				}
			}
		})
	}
}

// TestLoadSecurityPolicyContext_carriesTriStateGateFields：批量预载是真实生成
// 路径的唯一策略来源——其 SELECT 曾缺 ip_whitelist_enabled（零值 false 压制
// 信任规则发射，信任 IP 仍记 CRS 检测事件；单测直构 struct 绕过 loader 掩盖）。
// 本测试钉住 loader 携带三态门字段：whitelist_enabled / geoip_mode / refs。
func TestLoadSecurityPolicyContext_carriesTriStateGateFields(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_gate1','g','http','g.test',8081,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (7,'L','[{"value":"198.51.100.7","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,ip_whitelist,ip_whitelist_enabled,ip_whitelist_refs,geoip_countries,geoip_mode) VALUES (1,'p',1,'[]',0,'[7]','["CN"]','off')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_gate1',1)`); err != nil {
		t.Fatal(err)
	}
	ctx, err := loadSecurityPolicyContext(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	policies := ctx.policyByRule["lb_gate1"]
	if len(policies) != 1 {
		t.Fatalf("policies=%d, want 1", len(policies))
	}
	p := policies[0]
	if p.IPWhitelistEnabled {
		t.Fatal("IPWhitelistEnabled must be carried as false from DB (trust off)")
	}
	if p.GeoIPMode != "off" {
		t.Fatalf("GeoIPMode=%q, want off", p.GeoIPMode)
	}
	// refs-only 信任合并集仍应装载（数据在，仅被开关门压制）
	if len(p.MergedWhitelist) != 1 || p.MergedWhitelist[0] != "198.51.100.7" {
		t.Fatalf("MergedWhitelist=%v, want [198.51.100.7]", p.MergedWhitelist)
	}
}
