package services

// 拦截页按触发策略归因(合成中断码 483+；阶段码 481/482 固定)——引擎行为实证与渲染钉测试。
//
// TestEngineBehavior_SecRuleUpdateActionByIdLiftsInterruptionStatus 是本特性的
// 可行性门禁(coraza v3.7.0,与镜像 coraza-caddy v2.6.1 同版):CRS 拦截统一由
// 949110(inbound blocking evaluation)的 deny 中断产生,归因要求该中断携带
// 策略合成状态码。SecRuleUpdateActionById 949110 "deny,status:<syn>" 必须在
// 引擎层真实抬码(interruption.Status==<syn>)——若引擎不支持(coraza 与
// ModSecurity 行为差),fallback=CRS 中断走 403 兜底路由(计划 Assumptions 节)。
// 这是引擎行为实证,非字符串断言(R-10)。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/internal/models"
)

func TestEngineBehavior_SecRuleUpdateActionByIdLiftsInterruptionStatus(t *testing.T) {
	// Given:桩规则模拟 CRS 949110(普通 deny 不带 status)+ 合成码抬码指令
	directives := strings.Join([]string{
		"SecRuleEngine On",
		`SecRule REQUEST_URI "@rx .*" "id:949110,phase:1,deny,log"`,
		`SecRuleUpdateActionById 949110 "deny,status:482"`,
	}, "\n")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("engine must accept SecRuleUpdateActionById status lift: %v", err)
	}

	// When:跑一个触发事务
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessConnection("10.0.0.1", 5555, "127.0.0.1", 80)
	tx.ProcessURI("/anything", "GET", "HTTP/1.1")
	it := tx.ProcessRequestHeaders()

	// Then:中断必须携带抬升后的合成状态码(而非 deny 默认 403)
	if it == nil {
		t.Fatal("expected an interruption from the stub deny rule")
	}
	if it.Status != 482 {
		t.Fatalf("SecRuleUpdateActionById must lift interruption status to 482, got %d", it.Status)
	}
}

// ---------- 步骤 1.2：BuildCorazaDirectives 的 blockStatus 抬码（RED）----------

// blockStatus>0 时策略段内全部 deny 规则显式携带合成状态码（IP ACL id:2、
// 遗留黑名单 id:4、自定义规则 block 动作）。GeoIP 已迁预检（800000+ 段，
// 阶段 1 不抬码保持 403 兜底），策略引擎零 GeoIP 段。
func TestBuildCorazaDirectives_blockStatusLiftsDenyStatuses(t *testing.T) {
	// Given：blocking 策略，deny ACL + 遗留黑名单 + GeoIP + 自定义拦截规则
	policy := &models.SecurityPolicy{
		Mode:           "blocking",
		IPACLEnabled:   true,
		IPACLMode:      "deny",
		IPACLList:      `["203.0.113.0/24"]`,
		IPBlacklist:    json.RawMessage(`["198.51.100.9"]`),
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
		CustomRules:    json.RawMessage(`[{"id":11,"name":"拒绝规则","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}]}]`),
	}

	// When：以合成码 481 渲染
	directives := BuildCorazaDirectives(policy, nil, "", false, 481)

	// Then：三处 deny 全部抬码 481；GeoIP 不在策略引擎（预检承接）
	for _, want := range []string{
		`id:2,phase:1,deny,status:481,log,msg:'IP 黑名单拒绝'`,
		`id:4,phase:1,deny,status:481,log,msg:'IP 黑名单'`,
		`deny,status:481,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'自定义规则 拒绝规则 命中'`,
	} {
		if !strings.Contains(directives, want) {
			t.Fatalf("blockStatus=481 must lift deny status %q:\n%s", want, directives)
		}
	}
	if strings.Contains(directives, "msg:'GeoIP 区域拦截'") || strings.Contains(directives, "id:8,") {
		t.Fatalf("policy engine must not emit geoip rules (moved to precheck):\n%s", directives)
	}
	if strings.Contains(directives, "status:403") {
		t.Fatalf("lifted segment must not retain status:403:\n%s", directives)
	}
}

// allow 模式（白名单外拒绝）同样抬码。
func TestBuildCorazaDirectives_blockStatusLiftsAllowModeDeny(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:         "blocking",
		IPACLEnabled: true,
		IPACLMode:    "allow",
		IPACLList:    `["198.51.100.7"]`,
	}
	directives := BuildCorazaDirectives(policy, nil, "", false, 482)
	if !strings.Contains(directives, `id:2,phase:1,deny,status:482,log,msg:'IP 白名单拒绝'`) {
		t.Fatalf("allow-mode deny must lift to 482:\n%s", directives)
	}
}

// 多策略链式自排除形状：链首段（disruptive 仅在首段，SECLB33-1 引擎约束）抬码。
func TestBuildCorazaDirectives_blockStatusLiftsChainedTrustExclusion(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:               "blocking",
		IPACLEnabled:       true,
		IPACLMode:          "deny",
		IPACLList:          `["198.51.100.9"]`,
		IPWhitelistEnabled: true,
		IPWhitelist:        json.RawMessage(`["10.0.0.1"]`),
	}
	directives := BuildCorazaDirectives(policy, nil, "", true, 481)
	if !strings.Contains(directives, `id:2,phase:1,deny,status:481,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END,chain`) {
		t.Fatalf("chained trust-exclusion head must lift to 481:\n%s", directives)
	}
}

// blockStatus=0 回归形状：逐字节保持现状（403 / 缺省不带 status）。既有钉测试
// （security_test.go 的 403 链首形状、security_customrules_test.go 的
// customRuleDenyOmitsStatusCode、geoip_caddy_test.go 的 deny 不带 status）覆盖，
// 此处只补一条复合断言防回归。
func TestBuildCorazaDirectives_blockStatusZeroKeepsLegacyShapes(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:         "blocking",
		IPACLEnabled: true,
		IPACLMode:    "deny",
		IPACLList:    `["203.0.113.0/24"]`,
		CustomRules:  json.RawMessage(`[{"id":11,"name":"拒绝规则","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}]}]`),
	}
	directives := BuildCorazaDirectives(policy, nil, "", false, 0)
	if !strings.Contains(directives, `id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("blockStatus=0 must keep 403:\n%s", directives)
	}
	if !strings.Contains(directives, `deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'自定义规则 拒绝规则 命中'`) {
		t.Fatalf("blockStatus=0 must keep custom deny without status:\n%s", directives)
	}
}

// CRS 归因：blockStatus>0 且 949 评估文件存在（Include 必然覆盖 949110）时，
// 在 Include 之后发射 SecRuleUpdateActionById 949110 抬码；文件缺失时禁发——
// 指令在规则不存在时编译报错（directives.go:1262），不得拖垮整份配置加载。
func TestBuildCorazaDirectives_blockStatusCRSLiftGatedOn949File(t *testing.T) {
	// Given：含 949 文件的 CRS 目录
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "REQUEST-949-BLOCKING-EVALUATION.conf"), []byte("# stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	useCRSDirectivesDir(t, dir)

	// When：blocking 策略 + blockStatus=481
	directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"}, nil, "", false, 481)

	// Then：抬码指令存在且位于最后一个 Include 行之后
	const lift = `SecRuleUpdateActionById 949110 "deny,status:481"`
	liftIdx := strings.Index(directives, lift)
	if liftIdx < 0 {
		t.Fatalf("949 file present must emit CRS status lift:\n%s", directives)
	}
	if includeIdx := strings.LastIndex(directives, "Include "); includeIdx < 0 || liftIdx < includeIdx {
		t.Fatalf("CRS lift must follow the Include lines:\n%s", directives)
	}

	// Given：949 文件缺失的 CRS 目录
	emptyDir := t.TempDir()
	useCRSDirectivesDir(t, emptyDir)
	// When / Then：不发射抬码指令（949110 不会被注册，发射即编译失败）
	directives = BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"}, nil, "", false, 481)
	if strings.Contains(directives, "SecRuleUpdateActionById") {
		t.Fatalf("949 file missing must not emit CRS status lift:\n%s", directives)
	}
}

// ---------- 步骤 1.1：policySynthetic 按策略身份分配（RED）----------

// 全部被任一规则绑定的启用策略中 BlockPageID>0 且页内容非空者，按 policy_id ASC
// 分配 483+序号（阶段码 481/482 固定后逐策略码平移）；无页/空页/禁用策略不进表（值 0=不抬码）。
func TestLoadSecurityPolicyContext_policySyntheticAssignedByPolicyIdentity(t *testing.T) {
	// Given：页 7/8 有内容、页 9 内容为空；p1(页7) p2(页8) p3(无页) p4(空页9) p5(禁用+页7)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_syn", "syn.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>page-seven</html>")
	seedSecurityBlockPage(t, database, 8, "<html>page-eight</html>")
	seedSecurityBlockPage(t, database, 9, "")
	p1 := mpGenBindPolicy(t, database, "lb_syn", "syn-p1", mpGenPolicySpec{mode: "blocking", enabled: true, blockPageID: 7, blockStatusCode: 451})
	p2 := mpGenBindPolicy(t, database, "lb_syn", "syn-p2", mpGenPolicySpec{mode: "blocking", enabled: true, blockPageID: 8})
	p3 := mpGenBindPolicy(t, database, "lb_syn", "syn-p3", mpGenPolicySpec{mode: "blocking", enabled: true})
	p4 := mpGenBindPolicy(t, database, "lb_syn", "syn-p4", mpGenPolicySpec{mode: "blocking", enabled: true, blockPageID: 9})
	p5 := mpGenBindPolicy(t, database, "lb_syn", "syn-p5", mpGenPolicySpec{mode: "blocking", enabled: false, blockPageID: 7})
	if !(p1 < p2 && p2 < p3 && p3 < p4 && p4 < p5) {
		t.Fatalf("seed ids not ascending: %d %d %d %d %d", p1, p2, p3, p4, p5)
	}

	// When
	ctx, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext: %v", err)
	}

	// Then：按 policy_id ASC 分配 483/484；无页/空页/禁用不进表
	if got := ctx.policySynthetic[p1]; got != 483 {
		t.Fatalf("p1 synthetic=%d, want 483", got)
	}
	if got := ctx.policySynthetic[p2]; got != 484 {
		t.Fatalf("p2 synthetic=%d, want 484", got)
	}
	for _, id := range []int{p3, p4, p5} {
		if _, ok := ctx.policySynthetic[id]; ok {
			t.Fatalf("policy %d (no page/empty page/disabled) must not get a synthetic code", id)
		}
	}
}

// 合成码区间上限：483+116=599 为合法状态码上限，超出策略回落不抬码（403 兜底）。
func TestLoadSecurityPolicyContext_policySyntheticCappedAt599(t *testing.T) {
	// Given：125 条启用策略均配置同一有内容拦截页
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_cap", "cap.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>cap</html>")
	for i := 0; i < 125; i++ {
		mpGenBindPolicy(t, database, "lb_cap", "cap-p"+string(rune('a'+i%26))+string(rune('a'+i/26)), mpGenPolicySpec{mode: "blocking", enabled: true, blockPageID: 7})
	}

	// When
	ctx, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext: %v", err)
	}

	// Then：恰好 117 条策略获码（483..599），无越界码
	if len(ctx.policySynthetic) != 117 {
		t.Fatalf("synthetic entries=%d, want 117 (483..599)", len(ctx.policySynthetic))
	}
	for id, code := range ctx.policySynthetic {
		if code < 483 || code > 599 {
			t.Fatalf("policy %d synthetic=%d out of legal range", id, code)
		}
	}
}

// ---------- 步骤 1.3：按策略去重的归因错误路由（RED）----------

// wafDirectives 收集主路由链上全部 waf handler 的 directives 文本。
func wafDirectives(t *testing.T, routeValue interface{}) []string {
	t.Helper()
	route := mustMap(t, routeValue, "main route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("main route missing handle chain: %#v", route)
	}
	var out []string
	for _, h := range handlers {
		handler := mustMap(t, h, "handler")
		if handler["handler"] == "waf" {
			d, _ := handler["directives"].(string)
			out = append(out, d)
		}
	}
	return out
}

// 双策略绑定各配拦截页：每 server 错误路由 = 每规则 1 条 403 兜底（host 限定，
// 首绑定有页策略）+ 每有页策略 1 条合成码归因路由（无 host 键，按策略去重——
// 同 server 多规则共用同策略仅一条）；策略段 deny 行携带对应合成码。
func TestMultiPolicy_AttributionRoutes_PerPolicySyntheticCode(t *testing.T) {
	// Given：同端口两规则；p1(页7,451) 绑两规则，p2(页8,503) 仅绑 rule1
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_attr1", "attr1.example.test", 8080)
	seedHTTPRuleForGeneration(t, database, "lb_attr2", "attr2.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>first-block</html>")
	seedSecurityBlockPage(t, database, 8, "<html>second-block</html>")
	p1 := mpGenBindPolicy(t, database, "lb_attr1", "attr-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, blockPageID: 7, blockStatusCode: 451,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`,
	})
	p2 := mpGenBindPolicy(t, database, "lb_attr1", "attr-p2", mpGenPolicySpec{
		mode: "blocking", enabled: true, blockPageID: 8, blockStatusCode: 503, geoCountries: `["海外"]`,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["198.51.100.0/24"]`,
	})
	// 同一策略 p1 绑定第二条规则（归因路由按策略去重的被测形状）
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_attr2', ?)`, p1); err != nil {
		t.Fatalf("bind shared policy to rule2: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then：生成成功
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	// 2 条兜底（每规则）+ 2 条归因（483/484 各一，483 被两规则共用仍一条）
	if len(errorRoutes) != 4 {
		t.Fatalf("want 4 error routes (2 fallback + 2 attribution), got %d: %#v", len(errorRoutes), errorRoutes)
	}
	var fallbackHosts, attributionCodes []string
	attributionByCode := map[string]map[string]interface{}{}
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		matcher := routeMatcher(t, route)
		expr, _ := matcher["expression"].(string)
		if strings.Contains(expr, "== 403") {
			hosts, ok := matcher["host"].([]string)
			if !ok || len(hosts) == 0 {
				t.Fatalf("fallback route must keep host matcher: %#v", matcher)
			}
			fallbackHosts = append(fallbackHosts, hosts[0])
			continue
		}
		// 归因路由：无 host 键（合成码只可能由绑定该策略的规则段产生）
		if _, hasHost := matcher["host"]; hasHost {
			t.Fatalf("attribution route must not carry host matcher: %#v", matcher)
		}
		for _, code := range []string{"483", "484"} {
			if strings.Contains(expr, "== "+code+" &&") {
				attributionCodes = append(attributionCodes, code)
				attributionByCode[code] = route
			}
		}
	}
	if len(fallbackHosts) != 2 {
		t.Fatalf("want 2 host-scoped fallback routes, got %v", fallbackHosts)
	}
	if len(attributionCodes) != 2 || attributionByCode["483"] == nil || attributionByCode["484"] == nil {
		t.Fatalf("want exactly one 483 and one 484 attribution route, got %v", attributionCodes)
	}
	// 483 → p1 的页与状态码；484 → p2 的页与状态码；matcher 表达式含 interruption 消息子句
	h483 := firstHandler(t, attributionByCode["483"])
	assertEqual(t, h483["body"], "<html>first-block</html>")
	assertEqual(t, h483["status_code"], 451)
	assertEqual(t, routeMatcher(t, attributionByCode["483"])["expression"],
		"({http.error.status_code} == 483 && {http.error.message} == 'interruption triggered')")
	h484 := firstHandler(t, attributionByCode["484"])
	assertEqual(t, h484["body"], "<html>second-block</html>")
	assertEqual(t, h484["status_code"], 503)
	// terminal 语义与兜底一致
	if attributionByCode["483"]["terminal"] != true || attributionByCode["484"]["terminal"] != true {
		t.Fatalf("attribution routes must be terminal: %#v", attributionByCode)
	}

	// 主路由链：rule1 两个策略段分别携带各自合成码（渲染链贯穿实证）
	routes, _ := mpGenRoutes(t, database, mpGenHTTPRule("lb_attr1", "attr1.example.test"))
	if len(routes) == 0 {
		t.Fatal("rule1 must generate routes")
	}
	joined := strings.Join(wafDirectives(t, routes[len(routes)-1]), "\n")
	if !strings.Contains(joined, "deny,status:483") {
		t.Fatalf("p1 segment must lift deny to 483:\n%s", joined)
	}
	if !strings.Contains(joined, "deny,status:484") {
		t.Fatalf("p2 segment must lift deny to 484:\n%s", joined)
	}
	// GeoIP 已迁预检（id=800000+policyID 段）——预检 deny 不抬码（阶段 1 保持
	// 403 兜底归因边界，合成码抬码仅限策略引擎段）。
	geoipFound := false
	for _, line := range strings.Split(joined, "\n") {
		if strings.Contains(line, "msg:'GeoIP 区域拦截'") {
			geoipFound = true
			if strings.Contains(line, "status:") || !strings.Contains(line, fmt.Sprintf("id:%d,", 800000+p2)) {
				t.Fatalf("precheck geoip chain must stay un-lifted at id %d:\n%s", 800000+p2, line)
			}
		}
	}
	if !geoipFound {
		t.Fatalf("precheck must carry p2 geoip chain (id %d):\n%s", 800000+p2, joined)
	}
}

// 回归形状：无页策略不抬码（483+ 零出现）；其 deny 仍为 403，且只产兜底路由。
func TestMultiPolicy_AttributionRoutes_NoPagePolicyNotLifted(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_nolift", "nolift.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>only-page</html>")
	mpGenBindPolicy(t, database, "lb_nolift", "nolift-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, blockPageID: 7,
	})
	mpGenBindPolicy(t, database, "lb_nolift", "nolift-p2", mpGenPolicySpec{
		mode: "blocking", enabled: true,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`,
	})

	routes, _ := mpGenRoutes(t, database, mpGenHTTPRule("lb_nolift", "nolift.example.test"))
	joined := strings.Join(wafDirectives(t, routes[len(routes)-1]), "\n")
	if strings.Contains(joined, "status:48") {
		t.Fatalf("no-page policy segment must not lift (no 48x code):\n%s", joined)
	}
	if !strings.Contains(joined, "deny,status:403") {
		t.Fatalf("no-page policy deny must stay 403:\n%s", joined)
	}

	// 仅 1 条 403 兜底 + 1 条 483 归因（有页策略 p1）
	generated := generateCaddyConfigFromStore(database)
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	if len(errorRoutes) != 2 {
		t.Fatalf("want 2 error routes (fallback + 483 attribution), got %d: %#v", len(errorRoutes), errorRoutes)
	}
}
