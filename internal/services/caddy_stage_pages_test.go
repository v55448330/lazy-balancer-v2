package services

import (
	"strings"
	"testing"
)

// 阶段拦截页渲染（阶段化安全流水线批 2）：阶段码 481=阶段 1（IP 访问控制+
// 地域拦截预检）、482=阶段 3（WAF）固定；逐策略合成码平移 483+。规则配了
// 阶段页（id>0 且页内容非空）→ 对应阶段全部 deny 抬阶段码 + 按 code 去重
// 发射阶段错误路由（无 host、terminal、status 0 归一 403）；未配=跟随策略
// （v2.3.1 逐策略归因默认层完整保留，合成码 483+）。

// 阶段 1 覆盖：预检全部 deny（IP ACL 并集 id:2 与 GeoIP 链首 800000+）抬码
// 481，错误路由装配发射 481 阶段路由（阶段页内容+状态码）。
func TestStageBlockPages_stage1LiftsPrecheckAndRoute(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
	// Given：规则配阶段 1 页（页 7，状态码 451）；策略带 deny ACL + GeoIP（无策略页）
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_st1", "st1.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>stage-one</html>")
	mpGenBindPolicy(t, database, "lb_st1", "st1-p", mpGenPolicySpec{
		mode: "blocking", enabled: true,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`,
		geoCountries: `["海外"]`,
	})
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage1_id=7, block_page_stage1_status=451 WHERE caddy_id='lb_st1'`); err != nil {
		t.Fatal(err)
	}

	// When：全量渲染 + 链渲染
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	rule := mpGenHTTPRule("lb_st1", "st1.example.test")
	rule.BlockPageStage1ID = 7
	rule.BlockPageStage1Status = 451
	_, mainRoute := mpGenRoutes(t, database, rule)

	// Then：预检 id:2 deny 与 GeoIP 链首均抬 481
	joined := strings.Join(wafDirectives(t, mainRoute), "\n")
	if !strings.Contains(joined, `id:2,phase:1,deny,status:481,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("precheck ACL deny must lift to 481:\n%s", joined)
	}
	geoipFound := false
	for _, line := range strings.Split(joined, "\n") {
		if strings.Contains(line, "msg:'GeoIP 区域拦截'") {
			geoipFound = true
			if !strings.Contains(line, "status:481") {
				t.Fatalf("precheck geoip chain head must lift to 481:\n%s", line)
			}
		}
	}
	if !geoipFound {
		t.Fatalf("precheck must carry geoip chain:\n%s", joined)
	}
	// 策略引擎段不抬 481（阶段码域隔离：阶段 3 未配=跟随策略，无页策略保持 403）
	if strings.Contains(joined, "id:9,phase:1") && strings.Contains(joined, "status:481,log,msg:'自定义") {
		t.Fatalf("stage-1 code must not leak into policy engine segments:\n%s", joined)
	}

	// Then：481 阶段路由（无 host、阶段页内容+状态码、terminal）
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	var stageRoute map[string]interface{}
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, route)["expression"].(string)
		if strings.Contains(expr, "== 481") {
			stageRoute = route
		}
	}
	if stageRoute == nil {
		t.Fatalf("missing 481 stage route: %#v", errorRoutes)
	}
	if _, hasHost := routeMatcher(t, stageRoute)["host"]; hasHost {
		t.Fatalf("stage route must not carry host matcher: %#v", routeMatcher(t, stageRoute))
	}
	assertEqual(t, routeMatcher(t, stageRoute)["expression"],
		"({http.error.status_code} == 481 && {http.error.message} == 'interruption triggered')")
	handler := firstHandler(t, stageRoute)
	assertEqual(t, handler["body"], "<html>stage-one</html>")
	assertEqual(t, handler["status_code"], 451)
	if stageRoute["terminal"] != true {
		t.Fatalf("stage route must be terminal: %#v", stageRoute)
	}
}

// 阶段 3 覆盖：全部策略段 deny 抬 482（逐策略合成码 483+ 被覆盖层压过），
// 发射 482 阶段路由；阶段 1 未配 → 预检保持 403。
func TestStageBlockPages_stage3LiftsAllPolicySegmentsAndRoute(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
	// Given：两条有页策略（本可分 483/484）+ 规则配阶段 3 页（页 9，503）
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_st3", "st3.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>p-one</html>")
	seedSecurityBlockPage(t, database, 8, "<html>p-two</html>")
	seedSecurityBlockPage(t, database, 9, "<html>stage-three</html>")
	mpGenBindPolicy(t, database, "lb_st3", "st3-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, blockPageID: 7, blockStatusCode: 451,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`,
	})
	mpGenBindPolicy(t, database, "lb_st3", "st3-p2", mpGenPolicySpec{
		mode: "blocking", enabled: true, blockPageID: 8, blockStatusCode: 404,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["198.51.100.0/24"]`,
	})
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage3_id=9, block_page_stage3_status=503 WHERE caddy_id='lb_st3'`); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	rule := mpGenHTTPRule("lb_st3", "st3.example.test")
	rule.BlockPageStage3ID = 9
	rule.BlockPageStage3Status = 503
	_, mainRoute := mpGenRoutes(t, database, rule)

	// Then：两策略段 deny 均抬 482，段内无 483/484
	joined := strings.Join(wafDirectives(t, mainRoute), "\n")
	if !strings.Contains(joined, `id:2,phase:1,deny,status:482,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("stage3 configured must lift policy segments to 482:\n%s", joined)
	}
	if strings.Contains(joined, "status:483") || strings.Contains(joined, "status:484") {
		t.Fatalf("stage3 override must suppress per-policy synthetic codes in segments:\n%s", joined)
	}
	// 预检（阶段 1 未配）保持 403
	if !strings.Contains(joined, `id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("precheck must stay 403 when stage 1 unconfigured:\n%s", joined)
	}

	// Then：482 阶段路由（阶段 3 页内容+503）
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	var stageRoute map[string]interface{}
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, route)["expression"].(string)
		if strings.Contains(expr, "== 482") {
			stageRoute = route
		}
	}
	if stageRoute == nil {
		t.Fatalf("missing 482 stage route: %#v", errorRoutes)
	}
	handler := firstHandler(t, stageRoute)
	assertEqual(t, handler["body"], "<html>stage-three</html>")
	assertEqual(t, handler["status_code"], 503)
}

// 阶段页内容为空 = 视为未配（跟随策略）：策略段回落逐策略合成码 483+，
// 不发射 482 阶段路由。
func TestStageBlockPages_emptyPageContentFallsBackToPolicy(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
	// Given：阶段 3 页 id 指向空内容页；两条有页策略
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_ste", "ste.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>p-one</html>")
	seedSecurityBlockPage(t, database, 9, "")
	p1 := mpGenBindPolicy(t, database, "lb_ste", "ste-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, blockPageID: 7, blockStatusCode: 451,
		ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`,
	})
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage3_id=9, block_page_stage3_status=503 WHERE caddy_id='lb_ste'`); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	rule := mpGenHTTPRule("lb_ste", "ste.example.test")
	rule.BlockPageStage3ID = 9
	rule.BlockPageStage3Status = 503
	_, mainRoute := mpGenRoutes(t, database, rule)

	// Then：策略段回落 483（p1 唯一有页策略分得首码），无 482
	joined := strings.Join(wafDirectives(t, mainRoute), "\n")
	if !strings.Contains(joined, "deny,status:483") {
		t.Fatalf("empty stage page must fall back to policy synthetic 483:\n%s", joined)
	}
	if strings.Contains(joined, "status:482") {
		t.Fatalf("empty stage page must not emit stage-3 lift:\n%s", joined)
	}
	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	for _, routeValue := range errorRoutes {
		route := mustMap(t, routeValue, "error route")
		expr, _ := routeMatcher(t, route)["expression"].(string)
		if strings.Contains(expr, "== 482") {
			t.Fatalf("empty stage page must not emit 482 stage route: %#v", route)
		}
	}
	_ = p1
}
