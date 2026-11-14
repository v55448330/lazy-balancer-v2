package services

import "testing"

// 契约钉：「blocked_counter 恒包裹安全链」。
//
// 计时注册表（caddygeoip auditTiming*）的终态收点 auditTimingClose 只在
// lb_security_blocked_counter 的 post-next 执行；分段写点是
// lb_security_timing_pre/lb_security_timing_end 与 blocked_counter 自身，
// 审计行生产者是各 coraza waf（审计 Write 严格早于收点——coraza 中间件
// defer ProcessLogging）。渲染层若让任一分段写点/审计行生产者出现在
// counter 之后无包裹、或 counter 缺席，drain 侧等待语义失配：行入队时终态
// 永不到场（有 pre 无终态，等待满上限——正是沉陷形态的渲染侧根源）。
// 本钉测把每条规则渲染树扁平化为执行序，按形状矩阵断言：
//  1. 树内出现任一安全段元素（waf/lb_security_timing_pre/lb_security_timing_end/
//     rate_limit）⇒ counter 在场且先于全部安全段元素（最外层包裹）。覆盖
//     stage0 直通形态：安全段嵌套在信任 subroute 内层，counter 在外层——
//     扁平化后序关系不变（caddy_multi_policy_test.go 的序断言只锁单点主链，
//     本钉测的增量是全形状遍历+嵌套扁平化+双向条件）。
//  2. 无任何绑定策略的规则不发射 counter/waf/timing/rate_limit（包裹面与
//     安全面同生同灭的另一面）。counter 在场而安全链空（off-only 策略，
//     形状 4）是允许形态——counter 发射面键在 len(policies)>0，非链内容。
//
// 契约破裂的历史形态示例（本钉测应拦）：
//   - 新增安全段 handler 插到 counter 之前（耗时/计数漏记+drain 等待失配）；
//   - stage0 subroute 包裹时把 counter 误移进 subroute（信任 IP 拦截计数
//     缺失+counter 不再最外层）；
//   - 条件发射 counter 时漏掉某策略形状（有 waf 无 counter）。

// flattenRouteHandlers 递归扁平化路由处理器树为执行序（subroute.routes[].handle
// 按序展开——执行序 = 外层先于内层，同级保持数组序）。
func flattenRouteHandlers(t *testing.T, routeValue interface{}) []string {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		return nil
	}
	var names []string
	for _, hv := range handlers {
		h := mustMap(t, hv, "handler")
		name, _ := h["handler"].(string)
		names = append(names, name)
		if name == "subroute" {
			if innerRoutes, ok := h["routes"].([]interface{}); ok {
				for _, irv := range innerRoutes {
					names = append(names, flattenRouteHandlers(t, irv)...)
				}
			}
		}
	}
	return names
}

// assertBlockedCounterWrap 断言单条规则名下的路由执行序满足包裹契约。
func assertBlockedCounterWrap(t *testing.T, ruleID, routeDesc string, flat []string) {
	t.Helper()
	counterIdx := indexOfHandler(flat, "lb_security_blocked_counter")
	firstSecurity := -1
	for i, name := range flat {
		switch name {
		case "waf", "lb_security_timing_pre", "lb_security_timing_end", "rate_limit":
			if firstSecurity < 0 {
				firstSecurity = i
			}
		}
	}
	switch {
	case firstSecurity >= 0 && counterIdx < 0:
		t.Fatalf("rule %s %s: security chain present but blocked_counter missing (wrap contract broken): %v", ruleID, routeDesc, flat)
	case firstSecurity >= 0 && counterIdx > firstSecurity:
		t.Fatalf("rule %s %s: blocked_counter (idx %d) must precede all security-segment handlers (first at %d): %v", ruleID, routeDesc, counterIdx, firstSecurity, flat)
	}
}

// Given 五种策略绑定形状（渲染矩阵最小覆盖）:
//
//	1 blocking+限流+GeoIP（waf 多引擎+rate_limit+timing 双收点全场）
//	2 detection 单策略（waf+timing，无限流）
//	3 stage0 直通 + stage3 WAF（安全段嵌套信任 subroute 内层）
//	4 off-only 策略（counter 在场、安全链空——允许形态，不误报）
//	5 无任何绑定策略（counter/waf/timing/rate_limit 全不发射）
//
// When: 批量预载通道逐形状渲染全部路由
// Then: 形状 1-4 每条路由扁平执行序满足「有安全段必有 counter 且 counter 最外」；
// 形状 5 四类处理器全缺席。
func TestBlockedCounterWrapContract_acrossAllRenderShapes(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用

	// 形状 1：blocking + 挑战 + GeoIP
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_wrap1", "wrap1.example.test", 8080)
	mpGenBindPolicy(t, database, "lb_wrap1", "wrap1-p1", mpGenPolicySpec{
		mode: "blocking", enabled: true, geoCountries: `["海外"]`,
	})
	mpGenBindPolicy(t, database, "lb_wrap1", "wrap1-p2", mpGenPolicySpec{
		mode: "detection", enabled: true, challenge: true,
	})
	routes, mainRoute := mpGenRoutes(t, database, mpGenHTTPRule("lb_wrap1", "wrap1.example.test"))
	for i, route := range routes {
		assertBlockedCounterWrap(t, "lb_wrap1", "route["+string(rune('0'+i))+"]", flattenRouteHandlers(t, route))
	}
	assertBlockedCounterWrap(t, "lb_wrap1", "main", flattenRouteHandlers(t, mainRoute))
	// 最外层锚：主链前缀恰为 [headers, lb_rule_metrics, counter]（链首包裹）
	names := handlerNames(t, mainRoute)
	if len(names) < 3 || names[0] != "headers" || names[1] != "lb_rule_metrics" || names[2] != "lb_security_blocked_counter" {
		t.Fatalf("wrap1 main chain prefix=%v, want [headers, lb_rule_metrics, lb_security_blocked_counter, ...]", names)
	}

	// 形状 2：detection 单策略
	_, database2 := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database2, "lb_wrap2", "wrap2.example.test", 8080)
	mpGenBindPolicy(t, database2, "lb_wrap2", "wrap2-p1", mpGenPolicySpec{mode: "detection", enabled: true})
	routes2, mainRoute2 := mpGenRoutes(t, database2, mpGenHTTPRule("lb_wrap2", "wrap2.example.test"))
	for _, route := range routes2 {
		assertBlockedCounterWrap(t, "lb_wrap2", "route", flattenRouteHandlers(t, route))
	}
	assertBlockedCounterWrap(t, "lb_wrap2", "main", flattenRouteHandlers(t, mainRoute2))

	// 形状 3：stage0 直通（安全段嵌套 subroute 内层，counter 留在外层）
	_, database3 := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database3, "lb_wrap3", "wrap3.example.test", 8080)
	seedStage0Policy(t, database3, "lb_wrap3", `["10.0.0.9"]`, false)
	mpGenBindPolicy(t, database3, "lb_wrap3", "wrap3-waf", mpGenPolicySpec{mode: "blocking", enabled: true})
	routes3, mainRoute3 := mpGenRoutes(t, database3, mpGenHTTPRule("lb_wrap3", "wrap3.example.test"))
	for _, route := range routes3 {
		assertBlockedCounterWrap(t, "lb_wrap3", "route", flattenRouteHandlers(t, route))
	}
	assertBlockedCounterWrap(t, "lb_wrap3", "main", flattenRouteHandlers(t, mainRoute3))
	// 嵌套形态专项：counter 在外层、waf 在内层——扁平序仍 counter 先于 waf
	flat3 := flattenRouteHandlers(t, mainRoute3)
	if indexOfHandler(flat3, "lb_security_blocked_counter") > indexOfHandler(flat3, "waf") {
		t.Fatalf("stage0 passthrough: counter must stay outermost (flat order): %v", flat3)
	}

	// 形状 4：off-only 策略（counter 在场、无任何安全段——允许孤儿形态）
	_, database4 := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database4, "lb_wrap4", "wrap4.example.test", 8080)
	mpGenBindPolicy(t, database4, "lb_wrap4", "wrap4-off", mpGenPolicySpec{mode: "off", enabled: true})
	routes4, mainRoute4 := mpGenRoutes(t, database4, mpGenHTTPRule("lb_wrap4", "wrap4.example.test"))
	for _, route := range routes4 {
		flat := flattenRouteHandlers(t, route)
		assertBlockedCounterWrap(t, "lb_wrap4", "route", flat)
		if indexOfHandler(flat, "lb_security_blocked_counter") < 0 {
			t.Fatalf("off-only policy must still emit blocked_counter (policies>0): %v", flat)
		}
	}
	assertBlockedCounterWrap(t, "lb_wrap4", "main", flattenRouteHandlers(t, mainRoute4))

	// 形状 5：无策略规则——语义面处理器全不发射。（历史
	// 审计）起 lb_security_timing_end 也不再例外：无 counter 即无服务端
	// timing ID 注入/覆盖，发射 timing_end 会让客户端伪造的计时头直进
	// 进程内注册表（内存 DoS 面）——渲染层单点收口，无 counter 的路由
	// 不发射任何计时写点。
	_, database5 := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database5, "lb_wrap5", "wrap5.example.test", 8080)
	routes5, mainRoute5 := mpGenRoutes(t, database5, mpGenHTTPRule("lb_wrap5", "wrap5.example.test"))
	for _, route := range append(routes5, mainRoute5) {
		flat := flattenRouteHandlers(t, route)
		for _, unwanted := range []string{"lb_security_blocked_counter", "waf", "lb_security_timing_pre", "lb_security_timing_end", "rate_limit"} {
			if indexOfHandler(flat, unwanted) >= 0 {
				t.Fatalf("policy-less rule must not emit %s: %v", unwanted, flat)
			}
		}
	}
}
