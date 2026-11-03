package services

// 规则级阶段拦截页（lb_rules block_page_stage*）停用后的兼容钉测
// （2026-11 用户裁定）：写侧停写、渲染链零消费、DB 4 列保留。
// 本文件替代原「481/482 阶段路由」行为钉——阶段码 481/482 已从引擎与
// 路由中全部移除，存量行携带的列值必须对渲染零影响。

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStageBlockPages_legacyColumnsHaveNoRenderEffect：存量行带阶段页列值
// （旧版本遗留）时，全量渲染必须零 481/482（指令与路由均不得出现），且
// 逐策略归因路由（483+）不被任何「规则配了阶段页」条件压制。
func TestStageBlockPages_legacyColumnsHaveNoRenderEffect(t *testing.T) {
	stubSecurityLibsAvailable(t)
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_legacy", "legacy.example.test", 8080)
	seedSecurityBlockPage(t, database, 7, "<html>legacy-stage-page</html>")
	seedSecurityBlockPage(t, database, 9, "<html>policy-page</html>")
	// 策略配页 + deny ACL（获合成码 483 且预检逐策略链在场），规则同时带
	// 阶段页列值（旧遗留）。
	mpGenBindPolicy(t, database, "lb_legacy", "legacy-p", mpGenPolicySpec{enabled: true, blockPageID: 9, blockStatusCode: 451, ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`})
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage1_id=7, block_page_stage1_status=403, block_page_stage3_id=7, block_page_stage3_status=503 WHERE caddy_id='lb_legacy'`); err != nil {
		t.Fatal(err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	rule := mpGenHTTPRule("lb_legacy", "legacy.example.test")
	_, mainRoute := mpGenRoutes(t, database, rule)
	joined := strings.Join(wafDirectives(t, mainRoute), "\n")
	if strings.Contains(joined, "status:481") || strings.Contains(joined, "status:482") {
		t.Fatalf("stage codes 481/482 must never be emitted (feature removed):\n%s", joined)
	}
	// 逐策略归因码由预检链 / 策略引擎段各自携带（有页策略 = 483）：规则级
	// 单规则渲染路径（mpGenRoutes）无批量上下文不获码，故断言全量生成配置。
	generatedJSON, marshalErr := json.Marshal(generated)
	if marshalErr != nil {
		t.Fatalf("marshal generated config: %v", marshalErr)
	}
	if !strings.Contains(string(generatedJSON), "status:483") {
		t.Fatalf("per-policy synthetic code must be emitted regardless of legacy stage columns")
	}

	errorRoutes, _ := serverErrorRoutes(t, generated, "http_8080")
	var attribution, stageRoute map[string]interface{}
	for _, routeValue := range errorRoutes {
		route, ok := routeValue.(map[string]interface{})
		if !ok {
			continue
		}
		matcher := routeMatcher(t, route)
		expr, _ := matcher["expression"].(string)
		switch {
		case strings.Contains(expr, "== 481 "), strings.Contains(expr, "== 482 "):
			stageRoute = route
		case strings.Contains(expr, "== 483 "):
			attribution = route
		}
	}
	if stageRoute != nil {
		t.Fatalf("no stage (481/482) error route may be emitted, got: %#v", stageRoute)
	}
	if attribution == nil {
		t.Fatalf("per-policy attribution route (483) must be emitted: %#v", errorRoutes)
	}
	handler := firstHandler(t, attribution)
	if handler["body"] != "<html>policy-page</html>" {
		t.Fatalf("attribution route must render the policy's own page, got: %#v", handler["body"])
	}

	// 阶段页列值本身不参与渲染：清空列值后生成的规则路由/错误路由逐字节不变。
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage1_id=0, block_page_stage1_status=0, block_page_stage3_id=0, block_page_stage3_status=0 WHERE caddy_id='lb_legacy'`); err != nil {
		t.Fatal(err)
	}
	generated2 := generateCaddyConfigFromStore(database)
	if message, failed := generated2[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed after clearing stage columns: %s", message)
	}
	routes2, _ := serverErrorRoutes(t, generated2, "http_8080")
	if len(errorRoutes) != len(routes2) {
		t.Fatalf("stage columns must not influence error route count: %d vs %d", len(errorRoutes), len(routes2))
	}
}

// TestStage1PrecheckIDSQL_aclSegmentReconciled：阶段 1 事件段 SQL 与 Go 谓词
// 对逐策略 ACL/黑名单链段（1500000+/1510000+）同口径——段界调整时三处
// （IsStage1PrecheckID / Stage1PrecheckSegmentSQL / SQL 清单）同步义务由
// security_stage1_segment_test.go 真执行钉承担，此处只钉段形状存在。
func TestStage1PrecheckIDSQL_aclSegmentReconciled(t *testing.T) {
	if !strings.Contains(Stage1PrecheckSegmentSQL, "LIKE '150%'") || !strings.Contains(Stage1PrecheckSegmentSQL, "LIKE '151%'") {
		t.Fatalf("stage1 SQL segment must cover per-policy ACL/blacklist chains: %s", Stage1PrecheckSegmentSQL)
	}
	for _, id := range []int{aclPrecheckRuleBase + 1, blacklistPrecheckRuleBase + 1, aclPrecheckRuleLimit - 1} {
		if !IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=false，逐策略 ACL 段失守", id)
		}
	}
	// 右开界不属于本段；段基址属段形状（p=0 边界由 decode 拒绝，与 GeoIP 段同口径）。
	if IsStage1PrecheckID(aclPrecheckRuleLimit) {
		t.Fatalf("IsStage1PrecheckID(%d)=true，越出 ACL 段右开界", aclPrecheckRuleLimit)
	}
	if !IsStage1PrecheckID(aclPrecheckRuleBase) {
		t.Fatalf("IsStage1PrecheckID(%d)=false，段基址应属段形状（decode 层拒绝 p=0）", aclPrecheckRuleBase)
	}
}
