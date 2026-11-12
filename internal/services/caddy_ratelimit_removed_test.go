package services

import (
	"testing"
)

// 配额限流下线（2026-11-12 用户裁定）：阶段 2 仅保留 CC 人机挑战。
// 存量策略即使库里 rate_limit_* 仍为旧值，生成阶段也不得再发 rate_limit
// handler / 429 错误路由——旧数据不能复活已下线能力。
func TestStage2PolicyDoesNotEmitRetiredRateLimitHandler(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedWafRuleRow(t, database, "rule-http", "http")
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,rate_limit_enabled,rate_limit_rps,rate_limit_burst,enabled) VALUES ('legacy-rl','blocking',1,100,50,1)`); err != nil {
		t.Fatalf("seed legacy rate-limit policy: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) SELECT 'rule-http', id FROM security_policies WHERE name='legacy-rl'`); err != nil {
		t.Fatalf("bind legacy policy: %v", err)
	}
	rule := baseHTTPRule()

	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate routes: %v", err)
	}
	if names := handlerChainNames(t, routes[0]); indexOfHandler(names, "rate_limit") >= 0 {
		t.Fatalf("rate_limit handler 已下线，链中不得再出现: %v", names)
	}
	if findHandlerRecursive(routes, "rate_limit") != nil {
		t.Fatal("生成配置中仍存在 rate_limit handler")
	}
}
