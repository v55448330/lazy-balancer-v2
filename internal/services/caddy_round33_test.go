package services

import (
	"context"
	"errors"
	"testing"
)

// Round 33 N-1: 安全策略批量预载走生成所用 store——事务内生成必须读到未提交的
// 策略变更（此前逐规则 GetSecurityPolicyForRule 走全局 db.DB，SQLite 下另一
// 连接看不到未提交事务，主从节点事务性重载存在安全配置滞后）。
func TestGenerateCaddyConfigFromStore_readsUncommittedPolicyThroughTx(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_tx_policy", false)
	seedBoundSecurityPolicy(t, database, "lb_tx_policy", "blocking", true)

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	var policyID int
	if err := database.QueryRow(`SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id='lb_tx_policy'`).Scan(&policyID); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if _, err := tx.Exec(`UPDATE security_policies SET rate_limit_enabled=1, rate_limit_rps=5, rate_limit_burst=0 WHERE id=?`, policyID); err != nil {
		t.Fatalf("update policy in tx: %v", err)
	}

	// When 事务内生成（ApplyConfigFromTx 同通道）
	generated := generateCaddyConfigFromStore(tx)

	// Then 读到未提交的限流策略
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_8080")
	route := findRouteByID(t, routes, "lb_tx_policy")
	rateLimit := findChainHandler(t, route, "rate_limit")
	if rateLimit == nil {
		t.Fatalf("事务内生成必须读到未提交的限流策略: %#v", route)
	}
	zones := mustMap(t, rateLimit["rate_limits"], "rate_limits")
	zone := mustMap(t, zones["lb_tx_policy"], "rate limit zone")
	assertEqual(t, zone["max_events"], 5)

	// 负向对照：回滚后经全局 db.DB 生成看不到该变更
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	after := generateCaddyConfigFromStore(database)
	if message, failed := after[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config after rollback: %s", message)
	}
	routesAfter := httpRoutesFromServer(t, after, "http_8080")
	routeAfter := findRouteByID(t, routesAfter, "lb_tx_policy")
	if findChainHandler(t, routeAfter, "rate_limit") != nil {
		t.Fatalf("回滚后经 db.DB 生成不应读到未提交策略: %#v", routeAfter)
	}
}

// Round 33 N-2: 存量 upstreams.enabled 为 NULL（schema 无 NOT NULL）时生成
// 不得 scan 报错整配置失败——IIF 归一化后按禁用处理，不炸也不误启用。
// Round 35 F-1: schema 已 NOT NULL，先回退为迁移前可空结构再写入 NULL 行。
func TestGenerateCaddyConfig_toleratesNullEnabledUpstream(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`DROP TABLE upstreams`); err != nil {
		t.Fatalf("drop upstreams: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN DEFAULT TRUE,
		protocol VARCHAR(10) DEFAULT 'http',
		max_connections INTEGER DEFAULT 0,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	)`); err != nil {
		t.Fatalf("recreate legacy upstreams: %v", err)
	}
	seedGenerationRule(t, database, "lb_null_upstream", false)
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_null_upstream','10.0.0.9',9009,NULL,'http')`); err != nil {
		t.Fatalf("seed null-enabled upstream: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then 生成成功，NULL 上游按禁用处理（仅保留启用的 127.0.0.1:9000）
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_8080")
	route := findRouteByID(t, routes, "lb_null_upstream")
	if route == nil {
		t.Fatalf("规则主路由缺失: %#v", routes)
	}
	proxy := reverseProxyHandler(t, route)
	assertUpstreamDials(t, proxy["upstreams"], []string{"127.0.0.1:9000"})
}

// Round 33 N-3: 动态 DNS 多上游错误哨兵化（ErrDynamicDNSUpstreamCount），
// 两处产出点（GenerateSingleRuleCaddyConfig 直返 / buildHTTPHandleChain %w
// 包装）均须被 errors.Is 命中，替代脆弱的字符串匹配。
func TestDynamicDNSMultiUpstream_wrapsErrDynamicDNSUpstreamCount(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.DynamicDNS = true
	rule.Upstreams = []UpstreamConfig{
		{Host: "a.example.test", Port: 80, Weight: 1, Enabled: true},
		{Host: "b.example.test", Port: 80, Weight: 1, Enabled: true},
	}

	// When/Then 直返产出点
	config := GenerateSingleRuleCaddyConfig(rule)
	genErr, hasErr := config["error"].(error)
	if !hasErr {
		t.Fatalf("error 键应为 error 类型，实际 %T", config["error"])
	}
	if !errors.Is(genErr, ErrDynamicDNSUpstreamCount) {
		t.Fatalf("直返错误必须可 errors.Is 命中哨兵，实际: %v", genErr)
	}

	// When/Then %w 包装产出点
	_, chainErr := buildHTTPHandleChain(rule, rule.Upstreams)
	if chainErr == nil {
		t.Fatal("buildHTTPHandleChain 应返回错误")
	}
	if !errors.Is(chainErr, ErrDynamicDNSUpstreamCount) {
		t.Fatalf("包装错误必须可 errors.Is 命中哨兵，实际: %v", chainErr)
	}
}
