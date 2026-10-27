package services

import "testing"

func TestGenerateSingleRuleCaddyConfig_ruleProxyTimeoutsOverrideGlobals(t *testing.T) {
	// Given 每个规则级超时都与全局值不同；flush 使用 -1 立即刷新哨兵。
	rule := baseHTTPRule()
	rule.ProxyDialTimeout = 11
	rule.ProxyResponseHeaderTimeout = 12
	rule.ProxyReadTimeout = 13
	rule.ProxyWriteTimeout = 14
	rule.ProxyStreamTimeout = 15
	rule.ProxyFlushInterval = -1
	rule.ProxyStreamCloseDelay = 16
	rule.GlobalProxyDialTimeout = 101
	rule.GlobalProxyResponseHeaderTimeout = 102
	rule.GlobalProxyReadTimeout = 103
	rule.GlobalProxyWriteTimeout = 104
	rule.GlobalProxyStreamTimeout = 105
	rule.GlobalProxyFlushInterval = 8
	rule.GlobalProxyStreamCloseDelay = 106

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	proxy := reverseProxyHandler(t, routes[len(routes)-1])

	// Then 逐节点读取规则值，不能用整份配置的子串代替节点归属断言。
	assertEqual(t, proxy["stream_timeout"], "15s")
	assertEqual(t, proxy["flush_interval"], "-1s")
	assertEqual(t, proxy["stream_close_delay"], "16s")
	transport := mustMap(t, proxy["transport"], "transport")
	assertEqual(t, transport["dial_timeout"], "11s")
	assertEqual(t, transport["response_header_timeout"], "12s")
	assertEqual(t, transport["read_timeout"], "13s")
	assertEqual(t, transport["write_timeout"], "14s")
}

func TestGenerateSingleRuleCaddyConfig_zeroProxyTimeoutsOmitted(t *testing.T) {
	// Given 规则级与全局超时均为零值，明文上游不需要 transport。
	rule := baseHTTPRule()

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))
	proxy := reverseProxyHandler(t, routes[len(routes)-1])

	// Then proxy 键及整个空 transport 都省略。
	for _, key := range []string{"stream_timeout", "flush_interval", "stream_close_delay"} {
		if value, exists := proxy[key]; exists {
			t.Errorf("proxy[%q]=%v, want omitted", key, value)
		}
	}
	if value, exists := proxy["transport"]; exists {
		t.Fatalf("proxy transport=%v, want omitted", value)
	}
}
