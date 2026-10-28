package services

import (
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// health_check_host（HTTP-only）——保存族已清，传输族漏检会造成
// 主从/导入面同形性分叉。
func TestNormalizeRuleForTransport_clearsTCPHealthCheckHost(t *testing.T) {
	rule := models.LbRule{
		Protocol: "tcp", HealthCheckHost: "probe.example",
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
		TCPTryInterval: 250,
	}
	normalizeRuleForTransport(&rule)
	if rule.HealthCheckHost != "" {
		t.Fatalf("health_check_host=%q, want cleared for TCP transport", rule.HealthCheckHost)
	}
}

func TestNormalizeRuleForTransport_clearsTCPProxyRoutesAndStrategy(t *testing.T) {
	rule := models.LbRule{
		Protocol: "tcp", Strategy: "cookie", CustomRoutesEnabled: true, DynamicDNS: true,
		ProxyDialTimeout: 1, ProxyResponseHeaderTimeout: 2, ProxyReadTimeout: 3,
		ProxyWriteTimeout: 4, ProxyStreamTimeout: 5, ProxyFlushInterval: -1, ProxyStreamCloseDelay: 7,
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2, TCPTryInterval: 250,
	}
	normalizeRuleForTransport(&rule)
	proxyValues := [7]int{
		rule.ProxyDialTimeout, rule.ProxyResponseHeaderTimeout, rule.ProxyReadTimeout,
		rule.ProxyWriteTimeout, rule.ProxyStreamTimeout, rule.ProxyFlushInterval, rule.ProxyStreamCloseDelay,
	}
	if proxyValues != [7]int{} {
		t.Fatalf("TCP proxy timeouts=%v, want all zero", proxyValues)
	}
	if rule.CustomRoutesEnabled || rule.DynamicDNS || rule.Strategy != "weighted_round_robin" {
		t.Fatalf("TCP transport fields not normalized: custom_routes=%v dynamic_dns=%v strategy=%q",
			rule.CustomRoutesEnabled, rule.DynamicDNS, rule.Strategy)
	}

	// HTTP values are live configuration and must remain untouched.
	control := models.LbRule{
		Protocol: "http", Strategy: "cookie", CustomRoutesEnabled: true, DynamicDNS: true,
		ProxyDialTimeout: 1, ProxyResponseHeaderTimeout: 2, ProxyReadTimeout: 3,
		ProxyWriteTimeout: 4, ProxyStreamTimeout: 5, ProxyFlushInterval: -1, ProxyStreamCloseDelay: 7,
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2, TCPTryInterval: 250,
	}
	normalizeRuleForTransport(&control)
	if control.Strategy != "cookie" || !control.CustomRoutesEnabled || !control.DynamicDNS ||
		control.ProxyDialTimeout != 1 || control.ProxyFlushInterval != -1 || control.ProxyStreamCloseDelay != 7 {
		t.Fatalf("HTTP transport fields changed unexpectedly: %+v", control)
	}
}

func TestFormatDriftRoutes_capsDisplay(t *testing.T) {
	missing := make([]string, 25)
	for i := range missing {
		missing[i] = fmt.Sprintf("规则%02d", i)
	}
	extra := []string{"多余规则（lb_x）"}
	out := FormatDriftRoutes(missing, extra)
	if !strings.Contains(out, "缺失规则路由: ") || !strings.Contains(out, "多余规则路由: 多余规则（lb_x）") {
		t.Fatalf("out=%q, want 两段", out)
	}
	displayed := strings.Join(missing[:driftDisplayMaxEntries], "、")
	if !strings.Contains(out, "缺失规则路由: "+displayed+"…（共 25 条）") {
		t.Fatalf("out=%q, want 首条至第 %d 条后截断并标明共 25 条", out, driftDisplayMaxEntries)
	}
	if strings.Contains(out, missing[driftDisplayMaxEntries]) {
		t.Fatalf("out=%q, 第 %d 条之后不应展示", out, driftDisplayMaxEntries)
	}

	// 未超上限时必须完整保留且不带截断标记（回归形状）。
	if got, want := FormatDriftRoutes([]string{"规则甲", "规则乙"}, nil), "缺失规则路由: 规则甲、规则乙"; got != want {
		t.Fatalf("未超上限输出=%q, want %q", got, want)
	}
}
