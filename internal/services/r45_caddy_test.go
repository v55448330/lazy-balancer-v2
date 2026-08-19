package services

import (
	"strings"
	"testing"
)

// R45 F-5: GenerateSingleRuleCaddyConfig 入口协议白名单与 GenerateRouteObject
// 对齐——非法协议（如混合版本运行时写入的 https 行）硬错误而非静默按 TCP 渲染。
func TestGenerateSingleRuleCaddyConfig_unsupportedProtocol_returnsError(t *testing.T) {
	// Given 一条 protocol=https 的规则（正常 http/tcp 行不在此列）
	rule := SingleRuleConfig{
		CaddyID:    "lb_https",
		Protocol:   "https",
		ListenPort: 8443,
		Upstreams:  []UpstreamConfig{{Host: "10.0.0.1", Port: 8080, Enabled: true}},
	}

	// When
	config := GenerateSingleRuleCaddyConfig(rule)

	// Then 返回硬错误而非静默渲染 TCP
	genErr, isErr := config["error"].(error)
	if !isErr {
		t.Fatalf("https 协议应返回 error 键，实际 %T", config["error"])
	}
	if !strings.Contains(genErr.Error(), "unsupported protocol: https") {
		t.Fatalf("err=%q, want unsupported protocol: https", genErr)
	}
}
