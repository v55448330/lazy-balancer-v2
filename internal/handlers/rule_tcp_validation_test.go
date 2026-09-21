package handlers

// U3-4(第 45 轮审计修复)：TCP 三字段（tcp_health_check_port/tcp_try_duration/
// tcp_try_interval）此前无负值校验，渲染侧静默钳制（caddy.go 3503-3522）——
// 保存前拒绝显式负值。代理超时族的 -1 哨兵（proxy_flush_interval=-1=立即刷新）
// 仅属 http 侧，TCP 三字段无哨兵语义，负值一律拒。

import (
	"testing"
)

func TestValidateRuleFeatures_rejectsNegativeTcpFields(t *testing.T) {
	base := func() ruleFeatureInput {
		return ruleFeatureInput{
			Protocol:           "tcp",
			Strategy:           "weighted_round_robin",
			ListenPort:         19099,
			TCPTryInterval:     250,
			TCPTryDuration:     3,
			TCPHealthCheckPort: 9123,
		}
	}

	// 目标形状：三字段各自 -1 → 拒绝
	negativeCases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"tcp_health_check_port", func(i *ruleFeatureInput) { i.TCPHealthCheckPort = -1 }},
		{"tcp_try_duration", func(i *ruleFeatureInput) { i.TCPTryDuration = -1 }},
		{"tcp_try_interval", func(i *ruleFeatureInput) { i.TCPTryInterval = -1 }},
	}
	for _, tc := range negativeCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base()
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err == nil {
				t.Fatalf("negative %s must be rejected, got nil error", tc.name)
			}
		})
	}

	// 回归形状：零值（跟随默认）与正值放行
	validShapes := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"all zero", func(i *ruleFeatureInput) { i.TCPHealthCheckPort, i.TCPTryDuration, i.TCPTryInterval = 0, 0, 0 }},
		{"all positive", func(i *ruleFeatureInput) {}},
	}
	for _, tc := range validShapes {
		t.Run(tc.name, func(t *testing.T) {
			input := base()
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err != nil {
				t.Fatalf("tcp shape %s must pass, got %v", tc.name, err)
			}
		})
	}

	// 哨兵不变：http 侧 proxy_flush_interval=-1 仍放行（立即刷新哨兵）
	httpSentinel := ruleFeatureInput{Protocol: "http", Strategy: "weighted_round_robin", ListenPort: 8080, ProxyFlushInterval: -1}
	if err := validateRuleFeatures(httpSentinel); err != nil {
		t.Fatalf("http flush_interval=-1 sentinel must still pass, got %v", err)
	}
}
