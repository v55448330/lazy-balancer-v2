package handlers

import (
	"errors"
	"testing"

	"lazy-balancer-v2/internal/services"
)

const forwardAuthCredentialsUpstream = "http://user:pass@gw:7000"

// 认证网关地址带凭据的写侧拒绝必须可判别：
//   - services 只返回哨兵错误（errors.Is 判别，不靠错误字符串）；
//   - 错误文本是中文母本（后端不翻译）：英文界面由前端按 message_key 用自己的
//     词条渲染（2026-11-25 裁定：后端只下发稳定键 + 参数）。
func TestValidateRuleFeatures_forwardAuthCredentialsErrorIsKeyed(t *testing.T) {
	err := validateRuleFeatures(ruleFeatureInput{Protocol: "http", ForwardAuthEnabled: 1, ForwardAuthUpstream: forwardAuthCredentialsUpstream})
	if err == nil {
		t.Fatal("带凭据的认证网关地址必须被写侧拒绝")
	}
	if !errors.Is(err, services.ErrForwardAuthGatewayCredentials) {
		t.Fatalf("错误必须经 errors.Is 判别为 ErrForwardAuthGatewayCredentials，got %v", err)
	}
	const zh = `认证网关地址无效: 认证网关地址不能包含用户名/密码凭据（地址只承载 host:port；网关鉴权请在网关侧配置）: "http://user:pass@gw:7000"`
	if got := err.Error(); got != zh {
		t.Fatalf("中文母本文案漂移:\n got %q\nwant %q", got, zh)
	}
}
