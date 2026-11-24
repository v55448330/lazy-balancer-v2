package handlers

import (
	"errors"
	"testing"

	"lazy-balancer-v2/internal/i18n"
	"lazy-balancer-v2/internal/services"
)

const forwardAuthCredentialsUpstream = "http://user:pass@gw:7000"

const forwardAuthCredentialsEN = `Invalid authentication gateway address: the authentication gateway address must not contain username/password credentials (the address carries host:port only; configure gateway authentication on the gateway side): "http://user:pass@gw:7000"`

// 认证网关地址带凭据的写侧拒绝必须可判别且已键化：
//   - services 只返回哨兵错误（errors.Is 判别，不靠错误字符串）；
//   - handler 的 400 响应经 apimsg.ErrMsg 走错误模板翻译——英文请求得到
//     完整英文文案，而不是「英文前缀 + 中文内句」的半翻译。
func TestValidateRuleFeatures_forwardAuthCredentialsErrorIsKeyed(t *testing.T) {
	err := validateRuleFeatures(ruleFeatureInput{Protocol: "http", ForwardAuthEnabled: 1, ForwardAuthUpstream: forwardAuthCredentialsUpstream})
	if err == nil {
		t.Fatal("带凭据的认证网关地址必须被写侧拒绝")
	}
	if !errors.Is(err, services.ErrForwardAuthGatewayCredentials) {
		t.Fatalf("错误必须经 errors.Is 判别为 ErrForwardAuthGatewayCredentials，got %v", err)
	}

	const zh = `认证网关地址无效: 认证网关地址不能包含用户名/密码凭据（地址只承载 host:port；网关鉴权请在网关侧配置）: "http://user:pass@gw:7000"`
	if got := i18n.TrErr(err.Error(), i18n.ZH); got != zh {
		t.Fatalf("zh 文案漂移:\n got %q\nwant %q", got, zh)
	}
	if got := i18n.TrErr(err.Error(), i18n.EN); got != forwardAuthCredentialsEN {
		t.Fatalf("en 文案未键化（错误模板未登记或被更短模板抢先命中）:\n got %q\nwant %q", got, forwardAuthCredentialsEN)
	}
}
