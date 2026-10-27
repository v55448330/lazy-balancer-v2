package dnsprovider

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"lazy-balancer-v2/internal/dnsname"
)

// ResolveZone returns the DNS zone (registered domain) that a provider API call
// must target for the given input domain. The input domain itself is what the
// challenge FQDN is built from (e.g. _acme-challenge.www.example.com); the
// provider (DNSPod/Tencent) needs the registered zone (example.com) instead.
//
// It uses the Public Suffix List so multi-level TLDs (co.uk, com.cn) resolve
// correctly. For inputs the PSL cannot classify (unknown TLD, single label) it
// falls back to the last two labels, matching the issuance chain's historical
// behavior.
//
// Known limitation: a delegated sub-zone (account manages
// sub.example.com, not example.com) is invisible to the PSL and still resolves
// to example.com. Supporting delegated zones needs an explicit zone setting
// rather than guessing from the test input.
//
// DNS 名大小写不敏感：ResolveZone 必须先归一小写（dnsname.NormalizeName，与
// ownership/challenge_claims 同源）——PSL 查询与 provider 侧 Domain.List 的规范
// 形态都是小写，保留输入大小写会让混合大小写域名落进「last two labels」兜底
// （`API.Example.Co.UK` → `Co.UK`），并在 provider 侧精确比较时失配。
//
// IsPublicSuffix 判定 name 是否为公共后缀：单标签（TLD 本身、空名/根）或多标签
// 公共后缀（co.uk / com.cn / PSL 私有段如 s3.amazonaws.com）。
//
// PSL 单源：与 ResolveZone 同一判据（publicsuffix.EffectiveTLDPlusOne），消费方
// （ACME 权威 NS 上溯）不得自写第二份后缀知识——自写「至少两个标签」的粗判会
// 放过多标签公共后缀，把注册局服务器当成本域权威。
func IsPublicSuffix(name string) bool {
	trimmed := dnsname.NormalizeName(name)
	if trimmed == "" || !strings.Contains(trimmed, ".") {
		return true
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(trimmed)
	return err != nil
}

func ResolveZone(domain string) (string, error) {
	trimmed := dnsname.NormalizeName(domain)
	if trimmed == "" {
		return "", fmt.Errorf("dns zone: domain is empty")
	}
	if strings.HasPrefix(trimmed, ".") || strings.Contains(trimmed, "..") {
		return "", fmt.Errorf("dns zone: invalid domain %q", domain)
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(trimmed)
	if err == nil {
		return zone, nil
	}
	// Fallback to the last two labels (mirrors the pre-existing acme helper).
	parts := strings.Split(trimmed, ".")
	if len(parts) <= 2 {
		return trimmed, nil
	}
	return strings.Join(parts[len(parts)-2:], "."), nil
}
