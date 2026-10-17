package dnsprovider

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
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
// Known limitation (U06-F05): a delegated sub-zone (account manages
// sub.example.com, not example.com) is invisible to the PSL and still resolves
// to example.com. Supporting delegated zones needs an explicit zone setting
// rather than guessing from the test input.
func ResolveZone(domain string) (string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(domain), ".")
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
