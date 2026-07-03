package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/publicsuffix"
)

// Issuer orchestrates the full ACME DNS-01 issuance flow.
type Issuer struct {
	Client   *Client
	Provider dnsprovider.Provider
	Logger   Logger
}

// Issue obtains a certificate for the given domains via DNS-01 challenge.
// It logs each stage through the Logger and cleans up DNS records afterwards.
func (i *Issuer) Issue(ctx context.Context, domains []string) (certPEM, keyPEM string, challenges []ChallengeInfo, err error) {
	if len(domains) == 0 {
		return "", "", nil, fmt.Errorf("no domains requested")
	}

	log := func(stage, msg string) {
		if i.Logger != nil {
			i.Logger.Log(stage, msg)
		}
	}

	// Step 1: Register account
	log("creating_account", "注册 ACME 账户")
	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()
	if err := i.Client.RegisterAccount(regCtx); err != nil {
		return "", "", nil, fmt.Errorf("register account: %w", err)
	}

	// Step 2: Create order
	log("creating_order", fmt.Sprintf("为域名 %v 创建订单", domains))
	order, err := i.Client.AuthorizeOrder(ctx, domains)
	if err != nil {
		return "", "", nil, fmt.Errorf("authorize order: %w", err)
	}
	log("order_created", fmt.Sprintf("订单已创建，共 %d 个授权", len(order.AuthzURLs)))

	// Step 3: Clean up any stale DNS-01 TXT records first, then present new challenges.
	type challengeInfo struct {
		domain    string
		tokenFQDN string
		chal      *acme.Challenge
	}
	var localChallenges []challengeInfo

	for _, authURL := range order.AuthzURLs {
		auth, err := i.Client.GetAuthorization(ctx, authURL)
		if err != nil {
			return "", "", nil, fmt.Errorf("fetch authorization %s: %w", authURL, err)
		}

		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return "", "", nil, fmt.Errorf("no dns-01 challenge for %s", auth.Identifier.Value)
		}

		domain := auth.Identifier.Value
		tokenFQDN := "_acme-challenge." + domain + "."
		keyAuth, err := i.Client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return "", "", nil, fmt.Errorf("dns01 record: %w", err)
		}

		zone := zoneFromDomain(domain)
		log("cleanup_dns", fmt.Sprintf("清理可能残留的 TXT 记录 %s", tokenFQDN))
		if err := i.Provider.CleanUp(ctx, zone, tokenFQDN); err != nil {
			log("cleanup_warning", fmt.Sprintf("清理旧 TXT 记录失败 %s: %v", tokenFQDN, err))
		}

		log("presenting_dns", fmt.Sprintf("写入 TXT 记录 %s, 值: %s", tokenFQDN, keyAuth))
		if err := i.Provider.Present(ctx, zone, tokenFQDN, keyAuth, 600); err != nil {
			return "", "", nil, fmt.Errorf("present dns for %s: %w", domain, err)
		}

		localChallenges = append(localChallenges, challengeInfo{
			domain:    domain,
			tokenFQDN: tokenFQDN,
			chal:      chal,
		})
		challenges = append(challenges, ChallengeInfo{
			Domain:    domain,
			TokenFQDN: tokenFQDN,
		})
	}

	// Ensure DNS records are always cleaned up before returning.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		log("cleanup_dns", "清理 ACME DNS TXT 记录")
		i.Cleanup(cleanupCtx, challenges)
	}()

	// Step 4: Wait for DNS propagation and accept challenges
	for _, ci := range localChallenges {
		keyAuth, err := i.Client.DNS01ChallengeRecord(ci.chal.Token)
		if err != nil {
			return "", "", challenges, err
		}
		log("waiting_propagation", fmt.Sprintf("等待 DNS 传播 %s, 期望值: %s", ci.tokenFQDN, keyAuth))
		if err := i.waitForDNS(ctx, ci.tokenFQDN, keyAuth, 5*time.Minute); err != nil {
			return "", "", challenges, fmt.Errorf("dns propagation %s: %w", ci.tokenFQDN, err)
		}
		log("dns_propagated", fmt.Sprintf("DNS 已传播 %s", ci.tokenFQDN))

		log("accepting_challenge", fmt.Sprintf("提交验证 %s", ci.domain))
		if _, err := i.Client.AcceptChallenge(ctx, ci.chal); err != nil {
			return "", "", challenges, fmt.Errorf("accept challenge %s: %w", ci.domain, err)
		}
	}

	// Step 5: Wait for all authorizations to be valid
	for _, authURL := range order.AuthzURLs {
		log("validating", fmt.Sprintf("等待 CA 验证 %s", authURL))
		authCtx, authCancel := context.WithTimeout(ctx, 10*time.Minute)
		auth, err := i.Client.WaitAuthorization(authCtx, authURL)
		authCancel()
		if err != nil {
			return "", "", challenges, fmt.Errorf("wait authorization %s: %w", authURL, err)
		}
		if auth.Status != "valid" {
			return "", "", challenges, fmt.Errorf("authorization %s status: %s", authURL, auth.Status)
		}
	}
	log("validated", "所有域名验证通过")

	// Step 6: Finalize order with CSR
	log("finalizing", "生成 CSR 并提交订单")
	csrDER, key, err := CreateCSR(domains)
	if err != nil {
		return "", "", challenges, fmt.Errorf("create csr: %w", err)
	}
	finalizedOrder, err := i.Client.CreateCertRequest(ctx, order.FinalizeURL, csrDER)
	if err != nil {
		return "", "", challenges, fmt.Errorf("finalize order: %w", err)
	}
	if finalizedOrder.CertURL == "" {
		return "", "", challenges, fmt.Errorf("finalize returned empty cert url")
	}
	log("finalized", fmt.Sprintf("订单已完成，证书 URL: %s", finalizedOrder.CertURL))

	// Step 7: Download certificate
	log("downloading", "下载证书")
	certDER, err := i.Client.FetchCert(ctx, finalizedOrder.CertURL)
	if err != nil {
		return "", "", challenges, fmt.Errorf("fetch cert: %w", err)
	}
	log("downloaded", "证书下载完成")

	certPEM = EncodeCertPEM(certDER)
	keyPEM = EncodeKeyPEM(key)
	return certPEM, keyPEM, challenges, nil
}

// Cleanup removes DNS TXT records for all previously presented challenges.
func (i *Issuer) Cleanup(ctx context.Context, challenges []ChallengeInfo) {
	for _, ci := range challenges {
		if err := i.Provider.CleanUp(ctx, zoneFromDomain(ci.Domain), ci.TokenFQDN); err != nil {
			if i.Logger != nil {
				i.Logger.Log("cleanup_warning", fmt.Sprintf("清理 DNS 记录失败 %s: %v", ci.TokenFQDN, err))
			}
		}
	}
}

// ChallengeInfo holds the info needed to clean up a DNS record.
type ChallengeInfo struct {
	Domain    string
	TokenFQDN string
}

// zoneFromDomain extracts the DNS zone (registered domain) from a domain name.
// It uses the Public Suffix List so multi-level TLDs (e.g. co.uk, com.cn)
// are handled correctly.
func zoneFromDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return domain
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback to the last two labels.
		parts := strings.Split(domain, ".")
		if len(parts) <= 2 {
			return domain
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return zone
}

// waitForDNS polls DNS resolvers until the expected TXT record appears.
//
// It queries multiple resolvers (including ones reachable from mainland China
// such as AliDNS and DNSPod, plus global resolvers Google and Cloudflare) over
// both UDP and TCP. TCP is tried as a fallback because some networks block or
// poison UDP traffic to public resolvers.
//
// All progress is reported through the Issuer's Logger so that stuck DNS
// validation can be diagnosed: every miss logs the expected value and the
// values actually returned by the resolver.
func (i *Issuer) waitForDNS(ctx context.Context, fqdn, expected string, timeout time.Duration) error {
	// Order matters: China-friendly resolvers first, then global ones.
	resolvers := []string{
		"223.5.5.5:53",     // Alibaba AliDNS
		"119.29.29.29:53",  // Tencent DNSPod
		"8.8.8.8:53",       // Google Public DNS
		"1.1.1.1:53",       // Cloudflare
	}

	log := func(format string, args ...any) {
		if i.Logger != nil {
			i.Logger.Log("waiting_propagation", fmt.Sprintf(format, args...))
		}
	}

	// Bound the whole propagation wait by timeout, independent of the parent
	// context deadline.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastFound []string
	var lastResolver string

	for {
		for _, resolver := range resolvers {
			for _, net := range []string{"udp", "tcp"} {
				m := new(dns.Msg)
				m.SetQuestion(fqdn, dns.TypeTXT)
				m.RecursionDesired = true

				c := new(dns.Client)
				c.Net = net
				// Short per-exchange timeout so a blocked resolver fails over
				// quickly instead of consuming the whole propagation budget.
				exchangeCtx, exCancel := context.WithTimeout(ctx, 8*time.Second)
				r, _, err := c.ExchangeContext(exchangeCtx, m, resolver)
				exCancel()
				if err != nil || r == nil {
					log("查询失败 %s @ %s/%s: %v", fqdn, resolver, net, err)
					continue
				}

				var found []string
				for _, ans := range r.Answer {
					if t, ok := ans.(*dns.TXT); ok {
						got := strings.TrimSpace(strings.Join(t.Txt, ""))
						if got == "" {
							continue
						}
						found = append(found, got)
						if got == expected {
							log("DNS 已命中 %s @ %s/%s, 值: %s", fqdn, resolver, net, got)
							return nil
						}
					}
				}
				if len(found) > 0 {
					lastFound = found
					lastResolver = resolver + "/" + net
					log("DNS 未命中 %s @ %s/%s, 期望: %s, 实际: %s", fqdn, resolver, net, expected, strings.Join(found, "; "))
				}
			}
		}

		select {
		case <-ctx.Done():
			if len(lastFound) > 0 {
				return fmt.Errorf("dns propagation timeout for %s: expected %s, last found %s (via %s)",
					fqdn, expected, strings.Join(lastFound, "; "), lastResolver)
			}
			return fmt.Errorf("dns propagation timeout for %s: expected %s, no TXT record found from any resolver",
				fqdn, expected)
		case <-ticker.C:
		}
	}
}