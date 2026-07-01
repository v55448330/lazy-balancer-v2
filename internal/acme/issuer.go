package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

// Issuer orchestrates the full ACME DNS-01 issuance flow.
type Issuer struct {
	Client   *Client
	Provider dnsprovider.Provider
	Logger   Logger
}

// Issue obtains a certificate for the given domains via DNS-01 challenge.
// It logs each stage through the Logger and cleans up DNS records afterwards.
func (i *Issuer) Issue(ctx context.Context, domains []string) (certPEM, keyPEM string, err error) {
	if len(domains) == 0 {
		return "", "", fmt.Errorf("no domains requested")
	}

	log := func(stage, msg string) {
		if i.Logger != nil {
			i.Logger.Log(stage, msg)
		}
	}

	// Step 1: Register account
	log("creating_account", "注册 ACME 账户")
	if err := i.Client.RegisterAccount(ctx); err != nil {
		return "", "", fmt.Errorf("register account: %w", err)
	}

	// Step 2: Create order
	log("creating_order", fmt.Sprintf("为域名 %v 创建订单", domains))
	order, err := i.Client.AuthorizeOrder(ctx, domains)
	if err != nil {
		return "", "", fmt.Errorf("authorize order: %w", err)
	}
	log("order_created", fmt.Sprintf("订单已创建，共 %d 个授权", len(order.AuthzURLs)))

	// Step 3: Present DNS-01 challenges for all authorizations
	type challengeInfo struct {
		domain    string
		tokenFQDN string
		chal      *acme.Challenge
	}
	var challenges []challengeInfo

	for _, authURL := range order.AuthzURLs {
		auth, err := i.Client.GetAuthorization(ctx, authURL)
		if err != nil {
			return "", "", fmt.Errorf("fetch authorization %s: %w", authURL, err)
		}

		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return "", "", fmt.Errorf("no dns-01 challenge for %s", auth.Identifier.Value)
		}

		domain := auth.Identifier.Value
		tokenFQDN := "_acme-challenge." + domain + "."
		keyAuth, err := i.Client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return "", "", fmt.Errorf("dns01 record: %w", err)
		}

		log("presenting_dns", fmt.Sprintf("写入 TXT 记录 %s", tokenFQDN))
		if err := i.Provider.Present(ctx, zoneFromDomain(domain), tokenFQDN, keyAuth, 600); err != nil {
			return "", "", fmt.Errorf("present dns for %s: %w", domain, err)
		}

		challenges = append(challenges, challengeInfo{
			domain:    domain,
			tokenFQDN: tokenFQDN,
			chal:      chal,
		})
	}

	// Step 4: Wait for DNS propagation and accept challenges
	for _, ci := range challenges {
		log("waiting_propagation", fmt.Sprintf("等待 DNS 传播 %s", ci.tokenFQDN))
		keyAuth, err := i.Client.DNS01ChallengeRecord(ci.chal.Token)
		if err != nil {
			return "", "", err
		}
		if err := waitForDNS(ctx, ci.tokenFQDN, keyAuth, 2*time.Minute); err != nil {
			return "", "", fmt.Errorf("dns propagation %s: %w", ci.tokenFQDN, err)
		}
		log("dns_propagated", fmt.Sprintf("DNS 已传播 %s", ci.tokenFQDN))

		log("accepting_challenge", fmt.Sprintf("提交验证 %s", ci.domain))
		if _, err := i.Client.AcceptChallenge(ctx, ci.chal); err != nil {
			return "", "", fmt.Errorf("accept challenge %s: %w", ci.domain, err)
		}
	}

	// Step 5: Wait for all authorizations to be valid
	for _, authURL := range order.AuthzURLs {
		log("validating", fmt.Sprintf("等待 CA 验证 %s", authURL))
		auth, err := i.Client.WaitAuthorization(ctx, authURL)
		if err != nil {
			return "", "", fmt.Errorf("wait authorization %s: %w", authURL, err)
		}
		if auth.Status != "valid" {
			return "", "", fmt.Errorf("authorization %s status: %s", authURL, auth.Status)
		}
	}
	log("validated", "所有域名验证通过")

	// Step 6: Finalize order with CSR
	log("finalizing", "生成 CSR 并提交订单")
	csrDER, key, err := CreateCSR(domains)
	if err != nil {
		return "", "", fmt.Errorf("create csr: %w", err)
	}
 finalizedOrder, err := i.Client.CreateCertRequest(ctx, order.FinalizeURL, csrDER)
	if err != nil {
		return "", "", fmt.Errorf("finalize order: %w", err)
	}
	if finalizedOrder.CertURL == "" {
		return "", "", fmt.Errorf("finalize returned empty cert url")
	}
	log("finalized", fmt.Sprintf("订单已完成，证书 URL: %s", finalizedOrder.CertURL))

	// Step 7: Download certificate
	log("downloading", "下载证书")
	certDER, err := i.Client.FetchCert(ctx, finalizedOrder.CertURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch cert: %w", err)
	}
	log("downloaded", "证书下载完成")

	certPEM = EncodeCertPEM(certDER)
	keyPEM = EncodeKeyPEM(key)
	return certPEM, keyPEM, nil
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

// zoneFromDomain extracts the zone (root domain) from a domain name.
// This is a simple heuristic; for production use a proper zone detector.
func zoneFromDomain(domain string) string {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// waitForDNS polls DNS resolvers until the expected TXT record appears.
func waitForDNS(ctx context.Context, fqdn, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53"}

	for time.Now().Before(deadline) {
		for _, resolver := range resolvers {
			m := new(dns.Msg)
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = true

			c := new(dns.Client)
			c.Net = "udp"
			r, _, err := c.Exchange(m, resolver)
			if err != nil || r == nil {
				continue
			}
			for _, ans := range r.Answer {
				if t, ok := ans.(*dns.TXT); ok {
					got := strings.Join(t.Txt, "")
					if got == expected {
						return nil
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("timed out waiting for DNS propagation of %s", fqdn)
}