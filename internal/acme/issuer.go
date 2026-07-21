package acme

import (
	"context"
	"fmt"
	"net"
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
		authURL   string
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
			authURL:   authURL,
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
	for _, ci := range localChallenges {
		log("validating", fmt.Sprintf("等待 CA 验证 %s", ci.domain))
		if err := i.waitForValidation(ctx, ci.authURL, ci.chal.URI); err != nil {
			return "", "", challenges, fmt.Errorf("wait authorization %s: %w", ci.authURL, err)
		}
	}
	log("validated", "所有域名验证通过")

	// Step 5.5: Wait for the order to become ready before finalizing.
	log("waiting_order_ready", "等待订单就绪")
	readyCtx, readyCancel := context.WithTimeout(ctx, 3*time.Minute)
	readyOrder, err := i.Client.WaitOrder(readyCtx, order.URI)
	readyCancel()
	if err != nil {
		return "", "", challenges, fmt.Errorf("wait order ready: %w", err)
	}
	if readyOrder.Status != "ready" && readyOrder.Status != "valid" {
		errMsg := ""
		if readyOrder.Error != nil {
			errMsg = fmt.Sprintf(" (%d: %s)", readyOrder.Error.StatusCode, readyOrder.Error.Detail)
		}
		return "", "", challenges, fmt.Errorf("order status after ready wait: %s%s", readyOrder.Status, errMsg)
	}
	log("order_ready", fmt.Sprintf("订单已就绪，状态: %s", readyOrder.Status))

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
	log("finalized", fmt.Sprintf("订单已最终化，证书 URL: %s", finalizedOrder.CertURL))

	// Step 6.5: Wait for the order to become valid after finalization.
	log("waiting_order_valid", "等待订单最终完成")
	validCtx, validCancel := context.WithTimeout(ctx, 5*time.Minute)
	validOrder, err := i.Client.WaitOrder(validCtx, order.URI)
	validCancel()
	if err != nil {
		return "", "", challenges, fmt.Errorf("wait order valid: %w", err)
	}
	if validOrder.Status != "valid" {
		errMsg := ""
		if validOrder.Error != nil {
			errMsg = fmt.Sprintf(" (%d: %s)", validOrder.Error.StatusCode, validOrder.Error.Detail)
		}
		return "", "", challenges, fmt.Errorf("order status after finalize: %s%s", validOrder.Status, errMsg)
	}
	if validOrder.CertURL == "" {
		validOrder.CertURL = finalizedOrder.CertURL
	}
	log("order_valid", "订单验证完成")

	// Step 7: Download certificate
	log("downloading", "下载证书")
	certDER, err := i.Client.FetchCert(ctx, validOrder.CertURL)
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

// waitForValidation polls both the challenge URL and the authorization URL
// until the authorization reaches a final state. Polling the challenge as
// well is required for ZeroSSL compatibility: its authorization status can
// lag far behind the challenge status, and x/crypto's WaitAuthorization only
// watches the authorization, which then appears to hang forever. Every status
// transition is logged so a stuck CA is diagnosable from the job log.
func (i *Issuer) waitForValidation(ctx context.Context, authURL, chalURL string) error {
	log := func(msg string) {
		if i.Logger != nil {
			i.Logger.Log("validating", msg)
		}
	}

	// ZeroSSL validation can legitimately take several minutes, so allow a
	// generous budget instead of failing fast into an order-recreating retry.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastChalStatus, lastAuthStatus string
	var lastChal *acme.Challenge
	for {
		if chal, err := i.Client.GetChallenge(ctx, chalURL); err != nil {
			log(fmt.Sprintf("查询 challenge 状态失败: %v", err))
		} else {
			lastChal = chal
			if chal.Status != lastChalStatus {
				log(fmt.Sprintf("challenge 状态: %s", chal.Status))
				lastChalStatus = chal.Status
			}
		}

		if auth, err := i.Client.GetAuthorization(ctx, authURL); err != nil {
			log(fmt.Sprintf("查询授权状态失败: %v", err))
		} else {
			if auth.Status != lastAuthStatus {
				log(fmt.Sprintf("授权状态: %s", auth.Status))
				lastAuthStatus = auth.Status
			}
			switch auth.Status {
			case "valid":
				return nil
			case "invalid", "deactivated", "expired", "revoked":
				if lastChal != nil && lastChal.Error != nil {
					return fmt.Errorf("授权状态 %s: %v", auth.Status, lastChal.Error)
				}
				return fmt.Errorf("授权状态: %s", auth.Status)
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("等待 CA 验证超时 (challenge: %s, 授权: %s)", lastChalStatus, lastAuthStatus)
		case <-ticker.C:
		}
	}
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
		"223.5.5.5:53",    // Alibaba AliDNS
		"119.29.29.29:53", // Tencent DNSPod
		"8.8.8.8:53",      // Google Public DNS
		"1.1.1.1:53",      // Cloudflare
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

	// The CA validates against authoritative name servers, so probe them
	// directly: it is the strongest signal and usually much faster than
	// waiting for recursive resolvers' caches to expire.
	authServers := resolveAuthoritativeNS(ctx, fqdn, resolvers[0])
	if len(authServers) > 0 {
		log("权威 DNS 服务器: %s", strings.Join(authServers, ", "))
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastFound []string
	var lastResolver string

	for {
		// Authoritative name servers first: every reachable server must have
		// the record before we let the CA validate. Servers that fail to
		// respond are dropped from the list so a network-blocked server does
		// not consume the propagation budget on every tick.
		authReady := len(authServers) > 0
		var alive []string
		for _, server := range authServers {
			hit, found, err := probeTXT(ctx, server, fqdn, expected, false)
			switch {
			case err != nil:
				authReady = false
				log("权威 DNS 查询失败 %s @ %s: %v", fqdn, server, err)
			case hit:
				alive = append(alive, server)
				log("权威 DNS 已命中 %s @ %s, 值: %s", fqdn, server, expected)
			default:
				authReady = false
				alive = append(alive, server)
				if len(found) > 0 {
					lastFound = found
					lastResolver = server + " (auth)"
					log("权威 DNS 未命中 %s @ %s, 期望: %s, 实际: %s", fqdn, server, expected, strings.Join(found, "; "))
				} else {
					log("权威 DNS 无 TXT 记录 %s @ %s", fqdn, server)
				}
			}
		}
		authServers = alive
		if authReady {
			return nil
		}

		// Fallback: public recursive resolvers (slower due to caching).
		for _, resolver := range resolvers {
			hit, found, err := probeTXT(ctx, resolver, fqdn, expected, true)
			if err != nil {
				log("查询失败 %s @ %s: %v", fqdn, resolver, err)
				continue
			}
			if hit {
				log("DNS 已命中 %s @ %s, 值: %s", fqdn, resolver, expected)
				return nil
			}
			if len(found) > 0 {
				lastFound = found
				lastResolver = resolver
				log("DNS 未命中 %s @ %s, 期望: %s, 实际: %s", fqdn, resolver, expected, strings.Join(found, "; "))
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

// probeTXT queries a single DNS server for the TXT records of fqdn over UDP,
// falling back to TCP. It reports whether the expected value is present along
// with all values found.
func probeTXT(ctx context.Context, server, fqdn, expected string, recursion bool) (hit bool, found []string, err error) {
	var lastErr error
	for _, network := range []string{"udp", "tcp"} {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeTXT)
		m.RecursionDesired = recursion

		c := &dns.Client{Net: network}
		// Short per-exchange timeout so a blocked server fails over quickly
		// instead of consuming the whole propagation budget.
		exchangeCtx, exCancel := context.WithTimeout(ctx, 8*time.Second)
		r, _, err := c.ExchangeContext(exchangeCtx, m, server)
		exCancel()
		if err != nil || r == nil {
			lastErr = err
			continue
		}

		for _, ans := range r.Answer {
			if t, ok := ans.(*dns.TXT); ok {
				got := strings.TrimSpace(strings.Join(t.Txt, ""))
				if got == "" {
					continue
				}
				found = append(found, got)
				if got == expected {
					return true, found, nil
				}
			}
		}
		return false, found, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no response")
	}
	return false, nil, lastErr
}

// resolveAuthoritativeNS finds the authoritative name servers of fqdn's zone
// by walking up the domain labels and querying NS records through a public
// recursive resolver, then resolves the servers' addresses. Best-effort:
// returns nil when the zone cannot be determined.
func resolveAuthoritativeNS(ctx context.Context, fqdn, bootstrap string) []string {
	query := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		m.RecursionDesired = true
		c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, bootstrap)
		if err != nil {
			return nil
		}
		return r
	}

	// Walk up the labels until NS records are found, so delegated subdomains
	// resolve to their own zone's servers.
	name := fqdn
	var nsNames []string
	for {
		labels := strings.Split(strings.TrimSuffix(name, "."), ".")
		if len(labels) <= 1 {
			return nil
		}
		name = strings.Join(labels[1:], ".") + "."
		r := query(name, dns.TypeNS)
		if r == nil {
			return nil
		}
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}
		if len(nsNames) > 0 {
			break
		}
	}

	// Resolve addresses of each name server.
	seen := make(map[string]bool)
	var servers []string
	for _, ns := range nsNames {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r := query(ns, qtype)
			if r == nil {
				continue
			}
			for _, ans := range r.Answer {
				var ip string
				switch rr := ans.(type) {
				case *dns.A:
					ip = rr.A.String()
				case *dns.AAAA:
					ip = rr.AAAA.String()
				}
				if ip == "" {
					continue
				}
				server := net.JoinHostPort(ip, "53")
				if !seen[server] {
					seen[server] = true
					servers = append(servers, server)
				}
			}
		}
	}
	return servers
}
