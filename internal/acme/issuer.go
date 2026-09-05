package acme

import (
	"context"
	"errors"
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
	Client              *Client
	Provider            dnsprovider.Provider
	Logger              Logger
	RequireRecursiveDNS bool
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
	log("creating_account", "确认 ACME 账户（新账户注册，已注册则复用）")
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
	var presentedChallenges []ChallengeInfo
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		log("cleanup_dns", "清理 ACME DNS TXT 记录")
		i.Cleanup(cleanupCtx, presentedChallenges)
	}()

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
		// 按本次挑战值定向清理：同名记录中属于并发签发（不同值）的记录
		// 必须保留，只清掉本值残留与陈旧遗留
		if err := dnsprovider.CleanUpChallenge(ctx, i.Provider, zone, tokenFQDN, keyAuth); err != nil {
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
		challenge := ChallengeInfo{
			Domain:    domain,
			TokenFQDN: tokenFQDN,
			Value:     keyAuth,
		}
		challenges = append(challenges, challenge)
		presentedChallenges = append(presentedChallenges, challenge)
	}

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

		if i.RequireRecursiveDNS {
			if !i.checkRecursiveDNS(ctx, ci.tokenFQDN, keyAuth) {
				return "", "", challenges, fmt.Errorf("recursive DNS propagation failed for %s: record not visible on public resolvers", ci.tokenFQDN)
			}
			log("dns_propagated", fmt.Sprintf("递归 DNS 已传播 %s", ci.tokenFQDN))
		}

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
	finalizedOrder, err := i.finalizeOrder(ctx, order.FinalizeURL, csrDER)
	if err != nil {
		return "", "", challenges, err
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

// finalizeTimeout 为 finalize 提交（POST CSR + 轮询出证）设定的独立预算，
// 对齐邻近的 ready 3min / valid 5min 分段预算——卡死的 CA 以 finalize 阶段
// 错误暴露，而不是耗尽整个任务执行预算后报泛化超时。
var finalizeTimeout = 10 * time.Minute

// finalizeOrder submits the CSR with its own execution budget so a stalled CA
// is attributable to the finalize stage.
func (i *Issuer) finalizeOrder(ctx context.Context, finalizeURL string, csr []byte) (*acme.Order, error) {
	finalizeCtx, finalizeCancel := context.WithTimeout(ctx, finalizeTimeout)
	defer finalizeCancel()
	order, err := i.Client.CreateCertRequest(finalizeCtx, finalizeURL, csr)
	if err != nil {
		return nil, fmt.Errorf("finalize order: %w", err)
	}
	return order, nil
}

// Cleanup removes DNS TXT records for all previously presented challenges.
func (i *Issuer) Cleanup(ctx context.Context, challenges []ChallengeInfo) {
	for _, ci := range challenges {
		if err := dnsprovider.CleanUpChallenge(ctx, i.Provider, zoneFromDomain(ci.Domain), ci.TokenFQDN, ci.Value); err != nil {
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
	// Value is the DNS-01 TXT value (key authorization digest) this record
	// was presented with; cleanup removes only records of that value so
	// concurrent issuances for the same domain cannot delete each other.
	Value string
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
	var tickerIterations int
	for {
		tickerIterations++
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
				var authErr error
				if auth.Status == "invalid" {
					_, waitErr := i.Client.WaitAuthorization(ctx, authURL)
					var authorizationErr *acme.AuthorizationError
					if errors.As(waitErr, &authorizationErr) {
						authErr = authorizationErr
					}
				}
				return terminalAuthorizationError(auth.Status, authErr, lastChal)
			}
		}

		if tickerIterations%6 == 0 {
			log(fmt.Sprintf("仍在等待 CA 验证 (challenge: %s, 授权: %s)", lastChalStatus, lastAuthStatus))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待 CA 验证超时 (challenge: %s, 授权: %s)", lastChalStatus, lastAuthStatus)
		case <-ticker.C:
		}
	}
}

func terminalAuthorizationError(status string, authorizationErr error, challenge *acme.Challenge) error {
	if authorizationErr != nil {
		return fmt.Errorf("授权状态 %s: %v", status, authorizationErr)
	}
	if challenge != nil && challenge.Error != nil {
		return fmt.Errorf("授权状态 %s: %v", status, challenge.Error)
	}
	return fmt.Errorf("授权状态: %s", status)
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
		var authLastFound []string
		var authLastResolver string
		var authReady bool
		authServers, authReady, authLastFound, authLastResolver = i.probeAuthServers(ctx, authServers, fqdn, expected)
		if len(authLastFound) > 0 {
			lastFound = authLastFound
			lastResolver = authLastResolver
		}
		if authReady {
			return nil
		}

		// 审计 M9：递归兜底仅在权威存活列表为空（本轮 probeAuthServers 后已无
		// 任何可达权威）时执行；列表非空时成功只认 authReady——公共递归缓存可能
		// 取自已更新的单台 NS，CA 恰好询问滞后 NS 时挑战仍会失败并白烧配额
		// （LE 5 次/时），不得作为放行依据。
		if len(authServers) == 0 {
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

// recursiveDNSResolvers / recursiveDNSPollInterval / recursiveDNSDeadline 是
// checkRecursiveDNS 的测试接缝（var 而非 const，镜像 finalizeTimeout /
// caQueueDrainTimeout 先例：测试按比例缩放预算保持墙钟快速，生产代码不得改写）。
var (
	recursiveDNSResolvers    = []string{"223.5.5.5:53", "119.29.29.29:53", "8.8.8.8:53", "1.1.1.1:53"}
	recursiveDNSPollInterval = 3 * time.Second

	// recursiveDNSDeadline 必须覆盖公共递归负缓存（SOA negative TTL 通常
	// 300~600s）刷新抖动的一个有意义比例：权威快速路径收敛后记录已在权威
	// 侧生效，但写入前曾应答 NXDOMAIN 的递归解析器会持续返回否定缓存直到
	// 各自过期。四个受查解析器错峰刷新（缓存到期时间不同），120s 足以等到
	// 至少一个刷新放行，同时远小于 waitForDNS 的 5min 权威预算，且外层任务
	// 预算（caExecutionTimeoutFor：单域 30min，每域 +10min，封顶 60min）
	// 为每域最多 +90s 的最坏增量留足余量（单域最坏 5+2+15min < 30min）。
	recursiveDNSDeadline = 120 * time.Second
)

func (i *Issuer) checkRecursiveDNS(ctx context.Context, fqdn, expected string) bool {
	deadline := time.After(recursiveDNSDeadline)
	ticker := time.NewTicker(recursiveDNSPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return false
		case <-ticker.C:
			for _, r := range recursiveDNSResolvers {
				if hit, _, _ := probeTXT(ctx, r, fqdn, expected, true); hit {
					if i.Logger != nil {
						i.Logger.Log("waiting_propagation", fmt.Sprintf("递归 DNS 已命中 %s @ %s", fqdn, r))
					}
					return true
				}
			}
		}
	}
}

// probeAuthServers probes every authoritative name server once. Servers whose
// probe fails (transport error) are dropped from the returned alive list so
// they stop consuming propagation budget; a miss keeps the server alive for
// the next round. ready reports whether every server already holds the
// expected record.
func (i *Issuer) probeAuthServers(ctx context.Context, servers []string, fqdn, expected string) (alive []string, ready bool, lastFound []string, lastResolver string) {
	log := func(format string, args ...any) {
		if i.Logger != nil {
			i.Logger.Log("waiting_propagation", fmt.Sprintf(format, args...))
		}
	}
	ready = len(servers) > 0
	for _, server := range servers {
		hit, found, err := probeTXT(ctx, server, fqdn, expected, false)
		switch {
		case err != nil:
			ready = false
			log("权威 DNS 查询失败 %s @ %s: %v", fqdn, server, err)
		case hit:
			alive = append(alive, server)
			log("权威 DNS 已命中 %s @ %s, 值: %s", fqdn, server, expected)
		default:
			ready = false
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
	return alive, ready, lastFound, lastResolver
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
		// NXDOMAIN 是权威否定应答（「名称不存在」）：首发/彻底清理后 TXT 写入
		// 前的正常传播状态，与 NODATA 同为未命中，服务器保持存活；否则传播
		// 窗口内健康权威服务器被移出存活列表，叠加递归负缓存（SOA TTL
		// 300~600s）可致假阴性杀签发。
		if r.Rcode == dns.RcodeNameError {
			return false, nil, nil
		}
		// SERVFAIL/REFUSED 等其余错误应答不是「无记录」：必须按查询失败处理
		//（权威循环中移出存活列表），否则该服务器永远无法命中，authReady
		// 卡假直至传播预算耗尽，产生假阴性。
		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("dns %s: server %s", dns.RcodeToString[r.Rcode], server)
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
