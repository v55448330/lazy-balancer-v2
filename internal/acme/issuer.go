package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
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
	log("creating_account", "确认 ACME 账户（新账户注册，已注册则复用）")
	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()
	if err := i.Client.RegisterAccount(regCtx); err != nil {
		return "", "", fmt.Errorf("register account: %w", err)
	}

	// Step 2: Create order
	log("creating_order", fmt.Sprintf("为域名 %v 创建订单", domains))
	order, err := i.Client.AuthorizeOrder(ctx, domains)
	if err != nil {
		return "", "", fmt.Errorf("authorize order: %w", err)
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

		zone := zoneFromDomain(domain)
		log("cleanup_dns", fmt.Sprintf("清理可能残留的 TXT 记录 %s", tokenFQDN))
		// 按本次挑战值定向清理：同名记录中属于并发签发（不同值）的记录
		// 必须保留，只清掉本值残留与陈旧遗留
		if err := dnsprovider.CleanUpChallenge(ctx, i.Provider, zone, tokenFQDN, keyAuth); err != nil {
			log("cleanup_warning", fmt.Sprintf("清理旧 TXT 记录失败 %s: %v", tokenFQDN, err))
		}

		log("presenting_dns", fmt.Sprintf("写入 TXT 记录 %s, 值: %s", tokenFQDN, keyAuth))
		// U06-F01（第 78 轮）：挑战必须在 Present 之前登记进 deferred 清理集合——
		// provider 可能在记录已落 DNS 后仍返回错误（ownership.Add 失败且回滚删除
		// 亦失败的双失败形态），只在成功路径登记会让该临时 TXT 永久残留。
		// 清理按 value 定向（CleanUpValue 只删本挑战值），对未写入/未成功的挑战
		// 登记是幂等空操作。
		presentedChallenges = append(presentedChallenges, ChallengeInfo{
			Domain:    domain,
			TokenFQDN: tokenFQDN,
			Value:     keyAuth,
		})
		if err := i.Provider.Present(ctx, zone, tokenFQDN, keyAuth, 600); err != nil {
			return "", "", fmt.Errorf("present dns for %s: %w", domain, err)
		}

		localChallenges = append(localChallenges, challengeInfo{
			domain:    domain,
			tokenFQDN: tokenFQDN,
			authURL:   authURL,
			chal:      chal,
		})
	}

	// Step 4: Wait for DNS propagation and accept challenges
	for _, ci := range localChallenges {
		keyAuth, err := i.Client.DNS01ChallengeRecord(ci.chal.Token)
		if err != nil {
			return "", "", err
		}
		log("waiting_propagation", fmt.Sprintf("等待 DNS 传播 %s, 期望值: %s", ci.tokenFQDN, keyAuth))
		if err := i.waitForDNS(ctx, ci.tokenFQDN, keyAuth, 5*time.Minute); err != nil {
			return "", "", fmt.Errorf("dns propagation %s: %w", ci.tokenFQDN, err)
		}
		log("dns_propagated", fmt.Sprintf("DNS 已传播 %s", ci.tokenFQDN))

		if i.RequireRecursiveDNS {
			if !i.checkRecursiveDNS(ctx, ci.tokenFQDN, keyAuth) {
				return "", "", fmt.Errorf("recursive DNS propagation failed for %s: record not visible on public resolvers", ci.tokenFQDN)
			}
			log("dns_propagated", fmt.Sprintf("递归 DNS 已传播 %s", ci.tokenFQDN))
		}

		log("accepting_challenge", fmt.Sprintf("提交验证 %s", ci.domain))
		if _, err := i.Client.AcceptChallenge(ctx, ci.chal); err != nil {
			return "", "", fmt.Errorf("accept challenge %s: %w", ci.domain, err)
		}
	}

	// Step 5: Wait for all authorizations to be valid
	for _, ci := range localChallenges {
		log("validating", fmt.Sprintf("等待 CA 验证 %s", ci.domain))
		if err := i.waitForValidation(ctx, ci.authURL, ci.chal.URI); err != nil {
			return "", "", fmt.Errorf("wait authorization %s: %w", ci.authURL, err)
		}
	}
	log("validated", "所有域名验证通过")

	// Step 5.5: Wait for the order to become ready before finalizing.
	log("waiting_order_ready", "等待订单就绪")
	readyCtx, readyCancel := context.WithTimeout(ctx, 3*time.Minute)
	readyOrder, err := i.Client.WaitOrder(readyCtx, order.URI)
	readyCancel()
	if err != nil {
		return "", "", fmt.Errorf("wait order ready: %w", err)
	}
	if readyOrder.Status != "ready" && readyOrder.Status != "valid" {
		errMsg := ""
		if readyOrder.Error != nil {
			errMsg = fmt.Sprintf(" (%d: %s)", readyOrder.Error.StatusCode, readyOrder.Error.Detail)
		}
		return "", "", fmt.Errorf("order status after ready wait: %s%s", readyOrder.Status, errMsg)
	}
	log("order_ready", fmt.Sprintf("订单已就绪，状态: %s", readyOrder.Status))

	// Step 6: Finalize order with CSR
	log("finalizing", "生成 CSR 并提交订单")
	csrDER, key, err := CreateCSR(domains)
	if err != nil {
		return "", "", fmt.Errorf("create csr: %w", err)
	}
	finalizedOrder, err := i.finalizeOrder(ctx, order.FinalizeURL, csrDER)
	if err != nil {
		return "", "", err
	}
	if finalizedOrder.CertURL == "" {
		return "", "", fmt.Errorf("finalize returned empty cert url")
	}
	log("finalized", fmt.Sprintf("订单已最终化，证书 URL: %s", finalizedOrder.CertURL))

	// Step 6.5: Wait for the order to become valid after finalization.
	log("waiting_order_valid", "等待订单最终完成")
	validCtx, validCancel := context.WithTimeout(ctx, 5*time.Minute)
	validOrder, err := i.Client.WaitOrder(validCtx, order.URI)
	validCancel()
	if err != nil {
		return "", "", fmt.Errorf("wait order valid: %w", err)
	}
	if validOrder.Status != "valid" {
		errMsg := ""
		if validOrder.Error != nil {
			errMsg = fmt.Sprintf(" (%d: %s)", validOrder.Error.StatusCode, validOrder.Error.Detail)
		}
		return "", "", fmt.Errorf("order status after finalize: %s%s", validOrder.Status, errMsg)
	}
	if validOrder.CertURL == "" {
		validOrder.CertURL = finalizedOrder.CertURL
	}
	log("order_valid", "订单验证完成")

	// Step 7: Download certificate
	log("downloading", "下载证书")
	certDER, err := i.Client.FetchCert(ctx, validOrder.CertURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch cert: %w", err)
	}
	log("downloaded", "证书下载完成")

	certPEM = EncodeCertPEM(certDER)
	keyPEM = EncodeKeyPEM(key)
	return certPEM, keyPEM, nil
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
// U06-F05（第 78 轮）：解析单源已下沉到 dnsprovider.ResolveZone（PSL），签发链
// 与 DNS 凭证校验链共用同一口径；此处仅保留签发侧的空域兜底。
func zoneFromDomain(domain string) string {
	zone, err := dnsprovider.ResolveZone(domain)
	if err != nil {
		return strings.TrimSuffix(strings.TrimSpace(domain), ".")
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
		if chal, err := i.Client.GetChallenge(ctx, chalURL); err != nil {
			// F49-9：CA 限流（429）必须立即上抛——外层 detectRateLimit 据此把
			// 任务记入 waiting_ca 按 Retry-After 退避；吞掉继续轮询会把限流
			// 错误磨成 10 分钟超时，丢失限流语义并持续给 CA 加压。
			if isACMERRateLimit(err) {
				return err
			}
			log(fmt.Sprintf("查询 challenge 状态失败: %v", err))
		} else {
			lastChal = chal
			if chal.Status != lastChalStatus {
				log(fmt.Sprintf("challenge 状态: %s", chal.Status))
				lastChalStatus = chal.Status
			}
		}

		if auth, err := i.Client.GetAuthorization(ctx, authURL); err != nil {
			if isACMERRateLimit(err) {
				return err
			}
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

// isACMERRateLimit 判定错误是否携带 CA 的 429 限流（F49-9）：x/crypto 对 429
// 响应返回 *acme.Error（StatusCode=429，RetryBackoff 返回 0 时库内不重试
// 直接上抛）。仅结构化 429 命中——瞬时网络错误/5xx 维持「日志+重试」。
func isACMERRateLimit(err error) bool {
	var acmeErr *acme.Error
	return errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusTooManyRequests
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
	// propagationRecursiveResolvers 见下方接缝声明。
	resolvers := propagationRecursiveResolvers

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
	authServers := resolveAuthoritativeNSFn(ctx, fqdn, resolvers[0])
	initialAuthServers := append([]string(nil), authServers...)
	if len(authServers) > 0 {
		log("权威 DNS 服务器: %s", strings.Join(authServers, ", "))
	}

	ticker := time.NewTicker(propagationPollInterval)
	defer ticker.Stop()

	var lastFound []string
	var lastResolver string
	var lastRecursiveHits []string
	consensusRounds := 0
	firstProbeAt := time.Now()
	divergenceDiagnosed := false
	// C-3（第 73 轮）：逐台命中/失败/未命中行仅在「状态变化」时输出——
	// 镜像 waitForValidation 的 lastChalStatus 先例，避免 5min 传播预算内
	// 每轮逐台刷屏（单轮 4 递归 + N 权威，5min/3s≈100 轮可达数百行）。
	// 权威与递归各持一份状态表（同一 server 地址在不同角色下语义不同）。
	authState := &dnsLogState{}
	recState := &dnsLogState{}

	for {
		// Authoritative name servers first: every reachable server must have
		// the record before we let the CA validate. Servers that fail to
		// respond are dropped from the list so a network-blocked server does
		// not consume the propagation budget on every tick.
		var authLastFound []string
		var authLastResolver string
		var authReady bool
		authServers, authReady, authLastFound, authLastResolver = i.probeAuthServersLogged(ctx, authServers, fqdn, expected, authState)
		if len(authLastFound) > 0 {
			lastFound = authLastFound
			lastResolver = authLastResolver
		}
		if authReady {
			return nil
		}

		// W1（第 72 轮，用户裁定）：每轮并行于权威探测公共递归做共识统计。
		// 放行判据二选一：①authReady（上）；②≥MinHits 台递归命中当前期望值
		// ×连续 MinRounds 轮。权威全 miss 而递归命中的三形态（CNAME 委托/
		// NS 变更/权威集群分裂）LE 验证均能跟随实际 DNS 状态成功，客户端
		// 死等权威即恒超时；单台缓存超前（M9）由「多台共识×连续两轮」对冲。
		//
		// C-1（第 73 轮）：各台并行探测（每台独立 ctx 超时）——串行时黑洞
		// 解析器（8.8.8.8/1.1.1.1 各 UDP+TCP 两次 8s 超时）把单轮膨胀到
		// ~32s，5min 预算被磨成 ~10 轮；并行后单轮上界≈单台最坏耗时。
		// 结果按 resolvers 顺序回填（顺序无关且清单顺序可复现）；日志统一
		// 在调用方按顺序输出（Logger 非并发契约）。
		probes := probeRecursiveParallel(ctx, resolvers, fqdn, expected)
		var recursiveHits []string
		for _, pr := range probes {
			if pr.err != nil {
				if recState.changed(pr.resolver, "error") {
					log("查询失败 %s @ %s: %v", fqdn, pr.resolver, pr.err)
				}
				continue
			}
			if pr.hit {
				recursiveHits = append(recursiveHits, pr.resolver)
				if recState.changed(pr.resolver, "hit") {
					log("递归 DNS 已命中 %s @ %s, 值: %s", fqdn, pr.resolver, expected)
				}
				continue
			}
			if len(pr.found) > 0 {
				lastFound = pr.found
				lastResolver = pr.resolver
				if recState.changed(pr.resolver, "miss:"+strings.Join(pr.found, ";")) {
					log("DNS 未命中 %s @ %s, 期望: %s, 实际: %s", fqdn, pr.resolver, expected, strings.Join(pr.found, "; "))
				}
			}
		}
		lastRecursiveHits = recursiveHits
		if len(recursiveHits) >= propagationConsensusMinHits {
			consensusRounds++
			if consensusRounds >= propagationConsensusMinRounds {
				log("递归共识放行 %s @ %s（权威未见记录，放行依据=公共递归多台共识，详见诊断日志）",
					fqdn, strings.Join(recursiveHits, ", "))
				return nil
			}
		} else {
			consensusRounds = 0
		}

		// 现行兜底保留：权威存活列表为空（全部下线/解析失败）时单台递归命中
		// 即放行——此时无权威可问，递归是唯一信号（审计 M9 场景语义不变）。
		if len(authServers) == 0 && len(recursiveHits) > 0 {
			log("DNS 已命中 %s @ %s, 值: %s", fqdn, recursiveHits[0], expected)
			return nil
		}

		// W2（第 72 轮）：权威存活台全 miss 持续超阈值且递归未达共识——显式
		// 诊断一次（生产排障 30 秒自明根因，不再盲猜）。
		if !divergenceDiagnosed && len(authServers) > 0 &&
			time.Since(firstProbeAt) > propagationDivergenceDiagAfter {
			divergenceDiagnosed = true
			log("诊断: 权威与递归结果分歧已持续 %s——权威存活台(%s)全 miss，递归命中台(%s)；"+
				"疑似 CNAME 委托（_acme-challenge 下挂 CNAME）/NS 变更未收敛/权威集群分裂，可 nslookup -type=CNAME 核验",
				time.Since(firstProbeAt).Round(time.Second),
				strings.Join(authServers, ","), orNone(lastRecursiveHits))
		}

		select {
		case <-ctx.Done():
			if len(lastFound) > 0 {
				return fmt.Errorf("dns propagation timeout for %s: expected %s, last found %s (via %s); authoritative=%s recursive=%s(命中:%s)",
					fqdn, expected, strings.Join(lastFound, "; "), lastResolver,
					orNone(initialAuthServers), strings.Join(resolvers, ","), orNone(lastRecursiveHits))
			}
			return fmt.Errorf("dns propagation timeout for %s: expected %s, no TXT record found from any resolver; authoritative=%s recursive=%s(命中:%s)",
				fqdn, expected, orNone(initialAuthServers), strings.Join(resolvers, ","), orNone(lastRecursiveHits))
		case <-ticker.C:
		}
	}
}

// orNone 空切片显示占位（W2 诊断/超时清单用）。
func orNone(list []string) string {
	if len(list) == 0 {
		return "(无)"
	}
	return strings.Join(list, ",")
}

// W1/W2（第 72 轮，用户裁定）：waitForDNS 测试接缝（镜像 recursiveDNS* 先例：
// var 而非 const，测试按比例缩放预算保持墙钟快速，生产代码不得改写）。
var (
	// resolveAuthoritativeNSFn 权威 NS 解析入口（测试替换为固定假权威清单）。
	resolveAuthoritativeNSFn = resolveAuthoritativeNS
	// propagationRecursiveResolvers 公共递归清单（中国友好解析器在前）——
	// 单源：waitForDNS 共识统计与 checkRecursiveDNS 共用（C-2 第 73 轮）。
	propagationRecursiveResolvers = []string{
		"223.5.5.5:53",    // Alibaba AliDNS
		"119.29.29.29:53", // Tencent DNSPod
		"8.8.8.8:53",      // Google Public DNS
		"1.1.1.1:53",      // Cloudflare
	}
	// propagationPollInterval 探测轮询间隔（生产 3s）。
	propagationPollInterval = 3 * time.Second
	// propagationResolverProbeTimeout 单台递归探测的独立 ctx 超时（C-1）——
	// 每台 goroutine 各自 WithTimeout，一台黑洞解析器不得拖累同轮其余台。
	propagationResolverProbeTimeout = 8 * time.Second
	// propagationDivergenceDiagAfter 权威/递归分歧诊断日志阈值（生产 30s）。
	propagationDivergenceDiagAfter = 30 * time.Second
	// 递归共识放行阈值：≥MinHits 台递归命中当前值 × 连续 MinRounds 轮。
	// MinHits 下限=3、MinRounds 下限=2 由 TestPropagationConsensusDefaults
	// 钉死（M9：单台/双台缓存超前不得放行，2026-10-13 用户裁定 2→3）。
	propagationConsensusMinHits   = 3
	propagationConsensusMinRounds = 2
)

// recursiveDNSPollInterval / recursiveDNSDeadline 是 checkRecursiveDNS 的
// 测试接缝（var 而非 const，镜像 finalizeTimeout / caQueueDrainTimeout 先例：
// 测试按比例缩放预算保持墙钟快速，生产代码不得改写）。C-2（第 73 轮）：
// 解析器清单不再各自持有字面量——checkRecursiveDNS 与 waitForDNS 共用
// propagationRecursiveResolvers 单源（原 recursiveDNSResolvers 与
// propagationRecursiveResolvers 双份同内容字面量，任一处改地址会有漏改）。
var (
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

// checkRecursiveDNS 是 RequireRecursiveDNS（ZeroSSL）路径的递归可见性二次确认，
// 语义**刻意弱于** waitForDNS 的递归共识放行，两者分层不得合并（C-7，第 73 轮）：
//
//   - 判据：任意 1 台公共递归命中即放行（「任一台可见」），无 MinHits×MinRounds
//     共识门。ZeroSSL 只在 120s 内要求「公共递归已能解析到该 TXT」，单台可见
//     已满足其验证前置；引入共识门会把正常签发拖到 120s 超时（ZeroSSL 授权
//     窗口远短于 LE）。
//   - 预算：120s（recursiveDNSDeadline），远短于 waitForDNS 的 5min 权威预算。
//   - 定位：这是权威快速路径**之后**的额外确认，不是放行判据本身——权威已
//     authReady（或递归共识已在 waitForDNS 内放行）才会走到这里。
//
// 不得把 waitForDNS 的共识结论（哪几台已命中）回传复用为这里的放行依据：
// 两者解析器集合同源（C-2 单源），但判定时机/窗口/语义不同，复用会把
// waitForDNS 的放行时机误当成 ZeroSSL 的确认结果。
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
			for _, r := range propagationRecursiveResolvers {
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

// probeAuthServersLogged 是多轮轮询形态：state 跨轮记录每台权威上次打印的
// 状态，命中/失败/未命中/无记录行仅在状态变化时输出（镜像 waitForValidation
// 的 lastChalStatus 先例，收敛 5min 预算内的逐台刷屏噪音）。
func (i *Issuer) probeAuthServersLogged(ctx context.Context, servers []string, fqdn, expected string, state *dnsLogState) (alive []string, ready bool, lastFound []string, lastResolver string) {
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
			if state.changed(server, "error") {
				log("权威 DNS 查询失败 %s @ %s: %v", fqdn, server, err)
			}
		case hit:
			alive = append(alive, server)
			if state.changed(server, "hit") {
				log("权威 DNS 已命中 %s @ %s, 值: %s", fqdn, server, expected)
			}
		default:
			ready = false
			alive = append(alive, server)
			if len(found) > 0 {
				lastFound = found
				lastResolver = server + " (auth)"
				if state.changed(server, "miss:"+strings.Join(found, ";")) {
					log("权威 DNS 未命中 %s @ %s, 期望: %s, 实际: %s", fqdn, server, expected, strings.Join(found, "; "))
				}
			} else if state.changed(server, "nodata") {
				log("权威 DNS 无 TXT 记录 %s @ %s", fqdn, server)
			}
		}
	}
	return alive, ready, lastFound, lastResolver
}

// dnsLogState 记录每个探针目标上一次打印的状态，使逐台命中/失败/未命中行
// 仅在状态变化时输出（C-3 第 73 轮，镜像 waitForValidation 的 lastChalStatus
// 先例）。零值可用；nil 视为「总是变化」（首次必打）。
type dnsLogState struct {
	last map[string]string
}

func (s *dnsLogState) changed(key, state string) bool {
	if s == nil {
		return true
	}
	if s.last == nil {
		s.last = make(map[string]string)
	}
	if s.last[key] == state {
		return false
	}
	s.last[key] = state
	return true
}

// recursiveProbeResult 单台公共递归的一轮探测结果（C-1 并行收集用）。
type recursiveProbeResult struct {
	resolver string
	hit      bool
	found    []string
	err      error
}

// probeRecursiveParallel 并行探测全部公共递归，按输入顺序回填结果（C-1 第
// 73 轮）。每台独立 ctx 超时（propagationResolverProbeTimeout）——一台黑洞
// 解析器（8.8.8.8/1.1.1.1 在受限网络内 UDP/TCP 双 8s 超时）不再把单轮串行
// 拖到 ~32s。日志不在并发 goroutine 内写（Logger 非并发契约），统一由调用方
// 按结果顺序输出。
func probeRecursiveParallel(ctx context.Context, resolvers []string, fqdn, expected string) []recursiveProbeResult {
	results := make([]recursiveProbeResult, len(resolvers))
	var wg sync.WaitGroup
	for idx, resolver := range resolvers {
		wg.Add(1)
		go func(idx int, resolver string) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, propagationResolverProbeTimeout)
			defer cancel()
			hit, found, err := probeTXT(probeCtx, resolver, fqdn, expected, true)
			results[idx] = recursiveProbeResult{resolver: resolver, hit: hit, found: found, err: err}
		}(idx, resolver)
	}
	wg.Wait()
	return results
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
		// AD-3（第 70 轮审计）：TC=1 的「成功」应答其 Answer 段不可信（UDP
		// 512B 载荷上限内常被截空；同域并存多条 TXT 时权威应答恒截断）——
		// 按 miss 处理会致 authReady 永假、假阴性烧签发配额。continue 承接
		// 到下一网络（TCP）重查。
		if r.Truncated {
			lastErr = fmt.Errorf("dns: truncated response from %s (%s)", server, network)
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
