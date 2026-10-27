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

	"lazy-balancer-v2/internal/dnsname"
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
	// AccountPreRegistered 为 true 时跳过 Step 1 注册：调用方已用同一
	// Client 完成账户注册/复用验证（KID 已缓存于该 client）——重复注册是
	// 每次签发一次多余的 CA 往返。KID 缓存为
	// client 级，换 client 不得置位。
	AccountPreRegistered bool
}

// 签发分段预算（下发/执行使用的实际值）。每一段都独立设 ctx 预算，让卡住的
// CA 停在该阶段并以阶段错误暴露，而不是耗尽外层任务预算后报泛化超时。
//
// 跨层耦合：这些分段之和必须严格小于 CA 队列的外层执行预算
// （services.caExecutionTimeout / caExecutionTimeoutFor），否则最坏路径被外层
// ctx 抢先取消——错误归因退化、白烧一次 renewal_attempts。常量关系由 services
// 侧断言（IssuanceSegmentBudgetFor 与 caExecutionTimeoutFor 逐域对比），上调
// 任一分段会立刻失败而不是等线上出现泛化超时。
const (
	registrationSegmentBudget = 30 * time.Second
	propagationSegmentBudget  = 5 * time.Minute
	// recursiveDNSSegmentBudget 是传播判定内的递归可见性二次确认预算：必须
	// 覆盖公共递归负缓存刷新抖动的一个有意义比例。它在传播预算内执行，故求和
	// 时按独立分段累加属保守上界。
	recursiveDNSSegmentBudget = 120 * time.Second
	validationSegmentBudget   = 10 * time.Minute
	orderReadySegmentBudget   = 3 * time.Minute
	finalizeSegmentBudget     = 10 * time.Minute
	orderValidSegmentBudget   = 5 * time.Minute
)

// IssuanceSegmentBudgetFor 返回给定域名数下单次签发的分段预算之和（保守上界）：
// 注册/订单就绪/finalize/有效期等待各一次；传播、递归确认、验证按域名串行。
// 供上层（services）断言其小于 CA 队列外层执行预算——acme 是被依赖层，无法
// 导入 services 的常量，故断言放在 services 侧、由本 getter 取值。
func IssuanceSegmentBudgetFor(domainCount int) time.Duration {
	if domainCount < 1 {
		domainCount = 1
	}
	perDomain := propagationSegmentBudget + recursiveDNSSegmentBudget + validationSegmentBudget
	return registrationSegmentBudget + time.Duration(domainCount)*perDomain +
		orderReadySegmentBudget + finalizeSegmentBudget + orderValidSegmentBudget
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

	// Step 1: Register account（预检已注册同 client 时跳过——KID 缓存随
	// client 走，重复注册纯属多余 CA 往返）
	if i.AccountPreRegistered {
		log("creating_account", "ACME 账户已在预检中注册，跳过重复注册")
	} else {
		log("creating_account", "确认 ACME 账户（新账户注册，已注册则复用）")
		regCtx, regCancel := context.WithTimeout(ctx, registrationSegmentBudget)
		defer regCancel()
		if err := i.Client.RegisterAccount(regCtx); err != nil {
			return "", "", fmt.Errorf("register account: %w", err)
		}
	}

	// Step 2: Create order
	log("creating_order", fmt.Sprintf("为域名 %v 创建订单", domains))
	order, err := i.Client.AuthorizeOrder(ctx, domains)
	if err != nil {
		return "", "", fmt.Errorf("authorize order: %w", err)
	}
	log("order_created", fmt.Sprintf("订单已创建，共 %d 个授权", len(order.AuthzURLs)))
	// 订单初始状态必须分流。新建订单正常为 pending；
	// ready 表示授权已全部 valid（CA 幂等复用），继续走挑战循环是无害的空转；
	// valid 表示该订单已有证书——其证书绑定的是签发方当时的 CSR 私钥，本次
	// 新生成的 CSR 私钥与它不匹配，无法复用，必须显式失败而不是把 CA 对
	// finalize 的拒绝（403 orderAlreadyValid/orderNotReady）磨成泛化错误；
	// invalid 是终态。ready 无需在此拦截（下方授权分流已覆盖）。
	switch order.Status {
	case "valid":
		return "", "", fmt.Errorf("订单 %s 已处于 valid 状态（CA 返回了已完成订单，其证书与本次 CSR 不匹配），请稍后重试", order.URI)
	case "invalid":
		errMsg := ""
		if order.Error != nil {
			errMsg = fmt.Sprintf(" (%d: %s)", order.Error.StatusCode, order.Error.Detail)
		}
		return "", "", fmt.Errorf("订单 %s 状态 invalid%s", order.URI, errMsg)
	}

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
		// 清理预算按挑战数+选中记录数缩放——Cleanup 串行删除，单条
		// 删除链最坏 90s（dnspod http.Client.Timeout / tencent ReqTimeout=90），
		// 冷缓存域名解析同包络；K>1（legacy/stale 残留）时按挑战数的预算会
		// 让清理被 ctx 截断（cleanup_warning + 残留延长）。
		recordCount := 0
		for _, ci := range presentedChallenges {
			recordCount += dnsprovider.CountChallengeCleanupRecords(i.Provider, zoneFromDomain(ci.Domain), ci.TokenFQDN, ci.Value)
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), dnsCleanupBudget(len(presentedChallenges), recordCount))
		defer cleanupCancel()
		log("cleanup_dns", "清理 ACME DNS TXT 记录")
		i.Cleanup(cleanupCtx, presentedChallenges)
	}()

	for _, authURL := range order.AuthzURLs {
		auth, err := i.Client.GetAuthorization(ctx, authURL)
		if err != nil {
			return "", "", fmt.Errorf("fetch authorization %s: %w", authURL, err)
		}

		domain := auth.Identifier.Value
		// RFC 8555 §7.4.1 允许 CA 复用同账号同标识的
		// 已 valid 授权（Let's Encrypt boulder reuseValidAuthz 长期开启）。
		// valid 授权无需 TXT/挑战，直接视为已验证；终态（invalid 家族）必须
		// 立即失败。原实现对两者都无条件 Present（多写一条 TXT 并等满 5min
		// 传播）再 Accept，在授权复用窗口内把本可成功的签发打成持续失败。
		switch auth.Status {
		case "valid":
			log("validated", fmt.Sprintf("授权已有效（CA 复用），跳过 DNS-01 挑战 %s", domain))
			continue
		case "invalid", "deactivated", "expired", "revoked":
			return "", "", fmt.Errorf("wait authorization %s: %w", authURL,
				terminalAuthorizationError(auth.Status, nil, dns01Challenge(auth)))
		case "pending":
			// 常规路径：写 TXT → 等传播 → 提交挑战。
		default:
			// 未知状态 按 pending 处理会盲写 TXT 并提交挑战，
			// 按 valid 处理会掩盖真实状态，两者都可能把可在下一轮成功的
			// 签发拖成失败。
			return "", "", fmt.Errorf("授权 %s 状态 %q 无法继续 DNS-01 挑战", authURL, auth.Status)
		}

		chal := dns01Challenge(auth)
		if chal == nil {
			return "", "", fmt.Errorf("no dns-01 challenge for %s", domain)
		}

		tokenFQDN := "_acme-challenge." + domain + "."
		keyAuth, err := i.Client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return "", "", fmt.Errorf("dns01 record: %w", err)
		}

		zone := zoneFromDomain(domain)
		// 在途登记必须先于预清理：CA 复用 pending 授权时两条订单会拿到同一
		// token → 同一 keyAuth（Let's Encrypt reuseValidAuthz 长期开启），按值
		// 清理无法从记录本身区分两条在途签发。登记返回 first=false 表示另一次
		// 签发仍持有同名同值记录——此时预清理会删掉对方仍在等待验证的 TXT，
		// 必须跳过；最后由最后结束的签发统一回收（同值记录删一次即全清）。
		claim, firstClaim := dnsprovider.ClaimChallengeValue(zone, tokenFQDN, keyAuth)
		if firstClaim {
			log("cleanup_dns", fmt.Sprintf("清理可能残留的 TXT 记录 %s", tokenFQDN))
			// 按本次挑战值定向清理：同名记录中属于并发签发（不同值）的记录
			// 必须保留，只清掉本值残留与陈旧遗留
			if err := dnsprovider.CleanUpChallenge(ctx, i.Provider, zone, tokenFQDN, keyAuth); err != nil {
				log("cleanup_warning", fmt.Sprintf("清理旧 TXT 记录失败 %s: %v", tokenFQDN, err))
			}
		} else {
			log("cleanup_dns", fmt.Sprintf("同名同值的并发签发仍在进行，跳过预清理 %s（由最后结束的签发统一回收）", tokenFQDN))
		}

		log("presenting_dns", fmt.Sprintf("写入 TXT 记录 %s, 值: %s", tokenFQDN, keyAuth))
		// 挑战必须在 Present 之前登记进 deferred 清理集合——
		// provider 可能在记录已落 DNS 后仍返回错误（ownership.Add 失败且回滚删除
		// 亦失败的双失败形态），只在成功路径登记会让该临时 TXT 永久残留。
		// 清理按 value 定向（CleanUpValue 只删本挑战值），对未写入/未成功的挑战
		// 登记是幂等空操作。
		presentedChallenges = append(presentedChallenges, ChallengeInfo{
			Domain:    domain,
			TokenFQDN: tokenFQDN,
			Value:     keyAuth,
			claim:     claim,
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
		if err := i.waitForDNS(ctx, ci.tokenFQDN, keyAuth, propagationSegmentBudget); err != nil {
			return "", "", fmt.Errorf("dns propagation %s: %w", ci.tokenFQDN, err)
		}
		log("dns_propagated", fmt.Sprintf("DNS 已传播 %s", ci.tokenFQDN))

		if i.RequireRecursiveDNS {
			if !i.checkRecursiveDNS(ctx, ci.tokenFQDN, keyAuth) {
				return "", "", recursiveDNSCheckError(ctx, ci.tokenFQDN)
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
	readyCtx, readyCancel := context.WithTimeout(ctx, orderReadySegmentBudget)
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
	// 不可达防御：x/crypto CreateOrderCert 成功路径已 WaitOrder 到 valid 并
	// fetchCertRFC 取回证书，certURL 必非空——本分支仅防御上游库未来行为
	// 漂移。空 CertURL 无缓存条目可弃（DiscardFinalizedCert 以 URL 为键），
	// 故此处不适用「失败路径必须显式丢弃缓存」的口径。
	if finalizedOrder.CertURL == "" {
		return "", "", fmt.Errorf("finalize returned empty cert url")
	}
	log("finalized", fmt.Sprintf("订单已最终化，证书 URL: %s", finalizedOrder.CertURL))

	// Step 6.5: Wait for the order to become valid after finalization.
	// finalize 已在 client 缓存证书字节；此后的失败路径（wait-valid/状态非
	// valid/下载失败）必须显式丢弃缓存条目，不依赖 FIFO 上限兜底。
	log("waiting_order_valid", "等待订单最终完成")
	validCtx, validCancel := context.WithTimeout(ctx, orderValidSegmentBudget)
	validOrder, err := i.Client.WaitOrder(validCtx, order.URI)
	validCancel()
	if err != nil {
		i.Client.DiscardFinalizedCert(finalizedOrder.CertURL)
		return "", "", fmt.Errorf("wait order valid: %w", err)
	}
	if validOrder.Status != "valid" {
		i.Client.DiscardFinalizedCert(finalizedOrder.CertURL)
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
		i.Client.DiscardFinalizedCert(validOrder.CertURL)
		return "", "", fmt.Errorf("fetch cert: %w", err)
	}
	log("downloaded", "证书下载完成")

	certPEM = EncodeCertPEM(certDER)
	keyPEM, err = EncodeKeyPEM(key)
	if err != nil {
		return "", "", fmt.Errorf("encode private key: %w", err)
	}
	return certPEM, keyPEM, nil
}

// finalizeTimeout 为 finalize 提交（POST CSR + 轮询出证）设定的独立预算，
// 对齐邻近的 ready 3min / valid 5min 分段预算——卡死的 CA 以 finalize 阶段
// 错误暴露，而不是耗尽整个任务执行预算后报泛化超时。
var finalizeTimeout = finalizeSegmentBudget

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
//
// 每个挑战的注销先于按值清理：Release 返回 false 表示仍有其他在途签发持有同名
// 同值记录（CA 复用授权 → 同一 keyAuth），本次清理必须跳过——删掉的是对方仍在
// 等待验证的 TXT；最后结束的那次签发在 Release 时拿回判定权，一次回收全部同值
// 记录。未登记注销的 ChallengeInfo（测试/外部构造）按无并发处理。
func (i *Issuer) Cleanup(ctx context.Context, challenges []ChallengeInfo) {
	for _, ci := range challenges {
		if ci.claim != nil && !ci.claim.Release() {
			if i.Logger != nil {
				i.Logger.Log("cleanup_dns", fmt.Sprintf("同名同值的并发签发仍在进行，跳过清理 %s（由最后结束的签发统一回收）", ci.TokenFQDN))
			}
			continue
		}
		if err := dnsprovider.CleanUpChallenge(ctx, i.Provider, zoneFromDomain(ci.Domain), ci.TokenFQDN, ci.Value); err != nil {
			if i.Logger != nil {
				i.Logger.Log("cleanup_warning", fmt.Sprintf("清理 DNS 记录失败 %s: %v", ci.TokenFQDN, err))
			}
		}
	}
}

// 清理预算：单条删除链最坏 90s（dnspod
// http.Client.Timeout / tencent HttpProfile.ReqTimeout=90s，覆盖重试包络），
// 且每个挑战还要先解析 domain_id（冷缓存时 Domain.List 分页同包络）。
// 真实最坏链 = Σ(1+K_i)×90s（K_i=该挑战选中条目数：本挑战记录+legacy/stale
// 回收），故预算按「挑战数+选中记录数」缩放——只按挑战数会让带历史残留的
// 清理在 8min 内被 ctx 截断（cleanup_warning + 残留延长）。下限保留原
// 2min，上限 8min 保证「CA 队列执行预算 60min + 清理 ≤8min <
// StaleOwnershipAge 75min」——ownership 条目不会在清理进行中被他方判为
// 陈旧（耦合由 services 包的 TestCleanupBudget_staysBelowStaleOwnershipAge
// 钉住，见 internal/services/cert_cleanup_budget_coupling_test.go）。
// 超出上限时按 8min 尽力清理，失败条目由 ownership 自愈兜底（记录不泄漏）。
const (
	dnsCleanupBudgetMin       = 2 * time.Minute
	dnsCleanupBudgetPerRecord = 90 * time.Second
	dnsCleanupBudgetMax       = 8 * time.Minute
)

// dnsCleanupBudget 返回给定挑战数与选中记录总数下的清理总预算
// （下限 2min、每挑战/记录各 90s、上限 8min）。recordCount 由各 provider 的
// CleanupCounter 本地计数汇总；无计数能力时按每挑战 1 条计。
func dnsCleanupBudget(challengeCount, recordCount int) time.Duration {
	if challengeCount <= 0 && recordCount <= 0 {
		return dnsCleanupBudgetMin
	}
	budget := time.Duration(challengeCount+recordCount) * dnsCleanupBudgetPerRecord
	return min(max(budget, dnsCleanupBudgetMin), dnsCleanupBudgetMax)
}

// DNSCleanupBudgetMax 暴露清理预算上限，供上层（services）做跨层耦合断言：
// 「CA 队列执行预算上限 + 清理上限 < ownership.StaleOwnershipAge」是该不变量
// 的论证基础。acme 是被依赖层，无法导入 services 的常量，故把断言放在
// services 侧、由本 getter 取值——避免两侧各自字面量漂移。
func DNSCleanupBudgetMax() time.Duration { return dnsCleanupBudgetMax }

// ChallengeInfo holds the info needed to clean up a DNS record.
type ChallengeInfo struct {
	Domain    string
	TokenFQDN string
	// Value is the DNS-01 TXT value (key authorization digest) this record
	// was presented with; cleanup removes only records of that value so
	// concurrent issuances for the same domain cannot delete each other.
	Value string
	// claim 是本次挑战值的进程内在途登记（Issuer.Cleanup 注销后才允许按值
	// 清理）。未登记（零值）时按无并发处理，保持对外结构的可构造性。
	claim *dnsprovider.ChallengeClaim
}

// zoneFromDomain extracts the DNS zone (registered domain) from a domain name.
// 解析单源已下沉到 dnsprovider.ResolveZone（PSL），签发链
// 与 DNS 凭证校验链共用同一口径；此处仅保留签发侧的空域兜底。
func zoneFromDomain(domain string) string {
	zone, err := dnsprovider.ResolveZone(domain)
	if err != nil {
		return strings.TrimSuffix(strings.TrimSpace(domain), ".")
	}
	return zone
}

// validationPollInterval 验证轮询节拍（测试接缝：真实 CA 轮询 5s；测试缩短
// 以观察进度日志节流。生产不得改写）。
var validationPollInterval = 5 * time.Second

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
	ctx, cancel := context.WithTimeout(ctx, validationSegmentBudget)
	defer cancel()

	ticker := time.NewTicker(validationPollInterval)
	defer ticker.Stop()

	var lastChalStatus, lastAuthStatus string
	var lastChal *acme.Challenge
	var tickerIterations int
	for {
		if chal, err := i.Client.GetChallenge(ctx, chalURL); err != nil {
			// CA 限流（429）必须立即上抛——外层 detectRateLimit 据此把
			// 任务记入 waiting_ca 按退避；吞掉继续轮询会把限流
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
					switch {
					case errors.As(waitErr, &authorizationErr):
						authErr = authorizationErr
					case waitErr != nil:
						// 非授权错误的轮询失败（429/
						// 网络）此前被丢弃——429 的结构化 *acme.Error 因此
						// 无法传到 detectRateLimit，任务退化为普通失败退避
						// 而非 waiting_ca。原样保留错误链。
						authErr = waitErr
					}
				}
				return terminalAuthorizationError(auth.Status, authErr, lastChal)
			}
		}

		// 计数必须先自增再判定：从 0 起判定会让首轮（尚未等待任何 tick）
		// 命中 %6==0，刷出一条状态仍为空串的进度行。同时以「至少已知一个
		// 状态」为守卫——空状态行对排障无信息量。
		tickerIterations++
		if tickerIterations%6 == 0 && (lastChalStatus != "" || lastAuthStatus != "") {
			log(fmt.Sprintf("仍在等待 CA 验证 (challenge: %s, 授权: %s)", lastChalStatus, lastAuthStatus))
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return fmt.Errorf("等待 CA 验证取消 (challenge: %s, 授权: %s): %w", lastChalStatus, lastAuthStatus, ctx.Err())
			}
			return fmt.Errorf("等待 CA 验证超时 (challenge: %s, 授权: %s): %w", lastChalStatus, lastAuthStatus, ctx.Err())
		case <-ticker.C:
		}
	}
}

// isACMERRateLimit 判定错误是否携带 CA 的 429 限流：x/crypto 对 429
// 响应返回 *acme.Error（StatusCode=429，RetryBackoff 返回 0 时库内不重试
// 直接上抛）。仅结构化 429 命中——瞬时网络错误/5xx 维持「日志+重试」。
func isACMERRateLimit(err error) bool {
	var acmeErr *acme.Error
	return errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusTooManyRequests
}

// dns01Challenge 返回授权中的 dns-01 挑战（无则 nil）。
// 抽出供授权状态分流与常规路径共用，避免两处各写一遍遍历。
func dns01Challenge(auth *acme.Authorization) *acme.Challenge {
	if auth == nil {
		return nil
	}
	for _, c := range auth.Challenges {
		if c.Type == "dns-01" {
			return c
		}
	}
	return nil
}

func terminalAuthorizationError(status string, authorizationErr error, challenge *acme.Challenge) error {
	// %w 保留错误链——invalid 分支的 WaitAuthorization
	// 错误可能是 CA 429/网络错误，services/detectRateLimit 依赖
	// errors.As(*acme.Error) 把任务记入 waiting_ca；%v 会让它退化为字符串
	// 匹配。文案形态不变（单错误 %v/%w 渲染一致）。
	if authorizationErr != nil {
		return fmt.Errorf("授权状态 %s: %w", status, authorizationErr)
	}
	if challenge != nil && challenge.Error != nil {
		return fmt.Errorf("授权状态 %s: %w", status, challenge.Error)
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
	// 空清单是装配错误（接缝可被测试/运维注入）——显式报错而非在
	// resolvers[0] 处 panic：panic 会沿签发 goroutine 上抛终止整个 worker。
	if len(resolvers) == 0 {
		return fmt.Errorf("DNS 传播检测缺少递归解析器清单（propagationRecursiveResolvers 为空）")
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
	authServers := resolveAuthoritativeNSFn(ctx, fqdn, resolvers[0])
	initialAuthServers := append([]string(nil), authServers...)
	if len(authServers) > 0 {
		log("权威 DNS 服务器: %s", strings.Join(authServers, ", "))
	} else {
		// 权威快路径未建立必须留痕。原实现完全静默——用户
		// 只能看到 30s 后那句「疑似 CNAME 委托/NS 变更」，而真实原因
		// （查询丢包/超时/截断）在日志里没有任何痕迹。
		log("未发现权威 DNS 服务器（%s），本次仅依赖递归共识判定传播", fqdn)
	}

	ticker := time.NewTicker(propagationPollInterval)
	defer ticker.Stop()

	var lastFound []string
	var lastResolver string
	var lastRecursiveHits []string
	consensusRounds := 0
	firstProbeAt := time.Now()
	divergenceDiagnosed := false
	// 权威清单全失败后的重发现计数（上限 maxAuthRediscoveries，防抖）。
	authRediscoveries := 0
	// 逐台命中/失败/未命中行仅在「状态变化」时输出——
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
		// 一轮全失败（RTT 抖动/权威限流使所有探针同时超时）后清单会永久
		// 变空——曾有权威的域名只剩递归共识一条路，公共递归不可达时烧满
		// 预算报超时（记录其实已正确写入权威）。本轮存活集合变空时按上限
		// 重发现一次清单（≤2 次 NS 查询+地址解析/次，次数防抖），次轮直接
		// 探测新清单。递归共识/单台兜底判据不变（initialAuthServers 非空时
		// 单台兜底仍关闭）。
		if len(authServers) == 0 && len(initialAuthServers) > 0 && authRediscoveries < maxAuthRediscoveries {
			authRediscoveries++
			log("权威 DNS 全部探测失败，重新发现权威服务器（第 %d/%d 次）", authRediscoveries, maxAuthRediscoveries)
			if rediscovered := resolveAuthoritativeNSFn(ctx, fqdn, resolvers[0]); len(rediscovered) > 0 {
				authServers = rediscovered
				log("权威 DNS 重新发现: %s", strings.Join(rediscovered, ", "))
				continue
			}
		}

		// （用户裁定）：每轮并行于权威探测公共递归做共识统计。
		// 放行判据二选一：①authReady（上）；②≥MinHits 台递归命中当前期望值
		// ×连续 MinRounds 轮。权威全 miss 而递归命中的三形态（CNAME 委托/
		// NS 变更/权威集群分裂）LE 验证均能跟随实际 DNS 状态成功，客户端
		// 死等权威即恒超时；单台缓存超前由「多台共识×连续两轮」对冲。
		//
		// 各台并行探测（每台独立 ctx 超时）——串行时黑洞
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

		// 兜底限缩：仅当**从未发现过权威服务器**
		// （initialAuthServers 为空——域名没有可用 NS/解析失败）时，单台递归
		// 命中即放行，此时递归确实是无权威可问时的唯一信号。
		// 曾经有权威、而本轮全部探针瞬时失败的情形**不**适用该兜底：那是网络
		// 抖动窗口，放行单台×单轮会绕过 3 台×2 轮共识（缓存污染/超前
		// 会被当成真传播），CA 验证失败即消耗 Let's Encrypt 5 次/时配额。
		if len(authServers) == 0 && len(initialAuthServers) == 0 && len(recursiveHits) > 0 {
			log("DNS 已命中 %s @ %s, 值: %s（域名无可用权威，按递归单台放行）", fqdn, recursiveHits[0], expected)
			return nil
		}

		// 权威存活台全 miss 持续超阈值且递归未达共识——显式
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
			outcome := "timeout"
			if errors.Is(ctx.Err(), context.Canceled) {
				outcome = "canceled"
			}
			if len(lastFound) > 0 {
				return fmt.Errorf("dns propagation %s for %s: expected %s, last found %s (via %s); authoritative=%s recursive=%s(命中:%s): %w",
					outcome, fqdn, expected, strings.Join(lastFound, "; "), lastResolver,
					orNone(initialAuthServers), strings.Join(resolvers, ","), orNone(lastRecursiveHits), ctx.Err())
			}
			return fmt.Errorf("dns propagation %s for %s: expected %s, no TXT record found from any resolver; authoritative=%s recursive=%s(命中:%s): %w",
				outcome, fqdn, expected, orNone(initialAuthServers), strings.Join(resolvers, ","), orNone(lastRecursiveHits), ctx.Err())
		case <-ticker.C:
		}
	}
}

// orNone 空切片显示占位。
func orNone(list []string) string {
	if len(list) == 0 {
		return "(无)"
	}
	return strings.Join(list, ",")
}

// （用户裁定）：waitForDNS 测试接缝（镜像 recursiveDNS* 先例
// var 而非 const，测试按比例缩放预算保持墙钟快速，生产代码不得改写）。
var (
	// resolveAuthoritativeNSFn 权威 NS 解析入口（测试替换为固定假权威清单）。
	resolveAuthoritativeNSFn = resolveAuthoritativeNS
	// propagationRecursiveResolvers 公共递归清单（中国友好解析器在前）——
	// 单源：waitForDNS 共识统计与 checkRecursiveDNS 共用。
	//
	// 清单必须让「中国大陆可达的解析器 ≥ MinHits(3)」成立：8.8.8.8/1.1.1.1 在中国
	// 大陆常不可达或被投毒，而共识门只看命中台数——清单不足时「权威全 miss、
	// 递归已传播」（CNAME 委托/NS 变更/集群分裂）在最需要该机制的网络上恒超时，
	// 白烧一次 CA 配额。前五台为境内可达解析器（223.5.5.5/119.29.29.29/
	// 114.114.114.114/180.76.76.76/1.2.4.8），后三台为境外补充（9.9.9.9/8.8.8.8/
	// 1.1.1.1）——任一网络下只要境内三台可达即满足共识门，境外掉线不再把上限
	// 压到 2。
	propagationRecursiveResolvers = []string{
		"223.5.5.5:53",       // Alibaba AliDNS
		"119.29.29.29:53",    // Tencent DNSPod
		"114.114.114.114:53", // 114DNS（境内）
		"180.76.76.76:53",    // Baidu DNS（境内）
		"1.2.4.8:53",         // CNNIC sDNS（境内）
		"9.9.9.9:53",         // Quad9（境外）
		"8.8.8.8:53",         // Google Public DNS（境外）
		"1.1.1.1:53",         // Cloudflare（境外）
	}
	// propagationPollInterval 探测轮询间隔（生产 3s）。
	propagationPollInterval = 3 * time.Second
	// propagationResolverProbeTimeout 单台权威/递归探测的独立 ctx 超时——
	// 每台 goroutine 各自 WithTimeout，一台黑洞服务器不得拖累同轮其余台。
	propagationResolverProbeTimeout = 8 * time.Second
	// propagationDivergenceDiagAfter 权威/递归分歧诊断日志阈值（生产 30s）。
	propagationDivergenceDiagAfter = 30 * time.Second
	// 递归共识放行阈值：≥MinHits 台递归命中当前值 × 连续 MinRounds 轮。
	// MinHits 下限=3、MinRounds 下限=2 由 TestPropagationConsensusDefaults
	// 钉死（单台/双台缓存超前不得放行，2026-10-13 用户裁定 2→3）。
	propagationConsensusMinHits   = 3
	propagationConsensusMinRounds = 2
	// maxAuthRediscoveries 权威清单一轮全失败后的重发现次数上限（防抖：
	// 避免对 DNS 加压；每次重发现 ≤2 次 NS 查询 + NS 地址解析）。
	maxAuthRediscoveries = 2
)

// recursiveDNSPollInterval / recursiveDNSDeadline 是 checkRecursiveDNS 的
// 测试接缝（var 而非 const，镜像 finalizeTimeout / caQueueDrainTimeout 先例：
// 测试按比例缩放预算保持墙钟快速，生产代码不得改写）。
// 解析器清单不再各自持有字面量——checkRecursiveDNS 与 waitForDNS 共用
// propagationRecursiveResolvers 单源（原 recursiveDNSResolvers 与
// propagationRecursiveResolvers 双份同内容字面量，任一处改地址会有漏改）。
var (
	recursiveDNSPollInterval = 3 * time.Second

	// recursiveDNSDeadline 必须覆盖公共递归负缓存（SOA negative TTL 通常
	// 300~600s）刷新抖动的一个有意义比例：权威快速路径收敛后记录已在权威
	// 侧生效，但写入前曾应答 NXDOMAIN 的递归解析器会持续返回否定缓存直到
	// 各自过期。四个受查解析器错峰刷新（缓存到期时间不同），120s 足以等到
	// 至少一个刷新放行，同时远小于 waitForDNS 的 5min 权威预算。
	// 单域分段预算之和 = 注册 30s + 传播 5m + 本段 2m +
	// 验证 10m + 就绪 3m + finalize 10m + 有效 5m = 35.5m < 外层
	// caExecutionTimeout（40m，services/caqueue.go）——原注释的
	// 「5+2+15min < 30min」算式漏计就绪/finalize/有效三段且外层值错误。
	recursiveDNSDeadline = recursiveDNSSegmentBudget
)

// recursiveDNSCheckError 区分父上下文取消/截止与独立递归预算用尽。
// checkRecursiveDNS 的 bool 只表达是否命中；调用侧必须保留 ctx.Err() 链，
// 避免服务停止/用户取消被误报为公共递归传播失败。
func recursiveDNSCheckError(ctx context.Context, fqdn string) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("recursive DNS propagation canceled for %s: %w", fqdn, ctx.Err())
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("recursive DNS propagation timeout for %s: %w", fqdn, ctx.Err())
	default:
		return fmt.Errorf("recursive DNS propagation failed for %s: record not visible on public resolvers", fqdn)
	}
}

// checkRecursiveDNS 是 RequireRecursiveDNS（ZeroSSL）路径的递归可见性二次确认，
// 语义**刻意弱于** waitForDNS 的递归共识放行，两者分层不得合并
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
// 两者解析器集合同源，但判定时机/窗口/语义不同，复用会把
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
			// 复用 waitForDNS 的并行探测——逐台串行时
			// 一台黑洞解析器（UDP/TCP 双 8s）会把单轮拖到 ~32s，120s 预算仅剩
			// ≈3 轮；并行后单轮上界≈单台最坏耗时。结果按输入顺序回填，命中即放行
			// （语义不变：任意 1 台可见）。
			for _, probe := range probeRecursiveParallel(ctx, propagationRecursiveResolvers, fqdn, expected) {
				if !probe.hit {
					continue
				}
				if i.Logger != nil {
					i.Logger.Log("waiting_propagation", fmt.Sprintf("递归 DNS 已命中 %s @ %s", fqdn, probe.resolver))
				}
				return true
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
	for _, probe := range probeDNSParallel(ctx, servers, fqdn, expected, false) {
		server := probe.resolver
		hit, found, err := probe.hit, probe.found, probe.err
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
// 仅在状态变化时输出（镜像 waitForValidation 的 lastChalStatus
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

// dnsProbeResult 单台权威/递归 DNS 的一轮探测结果。
type dnsProbeResult struct {
	resolver string
	hit      bool
	found    []string
	err      error
}

// probeDNSParallel 并行探测全部 DNS 服务器，按输入顺序回填结果。每台独立
// ctx 超时（propagationResolverProbeTimeout）——一台黑洞服务器不再把单轮
// 串行拖到其余服务器耗时之和。日志不在并发 goroutine 内写（Logger 非并发
// 契约），统一由调用方按结果顺序输出。
func probeDNSParallel(ctx context.Context, servers []string, fqdn, expected string, recursion bool) []dnsProbeResult {
	results := make([]dnsProbeResult, len(servers))
	var wg sync.WaitGroup
	for idx, server := range servers {
		wg.Add(1)
		go func(idx int, server string) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, propagationResolverProbeTimeout)
			defer cancel()
			hit, found, err := probeTXT(probeCtx, server, fqdn, expected, recursion)
			results[idx] = dnsProbeResult{resolver: server, hit: hit, found: found, err: err}
		}(idx, server)
	}
	wg.Wait()
	return results
}

// probeRecursiveParallel 保留递归探测语义入口，与权威探测共享同一并行实现。
func probeRecursiveParallel(ctx context.Context, resolvers []string, fqdn, expected string) []dnsProbeResult {
	return probeDNSParallel(ctx, resolvers, fqdn, expected, true)
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
		// 单台预算单源——probeDNSParallel 已为每台
		// 设置 propagationResolverProbeTimeout 独立 ctx，此处不再叠加第二个
		// 8s 硬编码（原实现 UDP+TCP 各 8s=16s，与接缝同名不同义：按接缝上调
		// 单台预算时实际仍被内层 16s 截断）。直接调用方（测试）须自带 deadline。
		r, _, err := c.ExchangeContext(ctx, m, server)
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
		// TC=1 的「成功」应答其 Answer 段不可信（UDP
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

// ipv6EgressAvailable 报告本机是否存在可用 IPv6 出口（测试缝：var 而非直接
// 调用，测试按固定答案替换；生产代码不得改写）。
var ipv6EgressAvailable = detectIPv6Egress

// detectIPv6Egress 用 UDP Dial 查询本机路由表：UDP 不发送报文，无 v6 地址/
// 默认路由时立即失败。探测目标为 Google Public DNS 的 v6 地址（无需可达——
// 仅需本机有 v6 路由）。
func detectIPv6Egress() bool {
	conn, err := net.DialTimeout("udp6", "[2001:4860:4860::8888]:53", time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// 权威 NS 发现的网络参数。UDP 查询无连接：丢包只表现为
// 超时，一次超时就让权威快路径在整个传播预算内静默关闭并退化为共识路径，
// 因此 NS 查询做有限重试（2 次 + 200ms 间隔，代价远小于退化的等待）。
const (
	authoritativeNSQueryTimeout = 5 * time.Second
	authoritativeNSAttempts     = 2
	authoritativeNSRetryDelay   = 200 * time.Millisecond
)

// dnsExchange 是权威 NS 发现的 DNS 交换接缝（测试注入固定应答，生产走真实
// 网络）。返回 nil 表示本次交换失败。包级变量——测试替换后不得并行复用。
var dnsExchange = exchangeDNSMessage

func exchangeDNSMessage(ctx context.Context, m *dns.Msg, network, addr string) *dns.Msg {
	client := &dns.Client{Net: network, Timeout: authoritativeNSQueryTimeout}
	r, _, err := client.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil
	}
	return r
}

// resolveAuthoritativeNS finds the authoritative name servers of fqdn's zone
// by walking up the domain labels and querying NS records through a public
// recursive resolver, then resolves the servers' addresses. // returns nil when the zone cannot be determined (and logs why once)。
func resolveAuthoritativeNS(ctx context.Context, fqdn, bootstrap string) []string {
	servers, reason := discoverAuthoritativeNS(ctx, fqdn, bootstrap)
	if reason != "" {
		// 失败留痕：原实现静默返回 nil——签发表里只剩
		// 30s 后那条「疑似 CNAME 委托/NS 变更」的误导性诊断，无法区分解析器
		// 丢包与真的没有权威。每次签发至多一条（本函数每次等待只调用一次）。
		logf("warn", "acme: 权威 NS 发现失败 %s: %s（本次签发按递归共识判定传播）", fqdn, reason)
	}
	return servers
}

// discoverAuthoritativeNS 是 resolveAuthoritativeNS 的实现体：返回可用权威
// 地址清单，或 nil + 失败原因（供调用方/包级日志使用）。
func discoverAuthoritativeNS(ctx context.Context, fqdn, bootstrap string) ([]string, string) {
	var failure string
	query := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(normalizeDNSName(name), qtype)
		m.RecursionDesired = true
		// EDNS0 4096：默认 512B UDP 载荷下 NS 应答容易被
		// 截断（TC=1 且 Answer 段整体为空），截断应答被当作 NODATA 会一路
		// 上溯到父域/顶级域，把别人的服务器当成本域权威。
		m.SetEdns0(4096, false)
		for attempt := 1; attempt <= authoritativeNSAttempts; attempt++ {
			if attempt > 1 {
				select {
				case <-ctx.Done():
					failure = "查询被取消: " + ctx.Err().Error()
					return nil
				case <-time.After(authoritativeNSRetryDelay):
				}
			}
			r := dnsExchange(ctx, m, "udp", bootstrap)
			if r != nil && r.Truncated {
				// TC=1：UDP 应答不可信（Answer 可能被整体丢弃），必须 TCP 重查。
				tcp := dnsExchange(ctx, m, "tcp", bootstrap)
				if tcp == nil {
					failure = fmt.Sprintf("%s %s 查询 UDP 应答被截断且 TCP 重查失败", m.Question[0].Name, dns.TypeToString[qtype])
					continue
				}
				r = tcp
			}
			if r == nil {
				failure = fmt.Sprintf("%s %s 查询超时或网络错误（第 %d 次）", m.Question[0].Name, dns.TypeToString[qtype], attempt)
				continue
			}
			if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
				failure = fmt.Sprintf("%s %s 查询返回 %s", m.Question[0].Name, dns.TypeToString[qtype], dns.RcodeToString[r.Rcode])
				continue
			}
			return r
		}
		return nil
	}

	// Walk up the labels until NS records are found, so delegated subdomains
	// resolve to their own zone's servers.
	labels := strings.Split(strings.TrimSuffix(normalizeDNSName(fqdn), "."), ".")
	zone := ""
	var nsNames []string
	for {
		labels = labels[1:]
		// 顶级域（单标签）不是任何 ACME 域名的区：宁可返回 nil 走共识路径，
		// 也不把 TLD 服务器当成该域权威（88-03 的误走父域形态）。
		if len(labels) < 2 {
			if len(nsNames) == 0 {
				failure = fmt.Sprintf("上溯至 %q 仍未发现 NS（%s 的区无法确定）", strings.Join(labels, "."), fqdn)
			}
			break
		}
		candidate := normalizeDNSName(strings.Join(labels, "."))
		// 公共后缀（多标签 co.uk/com.cn 与单标签 TLD）没有 ACME 归属：把它当
		// 本域区会把注册局服务器当成域名权威（authReady 恒假、传播判定退化成
		// 递归共识、诊断文案误导）。判据与 provider 侧 zone 解析同源
		// （dnsprovider.IsPublicSuffix，PSL 单源）。
		if dnsprovider.IsPublicSuffix(candidate) {
			continue
		}
		r := query(candidate, dns.TypeNS)
		if r == nil {
			return nil, failure
		}
		for _, ans := range r.Answer {
			ns, ok := ans.(*dns.NS)
			// 只接受「回答问题本身」的 NS（owner 必须等于被查询名）：应答段
			// 里混入的其他 owner（CNAME 目标、上级区权威）不是本域的权威。
			if !ok || !sameDNSName(ns.Hdr.Name, candidate) {
				continue
			}
			nsNames = append(nsNames, normalizeDNSName(ns.Ns))
		}
		if len(nsNames) > 0 {
			zone = candidate
			break
		}
		// SOA 停止条件：NOERROR/NODATA 且 Authority 段带
		// SOA 时，SOA owner 就是被查名字所属的区（可能已跳过若干标签）。直接
		// 在该区上重查 NS，比继续按标签上溯更准确——上溯会把父域甚至顶级域
		// 当成本域。
		parent := soaOwner(r)
		if parent == "" || sameDNSName(parent, candidate) || dnsprovider.IsPublicSuffix(parent) {
			continue
		}
		if !dns.IsSubDomain(parent, normalizeDNSName(fqdn)) {
			continue
		}
		soaReply := query(parent, dns.TypeNS)
		if soaReply == nil {
			return nil, failure
		}
		for _, ans := range soaReply.Answer {
			ns, ok := ans.(*dns.NS)
			if !ok || !sameDNSName(ns.Hdr.Name, parent) {
				continue
			}
			nsNames = append(nsNames, normalizeDNSName(ns.Ns))
		}
		if len(nsNames) > 0 {
			zone = parent
			break
		}
	}
	if len(nsNames) == 0 {
		if failure == "" {
			failure = fmt.Sprintf("%s 的权威 NS 未解析出来", fqdn)
		}
		return nil, failure
	}
	// 区后缀校验：发现的区必须是 fqdn 的后缀，否则应答来自
	// 与本挑战无关的区（污染/错误应答），其服务器不可能持有记录。
	// NS 主机名本身不做 fqdn 后缀约束：权威服务器合法地部署在区外
	// （如 *.ns.cloudflare.com），按后缀丢弃会把大量真实域名的快路径砍掉；
	// 防止误走父域由「owner 等于被查询名」「顶级域拒绝」「SOA 停止」共同保证。
	if !dns.IsSubDomain(zone, normalizeDNSName(fqdn)) {
		return nil, fmt.Sprintf("发现的区 %s 不是 %s 的后缀", zone, fqdn)
	}

	// Resolve addresses of each name server.
	seen := make(map[string]bool)
	var servers []string
	// 本机无 IPv6 出口时预筛 AAAA——纯 v6 权威在无 v6 出口
	// 网络里每台 UDP/TCP 双 8s 白耗，且 AAAA 查询本身也是无用往返。能力探测
	// 仅查本机路由表（UDP Dial 不发报文），不是网络可用性断言。
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	if !ipv6EgressAvailable() {
		qtypes = qtypes[:1]
	}
	for _, ns := range nsNames {
		for _, qtype := range qtypes {
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
	if len(servers) == 0 {
		// 区与 NS 都找到了、地址却一台都没解析出来：同样是「快路径静默关闭」，
		// 必须留痕（此前只在调用方表现为权威清单为空）。
		return nil, fmt.Sprintf("权威区 %s 的 NS（%s）地址解析全部失败", zone, strings.Join(nsNames, ", "))
	}
	return servers, ""
}

// normalizeDNSName 统一 FQDN 形态（去空白、小写、补末尾点）：DNS 名字大小写
// 不敏感，而应答里的 owner 大小写不可控，比较前必须归一。基础归一与挑战登记/
// 清理账本共用 dnsname.NormalizeName，本侧只额外补 FQDN 末尾点（权威应答
// 比较需要规范形态）。
func normalizeDNSName(name string) string {
	return dns.Fqdn(dnsname.NormalizeName(name))
}

// sameDNSName 归一后比较两个 DNS 名字。
func sameDNSName(a, b string) bool {
	return normalizeDNSName(a) == normalizeDNSName(b)
}

// soaOwner 返回应答里 SOA 记录的 owner（Answer 优先，其次 Authority 段）：
// 递归解析器对「不是委托点」的 NS 查询返回 NOERROR/NODATA + 所属区的 SOA。
func soaOwner(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*dns.SOA); ok {
				return normalizeDNSName(soa.Hdr.Name)
			}
		}
	}
	return ""
}
