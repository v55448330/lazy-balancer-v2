package dnspod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/dnsname"
	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

const apiBase = "https://dnsapi.cn/"

// logf 是包级日志接缝（镜像 ownership/acme 同型接缝）：运维告警
// 进入统一日志级别/格式链，而不是裸 log.Printf 另走一条链路。main 启动
// 早期经 SetLogf 装配；零值回退标准库。
var logf = func(level, format string, args ...any) { log.Printf(format, args...) }

// SetLogf 装配包级日志函数（main 启动早期调用；nil 忽略）。
func SetLogf(f func(level, format string, args ...any)) {
	if f != nil {
		logf = f
	}
}

// Domain.List 分页参数：length 上限 3000（超出强制分页），maxPages 仅防御
// 忽略 offset 的异常服务端，避免死循环。
const (
	domainListPageSize = 3000
	domainListMaxPages = 100
)

// ownedRecord 记录本实例创建的记录 ID 及其挑战值，CleanUpValue 据此只删
// 属于本次签发的记录。
type ownedRecord struct {
	recordID string
	value    string
}

// Provider implements dnsprovider.Provider for DNSPod (dnsapi.cn).
type Provider struct {
	// loginToken 凭据保持私有——导出字段任何一次 %+v/JSON 序列化即泄密。
	// 生产读取全部是包内直读（构造 API 请求、缓存键派生）；本包不提供凭据
	// 访问器，日志/序列化形态走 String()（只暴露账户摘要）。
	loginToken string
	client     *http.Client
	mu         sync.Mutex
	owned      map[string][]ownedRecord
	ownership  *ownership.Store
	// account 是本实例凭据的账户摘要，写入所有权条目并参与
	// 清理归属判定：换凭据后旧条目的 record_id 属于另一个账户，按它删除会
	// 命中新账户下的无关记录。
	account string
}

// String 脱敏形态：只暴露账户摘要，任何日志/序列化路径不得回显凭据。
func (p *Provider) String() string { return "dnspod.Provider{account:" + p.account + "}" }

func NewPersistent(loginToken, dataDir string) (*Provider, error) {
	store, err := ownership.New(dataDir)
	if err != nil {
		return nil, err
	}
	provider := New(loginToken)
	provider.ownership = store
	return provider, nil
}

// New creates a DNSPod provider. loginToken must be "id,key" format.
func New(loginToken string) *Provider {
	return &Provider{
		loginToken: loginToken,
		client: &http.Client{
			// 覆盖整个重试包络（3 次尝试 + 每次至多 30s 退避/
			// 等待计入同一 RoundTrip），不能把退火循环中途掐断
			Timeout: 90 * time.Second,
			// 429/5xx 重试在传输层统一处理，瞬时 API 故障不再直接打挂挑战
			Transport: &retry.Transport{},
		},
		owned: make(map[string][]ownedRecord),
		// 账户身份由凭据派生（不落明文）：LoginToken 轮换即视为换账户，
		// 旧条目转为不可按 ID 删除（保守方向，见 ownership.DecideRemoval）。
		account: ownership.AccountDigest(loginToken),
	}
}

// Present creates a distinct _acme-challenge TXT record (no upsert): a repeated
// Present for the same name adds another record, and cleanup removes records by
// ownership record ID / value.
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	// zone 与 tokenFQDN 都按 dnsname 单源归一后再派生相对子域：DNS 名大小写
	// 不敏感，保存前探针的 FQDN 可能保留输入原样（`Example.COM`），大小写敏感
	// 的后缀比较会把整个 FQDN 当成 sub_domain 写进 API（TXT 落到错误名字）。
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	domainID, err := p.getDomainID(ctx, zone)
	if err != nil {
		return err
	}
	recordID, err := p.createRecord(ctx, domainID, subDomain, value, ttl)
	if errors.Is(err, errStaleDomainID) {
		// 缓存的 zone→domain_id 可能陈旧（域名被移出
		// 账户/删除后重建，新 ID 与缓存不符），Record.Create 报「域名不存在」类
		// 错误——作废该 zone 缓存重解析一次并重试一次；重解析或重试失败按最新
		// 错误返回，不循环（域名真正移出时重解析即失败，见
		// TestProvider_Present_staleCacheRetryStopsWhenDomainGone）。
		p.invalidateDomainIDCache(zone)
		freshID, resolveErr := p.getDomainID(ctx, zone)
		if resolveErr != nil {
			return resolveErr
		}
		recordID, err = p.createRecord(ctx, freshID, subDomain, value, ttl)
		if err == nil {
			// 自愈重试成功后回写 domainID=freshID（与
			// cleanUp deleteOne 的回写对称）——否则 ownership 回滚删除
			// 与内存 owned 键仍打向陈旧 ID（删除必败/TXT 泄漏、CleanUp 键
			// 不匹配静默零删除残留）。
			domainID = freshID
		}
	}
	if err != nil {
		return err
	}
	if p.ownership != nil {
		record := ownership.Record{Provider: "dnspod", Zone: zone, FQDN: tokenFQDN, Value: value, RecordID: recordID, Account: p.account}
		if err := p.ownership.Add(record); err != nil {
			rollbackErr := p.deleteRecord(ctx, domainID, recordID)
			if rollbackErr != nil {
				// ownership.Add 失败且回滚删除亦失败——TXT 已落
				// DNS，而 ownership 无条目可追踪（「删除失败不 Remove」的前提不
				// 成立）。告警留痕 + 回填内存兜底表：cleanUp 的 ownership 分支会
				// 排空兜底表并重试删除，避免该记录永久残留（无追踪窗口收口）。
				logf("warn", "dnspod: 所有权写入失败且回滚删除失败，TXT %s (recordID=%s) 可能残留: %v", tokenFQDN, recordID, rollbackErr)
				p.mu.Lock()
				p.owned[domainID+"|"+subDomain] = append(p.owned[domainID+"|"+subDomain], ownedRecord{recordID: recordID, value: value})
				p.mu.Unlock()
			}
			return errors.Join(err, rollbackErr)
		}
	} else {
		p.mu.Lock()
		p.owned[domainID+"|"+subDomain] = append(p.owned[domainID+"|"+subDomain], ownedRecord{recordID: recordID, value: value})
		p.mu.Unlock()
	}
	return nil
}

// CleanUp removes the _acme-challenge TXT record.
func (p *Provider) CleanUp(ctx context.Context, zone, tokenFQDN string) error {
	return p.cleanUp(ctx, zone, tokenFQDN, "", false)
}

// CleanUpValue removes only the record this issuance created (same challenge
// value), plus legacy/stale leftovers under the same name; a concurrent
// issuance's recent record of another value is spared.
//
// 空值必须 fail-fast：ownership 路径的 MatchingValue("") 会委托给按名匹配
// （命中同名全部记录），而内存兜底路径只选空值条目——同一入参两种语义，
// 一旦未来出现空值调用方，前者会删掉并发挑战的 TXT。按名清理只属于 CleanUp。
func (p *Provider) CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("按值清理必须提供非空挑战值（按名清空请使用 CleanUp）")
	}
	return p.cleanUp(ctx, zone, tokenFQDN, value, true)
}

// CountCleanupRecords 实现 dnsprovider.CleanupCounter：纯本地计数一次按值
// 清理将选中的记录条数（ownership 账本 MatchingValue + 内存兜底表条目）。
// 兜底表键含 domain_id，计数按 "|"+subDomain 后缀跨键聚合（避免为计数引入
// getDomainID 网络解析；跨 zone 同名子域的少量多计只会让预算偏大，方向安全）。
func (p *Provider) CountCleanupRecords(zone, tokenFQDN, value string) int {
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)
	p.mu.Lock()
	fallback := 0
	for key, entries := range p.owned {
		if !strings.HasSuffix(key, "|"+subDomain) {
			continue
		}
		for _, entry := range entries {
			if value == "" || entry.value == value {
				fallback++
			}
		}
	}
	p.mu.Unlock()
	if p.ownership == nil {
		return fallback
	}
	records, err := p.ownership.MatchingValue("dnspod", zone, tokenFQDN, value)
	if err != nil {
		// 账本读失败按至少 1 条计——预算宁大勿小（清理本身会再上抛该错误）。
		return max(fallback, 1)
	}
	return len(records) + fallback
}

// cleanUp 是 CleanUp/CleanUpValue 的共享实现（按值定向删除+陈旧条目清理）。
//
// 本函数与 internal/dnsprovider/tencent/tencent.go 的
// cleanUp 是同构双实现（有意保留——两者底层 SDK/记录 ID 类型不同，抽象共享
// 收益低于耦合成本）。任一侧修改删除/自愈/兜底排空逻辑时，MUST 同步另一侧
// 并保持语义一致（domain-id 自愈、ownership 条目留存、兜底排空）。
func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN, value string, byValue bool) error {
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	domainID, err := p.getDomainID(ctx, zone)
	if err != nil {
		return err
	}

	key := domainID + "|" + subDomain
	var records []ownership.Record
	var memorySelected []ownedRecord
	if p.ownership != nil {
		if byValue {
			records, err = p.ownership.MatchingValue("dnspod", zone, tokenFQDN, value)
		} else {
			records, err = p.ownership.Matching("dnspod", zone, tokenFQDN)
		}
		if err != nil {
			return err
		}
	} else {
		p.mu.Lock()
		entries := p.owned[key]
		kept := make([]ownedRecord, 0, len(entries))
		for _, entry := range entries {
			if byValue && entry.value != value {
				kept = append(kept, entry)
				continue
			}
			memorySelected = append(memorySelected, entry)
		}
		p.owned[key] = kept
		p.mu.Unlock()
	}

	var cleanupErr error
	var failed []ownedRecord
	deleteOne := func(recordID, value string) error {
		err := p.deleteRecord(ctx, domainID, recordID)
		if errors.Is(err, errStaleDomainID) {
			// cleanUp 侧的同族自愈——缓存的
			// zone→domain_id 陈旧（域名移出账户/删除重建）时删除对旧 ID 报
			// 「域名不存在」类错误。作废缓存重解析一次并重试一次；重解析
			// 或重试失败照旧记 failed，不循环。
			p.invalidateDomainIDCache(zone)
			freshID, resolveErr := p.getDomainID(ctx, zone)
			if resolveErr != nil {
				err = errors.Join(err, resolveErr)
			} else {
				// 自愈换新 domain_id 后 bookkeeping 键
				// 随之换代——残留旧键条目（kept 未选中之值/failed 回填/ownership
				// 模式的兜底表条目）同步迁移新键。否则后续 cleanUp/Present 按新键
				// 查找，旧键条目永不可达，「failed 回填供后续清理重试」失效。
				// 兜底表 p.owned 在 ownership 模式同样以 domainID+"|"+subDomain
				// 为键（Present 双失败回填/排空失败回填），故迁移不区分模式。
				p.mu.Lock()
				if freshKey := freshID + "|" + subDomain; freshKey != key {
					p.owned[freshKey] = append(p.owned[freshKey], p.owned[key]...)
					delete(p.owned, key)
					key = freshKey
				}
				p.mu.Unlock()
				domainID = freshID
				err = p.deleteRecord(ctx, freshID, recordID)
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				// 与 tencent deleteOne 同口径
				//——ctx 取消/超时并入错误链，保留原始 provider 错误（整体覆写
				// 会丢失具体 API 失败原因，诊断信息归零）。
				err = errors.Join(err, ctx.Err())
			}
			if p.ownership == nil {
				// failed 的唯一消费点是下方 ownership==nil 的 owned
				// 回填；ownership 模式下失败条目由 ownership 留存（删除失败
				// 不 Remove），不再写入死存储。
				// 回填必须保留 challenge value——后续按值
				// 清理（CleanUpValue）以 entry.value 过滤，空值条目永不被选中重试。
				failed = append(failed, ownedRecord{recordID: recordID, value: value})
			}
			cleanupErr = errors.Join(cleanupErr, err)
			return err
		}
		return nil
	}
	if p.ownership != nil {
		// 批量收敛：成功删除/判定丢弃的条目攒批，循环结束后一次
		// RemoveMany（单次全量重写+fsync）——逐条 Remove 的代价是
		// O(账本大小) 字节 × 条目数。中途崩溃只让已删记录的条目多留一轮
		// （下次清理命中 code 8 幂等删除后再移除），收敛语义不变。
		var removable []ownership.Record
		for _, record := range records {
			// 账户归属先于删除。换凭据后旧账户遗留条目仍按
			// name/value 被选中，但 record_id 属于旧账户——在新账户里可能指向
			// 同域无关记录，删除即数据面损失。此类条目只丢弃本地所有权条目并
			// 留痕（TXT 若仍在旧账户则永远不可达，属已知代价）。
			if ownership.DecideRemoval(record, p.account, time.Now()) == ownership.DispositionDrop {
				logf("warn", "dnspod: 所有权条目无法归属当前账户（%s, recordID=%s, account=%q），仅丢弃本地条目、不调用删除", tokenFQDN, record.RecordID, record.Account)
				removable = append(removable, record)
				continue
			}
			// independence: a record whose deletion failed keeps
			// its ownership entry (the DNS record may still exist), but an
			// earlier miss must not skip removal for records that WERE
			// deleted — that orphans them until self-heal.
			if deleteOne(record.RecordID, record.Value) != nil {
				continue
			}
			removable = append(removable, record)
		}
		cleanupErr = errors.Join(cleanupErr, p.ownership.RemoveMany(removable))
		// 兜底排空：Present 在「ownership.Add 失败 + 回滚删除
		// 失败」时把 recordID 回填进内存兜底表（store 无条目可追踪）。此处重试
		// 删除这些兜底条目——成功即清除，失败回填供下次重试（幂等）。store 模式
		// 下 p.owned 仅承载该兜底回填，正常路径为空，排空不影响既有语义。
		p.mu.Lock()
		fallback := p.owned[key]
		delete(p.owned, key)
		p.mu.Unlock()
		for _, entry := range fallback {
			if deleteOne(entry.recordID, entry.value) != nil {
				p.mu.Lock()
				p.owned[key] = append(p.owned[key], entry)
				p.mu.Unlock()
			}
		}
	} else {
		for _, entry := range memorySelected {
			deleteOne(entry.recordID, entry.value)
		}
	}
	if p.ownership == nil && len(failed) > 0 {
		p.mu.Lock()
		p.owned[key] = append(p.owned[key], failed...)
		p.mu.Unlock()
	}
	return cleanupErr
}

type apiStatus struct {
	Code    json.Number `json:"code"`
	Message string      `json:"message"`
}

// httpErrorBodyLimit 是 HTTP 错误响应体在错误文案中的取样上限（字节）。
const httpErrorBodyLimit = 512

func (p *Provider) apiCall(ctx context.Context, method string, params url.Values, result interface{}) error {
	params.Set("login_token", p.loginToken)
	params.Set("format", "json")
	if params.Get("lang") == "" {
		params.Set("lang", "cn")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+method, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "lazy-balancer/2.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// HTTP 状态码判定先于体内 status.code。retry.Transport
	// 重试耗尽后的 5xx/429 若恰好带回可解析 JSON（网关兜底体/厂商错误体），
	// 原实现解码成功即 return nil，记录内 code 被当业务判定——Record.Remove
	// 遇到「5xx + code:"1"」会被认作删除成功，所有权条目被清而 TXT 仍留在
	// DNS（残留且脱离追踪）。错误体只取样前 512 字节：网关错误页可达数百 KB，
	// 整读既无诊断增量又可能把响应体读进内存。
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, httpErrorBodyLimit))
		return fmt.Errorf("%s failed: HTTP %d: %s", method, resp.StatusCode, sanitizeHTTPErrorBody(string(body), p.loginToken))
	}
	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			// 网关返回 HTML/空体（502/503）时原文案
			// 「decode response: invalid character '<'…」丢失状态码与动作名，
			// 排障只能翻 network 日志。429/5xx 已由 retry.Transport 吸收，
			// 这里是最终失败形态——状态码与方法名必须自明。
			return fmt.Errorf("decode %s response (HTTP %d): %w", method, resp.StatusCode, err)
		}
	}
	return nil
}

// credentialEchoPattern 匹配中间网关/WAF 拦截页可能回声的凭据形态：表单
// （login_token=<id>,<key>）、URL 查询式与 JSON 键值（"login_token": "…"）。
// 形态正则只是兜底——真正的保证来自按已知凭据明文的定向替换（见
// sanitizeHTTPErrorBody），形态不匹配时宁可整段丢弃。
var credentialEchoPattern = regexp.MustCompile(`(?i)(login_token\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&;"'}\]]+)`)

// credentialEchoSecretMinLen 是凭据分段参与定向替换的最小长度：login_token
// 为 "id,key" 形态，任一分段被单独回声都等价于泄露，但过短的分段（如短 ID）
// 在任意文案里全局替换会伤及排障上下文，故只纳充分长的分段。
const credentialEchoSecretMinLen = 8

// credentialEchoSecrets 展开一段凭据的全部已知明文形态：完整值 + 各分段
// （逗号/空白分隔），排除过短分段。返回顺序保持「长值在前」，定向替换先命中
// 完整值再兜分段，避免同一片段被重复替换成多重掩码。
func credentialEchoSecrets(secret string) []string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	secrets := []string{secret}
	for _, part := range strings.FieldsFunc(secret, func(r rune) bool {
		return r == ',' || r == '\t' || r == '\n' || r == ' ' || r == ';'
	}) {
		part = strings.TrimSpace(part)
		if len(part) >= credentialEchoSecretMinLen && part != secret {
			secrets = append(secrets, part)
		}
	}
	return secrets
}

// sanitizeHTTPErrorBody 脱敏错误文案：先按已知凭据明文（variadic secrets）做
// 定向替换，再用形态正则兜底，与回声的编码形态无关。两者都没覆盖到的残余
// 凭据痕迹（login_token 字样存在但无掩码）或已知明文残留一律整段丢弃
// （fail-closed，只保留长度指纹）——凭据不进日志优先于排障原文。
func sanitizeHTTPErrorBody(body string, secrets ...string) string {
	redacted := body
	for _, secret := range secrets {
		for _, known := range credentialEchoSecrets(secret) {
			redacted = strings.ReplaceAll(redacted, known, "***")
		}
	}
	redacted = credentialEchoPattern.ReplaceAllString(redacted, "${1}***")
	for _, secret := range secrets {
		for _, known := range credentialEchoSecrets(secret) {
			if strings.Contains(redacted, known) {
				return fmt.Sprintf("[response body withheld: %d bytes]", len(body))
			}
		}
	}
	if strings.Contains(strings.ToLower(redacted), "login_token") && !strings.Contains(redacted, "***") {
		return fmt.Sprintf("[response body withheld: %d bytes]", len(body))
	}
	return strings.TrimSpace(redacted)
}

// sanitizeMessage 让业务层 status.message（厂商/中间网关可能回声凭据）与
// HTTP 错误体共用同一脱敏口径：所有拼进错误链的外部文本都必须经过本包装。
func (p *Provider) sanitizeMessage(message string) string {
	return sanitizeHTTPErrorBody(message, p.loginToken)
}

// flexNumber 接受 DNSPod 数字字段的历史两种形态（JSON 数字与带引号字符串）。
type flexNumber string

func (n *flexNumber) UnmarshalJSON(data []byte) error {
	*n = flexNumber(strings.Trim(string(data), `"`))
	return nil
}

// Int64 尽力解析；缺失/不可解析时返回 0（注释如实化
// 调用处的翻页终止实际由 len(domains)==0 独立兜底，total=0 永不命中
// total>0 分支——0 值语义是「不参与判定」而非「未知总量」）。
func (n flexNumber) Int64() int64 {
	value, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// errStaleDomainID 标记 Record.Create/Record.Remove 返回的「域名不存在/ID 失效」
// 类错误：缓存的 zone→domain_id 因域名移出账户/删除重建而
// 陈旧时由 Present 与 cleanUp 捕获，作废缓存重解析后重试一次。
var errStaleDomainID = errors.New("dnspod: 域名 ID 已失效")

// isDomainGoneStatus 判定 dnsapi.cn 状态是否属于「域名 ID 失效」类：code 6
// （Record.Remove/List 的 Invalid domain id / 域名ID错误），或消息显式含
// 域名缺失字样（apiCall 固定 lang=cn，消息为中文）。
// code 7 一律是「没有权限」（官方码表：Create/Remove 的 7=You don't have the
// permission），曾误入本分类——受限 Token 下权限拒绝被当成域名消失，触发
// 缓存作废 + 全量 Domain.List 重扫 + 重复写/删。权限错误的真实「域名不存在」
// 由消息字样分支命中，无需 code 7 快路径。
func isDomainGoneStatus(code, message string) bool {
	if code == "6" {
		return true
	}
	return strings.Contains(message, "域名不存在") ||
		strings.Contains(message, "域名ID错误") ||
		strings.Contains(message, "域名 ID 错误")
}

// invalidateDomainIDCache 作废本账户单个 zone 的缓存映射（键含账户摘要，
// 自此只能作废本账户的条目；正负缓存与 LRU 使用序一并清除——配置变更/
// errStaleDomainID 自愈后的下一次解析必须重新发起 Domain.List，负缓存不得
// 拦住重新核实）。
func (p *Provider) invalidateDomainIDCache(zone string) {
	domainIDCacheMu.Lock()
	key := p.domainIDCacheKey(zone)
	delete(domainIDCache, key)
	delete(domainIDNegativeCache, key)
	for i, k := range domainIDCacheOrder {
		if k == key {
			domainIDCacheOrder = append(domainIDCacheOrder[:i], domainIDCacheOrder[i+1:]...)
			break
		}
	}
	domainIDCacheMu.Unlock()
}

// domainIDCache:账户+zone→domain_id 进程内缓存——签发/续签的每次
// Present/CleanUp 都要解析 zone 的 domain_id,分页遍历 Domain.List 在多
// 域名/多任务并发下重复全额扫描;zone→id 映射在账户内稳定,命中即省。
// 键必须含账户（login_token 的 sha256 前 8 位十六
// 进制）——同进程可配置多条 DNS 凭证（多账户），裸 zone 键会让账户 B 首调
// 即命中账户 A 缓存的 domain_id；token 不落明文键（缓存转储/调试可读）。
// 容量与淘汰：进程级缓存必须有上限——domainIDCacheCapacity（LRU，命中触碰）
// 封顶正+负缓存总条目，超出淘汰最久未用键。domainIDNegativeCache 是负缓存
// （键同正缓存 → 最近一次「确认不存在」时刻）：误填/已移出账户的 zone 若
// 不落负缓存，每次 Present/CleanUp/Validate 都重新全量分页扫 Domain.List，
// 叠加重试会把配置错误放大成厂商限流。TTL 取短（domainIDNegativeTTL）：
// zone 后补进账户的收敛延迟上限即 TTL；过期条目读时惰性清除。
var (
	domainIDCacheMu       sync.Mutex
	domainIDCache         = map[string]string{}
	domainIDNegativeCache = map[string]time.Time{}
	domainIDCacheOrder    []string
)

// domainIDCacheCapacity 是正+负缓存合并的 LRU 容量上限：单进程数千 zone 已
// 远超真实部署面（每个 zone 只在签发/续签时解析），上限只为防无界增长。
const domainIDCacheCapacity = 1024

// domainIDNegativeTTL 是负缓存条目的存活时长：60s 短 TTL——账户内 zone→id
// 映射稳定（负缓存只拦「确认不存在」的重复扫描），但 zone 可能被补进账户，
// 收敛延迟上限即本值。var 供测试收窄。
var domainIDNegativeTTL = 60 * time.Second

// domainIDCacheKey 返回本账户隔离的缓存键：AccountDigest(loginToken)（16 位
// 十六进制）+ "|" + zone。摘要口径与 ownership.AccountDigest 单源——缓存隔离
// 与所有权账户身份必须由同一凭据派生，两处各自求值会出现「缓存按账户隔离、
// 所有权按另一账户身份判定」的漂移。
func (p *Provider) domainIDCacheKey(zone string) string {
	return ownership.AccountDigest(p.loginToken) + "|" + zone
}

// domainIDCacheTouchLRU 把键移到使用序队尾（调用方持 domainIDCacheMu）。
func domainIDCacheTouchLRU(key string) {
	for i, k := range domainIDCacheOrder {
		if k == key {
			domainIDCacheOrder = append(domainIDCacheOrder[:i], domainIDCacheOrder[i+1:]...)
			break
		}
	}
	domainIDCacheOrder = append(domainIDCacheOrder, key)
}

// domainIDCacheEvictLRU 容量淘汰：正+负缓存合并计数，从使用序队首逐出
// （调用方持 domainIDCacheMu）。
func domainIDCacheEvictLRU() {
	for len(domainIDCacheOrder) > domainIDCacheCapacity {
		oldest := domainIDCacheOrder[0]
		domainIDCacheOrder = domainIDCacheOrder[1:]
		delete(domainIDCache, oldest)
		delete(domainIDNegativeCache, oldest)
	}
}

// getDomainIDCache 读正缓存并触碰 LRU（生产读路径与测试共用）。
func (p *Provider) getDomainIDCache(key string) (string, bool) {
	domainIDCacheMu.Lock()
	defer domainIDCacheMu.Unlock()
	id, ok := domainIDCache[key]
	if ok {
		domainIDCacheTouchLRU(key)
	}
	return id, ok
}

// putDomainIDCache 写正缓存（清除同键负缓存）并触碰 LRU+容量淘汰
// （生产写路径与测试共用）。
func (p *Provider) putDomainIDCache(key, id string) {
	domainIDCacheMu.Lock()
	defer domainIDCacheMu.Unlock()
	delete(domainIDNegativeCache, key)
	domainIDCache[key] = id
	domainIDCacheTouchLRU(key)
	domainIDCacheEvictLRU()
}

func (p *Provider) getDomainID(ctx context.Context, zone string) (string, error) {
	// DNS 名大小写不敏感（与 ResolveZone/dnsname 单源同口径）：Domain.List 返回
	// 服务端规范形态（小写），输入侧归一后才能真正命中；缓存键随之归一，同一
	// zone 的不同书写形态不再各存一份 domain_id。
	zone = dnsname.NormalizeName(zone)
	cacheKey := p.domainIDCacheKey(zone)
	if id, ok := p.getDomainIDCache(cacheKey); ok {
		return id, nil
	}
	domainIDCacheMu.Lock()
	failedAt, negHit := domainIDNegativeCache[cacheKey]
	if negHit && time.Since(failedAt) >= domainIDNegativeTTL {
		// 负缓存过期即惰性清除，等价 miss。
		delete(domainIDNegativeCache, cacheKey)
		negHit = false
	}
	if negHit {
		domainIDCacheTouchLRU(cacheKey)
		domainIDCacheMu.Unlock()
		return "", fmt.Errorf("domain %s not found", zone)
	}
	domainIDCacheMu.Unlock()
	offset := 0
	for page := 0; page < domainListMaxPages; page++ {
		params := url.Values{}
		params.Set("offset", strconv.Itoa(offset))
		params.Set("length", strconv.Itoa(domainListPageSize))
		var result struct {
			Status  apiStatus `json:"status"`
			Domains []struct {
				ID   json.Number `json:"id"`
				Name string      `json:"name"`
			} `json:"domains"`
			Info struct {
				DomainTotal flexNumber `json:"domain_total"`
			} `json:"info"`
		}
		if err := p.apiCall(ctx, "Domain.List", params, &result); err != nil {
			return "", err
		}
		if result.Status.Code.String() != "1" {
			return "", fmt.Errorf("Domain.List failed: %s", p.sanitizeMessage(result.Status.Message))
		}
		for _, d := range result.Domains {
			// 两侧归一后再比较：服务端规范形态当前是小写，但依赖该实现细节会让
			// 「返回形态变化」静默变成「域名不在账户」的错误结论。
			if dnsname.NormalizeName(d.Name) == zone {
				id := d.ID.String()
				p.putDomainIDCache(cacheKey, id)
				return id, nil
			}
		}
		// 服务端可能按更小的页容量返回：按实际返回条数推进 offset，
		// 用 info.domain_total 判定是否已扫完。
		offset += len(result.Domains)
		total := result.Info.DomainTotal.Int64()
		if len(result.Domains) == 0 || (total > 0 && int64(offset) >= total) {
			break
		}
	}
	// 全量扫描终态「域名不在账户」才落负缓存——瞬时 API 失败（网络/5xx）不落，
	// 否则把瞬时故障放大成 TTL 内的持续失败。
	domainIDCacheMu.Lock()
	domainIDNegativeCache[cacheKey] = time.Now()
	domainIDCacheTouchLRU(cacheKey)
	domainIDCacheEvictLRU()
	domainIDCacheMu.Unlock()
	return "", fmt.Errorf("domain %s not found", zone)
}

func (p *Provider) createRecord(ctx context.Context, domainID, subDomain, value string, ttl int) (string, error) {
	params := url.Values{}
	params.Set("domain_id", domainID)
	params.Set("sub_domain", subDomain)
	params.Set("record_type", "TXT")
	params.Set("record_line", "默认")
	params.Set("value", value)
	params.Set("ttl", strconv.Itoa(ttl))

	var result struct {
		Status apiStatus `json:"status"`
		Record struct {
			ID json.Number `json:"id"`
		} `json:"record"`
	}
	if err := p.apiCall(ctx, "Record.Create", params, &result); err != nil {
		return "", err
	}
	if result.Status.Code.String() != "1" {
		err := fmt.Errorf("Record.Create failed: %s", p.sanitizeMessage(result.Status.Message))
		if isDomainGoneStatus(result.Status.Code.String(), result.Status.Message) {
			// 标记「域名不存在」类错误，供 Present 作废缓存重试。
			err = errors.Join(err, errStaleDomainID)
		}
		return "", err
	}
	if result.Record.ID.String() == "" {
		return "", fmt.Errorf("Record.Create returned no record ID")
	}
	return result.Record.ID.String(), nil
}

func (p *Provider) deleteRecord(ctx context.Context, domainID, recordID string) error {
	params := url.Values{}
	params.Set("domain_id", domainID)
	params.Set("record_id", recordID)

	var result struct {
		Status apiStatus `json:"status"`
	}
	if err := p.apiCall(ctx, "Record.Remove", params, &result); err != nil {
		return err
	}
	switch result.Status.Code.String() {
	case "1":
		return nil
	case "8":
		// 记录ID错误（记录已不存在）：按删除成功处理，保证清理幂等
		return nil
	}
	err := fmt.Errorf("Record.Remove failed: %s", p.sanitizeMessage(result.Status.Message))
	if isDomainGoneStatus(result.Status.Code.String(), result.Status.Message) {
		// 与 createRecord 同判据标记「域名不存在」类
		// 错误，供 cleanUp 作废缓存重试（Present 侧自愈的删除侧对偶）。
		err = errors.Join(err, errStaleDomainID)
	}
	return err
}
