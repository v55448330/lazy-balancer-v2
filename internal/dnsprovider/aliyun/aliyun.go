// Package aliyun implements dnsprovider.Provider for Alibaba Cloud DNS
// (Alidns) over the ACS3-HMAC-SHA256 signed RPC API。手写签名客户端（零新依赖）：
// 端点 https://alidns.aliyuncs.com（全局服务，无 region），凭据为 RAM
// AccessKey 对（授权 AliyunDNSFullAccess）。
//
// cleanUp 与 internal/dnsprovider/dnspod/dnspod.go、
// internal/dnsprovider/tencent/tencent.go 是同构多实现（有意保留——底层 API
// 与记录 ID 类型不同）。任一侧修改删除/留痕/兜底排空逻辑时，MUST 同步其他
// 侧并保持语义一致（对齐门禁见 cleanup_parity_test.go）。
package aliyun

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/dnsname"
	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// logf 是包级日志接缝（镜像 tencent/dnspod 同型接缝）：运维告警进入统一
// 日志级别/格式链，而不是裸 log.Printf 另走一条链路。main 启动早期经
// SetLogf 装配；零值回退标准库。
var logf = func(level, format string, args ...any) { log.Printf(format, args...) }

// SetLogf 装配包级日志函数（main 启动早期调用；nil 忽略）。
func SetLogf(f func(level, format string, args ...any)) {
	if f != nil {
		logf = f
	}
}

const (
	// apiEndpoint 是 Alidns 全局服务端点（云解析 DNS 无 region 维度）。
	apiEndpoint = "https://alidns.aliyuncs.com"
	// apiVersion 是 Alidns 的 x-acs-version。
	apiVersion = "2015-01-09"
	// signAlgorithm 是 ACS3 V3 签名算法标识（当前唯一取值）。
	signAlgorithm = "ACS3-HMAC-SHA256"
	// challengeKeyword 是挑战记录的 RR 前缀：DescribeDomainRecords 的
	// KeyWord 服务端过滤词，客户端再按 RR 精确匹配收窄。
	challengeKeyword = "_acme-challenge"
	// challengeListPageSize / challengeListPageLimit 是兜底枚举的翻页参数
	// 与页数上限（上限只防异常巨量下的失控翻页；KeyWord 过滤后通常单页）。
	challengeListPageSize  = 100
	challengeListPageLimit = 20
	// responseReadLimit 是单响应体的读取上限（DescribeDomainRecords 单页
	// 百条远小于此；上限只防异常响应撑爆内存）。
	responseReadLimit = 1 << 20
	// throttlingBodyProbeLimit 是限流判定读取错误体的上限（限流错误体
	// 数百字节；上限只防异常巨体）。
	throttlingBodyProbeLimit = 8 << 10
)

// signedHeaders 是本客户端全部参与签名的公共请求头（固定集合，按名升序）。
const signedHeaders = "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"

// ownedRecord 记录本实例创建的记录 ID 及其挑战值，CleanUpValue 据此只删
// 属于本次签发的记录。
type ownedRecord struct {
	recordID uint64
	value    string
}

// Provider implements dnsprovider.Provider for Alibaba Cloud DNS.
type Provider struct {
	// accessKeyID/accessKeySecret 凭据保持私有（与 dnspod/tencent 同口径）——
	// 导出字段任何一次 %+v/JSON 序列化即泄密。生产读取全部是包内直读（构造
	// 签名）；本包不提供凭据访问器，日志/序列化形态走 String()（只暴露账户
	// 摘要）。
	accessKeyID     string
	accessKeySecret string
	httpClient      *http.Client
	// endpoint 默认 apiEndpoint；测试注入 httptest 端点（签名按实际 host 计算）。
	endpoint  string
	mu        sync.Mutex
	owned     map[string][]ownedRecord
	ownership *ownership.Store
	// account 是本实例凭据的账户摘要，写入所有权条目并参与清理归属判定：
	// 换凭据后旧条目的 record_id 属于另一个账户，按它删除会命中新账户下的
	// 无关记录。
	account string
}

// String 脱敏形态：只暴露账户摘要，任何日志/序列化路径不得回显凭据。
func (p *Provider) String() string { return "aliyun.Provider{account:" + p.account + "}" }

// NewPersistent 构造带所有权账本的 provider（签发链入口）。
func NewPersistent(accessKeyID, accessKeySecret, dataDir string) (*Provider, error) {
	provider, err := New(accessKeyID, accessKeySecret)
	if err != nil {
		return nil, err
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		return nil, err
	}
	provider.ownership = store
	return provider, nil
}

// New creates an Alibaba Cloud DNS provider.
func New(accessKeyID, accessKeySecret string) (*Provider, error) {
	// 限流改写 + 429/5xx 重试在传输层统一处理，瞬时 API 故障不再直接打挂
	// 挑战；Timeout 覆盖整个重试包络（3 次尝试 + 每次至多 30s 退避，与
	// tencent 侧 90s 口径一致——SDK 默认 60s 会在包络内掐断）。
	return &Provider{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		httpClient: &http.Client{
			Timeout:   90 * time.Second,
			Transport: &retry.Transport{Base: &throttlingTransport{base: http.DefaultTransport}},
		},
		endpoint: apiEndpoint,
		owned:    make(map[string][]ownedRecord),
		// 账户身份由凭据对派生（不落明文）：「同一个域换另一账户的密钥」是
		// 清理归属缺陷的触发形态，AccessKeySecret 轮换同样按换账户处理（保守
		// 方向，见 ownership.DecideRemoval）。
		account: ownership.AccountDigest(accessKeyID + "\x00" + accessKeySecret),
	}, nil
}

// Present creates a distinct _acme-challenge TXT record (no upsert): a repeated
// Present for the same name adds another record, and cleanup removes records by
// ownership record ID / value.
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	// zone 与 tokenFQDN 都按 dnsname 单源归一后再派生相对子域（与
	// dnspod/tencent 侧同一实现）：大小写敏感的后缀比较会把混合大小写 FQDN
	// 整体当成 RR。
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	recordID, err := p.createRecord(ctx, zone, subDomain, value, ttl)
	if err != nil {
		return err
	}
	if p.ownership != nil {
		record := ownership.Record{Provider: "aliyun", Zone: zone, FQDN: tokenFQDN, Value: value, RecordID: strconv.FormatUint(recordID, 10), Account: p.account}
		if err := p.ownership.Add(record); err != nil {
			rollbackErr := p.deleteRecord(ctx, zone, recordID)
			if rollbackErr != nil {
				// ownership.Add 失败且回滚删除亦失败——TXT 已落 DNS，而
				// ownership 无条目可追踪。告警留痕 + 回填内存兜底表：cleanUp
				// 的兜底排空会重试删除，避免永久残留。
				logf("warn", "aliyun: 所有权写入失败且回滚删除失败，TXT %s (recordID=%d) 可能残留: %v", tokenFQDN, recordID, rollbackErr)
				p.mu.Lock()
				p.owned[zone+"|"+subDomain] = append(p.owned[zone+"|"+subDomain], ownedRecord{recordID: recordID, value: value})
				p.mu.Unlock()
			}
			return errors.Join(err, rollbackErr)
		}
	} else {
		p.mu.Lock()
		p.owned[zone+"|"+subDomain] = append(p.owned[zone+"|"+subDomain], ownedRecord{recordID: recordID, value: value})
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
// 空值必须 fail-fast：与 dnspod/tencent 侧同构（ownership MatchingValue("")
// 退化为按名匹配，内存兜底只选空值条目——双语义，未来空值调用会误删并发挑战）。
func (p *Provider) CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("按值清理必须提供非空挑战值（按名清空请使用 CleanUp）")
	}
	return p.cleanUp(ctx, zone, tokenFQDN, value, true)
}

// CountCleanupRecords 实现 dnsprovider.CleanupCounter（与 dnspod/tencent 侧
// 同构）：纯本地计数按值清理将选中的记录条数。键为 zone+"|"+subDomain——按
// "|"+subDomain 后缀聚合，跨 zone 同名子域的少量多计只会让预算偏大。
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
	records, err := p.ownership.MatchingValue("aliyun", zone, tokenFQDN, value)
	if err != nil {
		// 账本读失败按至少 1 条计——预算宁大勿小（清理本身会再上抛该错误）。
		return max(fallback, 1)
	}
	return len(records) + fallback
}

// cleanUp 是 CleanUp/CleanUpValue 的共享实现（按值定向删除+陈旧条目清理）。
//
// 本函数与 dnspod/tencent 的 cleanUp 是同构多实现（有意保留，见包注释）。
// aliyun 侧的额外能力是 provider 侧残余排空：账本与内存兜底表全部未命中时，
// TXT 仍可能存在于 provider（账本条目退役/丢失、旧版本遗留），按 RR 精确匹配
// + 按值过滤枚举并删除——ID 不来自账本，无「换账户后 ID 指向无关记录」风险，
// 但命中过账本候选的清理不做网络枚举（正常路径零额外往返）。
func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN, value string, byValue bool) error {
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	key := zone + "|" + subDomain
	var records []ownership.Record
	var memorySelected []ownedRecord
	if p.ownership != nil {
		var err error
		if byValue {
			records, err = p.ownership.MatchingValue("aliyun", zone, tokenFQDN, value)
		} else {
			records, err = p.ownership.Matching("aliyun", zone, tokenFQDN)
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

	attempted := 0
	var cleanupErr error
	var failed []ownedRecord
	deleteOne := func(recordID uint64, value string) error {
		attempted++
		if err := p.deleteRecord(ctx, zone, recordID); err != nil {
			if ctx.Err() != nil {
				// 保留原始 provider 错误（整体覆写会丢失具体 API 失败原因，
				// 诊断信息归零）；与 dnspod/tencent 侧口径对齐。
				err = errors.Join(err, ctx.Err())
			}
			if p.ownership == nil {
				// failed 的唯一消费点是下方 ownership==nil 的 owned 回填；
				// ownership 模式下失败条目由 ownership 留存（删除失败不
				// Remove），不再写入死存储。回填必须保留挑战值——后续按值
				// 清理（CleanUpValue）以 entry.value 过滤，空值条目永不被
				// 选中重试。
				failed = append(failed, ownedRecord{recordID: recordID, value: value})
			}
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("DeleteRecord failed: %w", p.sanitizeAPIError(err)))
			return err
		}
		return nil
	}
	if p.ownership != nil {
		// 批量收敛（与 dnspod/tencent 侧同构）：成功删除/判定丢弃的条目攒批，
		// 循环结束后一次 RemoveMany（单次全量重写+fsync）。中途崩溃只让
		// 已删记录的条目多留一轮（下次清理幂等删除后再移除），语义不变。
		var removable []ownership.Record
		for _, record := range records {
			// 账户归属先于删除（判定单源在 ownership.DecideRemoval）。
			// 换凭据后旧账户遗留条目的 record_id 在新账户里可能指向同域无关
			// 记录，删除即数据面损失；只丢弃本地条目并留痕。
			if ownership.DecideRemoval(record, p.account, time.Now()) == ownership.DispositionDrop {
				logf("warn", "aliyun: 所有权条目无法归属当前账户（%s, recordID=%s, account=%q），仅丢弃本地条目、不调用删除", tokenFQDN, record.RecordID, record.Account)
				removable = append(removable, record)
				continue
			}
			recordID, parseErr := strconv.ParseUint(record.RecordID, 10, 64)
			if parseErr != nil {
				parseFailure := fmt.Errorf("parse persisted Aliyun record ID %q: %w", record.RecordID, parseErr)
				// 无法解析的 ID 永远无法调用删除 API；保留条目只会让每次
				// 清理永久重复报错。告警并移除该不可恢复条目，本轮仍返回
				// 解析错误。
				logf("warn", "aliyun: 所有权 RecordID %q 无法解析，按不可恢复条目处理: %v", record.RecordID, parseErr)
				cleanupErr = errors.Join(cleanupErr, parseFailure)
				removable = append(removable, record)
				continue
			}
			// independence: a record whose deletion failed keeps
			// its ownership entry (the DNS record may still exist), but an
			// earlier miss must not skip removal for records that WERE
			// deleted — that orphans them until self-heal.
			if deleteOne(recordID, record.Value) != nil {
				continue
			}
			removable = append(removable, record)
		}
		cleanupErr = errors.Join(cleanupErr, p.ownership.RemoveMany(removable))
		// 兜底排空：Present 在「ownership.Add 失败 + 回滚删除失败」时把
		// recordID 回填进内存兜底表（store 无条目可追踪）。此处重试删除这些
		// 兜底条目——成功即清除，失败回填供下次重试（幂等）。
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
	// provider 侧残余排空（aliyun 专属，见函数注释）：账本候选、内存兜底、
	// 排空条目全部为空才触发——有任一候选即说明追踪链路仍在，残余排空只会
	// 平添网络往返。ctx 已取消时不再发起枚举。
	if len(records) == 0 && len(memorySelected) == 0 && attempted == 0 && ctx.Err() == nil {
		matches, listErr := p.listChallengeRecords(ctx, zone, subDomain)
		if listErr != nil {
			cleanupErr = errors.Join(cleanupErr, listErr)
		}
		for _, match := range matches {
			if byValue && match.value != value {
				continue
			}
			recordID, parseErr := strconv.ParseUint(match.recordID, 10, 64)
			if parseErr != nil {
				logf("warn", "aliyun: DescribeDomainRecords RecordID %q 无法解析，跳过删除: %v", match.recordID, parseErr)
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("parse enumerated record ID %q: %w", match.recordID, parseErr))
				continue
			}
			if err := p.deleteRecord(ctx, zone, recordID); err != nil {
				if ctx.Err() != nil {
					err = errors.Join(err, ctx.Err())
				}
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("DeleteRecord failed: %w", p.sanitizeAPIError(err)))
				// 删除失败回填内存兜底表供下次重试（幂等）——枚举条目没有
				// 账本归宿，兜底表是唯一追踪载体。
				p.mu.Lock()
				p.owned[key] = append(p.owned[key], ownedRecord{recordID: recordID, value: match.value})
				p.mu.Unlock()
			}
		}
	}
	return cleanupErr
}

// enumeratedRecord 是 DescribeDomainRecords 命中的一条挑战记录。
type enumeratedRecord struct {
	recordID string
	value    string
}

// listChallengeRecords 枚举 zone 下指定 RR 的 TXT 记录：KeyWord 前缀在服务端
// 过滤，客户端按 RR 精确匹配（大小写不敏感）收窄，翻页直到取尽。
func (p *Provider) listChallengeRecords(ctx context.Context, zone, subDomain string) ([]enumeratedRecord, error) {
	var collected []enumeratedRecord
	for page := 1; page <= challengeListPageLimit; page++ {
		body, err := p.apiCall(ctx, "DescribeDomainRecords", map[string]string{
			"DomainName": zone,
			"KeyWord":    challengeKeyword,
			"Type":       "TXT",
			"PageNumber": strconv.Itoa(page),
			"PageSize":   strconv.Itoa(challengeListPageSize),
		})
		if err != nil {
			if ctx.Err() != nil {
				err = errors.Join(err, ctx.Err())
			}
			return nil, fmt.Errorf("DescribeDomainRecords failed: %w", p.sanitizeAPIError(err))
		}
		var result struct {
			TotalCount    int64 `json:"TotalCount"`
			DomainRecords struct {
				Record []struct {
					RecordId string `json:"RecordId"`
					RR       string `json:"RR"`
					Type     string `json:"Type"`
					Value    string `json:"Value"`
				} `json:"Record"`
			} `json:"DomainRecords"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("DescribeDomainRecords response decode: %w", err)
		}
		for _, record := range result.DomainRecords.Record {
			if record.Type != "TXT" {
				continue
			}
			if dnsname.NormalizeName(record.RR) != subDomain {
				continue
			}
			collected = append(collected, enumeratedRecord{recordID: record.RecordId, value: record.Value})
		}
		fetched := int64(len(result.DomainRecords.Record))
		if fetched == 0 || int64(page)*challengeListPageSize >= result.TotalCount {
			return collected, nil
		}
	}
	return collected, nil
}

func (p *Provider) deleteRecord(ctx context.Context, zone string, recordID uint64) error {
	_, err := p.apiCall(ctx, "DeleteDomainRecord", map[string]string{
		"RecordId": strconv.FormatUint(recordID, 10),
	})
	if err != nil {
		if isRecordNotFound(err) {
			// 记录已不存在：按删除成功处理，保证清理幂等（不残留所有权条目）
			return nil
		}
		return p.sanitizeAPIError(err)
	}
	return nil
}

func (p *Provider) createRecord(ctx context.Context, zone, subDomain, value string, ttl int) (uint64, error) {
	body, err := p.apiCall(ctx, "AddDomainRecord", map[string]string{
		"DomainName": zone,
		"RR":         subDomain,
		"Type":       "TXT",
		"Value":      value,
		"TTL":        strconv.Itoa(ttl),
	})
	if err != nil {
		if ctx.Err() != nil {
			// 对齐 deleteOne 口径——ctx.Err() 整体覆写会丢失具体 API 失败
			// 原因（诊断信息归零），errors.Join 保留两者。
			err = errors.Join(err, ctx.Err())
		}
		return 0, fmt.Errorf("AddDomainRecord failed: %w", p.sanitizeAPIError(err))
	}
	var result struct {
		RecordId string `json:"RecordId"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("AddDomainRecord response decode: %w", err)
	}
	recordID, err := strconv.ParseUint(strings.TrimSpace(result.RecordId), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("AddDomainRecord returned invalid record ID %q", result.RecordId)
	}
	return recordID, nil
}

// apiError 是 Alidns 错误响应的解析形态（Code/Message/RequestId 用于文案与
// 分类判定；errors.As 判定在脱敏包装前完成，脱敏层的 Unwrap 保留分类语义）。
type apiError struct {
	Status    int
	Code      string
	Message   string
	RequestId string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("alidns api error: status=%d code=%s message=%q requestId=%s", e.Status, e.Code, e.Message, e.RequestId)
}

func parseAPIError(status int, body []byte) error {
	apiErr := &apiError{Status: status}
	var envelope struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestId string `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		apiErr.Code, apiErr.Message, apiErr.RequestId = envelope.Code, envelope.Message, envelope.RequestId
	}
	if apiErr.Code == "" && apiErr.Message == "" {
		return fmt.Errorf("alidns api error: status=%d body=%d bytes (unparseable)", status, len(body))
	}
	return apiErr
}

// isRecordNotFound 识别 Alidns DeleteDomainRecord 的记录不存在信号：
// InvalidRecordId 族（含 InvalidRecordId.* 子码）与 RecordNotFound 前缀。
// 认不全的代价是幂等重试持续报错（fail-safe 方向），不会误删——宁缺勿滥。
func isRecordNotFound(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Code == "InvalidRecordId" || strings.HasPrefix(apiErr.Code, "InvalidRecordId.") {
		return true
	}
	return strings.HasPrefix(apiErr.Code, "RecordNotFound")
}

// credentialEchoSecretMinLen 是凭据分段参与定向替换的最小长度（与
// dnspod/tencent 侧同口径）：过短分段在任意文案里全局替换会伤及排障上下文，
// 只纳充分长分段。
const credentialEchoSecretMinLen = 8

// credentialEchoSecrets 展开一段凭据的全部已知明文形态：完整值 + 各分段
// （逗号/空白分隔，AccessKey 对通常无分段），排除过短分段。
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

// sanitizedAPIError 包装脱敏后的 API 错误：Error() 输出脱敏文案，Unwrap 保留
// 原错误链（errors.Is/As 的分类语义不受影响——isRecordNotFound 等判定在脱敏
// 前完成，链上原始错误仅经显式 Unwrap 可见，日志/错误文案不会带出）。
type sanitizedAPIError struct {
	msg string
	err error
}

func (e *sanitizedAPIError) Error() string { return e.msg }
func (e *sanitizedAPIError) Unwrap() error { return e.err }

// sanitizeAPIError 对拼进错误链的外部文本（Alidns 错误 Message/网关兜底体）
// 做凭据脱敏：先按已知明文（AccessKey 对及其分段）定向替换；替换后仍有已知
// 明文残留（大小写变换等变体回声，不参与替换但同为泄露）即整段丢弃
// （fail-closed，只保留长度指纹）。AccessKey 对无表单形态，无形态正则兜底
// 通道；正常错误只含 Code/Message/RequestId，无凭据痕迹时原样返回（文案与
// 错误链零变化）。dnspod/tencent 侧同口径实现见各自包（凭据形态不同，有意
// 各自保留）。
func (p *Provider) sanitizeAPIError(err error) error {
	if err == nil {
		return nil
	}
	secrets := credentialEchoSecrets(p.accessKeyID)
	secrets = append(secrets, credentialEchoSecrets(p.accessKeySecret)...)
	if len(secrets) == 0 {
		return err
	}
	msg := err.Error()
	redacted := msg
	for _, known := range secrets {
		redacted = strings.ReplaceAll(redacted, known, "***")
	}
	for _, known := range secrets {
		if strings.Contains(strings.ToLower(redacted), strings.ToLower(known)) {
			return &sanitizedAPIError{msg: fmt.Sprintf("[alidns error withheld: %d bytes]", len(msg)), err: err}
		}
	}
	if redacted == msg {
		return err
	}
	return &sanitizedAPIError{msg: redacted, err: err}
}

// apiCall 构造、签名并发送一次 Alidns RPC 调用，返回 2xx 响应体。
// 业务参数全部放查询串（RPC 风格，body 恒空），签名覆盖的公共请求头与
// 规范化查询串严格一致（服务端按同一口径重算）。
func (p *Provider) apiCall(ctx context.Context, action string, params map[string]string) ([]byte, error) {
	endpoint := p.endpoint
	if endpoint == "" {
		endpoint = apiEndpoint
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse alidns endpoint: %w", err)
	}
	query := canonicalQueryString(params)
	target.RawQuery = query

	input := signingInput{
		method:  http.MethodPost,
		host:    target.Host,
		path:    "/",
		query:   query,
		action:  action,
		version: apiVersion,
		date:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		nonce:   signatureNonce(),
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build alidns request: %w", err)
	}
	request.Header.Set("x-acs-action", action)
	request.Header.Set("x-acs-version", apiVersion)
	request.Header.Set("x-acs-date", input.date)
	request.Header.Set("x-acs-signature-nonce", input.nonce)
	request.Header.Set("x-acs-content-sha256", input.hashedPayload())
	request.Header.Set("Authorization", input.authorization(p.accessKeyID, p.accessKeySecret))

	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, responseReadLimit))
	if err != nil {
		return nil, fmt.Errorf("read alidns response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, parseAPIError(response.StatusCode, body)
	}
	return body, nil
}

// signatureNonce 生成 16 字节十六进制随机数（防重放；crypto/rand 失败时
// 显性报错，不静默降级到可预测源）。
func signatureNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("alidns: signature nonce entropy unavailable: %v", err))
	}
	return hex.EncodeToString(buf)
}

// signingInput 是一次 ACS3-HMAC-SHA256 签名的全部输入（date/nonce 显式化，
// 固定向量单测钉死实现，见 aliyun_test.go）。
type signingInput struct {
	method  string
	host    string
	path    string
	query   string
	action  string
	version string
	date    string
	nonce   string
	body    []byte
}

func (in signingInput) hashedPayload() string {
	sum := sha256.Sum256(in.body)
	return hex.EncodeToString(sum[:])
}

// canonicalHeaders 按 SignedHeaders 同序拼出规范化请求头（每行尾随 \n）。
func (in signingInput) canonicalHeaders() string {
	return "host:" + in.host + "\n" +
		"x-acs-action:" + in.action + "\n" +
		"x-acs-content-sha256:" + in.hashedPayload() + "\n" +
		"x-acs-date:" + in.date + "\n" +
		"x-acs-signature-nonce:" + in.nonce + "\n" +
		"x-acs-version:" + in.version + "\n"
}

func (in signingInput) canonicalRequest() string {
	return strings.Join([]string{
		in.method,
		in.path,
		in.query,
		in.canonicalHeaders(),
		signedHeaders,
		in.hashedPayload(),
	}, "\n")
}

func (in signingInput) stringToSign() string {
	sum := sha256.Sum256([]byte(in.canonicalRequest()))
	return signAlgorithm + "\n" + hex.EncodeToString(sum[:])
}

func (in signingInput) authorization(accessKeyID, accessKeySecret string) string {
	mac := hmac.New(sha256.New, []byte(accessKeySecret))
	mac.Write([]byte(in.stringToSign()))
	return fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		signAlgorithm, accessKeyID, signedHeaders, hex.EncodeToString(mac.Sum(nil)))
}

// canonicalQueryString 按参数名升序 + RFC3986 编码拼出规范化查询串；
// 该串同时是实际请求的 RawQuery（发送形态与签名形态严格一致）。
func canonicalQueryString(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, acsURIEncode(key)+"="+acsURIEncode(params[key]))
	}
	return strings.Join(parts, "&")
}

// acsURIEncode 按 RFC3986 编码：A-Za-z0-9 与 -_.~ 不编码，其余逐字节 %XX
// 大写（空格 %20、+ %2B、* %2A，多字节 UTF-8 逐字节编码）。不用
// url.QueryEscape：其空格编码为 +、波浪号编码为 %7E，均不符合 ACS3 口径。
func acsURIEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			b.WriteByte(c)
		case c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			const hexDigits = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

// throttlingTransport 把 Alidns 的「HTTP 400 + Code=Throttling」限流响应改写
// 为 429 语义（body 原样保留），让共享 retry.Transport 的既有机制按限流处理
// ——retry.Transport 只按状态码判定可重试性（429/5xx），而 Alidns 的限流走
// 400。body 保留意味着错误解析仍读到真实 Code/Message；前缀匹配同时覆盖
// Throttling 与 Throttling.* 子码。
type throttlingTransport struct {
	base http.RoundTripper
}

func (t *throttlingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		return response, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, throttlingBodyProbeLimit))
	if err != nil {
		response.Body.Close()
		return nil, fmt.Errorf("read alidns error body: %w", err)
	}
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	if bytes.Contains(body, []byte(`"Code":"Throttling`)) {
		response.StatusCode = http.StatusTooManyRequests
		response.Status = "429 Too Many Requests"
	}
	return response, nil
}
