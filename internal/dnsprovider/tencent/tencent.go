package tencent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	"lazy-balancer-v2/internal/dnsname"
	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

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

// ownedRecord 记录本实例创建的记录 ID 及其挑战值，CleanUpValue 据此只删
// 属于本次签发的记录。
type ownedRecord struct {
	recordID uint64
	value    string
}

// Provider implements dnsprovider.Provider for Tencent Cloud DNSPod.
type Provider struct {
	// secretID/secretKey 凭据保持私有（与 dnspod.Provider 同口径）——
	// 导出字段任何一次 %+v/JSON 序列化即泄密。生产读取全部是包内直读
	// （构造 SDK 凭证）；本包不提供凭据访问器，日志/序列化形态走 String()
	// （只暴露账户摘要）。
	secretID  string
	secretKey string
	client    *dnspod.Client
	mu        sync.Mutex
	owned     map[string][]ownedRecord
	ownership *ownership.Store
	// account 是本实例凭据的账户摘要，写入所有权条目并参与
	// 清理归属判定：换凭据后旧条目的 record_id 属于另一个账户，按它删除会
	// 命中新账户下的无关记录。
	account string
}

// String 脱敏形态：只暴露账户摘要，任何日志/序列化路径不得回显凭据。
func (p *Provider) String() string { return "tencent.Provider{account:" + p.account + "}" }

func NewPersistent(secretID, secretKey, dataDir string) (*Provider, error) {
	provider, err := New(secretID, secretKey)
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

// New creates a Tencent Cloud DNSPod provider.
func New(secretID, secretKey string) (*Provider, error) {
	credential := common.NewCredential(secretID, secretKey)
	prof := profile.NewClientProfile()
	prof.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
	// 覆盖整个重试包络（3 次尝试 + 每次至多 30s 退避/ 等待计入
	// 同一请求的 http.Client.Timeout，SDK 默认 60s 会在包络内掐断）
	prof.HttpProfile.ReqTimeout = 90
	client, err := dnspod.NewClient(credential, "", prof)
	if err != nil {
		return nil, fmt.Errorf("create tencent dnspod client: %w", err)
	}
	// 429/5xx 重试在传输层统一处理，瞬时 API 故障不再直接打挂挑战
	client.WithHttpTransport(&retry.Transport{})
	return &Provider{
		secretID:  secretID,
		secretKey: secretKey,
		client:    client,
		owned:     make(map[string][]ownedRecord),
		// 账户身份由凭据对派生（不落明文）：「同一个域换另一账户的密钥」是本
		// 缺陷的触发形态，SecretKey 轮换同样按换账户处理（保守方向，见
		// ownership.DecideRemoval）。
		account: ownership.AccountDigest(secretID + "\x00" + secretKey),
	}, nil
}

// Present creates a distinct _acme-challenge TXT record (no upsert): a repeated
// Present for the same name adds another record, and cleanup removes records by
// ownership record ID / value.
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	// zone 与 tokenFQDN 都按 dnsname 单源归一后再派生相对子域（与 dnspod 侧
	// 同一实现）：大小写敏感的后缀比较会把混合大小写 FQDN 整体当成 sub_domain。
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	recordID, err := p.createRecord(ctx, zone, subDomain, value, ttl)
	if err != nil {
		return err
	}
	if p.ownership != nil {
		record := ownership.Record{Provider: "tencent", Zone: zone, FQDN: tokenFQDN, Value: value, RecordID: strconv.FormatUint(recordID, 10), Account: p.account}
		if err := p.ownership.Add(record); err != nil {
			rollbackErr := p.deleteRecord(ctx, zone, recordID)
			if rollbackErr != nil {
				// ownership.Add 失败且回滚删除亦失败——TXT 已落
				// DNS，而 ownership 无条目可追踪。告警留痕 + 回填内存兜底表：
				// cleanUp 的 ownership 分支会排空兜底表并重试删除，避免永久残留。
				logf("warn", "tencent: 所有权写入失败且回滚删除失败，TXT %s (recordID=%d) 可能残留: %v", tokenFQDN, recordID, rollbackErr)
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
// 空值必须 fail-fast：与 dnspod 侧同构（ownership MatchingValue("") 退化为
// 按名匹配，内存兜底只选空值条目——双语义，未来空值调用会误删并发挑战）。
func (p *Provider) CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("按值清理必须提供非空挑战值（按名清空请使用 CleanUp）")
	}
	return p.cleanUp(ctx, zone, tokenFQDN, value, true)
}

// CountCleanupRecords 实现 dnsprovider.CleanupCounter（与 dnspod 侧同构）：
// 纯本地计数按值清理将选中的记录条数。键为 zone+"|"+subDomain——按
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
	records, err := p.ownership.MatchingValue("tencent", zone, tokenFQDN, value)
	if err != nil {
		// 账本读失败按至少 1 条计——预算宁大勿小（清理本身会再上抛该错误）。
		return max(fallback, 1)
	}
	return len(records) + fallback
}

// cleanUp 是 CleanUp/CleanUpValue 的共享实现（按值定向删除+陈旧条目清理）。
//
// 本函数与 internal/dnsprovider/dnspod/dnspod.go 的
// cleanUp 是同构双实现（有意保留——两者底层 SDK/记录 ID 类型不同）。任一侧
// 修改删除/留痕/兜底排空逻辑时，MUST 同步另一侧并保持语义一致。
func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN, value string, byValue bool) error {
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	key := zone + "|" + subDomain
	var records []ownership.Record
	var memorySelected []ownedRecord
	if p.ownership != nil {
		var err error
		if byValue {
			records, err = p.ownership.MatchingValue("tencent", zone, tokenFQDN, value)
		} else {
			records, err = p.ownership.Matching("tencent", zone, tokenFQDN)
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
	deleteOne := func(recordID uint64, value string) error {
		if err := p.deleteRecord(ctx, zone, recordID); err != nil {
			if ctx.Err() != nil {
				// 保留原始 provider 错误（整体覆写会丢失具体
				// API 失败原因，诊断信息归零）；与 dnspod 侧口径对齐。
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
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("DeleteRecord failed: %w", p.sanitizeSDKError(err)))
			return err
		}
		return nil
	}
	if p.ownership != nil {
		// 批量收敛（与 dnspod 侧同构）：成功删除/判定丢弃的条目攒批，
		// 循环结束后一次 RemoveMany（单次全量重写+fsync）。中途崩溃只让
		// 已删记录的条目多留一轮（下次清理幂等删除后再移除），语义不变。
		var removable []ownership.Record
		for _, record := range records {
			// 账户归属先于删除（与 dnspod 侧同口径，判定
			// 单源在 ownership.DecideRemoval）。换凭据后旧账户遗留条目的
			// record_id 在新账户里可能指向同域无关记录，删除即数据面损失；
			// 只丢弃本地条目并留痕。
			if ownership.DecideRemoval(record, p.account, time.Now()) == ownership.DispositionDrop {
				logf("warn", "tencent: 所有权条目无法归属当前账户（%s, recordID=%s, account=%q），仅丢弃本地条目、不调用删除", tokenFQDN, record.RecordID, record.Account)
				removable = append(removable, record)
				continue
			}
			recordID, parseErr := strconv.ParseUint(record.RecordID, 10, 64)
			if parseErr != nil {
				parseFailure := fmt.Errorf("parse persisted Tencent record ID %q: %w", record.RecordID, parseErr)
				// 无法解析的 ID 永远无法调用删除 API；保留条目只会让每次清理
				// 永久重复报错。告警并移除该不可恢复条目，本轮仍返回解析错误。
				logf("warn", "tencent: 所有权 RecordID %q 无法解析，按不可恢复条目处理: %v", record.RecordID, parseErr)
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

func (p *Provider) deleteRecord(ctx context.Context, zone string, recordID uint64) error {
	req := dnspod.NewDeleteRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordId = common.Uint64Ptr(recordID)
	_, err := p.client.DeleteRecordWithContext(ctx, req)
	if err != nil && isRecordNotFound(err) {
		// 记录已不存在：按删除成功处理，保证清理幂等（不残留所有权条目）
		return nil
	}
	return p.sanitizeSDKError(err)
}

// credentialEchoSecretMinLen 是凭据分段参与定向替换的最小长度（与 dnspod 侧
// 同口径）：过短分段在任意文案里全局替换会伤及排障上下文，只纳充分长分段。
const credentialEchoSecretMinLen = 8

// credentialEchoSecrets 展开一段凭据的全部已知明文形态：完整值 + 各分段
// （逗号/空白分隔，secretId/secretKey 通常无分段），排除过短分段。
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

// sanitizedSDKError 包装脱敏后的 SDK 错误：Error() 输出脱敏文案，Unwrap 保留
// 原错误链（errors.Is/As 的分类语义不受影响——isRecordNotFound 等判定在脱敏
// 前完成，链上原始错误仅经显式 Unwrap 可见，日志/错误文案不会带出）。
type sanitizedSDKError struct {
	msg string
	err error
}

func (e *sanitizedSDKError) Error() string { return e.msg }
func (e *sanitizedSDKError) Unwrap() error { return e.err }

// sanitizeSDKError 对拼进错误链的外部文本（SDK 错误 Message/中间网关兜底体）
// 做凭据脱敏：先按已知明文（secretId/secretKey 及其分段）定向替换；替换后仍
// 有已知明文残留（大小写变换等变体回声，不参与替换但同为泄露）即整段丢弃
// （fail-closed，只保留长度指纹）。凭据形态与 dnspod 不同（secretId/secretKey，
// 无 login_token 表单形态），无形态正则兜底通道；正常 SDK 错误只含
// Code/Message/RequestId，无凭据痕迹时原样返回（文案与错误链零变化）。
// DNSPod 侧同口径实现见 dnspod.sanitizeHTTPErrorBody（凭据形态不同，有意
// 各自保留）。
func (p *Provider) sanitizeSDKError(err error) error {
	if err == nil {
		return nil
	}
	secrets := credentialEchoSecrets(p.secretID)
	secrets = append(secrets, credentialEchoSecrets(p.secretKey)...)
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
			return &sanitizedSDKError{msg: fmt.Sprintf("[tencent sdk error withheld: %d bytes]", len(msg)), err: err}
		}
	}
	if redacted == msg {
		return err
	}
	return &sanitizedSDKError{msg: redacted, err: err}
}

// isRecordNotFound 识别 TencentCloud DeleteRecord 的记录不存在信号：
// ResourceNotFound.NoDataOfRecord，或记录 ID 失效类错误码。
func isRecordNotFound(err error) bool {
	var sdkErr *tcerr.TencentCloudSDKError
	if !errors.As(err, &sdkErr) {
		return false
	}
	if strings.HasPrefix(sdkErr.Code, "ResourceNotFound") {
		return true
	}
	switch sdkErr.Code {
	case "InvalidParameter.RecordIdInvalid", "InvalidRecord.Id":
		return true
	}
	return false
}

func (p *Provider) createRecord(ctx context.Context, zone, subDomain, value string, ttl int) (uint64, error) {
	req := dnspod.NewCreateRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordType = common.StringPtr("TXT")
	req.RecordLine = common.StringPtr("默认")
	req.Value = common.StringPtr(value)
	req.SubDomain = common.StringPtr(subDomain)
	req.TTL = common.Uint64Ptr(uint64(ttl))

	resp, err := p.client.CreateRecordWithContext(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			// 对齐 deleteOne 口径——以
			// ctx.Err() 整体覆写会丢失具体 API 失败原因（诊断信息归零），
			// errors.Join 保留两者。
			err = errors.Join(err, ctx.Err())
		}
		return 0, fmt.Errorf("CreateRecord failed: %w", p.sanitizeSDKError(err))
	}
	if resp.Response == nil || resp.Response.RecordId == nil {
		return 0, fmt.Errorf("CreateRecord returned no record ID")
	}
	return *resp.Response.RecordId, nil
}
