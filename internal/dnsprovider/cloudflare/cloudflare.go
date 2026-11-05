// Package cloudflare implements dnsprovider.Provider for Cloudflare DNS over
// the REST API v4（端点 https://api.cloudflare.com/client/v4）。手写 HTTP 客户端
// （零新依赖），凭据为 API Token（Authorization: Bearer 头承载；Global API Key
// 有意不支持——全账户权限、无 scope 收敛，安全面不可接受，注册表元数据只暴露
// api_token 单形态）。挑战 TXT 的 TTL 固定 challengeRecordTTL（120，与 lego
// 同口径），不透传调用方值。
//
// cleanUp 与 internal/dnsprovider/dnspod/dnspod.go、tencent/tencent.go、
// aliyun/aliyun.go 是同构多实现（有意保留——底层 API 与记录 ID 类型不同）。
// 任一侧修改删除/留痕/兜底排空/残余排空逻辑时，MUST 同步全部实现并保持语义
// 一致（对齐门禁见 internal/dnsprovider/cleanup_parity_test.go）。
package cloudflare

import (
	"bytes"
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

const apiBase = "https://api.cloudflare.com/client/v4"

// challengeRecordTTL 是挑战 TXT 的固定 TTL：ACME 挑战记录生命周期以分钟计，
// 与调用方传入值无关——Cloudflare 最小 TTL 60，签发/探针侧传入的更大值只会
// 拉长失败残留的传播时间，固定 120 让残留自清更快（lego 同口径）。
const challengeRecordTTL = 120

// 残余排空的翻页参数（与 dnspod/aliyun 侧同口径）：per_page 取 API 单页上限
// 100；pageLimit 仅防御异常巨量下的失控翻页（name 过滤后通常单页）。
const (
	challengeListPageSize  = 100
	challengeListPageLimit = 20
)

// responseReadLimit 是单响应体的读取上限（记录列表单页百条远小于此；上限
// 只防异常响应撑爆内存）。
const responseReadLimit = 1 << 20

// httpErrorBodyLimit 是 HTTP 错误响应体在错误文案中的取样上限（字节；
// 网关错误页可达数百 KB，整读既无诊断增量又可能把响应体读进内存）。
const httpErrorBodyLimit = 512

// logf 是包级日志接缝（镜像 dnspod/tencent/aliyun 同型接缝）：运维告警进入
// 统一日志级别/格式链，而不是裸 log.Printf 另走一条链路。main 启动早期经
// SetLogf 装配；零值回退标准库。
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
	recordID string
	value    string
}

// enumeratedRecord 是记录列表命中的一条挑战记录。
type enumeratedRecord struct {
	recordID string
	value    string
}

// Provider implements dnsprovider.Provider for Cloudflare DNS.
type Provider struct {
	// apiToken 凭据保持私有——导出字段任何一次 %+v/JSON 序列化即泄密。
	// 生产读取全部是包内直读（构造 API 请求、缓存键派生）；本包不提供凭据
	// 访问器，日志/序列化形态走 String()（只暴露账户摘要）。
	apiToken string
	client   *http.Client
	// endpoint 默认 apiBase；测试注入 httptest 端点（含 /client/v4 前缀）。
	endpoint string
	mu       sync.Mutex
	owned    map[string][]ownedRecord
	// 兜底表键 = zoneID + "|" + subDomain（与 dnspod 的 domainID 键同构）。
	ownership *ownership.Store
	// account 是本实例凭据的账户摘要，写入所有权条目并参与清理归属判定：
	// 换凭据后旧条目的 record_id 属于另一个账户，按它删除会命中新账户下的
	// 无关记录。
	account string
}

// String 脱敏形态：只暴露账户摘要，任何日志/序列化路径不得回显凭据。
func (p *Provider) String() string { return "cloudflare.Provider{account:" + p.account + "}" }

// NewPersistent 构造带所有权账本的 provider（签发链入口）。
func NewPersistent(apiToken, dataDir string) (*Provider, error) {
	store, err := ownership.New(dataDir)
	if err != nil {
		return nil, err
	}
	provider := New(apiToken)
	provider.ownership = store
	return provider, nil
}

// New creates a Cloudflare provider.
func New(apiToken string) *Provider {
	apiToken = strings.TrimSpace(apiToken)
	return &Provider{
		apiToken: apiToken,
		client: &http.Client{
			// 覆盖整个重试包络（3 次尝试 + 每次至多 30s 退避/等待计入同一
			// RoundTrip），不能把退避循环中途掐断——与 dnspod/tencent/aliyun
			// 侧 90s 口径一致。429/5xx 重试在传输层统一处理，瞬时 API 故障
			// 不再直接打挂挑战。
			Timeout:   90 * time.Second,
			Transport: &retry.Transport{},
		},
		endpoint: apiBase,
		owned:    make(map[string][]ownedRecord),
		// 账户身份由凭据派生（不落明文）：Token 轮换即视为换账户，旧条目
		// 转为不可按 ID 删除（保守方向，见 ownership.DecideRemoval）。
		account: ownership.AccountDigest(apiToken),
	}
}

// Present creates a distinct _acme-challenge TXT record: 同名同值的既有记录
// 直接复用（并发/重试安全，见 createRecord），同名不同值各建一条，清理按
// ownership 记录 ID / 挑战值收回。ttl 形参固定不透传（challengeRecordTTL）。
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	// zone 与 tokenFQDN 都按 dnsname 单源归一后再派生（与 dnspod/tencent/
	// aliyun 侧同一实现）：大小写敏感的后缀比较会把混合大小写 FQDN 整体当成
	// 子域（TXT 落到错误名字）。
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)
	recordName := dnsname.NormalizeName(tokenFQDN)

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return err
	}
	recordID, err := p.createRecord(ctx, zoneID, recordName, value)
	if errors.Is(err, errStaleZoneID) {
		// 缓存的 zone→id 可能陈旧（zone 删除后重建，新 id 与缓存不符），
		// zone 侧调用报 404/7003——作废缓存重解析一次并重试一次；重解析或
		// 重试失败按最新错误返回，不循环（zone 真正移出 token 可见范围时
		// 重解析即失败）。
		p.invalidateZoneIDCache(zone)
		freshID, resolveErr := p.getZoneID(ctx, zone)
		if resolveErr != nil {
			return resolveErr
		}
		recordID, err = p.createRecord(ctx, freshID, recordName, value)
		if err == nil {
			// 自愈重试成功后回写 zoneID=freshID（与 dnspod 侧 domain-id 自愈
			// 的回写对称）——否则兜底表键仍打向陈旧 zone id（删除必败/TXT
			// 泄漏、CleanUp 键不匹配静默零删除残留）。
			zoneID = freshID
		}
	}
	if err != nil {
		return err
	}
	if p.ownership != nil {
		record := ownership.Record{Provider: "cloudflare", Zone: zone, FQDN: tokenFQDN, Value: value, RecordID: recordID, Account: p.account}
		if err := p.ownership.Add(record); err != nil {
			rollbackErr := p.deleteRecord(ctx, zoneID, recordID)
			if rollbackErr != nil {
				// ownership.Add 失败且回滚删除亦失败——TXT 已落
				// DNS，而 ownership 无条目可追踪（「删除失败不 Remove」的前提
				// 不成立）。告警留痕 + 回填内存兜底表：cleanUp 的兜底排空会
				// 重试删除，避免该记录永久残留（无追踪窗口收口）。
				logf("warn", "cloudflare: 所有权写入失败且回滚删除失败，TXT %s (recordID=%s) 可能残留: %v", tokenFQDN, recordID, rollbackErr)
				p.mu.Lock()
				p.owned[zoneID+"|"+subDomain] = append(p.owned[zoneID+"|"+subDomain], ownedRecord{recordID: recordID, value: value})
				p.mu.Unlock()
			}
			return errors.Join(err, rollbackErr)
		}
	} else {
		p.mu.Lock()
		p.owned[zoneID+"|"+subDomain] = append(p.owned[zoneID+"|"+subDomain], ownedRecord{recordID: recordID, value: value})
		p.mu.Unlock()
	}
	return nil
}

// CleanUp removes the _acme-challenge TXT records.
func (p *Provider) CleanUp(ctx context.Context, zone, tokenFQDN string) error {
	return p.cleanUp(ctx, zone, tokenFQDN, "", false)
}

// CleanUpValue removes only the record this issuance created (same challenge
// value), plus legacy/stale leftovers under the same name; a concurrent
// issuance's recent record of another value is spared.
//
// 空值必须 fail-fast：ownership MatchingValue("") 会委托给按名匹配（命中同名
// 全部记录），而内存兜底路径只选空值条目——同一入参两种语义，一旦未来出现
// 空值调用方，前者会删掉并发挑战的 TXT。按名清理只属于 CleanUp。
func (p *Provider) CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("按值清理必须提供非空挑战值（按名清空请使用 CleanUp）")
	}
	return p.cleanUp(ctx, zone, tokenFQDN, value, true)
}

// CountCleanupRecords 实现 dnsprovider.CleanupCounter（与 dnspod/tencent/
// aliyun 侧同构）：纯本地计数一次按值清理将选中的记录条数（ownership 账本
// MatchingValue + 内存兜底表条目），零网络往返。兜底表键含 zoneID，计数按
// "|"+subDomain 后缀跨键聚合（避免为计数引入 getZoneID 网络解析；跨 zone
// 同名子域的少量多计只会让预算偏大，方向安全）。
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
	records, err := p.ownership.MatchingValue("cloudflare", zone, tokenFQDN, value)
	if err != nil {
		// 账本读失败按至少 1 条计——预算宁大勿小（清理本身会再上抛该错误）。
		return max(fallback, 1)
	}
	return len(records) + fallback
}

// cleanUp 是 CleanUp/CleanUpValue 的共享实现（按值定向删除+陈旧条目清理）。
//
// 本函数与 internal/dnsprovider/dnspod/dnspod.go、tencent/tencent.go、
// aliyun/aliyun.go 的 cleanUp 是同构多实现（有意保留——底层 API 与记录 ID
// 类型不同，抽象共享收益低于耦合成本）。任一侧修改删除/自愈/兜底排空/残余
// 排空逻辑时，MUST 同步全部实现并保持语义一致（zone-id 自愈为 cloudflare/
// dnspod 各自的 provider 专属能力；对齐门禁见
// internal/dnsprovider/cleanup_parity_test.go）。
func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN, value string, byValue bool) error {
	zone = dnsname.NormalizeName(zone)
	subDomain := dnsname.RelativeTo(tokenFQDN, zone)

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return err
	}

	key := zoneID + "|" + subDomain
	var records []ownership.Record
	var memorySelected []ownedRecord
	if p.ownership != nil {
		if byValue {
			records, err = p.ownership.MatchingValue("cloudflare", zone, tokenFQDN, value)
		} else {
			records, err = p.ownership.Matching("cloudflare", zone, tokenFQDN)
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
	attempted := 0
	deleteOne := func(recordID, value string) error {
		attempted++
		err := p.deleteRecord(ctx, zoneID, recordID)
		if err != nil {
			if ctx.Err() != nil {
				// 与 dnspod/tencent/aliyun 的 deleteOne 同口径
				// ——ctx 取消/超时并入错误链，保留原始 provider 错误（整体覆写
				// 会丢失具体 API 失败原因，诊断信息归零）。
				err = errors.Join(err, ctx.Err())
			}
			if p.ownership == nil {
				// failed 的唯一消费点是下方 ownership==nil 的 owned
				// 回填；ownership 模式下失败条目由 ownership 留存（删除失败
				// 不 Remove），不再写入死存储。回填必须保留挑战值——后续按值
				// 清理（CleanUpValue）以 entry.value 过滤，空值条目永不被选中
				// 重试。
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
		// （下次清理命中 DELETE 404 幂等后再移除），收敛语义不变。
		var removable []ownership.Record
		for _, record := range records {
			// 账户归属先于删除。换凭据后旧账户遗留条目仍按
			// name/value 被选中，但 record_id 属于旧账户——在新账户里可能指向
			// 同域无关记录，删除即数据面损失。此类条目只丢弃本地所有权条目并
			// 留痕（TXT 若仍在旧账户则永远不可达，属已知代价）。
			if ownership.DecideRemoval(record, p.account, time.Now()) == ownership.DispositionDrop {
				logf("warn", "cloudflare: 所有权条目无法归属当前账户（%s, recordID=%s, account=%q），仅丢弃本地条目、不调用删除", tokenFQDN, record.RecordID, record.Account)
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
	// provider 侧残余排空（与 dnspod/tencent/aliyun 侧同构，见各函数注释）：
	// 账本候选、内存兜底、排空条目全部为空才触发——有任一候选即说明追踪链路
	// 仍在，残余排空只会平添网络往返。ctx 已取消时不再发起枚举。
	if len(records) == 0 && len(memorySelected) == 0 && attempted == 0 && ctx.Err() == nil {
		matches, listErr := p.listChallengeRecords(ctx, zone, subDomain)
		if listErr != nil {
			if errors.Is(listErr, errStaleZoneID) {
				// 陈旧 zone id 毒化后续清理（每次排空都命中同一路由 404）：
				// 作废缓存供下一次清理重解析（本轮错误照旧上抛）。
				p.invalidateZoneIDCache(zone)
			}
			cleanupErr = errors.Join(cleanupErr, listErr)
		}
		for _, match := range matches {
			if byValue && match.value != value {
				continue
			}
			if match.recordID == "" {
				logf("warn", "cloudflare: 记录列表返回空记录 ID，跳过删除")
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("记录列表返回空记录 ID"))
				continue
			}
			if err := p.deleteRecord(ctx, zoneID, match.recordID); err != nil {
				if ctx.Err() != nil {
					// 与 deleteOne 同口径——ctx 取消/超时并入错误链，
					// 保留原始 provider 错误（整体覆写会丢失具体 API 失败
					// 原因，诊断信息归零）。
					err = errors.Join(err, ctx.Err())
				}
				cleanupErr = errors.Join(cleanupErr, err)
				// 删除失败回填内存兜底表供下次重试（幂等）——枚举条目没有
				// 账本归宿，兜底表是唯一追踪载体。
				p.mu.Lock()
				p.owned[key] = append(p.owned[key], ownedRecord{recordID: match.recordID, value: match.value})
				p.mu.Unlock()
			}
		}
	}
	return cleanupErr
}

// errStaleZoneID 标记 zone 侧调用返回的「zone 路由不存在/ID 失效」类错误
// （HTTP 404 或错误码 7003 "No route for that URI"）：缓存的 zone→id 因 zone
// 删除重建而陈旧时由 Present 捕获，作废缓存重解析后重试一次。DELETE 的
// 404 不进本分类（记录已不存在按删除成功处理，保证清理幂等）。
var errStaleZoneID = errors.New("cloudflare: zone ID 已失效")

// isStaleZoneError 判定错误是否属于「zone 路由不存在」类：HTTP 404，或
// Cloudflare 错误码 7003（No route for that URI——zone id 无法识别/路由未命中）。
// 经 sanitizedAPIError.Unwrap 与 errors.Join 都可达（errors.As 语义不受脱敏
// 包装影响）。
func isStaleZoneError(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status == http.StatusNotFound {
		return true
	}
	for _, item := range apiErr.Items {
		if item.Code == 7003 {
			return true
		}
	}
	return false
}

// createRecord 创建一条挑战 TXT 记录（幂等：同名同值已存在则复用既有记录
// ID——并发/重试安全。重复创建会让同名多值记录越积越多，且重试路径的重复
// 创建会在 ownership 之外留下无追踪 TXT）。
func (p *Provider) createRecord(ctx context.Context, zoneID, recordName, value string) (string, error) {
	existing, err := p.listRecordsByName(ctx, zoneID, recordName)
	if err != nil {
		return "", err
	}
	for _, record := range existing {
		if record.value == value {
			return record.recordID, nil
		}
	}
	payload := map[string]any{"type": "TXT", "name": recordName, "content": value, "ttl": challengeRecordTTL}
	var result struct {
		ID string `json:"id"`
	}
	if err := p.apiCall(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload, &result); err != nil {
		if isStaleZoneError(err) {
			// 标记「zone 路由不存在」类错误，供 Present 作废缓存重试。
			err = errors.Join(err, errStaleZoneID)
		}
		return "", err
	}
	if result.ID == "" {
		return "", fmt.Errorf("cloudflare: 创建 TXT 记录成功但响应缺少记录 ID")
	}
	return result.ID, nil
}

// listRecordsByName 枚举 zone 下指定记录名的 TXT 记录：name/type 由服务端
// 过滤，客户端按记录名精确匹配（大小写不敏感）收窄。翻页终止判定与
// dnspod/tencent/aliyun 侧统一（total 优先、短页兜底、按实际取到条数推进
// 游标）：fetched==0 即终止；result_info.total_count>0 时按累计取到数 ≥
// total 终止——中途短页（页间漂移/服务端单页容量波动）继续翻页不漏扫；
// total 缺失时退回「短页即终止」（per_page=100 已是 API 单页上限）。
func (p *Provider) listRecordsByName(ctx context.Context, zoneID, recordName string) ([]enumeratedRecord, error) {
	var collected []enumeratedRecord
	fetchedTotal := 0
	for page := 1; page <= challengeListPageLimit; page++ {
		query := url.Values{}
		query.Set("type", "TXT")
		query.Set("name", recordName)
		query.Set("per_page", strconv.Itoa(challengeListPageSize))
		query.Set("page", strconv.Itoa(page))
		var envelope apiEnvelope
		status, err := p.apiCallEnvelope(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+query.Encode(), nil, &envelope)
		if err != nil {
			if ctx.Err() != nil {
				err = errors.Join(err, ctx.Err())
			}
			if isStaleZoneError(err) {
				// 陈旧 zone id：供 Present/cleanUp 的上层语义识别。
				err = errors.Join(errStaleZoneID, err)
			}
			return nil, err
		}
		var pageRecords []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
		}
		if len(envelope.Result) > 0 {
			if err := json.Unmarshal(envelope.Result, &pageRecords); err != nil {
				return nil, fmt.Errorf("decode GET /zones/%s/dns_records result (HTTP %d): %w", zoneID, status, err)
			}
		}
		fetched := len(pageRecords)
		if fetched == 0 {
			break
		}
		for _, record := range pageRecords {
			if record.Type != "TXT" {
				continue
			}
			if dnsname.NormalizeName(record.Name) != recordName {
				continue
			}
			collected = append(collected, enumeratedRecord{recordID: record.ID, value: record.Content})
		}
		fetchedTotal += fetched
		if total := envelope.ResultInfo.TotalCount; total > 0 {
			if fetchedTotal >= total {
				break
			}
			continue
		}
		if fetched < challengeListPageSize {
			break
		}
	}
	return collected, nil
}

// listChallengeRecords 枚举 zone 下指定主机记录名的 TXT 记录（残余排空入口，
// 与 dnspod/tencent/aliyun 侧同签名）：zone id 走进程内缓存（cleanUp 的排空
// 路径在函数头已解析过——此处命中缓存，零额外网络往返；缓存被中途作废时
// 重新解析同样是正确行为）。
func (p *Provider) listChallengeRecords(ctx context.Context, zone, subDomain string) ([]enumeratedRecord, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	recordName := dnsname.NormalizeName(subDomain + "." + zone)
	return p.listRecordsByName(ctx, zoneID, recordName)
}

// deleteRecord 删除一条 DNS 记录。DELETE 404 一律按删除成功处理：记录已
// 不存在（81044）或所属 zone 已删除（记录随之消亡）两种形态下都无残留可
// 清，幂等保证清理不误报、所有权条目正常移除。
func (p *Provider) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	if recordID == "" || strings.ContainsAny(recordID, "/?# \t\r\n") {
		// 记录 ID 直接拼进 URL 路径：账本条目可能来自集群快照/旧版本写入，
		// 路径敌对字符必须 fail-visible 拒绝，而不是静默构造错误请求。
		return fmt.Errorf("cloudflare: 非法记录 ID %q，拒绝构造删除请求", recordID)
	}
	if err := p.apiCall(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	return nil
}

// VerifyToken 以 GET /user/tokens/verify 真实验证 API Token 有效性（保存前
// 验证入口，registry 侧经 newDNSProviderFromCredentials 构造后调用）：请求
// 成功且 Token 状态为 active 才算通过——不触 DNS 写入、无需 zone。
func (p *Provider) VerifyToken(ctx context.Context) error {
	var result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := p.apiCall(ctx, http.MethodGet, "/user/tokens/verify", nil, &result); err != nil {
		return err
	}
	if result.Status != "active" {
		return fmt.Errorf("Cloudflare API Token 状态为 %q（需要 active 状态的 Token）", result.Status)
	}
	return nil
}

// apiEnvelope 是 Cloudflare REST v4 的统一响应包络。
type apiEnvelope struct {
	Success bool            `json:"success"`
	Errors  []apiErrorItem  `json:"errors"`
	Result  json.RawMessage `json:"result"`
	// ResultInfo 是列表端点的分页元数据（翻页终止判定用；其余端点为空）。
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

// apiErrorItem 是 errors[] 的一条官方错误（code + message）。
type apiErrorItem struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// apiError 是 HTTP 状态 + errors[] 的解析形态（isStaleZoneError/DELETE 幂等
// 判定经 errors.As 消费；readableAPIError 脱敏包装的 Unwrap 保留分类语义）。
type apiError struct {
	Status int
	Items  []apiErrorItem
}

func (e *apiError) Error() string {
	return fmt.Sprintf("cloudflare api error: status=%d errors=%s", e.Status, joinErrorItems(e.Items))
}

// parseAPIError 解析错误包络；body 不可解析（网关 HTML/空体）时按纯状态错误
// 处理（Items 为空）。
func parseAPIError(status int, body []byte) *apiError {
	apiErr := &apiError{Status: status}
	var envelope struct {
		Errors []apiErrorItem `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		apiErr.Items = envelope.Errors
	}
	return apiErr
}

func joinErrorItems(items []apiErrorItem) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("code=%d: %s", item.Code, item.Message))
	}
	return strings.Join(parts, "; ")
}

// sanitizedAPIError 包装脱敏后的可读错误：Error() 输出中文可读文案，Unwrap
// 保留原错误链（errors.Is/As 的分类语义不受影响——isStaleZoneError 等判定在
// 脱敏包装外经 Unwrap 完成，日志/错误文案不会带出原始错误体）。
type sanitizedAPIError struct {
	msg string
	err error
}

func (e *sanitizedAPIError) Error() string { return e.msg }
func (e *sanitizedAPIError) Unwrap() error { return e.err }

// readableAPIError 把 API 错误映射为中文可读文案（外部文本全部经脱敏，
// errors[] 逐条拼入消息）：9109/invalid api token=Token 无效（先于 403 判定
// ——Token 无效与权限不足的用户修法不同：重建 Token vs 补权限）、403=权限
// 不足（点名所需权限）、429=限流（重试耗尽）、其余按状态码通用文案。
func (p *Provider) readableAPIError(apiErr *apiError, body []byte) error {
	sample := body
	if len(sample) > httpErrorBodyLimit {
		sample = sample[:httpErrorBodyLimit]
	}
	joined := p.sanitizeMessage(joinErrorItems(apiErr.Items))
	if joined == "" {
		if trimmed := strings.TrimSpace(string(sample)); trimmed != "" {
			joined = p.sanitizeMessage(trimmed)
		} else {
			joined = fmt.Sprintf("%d bytes", len(body))
		}
	}
	if isInvalidToken(apiErr) {
		return &sanitizedAPIError{msg: fmt.Sprintf("Cloudflare API Token 无效或已被撤销: %s", joined), err: apiErr}
	}
	switch apiErr.Status {
	case http.StatusForbidden:
		return &sanitizedAPIError{msg: fmt.Sprintf("Cloudflare API Token 权限不足（需要 Zone → DNS → Edit 与 Zone → Zone → Read 权限）: %s", joined), err: apiErr}
	case http.StatusTooManyRequests:
		return &sanitizedAPIError{msg: fmt.Sprintf("Cloudflare API 请求被限流（重试耗尽后仍 429，请稍后重试）: %s", joined), err: apiErr}
	}
	return &sanitizedAPIError{msg: fmt.Sprintf("Cloudflare API 调用失败（HTTP %d）: %s", apiErr.Status, joined), err: apiErr}
}

// isInvalidToken 识别 Token 失效信号：官方错误码 9109（Invalid API Token）或
// 错误消息字样。
func isInvalidToken(apiErr *apiError) bool {
	for _, item := range apiErr.Items {
		if item.Code == 9109 {
			return true
		}
		if strings.Contains(strings.ToLower(item.Message), "invalid api token") {
			return true
		}
	}
	return false
}

// credentialEchoPattern 匹配中间网关/WAF 拦截页可能回声的凭据形态：
// Authorization 头的 Bearer 形态（JSON 键值/文本冒号形态）。形态正则只是
// 兜底——真正的保证来自按已知凭据明文的定向替换，形态不匹配时宁可整段丢弃。
var credentialEchoPattern = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+)("[^"]*"|'[^']*'|[^\s&;"'}\]]+)`)

// sanitizeHTTPErrorBody 脱敏错误文案：先按已知凭据明文定向替换，再用 Bearer
// 形态正则兜底；替换后仍有已知明文残留（大小写变换等变体回声，不参与替换但
// 同为泄露）即整段丢弃（fail-closed，只保留长度指纹）——凭据不进日志优先于
// 排障原文。dnspod/tencent/aliyun 侧同口径实现见各自包（凭据形态不同，有意
// 各自保留）。
func sanitizeHTTPErrorBody(body string, secrets ...string) string {
	redacted := body
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret, "***")
	}
	redacted = credentialEchoPattern.ReplaceAllString(redacted, "${1}***")
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret != "" && strings.Contains(strings.ToLower(redacted), strings.ToLower(secret)) {
			return fmt.Sprintf("[response body withheld: %d bytes]", len(body))
		}
	}
	return strings.TrimSpace(redacted)
}

// sanitizeMessage 让业务层错误消息（厂商/中间网关可能回声凭据）与 HTTP 错误
// 体共用同一脱敏口径：所有拼进错误链的外部文本都必须经过本包装。
func (p *Provider) sanitizeMessage(message string) string {
	return sanitizeHTTPErrorBody(message, p.apiToken)
}

// apiCallEnvelope 构造并发送一次 Cloudflare REST v4 调用，返回 HTTP 状态码
// 与完整包络（result + result_info；分页判定需要 result_info，见
// listRecordsByName）。429/5xx 由 retry.Transport 吸收（创建类 POST 对 5xx
// 不重放——幽灵 TXT，见 retry 包注释）；网络失败与最终失败形态均输出中文
// 可读文案。
func (p *Provider) apiCallEnvelope(ctx context.Context, method, path string, body interface{}, envelope *apiEnvelope) (int, error) {
	endpoint := p.endpoint
	if endpoint == "" {
		endpoint = apiBase
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encode cloudflare request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, payload)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "lazy-balancer/2.0")

	resp, err := p.client.Do(req)
	if err != nil {
		// 网络错误文案点名超时/连接失败——429/5xx 已由 retry.Transport 吸收，
		// 这里是最终失败形态（传输层错误不携带凭据：Token 只在请求头）。
		return 0, fmt.Errorf("Cloudflare API 网络请求失败（超时或连接错误）: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, responseReadLimit))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read cloudflare response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return resp.StatusCode, p.readableAPIError(parseAPIError(resp.StatusCode, respBody), respBody)
	}
	if err := json.Unmarshal(respBody, envelope); err != nil {
		// 网关返回 HTML/空体时裸 decode 错误丢失状态码与动作，排障只能翻
		// network 日志——状态码与路径必须自明。
		return resp.StatusCode, fmt.Errorf("decode %s %s response (HTTP %d): %w", method, path, resp.StatusCode, err)
	}
	if !envelope.Success {
		// 2xx 但 success=false：官方包络的失败形态，errors[] 拼入消息。
		return resp.StatusCode, errors.New("Cloudflare API 调用失败: " + p.sanitizeMessage(joinErrorItems(envelope.Errors)))
	}
	return resp.StatusCode, nil
}

// apiCall 构造并发送一次 Cloudflare REST v4 调用，返回 2xx 包络中的 result。
func (p *Provider) apiCall(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var envelope apiEnvelope
	status, err := p.apiCallEnvelope(ctx, method, path, body, &envelope)
	if err != nil {
		return err
	}
	if result != nil && len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return fmt.Errorf("decode %s %s result (HTTP %d): %w", method, path, status, err)
		}
	}
	return nil
}

// zoneIDCache:账户+zone→zone id 进程内缓存（镜像 dnspod 的 domainID 缓存
// 形态）——签发/续签的每次 Present/CleanUp 都要解析 zone id；zone→id 映射在
// 账户内稳定，命中即省。键必须含账户（apiToken 的 sha256 前 8 字节十六进制）
// ——同进程可配置多条 DNS 凭证（多账户），裸 zone 键会让账户 B 首调即命中
// 账户 A 缓存的 zone id；token 不落明文键（缓存转储/调试可读）。容量与淘汰：
// zoneIDCacheCapacity（LRU，命中触碰）封顶正+负缓存总条目，超出淘汰最久未用
// 键。zoneIDNegativeCache 是负缓存（键同正缓存 → 最近一次「确认不存在」时刻）：
// 误填/token 无权访问的 zone 若不落负缓存，每次调用都重新查询，叠加限流退避
// 会把配置错误放大成厂商限流。TTL 取短（zoneIDNegativeTTL）：zone 后补进
// token 可见范围的收敛延迟上限即 TTL；过期条目读时惰性清除。
var (
	zoneIDCacheMu       sync.Mutex
	zoneIDCache         = map[string]string{}
	zoneIDNegativeCache = map[string]time.Time{}
	zoneIDCacheOrder    []string
)

// zoneIDCacheCapacity 是正+负缓存合并的 LRU 容量上限：单进程数千 zone 已
// 远超真实部署面（每个 zone 只在签发/续签时解析），上限只为防无界增长。
const zoneIDCacheCapacity = 1024

// zoneIDNegativeTTL 是负缓存条目的存活时长：60s 短 TTL——与 dnspod 侧同口径。
// var 供测试收窄。
var zoneIDNegativeTTL = 60 * time.Second

// zoneIDCacheKey 返回本账户隔离的缓存键：AccountDigest(apiToken)（16 位十六
// 进制）+ "|" + zone。摘要口径与 ownership.AccountDigest 单源——缓存隔离与
// 所有权账户身份必须由同一凭据派生，两处各自求值会出现「缓存按账户隔离、
// 所有权按另一账户身份判定」的漂移。
func (p *Provider) zoneIDCacheKey(zone string) string {
	return ownership.AccountDigest(p.apiToken) + "|" + zone
}

// zoneIDCacheTouchLRU 把键移到使用序队尾（调用方持 zoneIDCacheMu）。
func zoneIDCacheTouchLRU(key string) {
	for i, k := range zoneIDCacheOrder {
		if k == key {
			zoneIDCacheOrder = append(zoneIDCacheOrder[:i], zoneIDCacheOrder[i+1:]...)
			break
		}
	}
	zoneIDCacheOrder = append(zoneIDCacheOrder, key)
}

// zoneIDCacheEvictLRU 容量淘汰：正+负缓存合并计数，从使用序队首逐出
// （调用方持 zoneIDCacheMu）。
func zoneIDCacheEvictLRU() {
	for len(zoneIDCacheOrder) > zoneIDCacheCapacity {
		oldest := zoneIDCacheOrder[0]
		zoneIDCacheOrder = zoneIDCacheOrder[1:]
		delete(zoneIDCache, oldest)
		delete(zoneIDNegativeCache, oldest)
	}
}

// getZoneIDCache 读正缓存并触碰 LRU（生产读路径与测试共用）。
func (p *Provider) getZoneIDCache(key string) (string, bool) {
	zoneIDCacheMu.Lock()
	defer zoneIDCacheMu.Unlock()
	id, ok := zoneIDCache[key]
	if ok {
		zoneIDCacheTouchLRU(key)
	}
	return id, ok
}

// putZoneIDCache 写正缓存（清除同键负缓存）并触碰 LRU+容量淘汰
// （生产写路径与测试共用）。
func (p *Provider) putZoneIDCache(key, id string) {
	zoneIDCacheMu.Lock()
	defer zoneIDCacheMu.Unlock()
	delete(zoneIDNegativeCache, key)
	zoneIDCache[key] = id
	zoneIDCacheTouchLRU(key)
	zoneIDCacheEvictLRU()
}

// invalidateZoneIDCache 作废本账户单个 zone 的缓存映射（键含账户摘要，
// 自此只能作废本账户的条目；正负缓存与 LRU 使用序一并清除——errStaleZoneID
// 自愈后的下一次解析必须重新发起 GET /zones，负缓存不得拦住重新核实）。
func (p *Provider) invalidateZoneIDCache(zone string) {
	zoneIDCacheMu.Lock()
	key := p.zoneIDCacheKey(zone)
	delete(zoneIDCache, key)
	delete(zoneIDNegativeCache, key)
	for i, k := range zoneIDCacheOrder {
		if k == key {
			zoneIDCacheOrder = append(zoneIDCacheOrder[:i], zoneIDCacheOrder[i+1:]...)
			break
		}
	}
	zoneIDCacheMu.Unlock()
}

// zoneNotFoundErr 是 zone 解析失败的统一中文文案（provider 名+资源+建议
// 动作；与 dnspod 侧 domainNotFoundErr 同模板家族，负缓存命中与全量扫描
// 终态共用）。
func zoneNotFoundErr(zone string) error {
	return fmt.Errorf("Cloudflare: zone %s 不存在或 API Token 无权访问（请确认 zone 已添加到账户且 Token 具有 Zone 读取权限后重试）", zone)
}

// getZoneID 解析 zone 名 → zone id（服务端 name= 过滤为精确匹配，仍按归一
// 形态客户端复核——依赖「服务端返回形态已小写」这类实现细节会让返回形态变化
// 静默变成「zone 不在 token 可见范围」的错误结论）。
func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	zone = dnsname.NormalizeName(zone)
	cacheKey := p.zoneIDCacheKey(zone)
	if id, ok := p.getZoneIDCache(cacheKey); ok {
		return id, nil
	}
	zoneIDCacheMu.Lock()
	failedAt, negHit := zoneIDNegativeCache[cacheKey]
	if negHit && time.Since(failedAt) >= zoneIDNegativeTTL {
		// 负缓存过期即惰性清除，等价 miss。
		delete(zoneIDNegativeCache, cacheKey)
		negHit = false
	}
	if negHit {
		zoneIDCacheTouchLRU(cacheKey)
		zoneIDCacheMu.Unlock()
		return "", zoneNotFoundErr(zone)
	}
	zoneIDCacheMu.Unlock()
	query := url.Values{}
	query.Set("name", zone)
	query.Set("per_page", "5")
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := p.apiCall(ctx, http.MethodGet, "/zones?"+query.Encode(), nil, &zones); err != nil {
		// 瞬时 API 失败（网络/5xx/权限/Token 无效）不落负缓存——把瞬时故障
		// 放大成 TTL 内的持续失败是错误方向（与 dnspod 侧同口径）。
		return "", err
	}
	for _, z := range zones {
		if dnsname.NormalizeName(z.Name) == zone {
			p.putZoneIDCache(cacheKey, z.ID)
			return z.ID, nil
		}
	}
	// 全量判定终态「zone 不在 token 可见范围」才落负缓存。
	zoneIDCacheMu.Lock()
	zoneIDNegativeCache[cacheKey] = time.Now()
	zoneIDCacheTouchLRU(cacheKey)
	zoneIDCacheEvictLRU()
	zoneIDCacheMu.Unlock()
	return "", zoneNotFoundErr(zone)
}
