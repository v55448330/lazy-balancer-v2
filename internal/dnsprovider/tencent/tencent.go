package tencent

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// ownedRecord 记录本实例创建的记录 ID 及其挑战值，CleanUpValue 据此只删
// 属于本次签发的记录。
type ownedRecord struct {
	recordID uint64
	value    string
}

// Provider implements dnsprovider.Provider for Tencent Cloud DNSPod.
type Provider struct {
	SecretID  string
	SecretKey string
	client    *dnspod.Client
	mu        sync.Mutex
	owned     map[string][]ownedRecord
	ownership *ownership.Store
}

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
	// 覆盖整个重试包络（3 次尝试 + 每次至多 30s 退避/Retry-After 等待计入
	// 同一请求的 http.Client.Timeout，SDK 默认 60s 会在包络内掐断）
	prof.HttpProfile.ReqTimeout = 90
	client, err := dnspod.NewClient(credential, "", prof)
	if err != nil {
		return nil, fmt.Errorf("create tencent dnspod client: %w", err)
	}
	// 429/5xx 重试在传输层统一处理，瞬时 API 故障不再直接打挂挑战
	client.WithHttpTransport(&retry.Transport{})
	return &Provider{
		SecretID:  secretID,
		SecretKey: secretKey,
		client:    client,
		owned:     make(map[string][]ownedRecord),
	}, nil
}

// Present creates or updates the _acme-challenge TXT record.
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

	recordID, err := p.createRecord(ctx, zone, subDomain, value, ttl)
	if err != nil {
		return err
	}
	if p.ownership != nil {
		record := ownership.Record{Provider: "tencent", Zone: zone, FQDN: tokenFQDN, Value: value, RecordID: strconv.FormatUint(recordID, 10)}
		if err := p.ownership.Add(record); err != nil {
			return errors.Join(err, p.deleteRecord(ctx, zone, recordID))
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
func (p *Provider) CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error {
	return p.cleanUp(ctx, zone, tokenFQDN, value, true)
}

func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN, value string, byValue bool) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

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
	deleteOne := func(recordID uint64) error {
		if err := p.deleteRecord(ctx, zone, recordID); err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			failed = append(failed, ownedRecord{recordID: recordID})
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("DeleteRecord failed: %w", err))
			return err
		}
		return nil
	}
	if p.ownership != nil {
		for _, record := range records {
			recordID, parseErr := strconv.ParseUint(record.RecordID, 10, 64)
			if parseErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("parse persisted Tencent record ID %q: %w", record.RecordID, parseErr))
				continue
			}
			// Per-record independence: a record whose deletion failed keeps
			// its ownership entry (the DNS record may still exist), but an
			// earlier miss must not skip Remove for records that WERE
			// deleted — that orphans them until self-heal.
			if deleteOne(recordID) != nil {
				continue
			}
			cleanupErr = errors.Join(cleanupErr, p.ownership.Remove(record))
		}
	} else {
		for _, entry := range memorySelected {
			deleteOne(entry.recordID)
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
	return err
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
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("CreateRecord failed: %w", err)
	}
	if resp.Response == nil || resp.Response.RecordId == nil {
		return 0, fmt.Errorf("CreateRecord returned no record ID")
	}
	return *resp.Response.RecordId, nil
}
