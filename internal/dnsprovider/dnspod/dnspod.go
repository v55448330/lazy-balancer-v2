package dnspod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

const apiBase = "https://dnsapi.cn/"

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
	LoginToken string
	client     *http.Client
	mu         sync.Mutex
	owned      map[string][]ownedRecord
	ownership  *ownership.Store
}

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
		LoginToken: loginToken,
		client: &http.Client{
			// 覆盖整个重试包络（3 次尝试 + 每次至多 30s 退避/Retry-After
			// 等待计入同一 RoundTrip），不能把退火循环中途掐断
			Timeout: 90 * time.Second,
			// 429/5xx 重试在传输层统一处理，瞬时 API 故障不再直接打挂挑战
			Transport: &retry.Transport{},
		},
		owned: make(map[string][]ownedRecord),
	}
}

// Present creates or updates the _acme-challenge TXT record.
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

	domainID, err := p.getDomainID(ctx, zone)
	if err != nil {
		return err
	}

	recordID, err := p.createRecord(ctx, domainID, subDomain, value, ttl)
	if err != nil {
		return err
	}
	if p.ownership != nil {
		record := ownership.Record{Provider: "dnspod", Zone: zone, FQDN: tokenFQDN, Value: value, RecordID: recordID}
		if err := p.ownership.Add(record); err != nil {
			return errors.Join(err, p.deleteRecord(ctx, domainID, recordID))
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
func (p *Provider) CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error {
	return p.cleanUp(ctx, zone, tokenFQDN, value, true)
}

func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN, value string, byValue bool) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

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
	deleteOne := func(recordID string) error {
		if err := p.deleteRecord(ctx, domainID, recordID); err != nil {
			failed = append(failed, ownedRecord{recordID: recordID})
			cleanupErr = errors.Join(cleanupErr, err)
			return err
		}
		return nil
	}
	if p.ownership != nil {
		for _, record := range records {
			// Per-record independence: a record whose deletion failed keeps
			// its ownership entry (the DNS record may still exist), but an
			// earlier miss must not skip Remove for records that WERE
			// deleted — that orphans them until self-heal.
			if deleteOne(record.RecordID) != nil {
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

type apiStatus struct {
	Code    json.Number `json:"code"`
	Message string      `json:"message"`
}

func (p *Provider) apiCall(ctx context.Context, method string, params url.Values, result interface{}) error {
	params.Set("login_token", p.LoginToken)
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

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// flexNumber 接受 DNSPod 数字字段的历史两种形态（JSON 数字与带引号字符串）。
type flexNumber string

func (n *flexNumber) UnmarshalJSON(data []byte) error {
	*n = flexNumber(strings.Trim(string(data), `"`))
	return nil
}

// Int64 尽力解析；缺失/不可解析时返回 0，调用方按"未知总量"处理。
func (n flexNumber) Int64() int64 {
	value, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func (p *Provider) getDomainID(ctx context.Context, zone string) (string, error) {
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
			return "", fmt.Errorf("Domain.List failed: %s", result.Status.Message)
		}
		for _, d := range result.Domains {
			if d.Name == zone {
				return d.ID.String(), nil
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
		return "", fmt.Errorf("Record.Create failed: %s", result.Status.Message)
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
	return fmt.Errorf("Record.Remove failed: %s", result.Status.Message)
}
