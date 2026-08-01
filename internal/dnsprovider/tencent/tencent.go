package tencent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

// Provider implements dnsprovider.Provider for Tencent Cloud DNSPod.
type Provider struct {
	SecretID  string
	SecretKey string
	client    *dnspod.Client
	mu        sync.Mutex
	owned     map[string][]uint64
}

// New creates a Tencent Cloud DNSPod provider.
func New(secretID, secretKey string) (*Provider, error) {
	credential := common.NewCredential(secretID, secretKey)
	prof := profile.NewClientProfile()
	prof.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
	client, err := dnspod.NewClient(credential, "", prof)
	if err != nil {
		return nil, fmt.Errorf("create tencent dnspod client: %w", err)
	}
	return &Provider{
		SecretID:  secretID,
		SecretKey: secretKey,
		client:    client,
		owned:     make(map[string][]uint64),
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
	p.mu.Lock()
	p.owned[zone+"|"+subDomain] = append(p.owned[zone+"|"+subDomain], recordID)
	p.mu.Unlock()
	return nil
}

// CleanUp removes the _acme-challenge TXT record.
func (p *Provider) CleanUp(ctx context.Context, zone, tokenFQDN string) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

	key := zone + "|" + subDomain
	p.mu.Lock()
	recordIDs := append([]uint64(nil), p.owned[key]...)
	delete(p.owned, key)
	p.mu.Unlock()
	var cleanupErr error
	var failed []uint64
	for _, recordID := range recordIDs {
		req := dnspod.NewDeleteRecordRequest()
		req.Domain = common.StringPtr(zone)
		req.RecordId = common.Uint64Ptr(recordID)
		if _, err := p.client.DeleteRecordWithContext(ctx, req); err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			failed = append(failed, recordID)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("DeleteRecord failed: %w", err))
		}
	}
	if len(failed) > 0 {
		p.mu.Lock()
		p.owned[key] = append(p.owned[key], failed...)
		p.mu.Unlock()
	}
	return cleanupErr
}

func (p *Provider) findRecordID(ctx context.Context, zone, subDomain string) (uint64, error) {
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = common.StringPtr(zone)
	req.Subdomain = common.StringPtr(subDomain)

	resp, err := p.client.DescribeRecordListWithContext(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return 0, fmt.Errorf("DescribeRecordList failed: %w", err)
	}
	if resp.Response == nil || resp.Response.RecordList == nil {
		return 0, nil
	}
	for _, r := range resp.Response.RecordList {
		if r.Type != nil && *r.Type == "TXT" && r.Name != nil && *r.Name == subDomain {
			return *r.RecordId, nil
		}
	}
	return 0, nil
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

func (p *Provider) modifyRecord(ctx context.Context, zone string, recordID uint64, subDomain, value string, ttl int) error {
	req := dnspod.NewModifyRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordId = common.Uint64Ptr(recordID)
	req.RecordType = common.StringPtr("TXT")
	req.RecordLine = common.StringPtr("默认")
	req.Value = common.StringPtr(value)
	req.SubDomain = common.StringPtr(subDomain)
	req.TTL = common.Uint64Ptr(uint64(ttl))

	_, err := p.client.ModifyRecordWithContext(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("ModifyRecord failed: %w", err)
	}
	return nil
}
