package tencent

import (
	"context"
	"fmt"
	"strings"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

// Provider implements dnsprovider.Provider for Tencent Cloud DNSPod.
type Provider struct {
	SecretID  string
	SecretKey string
	client    *dnspod.Client
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
	}, nil
}

// Present creates or updates the _acme-challenge TXT record.
func (p *Provider) Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

	recordID, err := p.findRecordID(ctx, zone, subDomain)
	if err != nil {
		return err
	}
	if recordID != 0 {
		return p.modifyRecord(ctx, zone, recordID, subDomain, value, ttl)
	}
	return p.createRecord(ctx, zone, subDomain, value, ttl)
}

// CleanUp removes the _acme-challenge TXT record.
func (p *Provider) CleanUp(ctx context.Context, zone, tokenFQDN string) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

	recordID, err := p.findRecordID(ctx, zone, subDomain)
	if err != nil || recordID == 0 {
		return err
	}

	req := dnspod.NewDeleteRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordId = common.Uint64Ptr(recordID)
	_, err = p.client.DeleteRecord(req)
	if err != nil {
		return fmt.Errorf("DeleteRecord failed: %w", err)
	}
	return nil
}

func (p *Provider) findRecordID(ctx context.Context, zone, subDomain string) (uint64, error) {
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = common.StringPtr(zone)
	req.Subdomain = common.StringPtr(subDomain)

	resp, err := p.client.DescribeRecordList(req)
	if err != nil {
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

func (p *Provider) createRecord(ctx context.Context, zone, subDomain, value string, ttl int) error {
	req := dnspod.NewCreateRecordRequest()
	req.Domain = common.StringPtr(zone)
	req.RecordType = common.StringPtr("TXT")
	req.RecordLine = common.StringPtr("默认")
	req.Value = common.StringPtr(value)
	req.SubDomain = common.StringPtr(subDomain)
	req.TTL = common.Uint64Ptr(uint64(ttl))

	_, err := p.client.CreateRecord(req)
	if err != nil {
		return fmt.Errorf("CreateRecord failed: %w", err)
	}
	return nil
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

	_, err := p.client.ModifyRecord(req)
	if err != nil {
		return fmt.Errorf("ModifyRecord failed: %w", err)
	}
	return nil
}
