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

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

const apiBase = "https://dnsapi.cn/"

// Provider implements dnsprovider.Provider for DNSPod (dnsapi.cn).
type Provider struct {
	LoginToken string
	client     *http.Client
	mu         sync.Mutex
	owned      map[string][]string
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
		client:     &http.Client{Timeout: 30 * time.Second},
		owned:      make(map[string][]string),
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
		p.owned[domainID+"|"+subDomain] = append(p.owned[domainID+"|"+subDomain], recordID)
		p.mu.Unlock()
	}
	return nil
}

// CleanUp removes the _acme-challenge TXT record.
func (p *Provider) CleanUp(ctx context.Context, zone, tokenFQDN string) error {
	zone = strings.TrimSuffix(zone, ".")
	subDomain := strings.TrimSuffix(tokenFQDN, ".")
	subDomain = strings.TrimSuffix(subDomain, "."+zone)

	domainID, err := p.getDomainID(ctx, zone)
	if err != nil {
		return err
	}

	key := domainID + "|" + subDomain
	var records []ownership.Record
	var recordIDs []string
	if p.ownership != nil {
		records, err = p.ownership.Matching("dnspod", zone, tokenFQDN)
		if err != nil {
			return err
		}
		for _, record := range records {
			recordIDs = append(recordIDs, record.RecordID)
		}
	} else {
		p.mu.Lock()
		recordIDs = append([]string(nil), p.owned[key]...)
		delete(p.owned, key)
		p.mu.Unlock()
	}
	var cleanupErr error
	var failed []string
	for index, recordID := range recordIDs {
		if err := p.deleteRecord(ctx, domainID, recordID); err != nil {
			failed = append(failed, recordID)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		if p.ownership != nil {
			cleanupErr = errors.Join(cleanupErr, p.ownership.Remove(records[index]))
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

func (p *Provider) getDomainID(ctx context.Context, zone string) (string, error) {
	params := url.Values{}
	var result struct {
		Status  apiStatus `json:"status"`
		Domains []struct {
			ID   json.Number `json:"id"`
			Name string      `json:"name"`
		} `json:"domains"`
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

func (p *Provider) modifyRecord(ctx context.Context, domainID, recordID, subDomain, value string, ttl int) error {
	params := url.Values{}
	params.Set("domain_id", domainID)
	params.Set("record_id", recordID)
	params.Set("sub_domain", subDomain)
	params.Set("record_type", "TXT")
	params.Set("record_line", "默认")
	params.Set("value", value)
	params.Set("ttl", strconv.Itoa(ttl))

	var result struct {
		Status apiStatus `json:"status"`
	}
	if err := p.apiCall(ctx, "Record.Modify", params, &result); err != nil {
		return err
	}
	if result.Status.Code.String() != "1" {
		return fmt.Errorf("Record.Modify failed: %s", result.Status.Message)
	}
	return nil
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
	if result.Status.Code.String() != "1" {
		return fmt.Errorf("Record.Remove failed: %s", result.Status.Message)
	}
	return nil
}
