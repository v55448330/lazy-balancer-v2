package dnspod

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const apiBase = "https://dnsapi.cn/"

// Provider implements dnsprovider.Provider for DNSPod (dnsapi.cn).
type Provider struct {
	LoginToken string
	client     *http.Client
}

// New creates a DNSPod provider. loginToken must be "id,key" format.
func New(loginToken string) *Provider {
	return &Provider{
		LoginToken: loginToken,
		client:     &http.Client{Timeout: 30 * time.Second},
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

	records, err := p.listRecords(ctx, domainID, subDomain)
	if err != nil {
		return err
	}

	if len(records) > 0 {
		return p.modifyRecord(ctx, domainID, records[0].ID.String(), subDomain, value, ttl)
	}
	return p.createRecord(ctx, domainID, subDomain, value, ttl)
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

	records, err := p.listRecords(ctx, domainID, subDomain)
	if err != nil {
		return err
	}

	var lastErr error
	for _, r := range records {
		if err := p.deleteRecord(ctx, domainID, r.ID.String()); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

type apiStatus struct {
	Code    json.Number `json:"code"`
	Message string      `json:"message"`
}

type record struct {
	ID    json.Number `json:"id"`
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Value string      `json:"value"`
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

func (p *Provider) listRecords(ctx context.Context, domainID, subDomain string) ([]record, error) {
	params := url.Values{}
	params.Set("domain_id", domainID)
	if subDomain != "" {
		params.Set("sub_domain", subDomain)
	}
	var result struct {
		Status  apiStatus `json:"status"`
		Records []record  `json:"records"`
	}
	if err := p.apiCall(ctx, "Record.List", params, &result); err != nil {
		return nil, err
	}
	if result.Status.Code.String() != "1" {
		if result.Status.Code.String() == "10" {
			return nil, nil
		}
		return nil, fmt.Errorf("Record.List failed: %s", result.Status.Message)
	}
	var out []record
	for _, r := range result.Records {
		if r.Type == "TXT" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (p *Provider) createRecord(ctx context.Context, domainID, subDomain, value string, ttl int) error {
	params := url.Values{}
	params.Set("domain_id", domainID)
	params.Set("sub_domain", subDomain)
	params.Set("record_type", "TXT")
	params.Set("record_line", "默认")
	params.Set("value", value)
	params.Set("ttl", strconv.Itoa(ttl))

	var result struct {
		Status apiStatus `json:"status"`
	}
	if err := p.apiCall(ctx, "Record.Create", params, &result); err != nil {
		return err
	}
	if result.Status.Code.String() != "1" {
		return fmt.Errorf("Record.Create failed: %s", result.Status.Message)
	}
	return nil
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
