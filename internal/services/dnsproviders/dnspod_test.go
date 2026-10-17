package dnsproviders

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

// recordingDNSProvider 记录 provider 调用收到的 zone/FQDN（U06-F05：输入域用于
// challenge FQDN，可注册根域用于 provider 调用）。
type recordingDNSProvider struct {
	presentZone  string
	presentFQDN  string
	cleanupZone  string
	cleanupFQDN  string
	presentCalls int
}

func (p *recordingDNSProvider) Present(_ context.Context, zone, tokenFQDN, _ string, _ int) error {
	p.presentZone = zone
	p.presentFQDN = tokenFQDN
	p.presentCalls++
	return nil
}

func (p *recordingDNSProvider) CleanUp(_ context.Context, zone, tokenFQDN string) error {
	p.cleanupZone = zone
	p.cleanupFQDN = tokenFQDN
	return nil
}

// U06-F05：DNSPod 凭证校验不得把用户输入整体当 zone——www 子域必须解析到可注册
// 根域（PSL），challenge FQDN 仍基于完整输入域，否则账户只管理 example.com 时
// 校验误报「domain not found」。
func TestDNSPod_Validate_usesRegisteredZoneForProviderCalls(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantZone string
		wantFQDN string
	}{
		{
			name:     "subdomain resolves to registered zone",
			input:    "www.example.com",
			wantZone: "example.com",
			wantFQDN: "_acme-challenge.lb-test.www.example.com.",
		},
		{
			name:     "two-level suffix",
			input:    "api.example.co.uk",
			wantZone: "example.co.uk",
			wantFQDN: "_acme-challenge.lb-test.api.example.co.uk.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &recordingDNSProvider{}
			original := newDNSProviderFromCredentials
			newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
			t.Cleanup(func() { newDNSProviderFromCredentials = original })

			provider := &DNSPod{}
			credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}
			if err := provider.Validate(credentials, tt.input); err != nil {
				t.Fatalf("validate %q: %v", tt.input, err)
			}
			if fake.presentZone != tt.wantZone {
				t.Fatalf("Present zone=%q, want %q（provider 调用须用可注册根域）", fake.presentZone, tt.wantZone)
			}
			if fake.presentFQDN != tt.wantFQDN {
				t.Fatalf("Present FQDN=%q, want %q（challenge 名须基于完整输入域）", fake.presentFQDN, tt.wantFQDN)
			}
			if fake.cleanupZone != tt.wantZone || fake.cleanupFQDN != tt.wantFQDN {
				t.Fatalf("CleanUp zone/FQDN=%q/%q, want %q/%q", fake.cleanupZone, fake.cleanupFQDN, tt.wantZone, tt.wantFQDN)
			}
		})
	}
}

func TestDNSPod_Validate_rejects_whitespace_test_domain(t *testing.T) {
	// Given
	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}

	// When
	err := provider.Validate(credentials, "   ")

	// Then
	if err == nil || !strings.Contains(err.Error(), "测试域名不能为空") {
		t.Fatalf("validation error=%v, want empty-domain error", err)
	}
}
