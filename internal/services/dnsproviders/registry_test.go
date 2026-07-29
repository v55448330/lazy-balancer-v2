package dnsproviders

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

func TestDNSPodCredentials(t *testing.T) {
	p, ok := Get("dnspod")
	if !ok {
		t.Fatal("dnspod not registered")
	}
	_, err := p.BuildCredentialsJSON(map[string]string{})
	if err == nil {
		t.Fatal("expected error for empty credentials")
	}
	creds, err := p.BuildCredentialsJSON(map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds["api_token"] != "123,abc" {
		t.Fatalf("expected api_token 123,abc, got %v", creds["api_token"])
	}
	tencent, err := p.BuildCredentialsJSON(map[string]string{"auth_mode": "tencent_cloud", "secret_id": "sid", "secret_key": "skey"})
	if err != nil {
		t.Fatalf("unexpected error for tencent cloud: %v", err)
	}
	if tencent["api_token"] != "sid,skey" {
		t.Fatalf("expected tencent api_token sid,skey, got %v", tencent["api_token"])
	}
}

type cleanupFailingProvider struct{}

func (cleanupFailingProvider) Present(context.Context, string, string, string, int) error { return nil }
func (cleanupFailingProvider) CleanUp(context.Context, string, string) error {
	return errors.New("cleanup failed")
}

func TestDNSPod_Validate_returns_cleanup_error(t *testing.T) {
	// Given
	originalFactory := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) {
		return cleanupFailingProvider{}, nil
	}
	t.Cleanup(func() { newDNSProviderFromCredentials = originalFactory })
	provider := &DNSPod{}

	// When
	err := provider.Validate(map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}, "example.com")

	// Then
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("cleanup error=%v, want cleanup failure", err)
	}
}

func TestListProviders(t *testing.T) {
	list := List()
	if len(list) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(list))
	}
}
