package services

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCAProviderQueries_mask_list_but_not_business_load(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	credentials := `{"eab_kid":"kid","eab_hmac_key":"secret"}`
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('private','zerossl',?,?,1,1000,1)`, ZeroSSLDirectoryURL, credentials)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}

	// When
	listed, err := NewCAProviderService().ListCAProviders()
	if err != nil {
		t.Fatalf("list CA providers: %v", err)
	}
	loaded, err := loadCAProvider(int(providerID))
	if err != nil {
		t.Fatalf("load CA provider for business use: %v", err)
	}

	// Then
	var listedCredentials string
	for _, provider := range listed {
		if provider.ID == int(providerID) {
			listedCredentials = provider.Credentials
			break
		}
	}
	if strings.Contains(listedCredentials, "secret") || !strings.Contains(listedCredentials, MaskedHMACKey) {
		t.Fatalf("listed credentials=%q, want masked HMAC key", listedCredentials)
	}
	if loaded.Credentials != credentials {
		t.Fatalf("business credentials=%q, want unmasked credentials", loaded.Credentials)
	}
}

func TestCAProviderService_TestCAProviderWithContext_honors_parent_cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewCAProviderService().TestCAProviderWithContext(ctx, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("test provider error=%v, want context canceled", err)
	}
}
