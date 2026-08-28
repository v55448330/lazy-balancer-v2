package dnsprovider

import (
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

func TestNewProviderFromCredentials_infers_mode_from_credential_fields(t *testing.T) {
	// Given/When/Then: legacy rows migrated before the mode field existed
	// carry only the credential fields — infer instead of rejecting
	provider, err := NewProviderFromCredentials(`{"api_token":"123,abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from api_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}

	provider, err = NewProviderFromCredentials(`{"secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("infer tencent from secret pair: %v", err)
	}
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}

	// Legacy UI form without auth_mode also infers dnspod from app_id/app_token
	provider, err = NewProviderFromCredentials(`{"app_id":"123","app_token":"abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from legacy app_id/app_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}
}

func TestNewProviderFromCredentials_rejects_ambiguous_or_missing_credentials(t *testing.T) {
	// Given/When/Then: both credential families present is ambiguous
	if _, err := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`); err == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	// No credentials at all
	if _, err := NewProviderFromCredentials(`{}`); err == nil {
		t.Fatal("missing credentials must be rejected")
	}
	// Incomplete secret pair cannot select tencent and has no token either
	if _, err := NewProviderFromCredentials(`{"secret_id":"id"}`); err == nil {
		t.Fatal("incomplete secret pair must be rejected")
	}
}

func TestNewProviderFromCredentials_explicit_mode_still_wins(t *testing.T) {
	// Given/When: explicit mode with matching credentials
	provider, err := NewProviderFromCredentials(`{"mode":"tencent","secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("explicit mode: %v", err)
	}

	// Then
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}
}
