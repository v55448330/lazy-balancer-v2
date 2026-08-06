package services

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestCAProviderQueries_returns_credentials(t *testing.T) {
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

	// Then: both list and business load return actual credentials
	var listedCredentials string
	for _, provider := range listed {
		if provider.ID == int(providerID) {
			listedCredentials = provider.Credentials
			break
		}
	}
	if !strings.Contains(listedCredentials, "secret") {
		t.Fatalf("listed credentials=%q, want actual HMAC key", listedCredentials)
	}
	if loaded.Credentials != credentials {
		t.Fatalf("business credentials=%q, want actual credentials", loaded.Credentials)
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

func TestCAProviderService_TestCAProviderWithContext_cancels_while_query_waits(t *testing.T) {
	_, database := newClusterTestService(t)
	database.SetMaxOpenConns(1)
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("hold database connection: %v", err)
	}
	defer connection.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- NewCAProviderService().TestCAProviderWithContext(ctx, 1)
	}()
	for database.Stats().WaitCount == 0 {
		runtime.Gosched()
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("test provider error=%v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider query did not stop after context cancellation")
	}
}

func TestCAProviderService_UpdateCAProvider_rejects_disabling_last_enabled(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('only','letsencrypt',?,'',1,1000,1)`, LetsEncryptDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	disabled := false

	err = NewCAProviderService().UpdateCAProvider(int(id), models.UpdateCAProviderRequest{Enabled: &disabled})
	if !errors.Is(err, ErrCAProviderLastEnabled) {
		t.Fatalf("disable last provider error=%v, want %v", err, ErrCAProviderLastEnabled)
	}
	var enabled bool
	if err := database.QueryRow("SELECT enabled FROM ca_providers WHERE id=?", id).Scan(&enabled); err != nil {
		t.Fatalf("read CA provider after rollback: %v", err)
	}
	if !enabled {
		t.Fatal("last CA provider was disabled despite rollback")
	}
}
