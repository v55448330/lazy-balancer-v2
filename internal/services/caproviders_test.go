package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestCAProviderService_TestCAProviderWithContext_bounds_EAB_auto_provision_with_deadline(t *testing.T) {
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET acme_email='admin@example.test' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}

	// N+13 H3-S：伪 ZeroSSL EAB 端点延迟响应，晚于注入的 100ms 时限。父 ctx
	// 为 Background（永不取消），服务端不自败——若 EAB 自动获取未被独立超时
	// 包裹（原实现仅 RegisterAccount 有 10s 界），本调用将阻塞至 30s HTTP
	// 客户端兜底；唯一可能的快速取消源即子超时。
	oldTimeout := zerosslEABProvisionTimeout
	zerosslEABProvisionTimeout = 100 * time.Millisecond
	t.Cleanup(func() { zerosslEABProvisionTimeout = oldTimeout })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"error":"fixture"}`))
	}))
	defer server.Close()
	oldURL := zerosslEABURL
	zerosslEABURL = server.URL
	t.Cleanup(func() { zerosslEABURL = oldURL })

	done := make(chan error, 1)
	go func() {
		done <- NewCAProviderService().TestCAProviderWithContext(context.Background(), int(providerID))
	}()
	select {
	case err := <-done:
		var testErr *CAProviderTestError
		if !errors.As(err, &testErr) || testErr.Phase != "config" {
			t.Fatalf("test provider error=%v, want CAProviderTestError phase=config", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("test provider error=%v, want context.DeadlineExceeded from the EAB bound", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EAB auto-provision hung — test path is unbounded without its own timeout")
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
