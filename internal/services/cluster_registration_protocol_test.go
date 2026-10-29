package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
)

func TestPollRegistration_invalidSuccessEnvelopeSurfacesRetryableError(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{name: "empty object", body: `{}`},
		{name: "unrelated success", body: `{"code":0,"message":"ok"}`},
		{name: "unknown status", body: `{"data":{"status":"waiting"}}`},
		{name: "html", body: `<html>maintenance</html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer master.Close()
			if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url=?, registration_id=7,
				registration_secret='pending-secret', cluster_token='', last_sync_error='', registration_confirm_failures=0 WHERE id=1`, master.URL); err != nil {
				t.Fatal(err)
			}
			service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
			t.Cleanup(func() { unregisterSyncDrainer(service) })

			service.pollRegistration(context.Background())

			var stored, secret, token string
			var failures int
			if err := database.QueryRow(`SELECT COALESCE(last_sync_error,''), COALESCE(registration_secret,''),
				COALESCE(cluster_token,''), COALESCE(registration_confirm_failures,0) FROM global_config WHERE id=1`).
				Scan(&stored, &secret, &token, &failures); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stored, "注册状态") {
				t.Fatalf("last_sync_error=%q, want explicit registration protocol error", stored)
			}
			if secret != "pending-secret" || token != "" || failures != 0 {
				t.Fatalf("registration state changed: secret=%q token=%q failures=%d", secret, token, failures)
			}
		})
	}
}

func TestPollRegistration_pendingEnvelopeRemainsValid(t *testing.T) {
	_, database := newClusterTestService(t)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"status":"pending"}}`))
	}))
	defer master.Close()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url=?, registration_id=7,
		registration_secret='pending-secret', cluster_token='', last_sync_error='' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	t.Cleanup(func() { unregisterSyncDrainer(service) })
	service.pollRegistration(context.Background())
	var stored string
	if err := database.QueryRow(`SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("valid pending response produced error %q", stored)
	}
}
