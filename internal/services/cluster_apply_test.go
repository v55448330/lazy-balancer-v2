package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_applySnapshot_restarts_for_uploaded_admin_certificate_rotation(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert='old-cert', admin_tls_key='old-key' WHERE id=1`); err != nil {
		t.Fatalf("seed slave admin TLS: %v", err)
	}
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "old-cert", Key: "old-key"})
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	restarted := make(chan struct{}, 1)
	SetRestartRequiredHandler(func() { restarted <- struct{}{} })
	t.Cleanup(func() { SetRestartRequiredHandler(nil) })
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := models.ClusterSnapshot{Version: 2, BasicSettings: models.ClusterBasicSettings{
		LogLevel: "info", Timezone: "Asia/Shanghai", AdminTLSEnabled: true, AdminTLSMode: "upload", AdminTLSCert: "new-cert", AdminTLSKey: "new-key",
	}}

	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	select {
	case <-restarted:
	case <-time.After(time.Second):
		t.Fatal("restart callback was not invoked for certificate rotation")
	}
}
