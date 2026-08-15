package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_applySnapshot_keeps_valid_certificate_while_master_job_is_queued(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	certPEM, keyPEM := matchingCertificatePair(t, "example.com")
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled) VALUES (7,'queued cert CA','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (11,'queued cert DNS','dnspod','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
		VALUES ('lb_queued_cert','queued cert','http','Example.COM',443,1,'acme_dns',11,7,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_queued_cert','127.0.0.1',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_queued_cert','example.com','queued',datetime('now','+30 days'),?,?,7,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_queued_cert','WWW.Example.com,example.com','issued',datetime('now','-1 day'),'expired-cert','expired-key',8,datetime('now','+2 minutes')),
		('lb_queued_cert','www.example.com,example.com','disabled',datetime('now','+90 days'),'retired-cert','retired-key',9,datetime('now','+1 minute'))`); err != nil {
		t.Fatal(err)
	}
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='lb_queued_cert'"); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	if err := WriteCertFiles("lb_queued_cert", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	err = syncService.applySnapshot(context.Background(), incoming)

	// Then
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := CertFilePaths("lb_queued_cert")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("synced certificate was removed: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("synced private key was removed: %v", err)
	}
	var status string
	var providerID int
	if err := database.QueryRow("SELECT status,ca_provider_id FROM cert_jobs WHERE rule_id='lb_queued_cert'").Scan(&status, &providerID); err != nil {
		t.Fatal(err)
	}
	if status != "issued" || providerID != 7 {
		t.Fatalf("synced job status=%q provider=%d", status, providerID)
	}
}

func TestClusterSnapshot_roundTrip_preservesACMEState_for_promoted_slave(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	var sequence int
	var databaseName, databasePath string
	if err := database.QueryRow("PRAGMA database_list").Scan(&sequence, &databaseName, &databasePath); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Dir(databasePath)
	ownership := `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"token","record_id":"record-1"}]}`
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), []byte(ownership), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES (7,'ZeroSSL promotion','zerossl','https://acme.zerossl.com/v2/DV90','{"eab_kid":"kid","eab_hmac_key":"secret"}',3,750,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled)
		VALUES (11,'DNSPod promotion','dnspod','{"secret_id":"dns-id","secret_key":"dns-secret"}',1)`); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := matchingCertificatePair(t, "promotion.example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
		VALUES ('lb_promote_acme','promotion','http','promotion.example.com',443,1,'acme_dns',11,7,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_promote_acme','127.0.0.1',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_promote_acme','promotion.example.com','waiting_ca',datetime('now','+60 days'),?,?,7,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "cluster-token")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ACME == nil {
		t.Fatal("snapshot omitted ACME state")
	}
	if _, err := database.Exec("DELETE FROM cert_jobs; DELETE FROM lb_rules; DELETE FROM certificate_configs; DELETE FROM ca_providers"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (99,'stale','letsencrypt','https://acme-v02.api.letsencrypt.org/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (99,'stale','dnspod','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), []byte(`{"version":1,"records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0"); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	lifecycle := &clusterLifecycleFake{}
	promotable := NewClusterService(database, lifecycle)

	// When
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := promotable.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Then
	var providerCredentials, dnsCredentials, jobStatus string
	var jobProviderID int
	if err := database.QueryRow(`SELECT p.credentials,c.dns_credentials,j.status,j.ca_provider_id
		FROM ca_providers p CROSS JOIN certificate_configs c JOIN cert_jobs j ON j.rule_id='lb_promote_acme'
		WHERE p.id=7 AND c.id=11`).Scan(&providerCredentials, &dnsCredentials, &jobStatus, &jobProviderID); err != nil {
		t.Fatal(err)
	}
	if providerCredentials != `{"eab_kid":"kid","eab_hmac_key":"secret"}` || dnsCredentials != `{"secret_id":"dns-id","secret_key":"dns-secret"}` {
		t.Fatalf("restored credentials provider=%q dns=%q", providerCredentials, dnsCredentials)
	}
	if jobStatus != "issued" || jobProviderID != 7 || !lifecycle.acmeStarted {
		t.Fatalf("promoted job status=%q provider=%d acme_started=%v", jobStatus, jobProviderID, lifecycle.acmeStarted)
	}
	var staleProviders, staleConfigs int
	if err := database.QueryRow(`SELECT (SELECT COUNT(*) FROM ca_providers WHERE id=99),(SELECT COUNT(*) FROM certificate_configs WHERE id=99)`).Scan(&staleProviders, &staleConfigs); err != nil {
		t.Fatal(err)
	}
	if staleProviders != 0 || staleConfigs != 0 {
		t.Fatalf("stale ACME rows remain providers=%d configs=%d", staleProviders, staleConfigs)
	}
	restoredOwnership, err := os.ReadFile(filepath.Join(dataDir, "acme_dns_ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredOwnership) != ownership {
		t.Fatalf("restored DNS ownership=%s", restoredOwnership)
	}
}

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

func TestSyncService_applySnapshot_replays_cert_jobs_when_rules_section_skipped(t *testing.T) {
	// Given：从节点已应用过 rules 节（哈希一致将被跳过），但主节点另发来一张
	// 证书。cert_jobs 有唯一索引 (rule_id,domain)，若 rules 节跳过时不清理
	// cert_jobs，证书 INSERT 重放会撞唯一索引，导致同步永久失败。
	_, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
		VALUES ('lb_b1','b1','http','example.com',443,1,'acme_dns',11,7,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_b1','example.com','issued',datetime('now','+30 days'),'old-cert','old-key',7,datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	newCertPEM, newKeyPEM := matchingCertificatePair(t, "example.com")
	snapshot := models.ClusterSnapshot{
		Version: 3,
		Rules: []models.LbRule{{
			CaddyID: "lb_b1", Name: "b1", Protocol: "http", Domain: "example.com",
			ListenPort: 443, EnableTLS: true, TLSSource: "acme_dns",
			ACMEConfigID: 11, CAProviderID: 7, Enabled: true,
		}},
		Certs: []models.ClusterCertificate{{
			RuleID: "lb_b1", Domain: "example.com",
			CertPEM: newCertPEM, KeyPEM: newKeyPEM, CAProviderID: 7,
		}},
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version) VALUES ('rules', ?, ?)`,
		snapshot.SectionHashes["rules"], snapshot.Version); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	err := syncService.applySnapshot(context.Background(), snapshot)

	// Then
	if err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var certPEM string
	if err := database.QueryRow(`SELECT cert_pem FROM cert_jobs WHERE rule_id='lb_b1' AND domain='example.com'`).Scan(&certPEM); err != nil {
		t.Fatal(err)
	}
	if certPEM != newCertPEM {
		t.Fatalf("cert_jobs 未被主节点证书替换: got %q", certPEM)
	}
}

func TestClearSyncTables_propagatesDeleteError(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// When
	err = clearSyncTables(context.Background(), tx, "nonexistent_table")

	// Then
	if err == nil {
		t.Fatal("expected delete error for nonexistent table")
	}
	if !strings.Contains(err.Error(), "清理同步表 nonexistent_table 失败") {
		t.Fatalf("error=%v, want table context", err)
	}
}
