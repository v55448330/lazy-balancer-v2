package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestClusterService_Snapshot_schemaV3WireContainsOnlySignedCanonicalPayload(t *testing.T) {
	// Given
	service, _ := newClusterTestService(t)

	// When
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "cluster-token")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}

	// Then
	want := []string{"canonical_payload", "fingerprint", "min_reader_version", "schema_version", "signature", "version"}
	if len(fields) != len(want) {
		t.Fatalf("wire fields=%v, want only v3 envelope", fields)
	}
	for _, field := range want {
		if _, exists := fields[field]; !exists {
			t.Fatalf("wire omitted %q: %s", field, wire)
		}
	}
}

func TestClusterService_Snapshot_rebuildsWhenDNSOwnershipChangesWithoutVersionBump(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	initial, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	dataDir, err := clusterDatabaseDir(database)
	if err != nil {
		t.Fatal(err)
	}
	changedOwnership := []byte(`{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"token","record_id":"record-1"}]}`)
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), changedOwnership, 0600); err != nil {
		t.Fatal(err)
	}

	// When
	updated, changed, err := service.Snapshot(context.Background(), initial.Version, initial.Fingerprint, "")

	// Then
	if err != nil || !changed || updated.Fingerprint == initial.Fingerprint {
		t.Fatalf("snapshot changed=%v fingerprint=%q initial=%q error=%v", changed, updated.Fingerprint, initial.Fingerprint, err)
	}
}

func TestClusterService_Snapshot_rebuildsAfterSelectedCertificateNaturallyExpires(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	base := time.Now().UTC()
	service.snapshotNow = func() time.Time { return base }
	certPEM, keyPEM := certificatePairForDomains(t, base.Add(-time.Hour), base.Add(time.Hour), "expiry.example.com")
	seedSnapshotCertificate(t, database, "lb_expiry_boundary", "expiry.example.com", "expiry.example.com", certPEM, keyPEM, base.Add(time.Hour), 1)
	initial, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(initial.Certs) != 1 {
		t.Fatalf("initial certs=%d error=%v", len(initial.Certs), err)
	}
	service.snapshotNow = func() time.Time { return base.Add(2 * time.Hour) }

	// When
	updated, changed, err := service.Snapshot(context.Background(), initial.Version, initial.Fingerprint, "")

	// Then
	if err != nil || !changed || len(updated.Certs) != 0 || updated.Version != initial.Version {
		t.Fatalf("updated version=%d certs=%d changed=%v error=%v", updated.Version, len(updated.Certs), changed, err)
	}
}

func TestValidateDNSOwnership_rejectsRecordsMissingZoneOrValue(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "missing zone", data: `{"version":1,"records":[{"provider":"dnspod","fqdn":"_acme.example.com","value":"token","record_id":"1"}]}`},
		{name: "missing value", data: `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme.example.com","record_id":"1"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			err := validateDNSOwnership([]byte(test.data))

			// Then
			if err == nil {
				t.Fatal("incomplete ownership record was accepted")
			}
		})
	}
}

func TestValidateSnapshotACMEState_schemaV3RequiresACMESection(t *testing.T) {
	// Given
	v3 := models.ClusterSnapshot{SchemaVersion: 3}
	v2 := models.ClusterSnapshot{SchemaVersion: 2}

	// When
	v3Err := validateSnapshotACMEState(v3)
	v2Err := validateSnapshotACMEState(v2)

	// Then
	if v3Err == nil || v2Err != nil {
		t.Fatalf("v3 error=%v v2 error=%v", v3Err, v2Err)
	}
}

func TestValidateSnapshotACMEState_acceptsDefaultCAAndDisabledTLSRule(t *testing.T) {
	// Given
	snapshot := models.ClusterSnapshot{
		SchemaVersion: 3,
		ACME: &models.ClusterACMEState{
			CAProviders:        []models.CAProvider{},
			CertificateConfigs: []models.CertificateConfig{{ID: 11, Name: "dns", DNSProvider: "dnspod"}},
			DNSOwnership:       json.RawMessage(`{"version":1,"records":[]}`),
		},
		Rules: []models.LbRule{
			{CaddyID: "lb_default_ca", EnableTLS: true, TLSSource: "acme_dns", ACMEConfigID: 11, CAProviderID: 0},
			{CaddyID: "lb_tls_disabled", EnableTLS: false, TLSSource: "acme_dns", ACMEConfigID: 0, CAProviderID: 99},
		},
	}

	// When
	err := validateSnapshotACMEState(snapshot)

	// Then
	if err != nil {
		t.Fatalf("valid default/disabled ACME rules rejected: %v", err)
	}
}

func TestValidateSnapshotACMEState_distinguishesUnsetConfigFromMissingReference(t *testing.T) {
	// Given
	base := models.ClusterSnapshot{SchemaVersion: 3, ACME: &models.ClusterACMEState{
		CAProviders: []models.CAProvider{}, CertificateConfigs: []models.CertificateConfig{}, DNSOwnership: json.RawMessage(`{"version":1,"records":[]}`),
	}}
	unset := base
	unset.Rules = []models.LbRule{{CaddyID: "lb_unset", EnableTLS: true, TLSSource: "acme_dns"}}
	missing := base
	missing.Rules = []models.LbRule{{CaddyID: "lb_missing", EnableTLS: true, TLSSource: "acme_dns", ACMEConfigID: 42}}

	// When
	unsetErr := validateSnapshotACMEState(unset)
	missingErr := validateSnapshotACMEState(missing)

	// Then
	if unsetErr == nil || !strings.Contains(unsetErr.Error(), "未设置") || missingErr == nil || !strings.Contains(missingErr.Error(), "不存在") {
		t.Fatalf("unset error=%v missing error=%v", unsetErr, missingErr)
	}
}

func TestClusterService_Snapshot_prefersLaterExpiryBeforeExactDomainMatch(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	now := time.Now().UTC()
	service.snapshotNow = func() time.Time { return now }
	exactCert, exactKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "example.com")
	coveringCert, coveringKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "example.com", "www.example.com")
	seedSnapshotCertificate(t, database, "lb_selection", "example.com", "example.com", exactCert, exactKey, now.Add(24*time.Hour), 1)
	seedSnapshotCertificateJob(t, database, "lb_selection", "example.com,www.example.com", coveringCert, coveringKey, now.Add(90*24*time.Hour), 2)

	// When
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")

	// Then
	if err != nil || len(snapshot.Certs) != 1 || snapshot.Certs[0].CertPEM != coveringCert {
		t.Fatalf("selected certs=%d covering=%v error=%v", len(snapshot.Certs), len(snapshot.Certs) == 1 && snapshot.Certs[0].CertPEM == coveringCert, err)
	}
}

func TestClusterService_Snapshot_rateLimitsMalformedCertificateWarningByRuleAndJob(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	now := time.Now().UTC()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,enabled) VALUES ('lb_bad_candidate','bad','http','bad.example.com',443,1,'acme_dns',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,cert_pem,key_pem) VALUES (991,'lb_bad_candidate','bad.example.com','issued',?,'bad-cert','bad-key')`, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	previousLevel := CurrentLogLevel()
	if err := ConfigureLogLevel("warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureLogLevel(previousLevel) })
	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	// When
	if _, _, err := service.Snapshot(context.Background(), 0, "", ""); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	if _, _, err := service.Snapshot(context.Background(), 0, "", ""); err != nil {
		t.Fatal(err)
	}

	// Then
	message := logs.String()
	if strings.Count(message, "lb_bad_candidate") != 1 || !strings.Contains(message, "991") {
		t.Fatalf("warning output=%q", message)
	}
}

func seedSnapshotCertificate(t *testing.T, database *sql.DB, ruleID, ruleDomain, jobDomain, certPEM, keyPEM string, expiresAt time.Time, jobID int) {
	t.Helper()
	if _, err := database.Exec(`INSERT OR IGNORE INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'snapshot CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO certificate_configs (id,name,dns_provider,enabled) VALUES (11,'snapshot DNS','dnspod',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled) VALUES (?,?,'http',?,443,1,'acme_dns',11,7,1)`, ruleID, ruleID, ruleDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES (?,'127.0.0.1',8080,1)`, ruleID); err != nil {
		t.Fatal(err)
	}
	seedSnapshotCertificateJob(t, database, ruleID, jobDomain, certPEM, keyPEM, expiresAt, jobID)
}

func seedSnapshotCertificateJob(t *testing.T, database *sql.DB, ruleID, jobDomain, certPEM, keyPEM string, expiresAt time.Time, jobID int) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at) VALUES (?, ?, ?, 'issued', ?, ?, ?, 7, ?)`, jobID, ruleID, jobDomain, expiresAt, certPEM, keyPEM, expiresAt.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func certificatePairForDomains(t *testing.T, notBefore, notAfter time.Time, domains ...string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(notAfter.UnixNano()), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
