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

func TestValidateSnapshotACMEState_missingACMESectionRejected(t *testing.T) {
	// Given：缺 ACME 区段的快照。生产仅 v3 可达（verifiedSnapshotIntegrity
	// 先按 schema 拒掉过旧/过新），R54 S-4 移除 v2 放行死分支后统一硬拒。
	v3 := models.ClusterSnapshot{SchemaVersion: 3}
	v2 := models.ClusterSnapshot{SchemaVersion: 2}

	// When
	v3Err := validateSnapshotACMEState(v3)
	v2Err := validateSnapshotACMEState(v2)

	// Then
	if v3Err == nil {
		t.Fatal("schema v3 快照缺少 ACME 区段被放行")
	}
	if v2Err == nil {
		t.Fatal("缺少 ACME 区段的快照被放行（v2 放行分支是不可达死代码，已移除）")
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

func TestValidateSnapshotACMEState_toleratesUnsetOrDanglingConfigWithWarning(t *testing.T) {
	// R51 发现3(b)：acme_config_id=0 / 悬挂配置引用的规则在主节点是「单规则
	// 损坏」状态（issuer 按单任务失败），整包拒绝会让一条可经 API/导入产生的
	// 坏规则瘫痪全部从节点同步——对齐 verifySnapshotConsistency 的 fail-open
	// 哲学，逐条跳过+warn，主节点修复后随后续同步自愈。
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
	if unsetErr != nil || missingErr != nil {
		t.Fatalf("bad-rule snapshots must not be rejected wholesale: unset error=%v missing error=%v", unsetErr, missingErr)
	}
}

func TestValidateSnapshotACMEState_toleratesDanglingCAProviderWithWarning(t *testing.T) {
	// R52 N3 + F-1（从节点侧）：rules 循环的 ca_provider 分支与 certs 循环
	// 仍对悬挂 ca_provider_id 整包硬拒——重新引入 R51 发现3 已消灭的
	// 「一条坏规则/坏证书瘫痪全部从节点同步」失败模式。对齐 fail-open：
	// 逐条 skip+warn，主节点修复后随后续同步自愈。
	// Given：规则与证书各携带一个悬挂 ca_provider_id（providers 集合为空）
	snapshot := models.ClusterSnapshot{SchemaVersion: 3, ACME: &models.ClusterACMEState{
		CAProviders:        []models.CAProvider{},
		CertificateConfigs: []models.CertificateConfig{{ID: 11, Name: "dns", DNSProvider: "dnspod"}},
		DNSOwnership:       json.RawMessage(`{"version":1,"records":[]}`),
	}}
	snapshot.Rules = []models.LbRule{{CaddyID: "lb_dangling_ca", EnableTLS: true, TLSSource: "acme_dns", ACMEConfigID: 11, CAProviderID: 99}}
	snapshot.Certs = []models.ClusterCertificate{{RuleID: "lb_dangling_ca", CAProviderID: 98}}

	// When
	err := validateSnapshotACMEState(snapshot)

	// Then
	if err != nil {
		t.Fatalf("dangling ca_provider_id must not reject the whole snapshot: %v", err)
	}
}

func TestValidateSnapshotACMEState_toleratesBrokenProviderAndConfigRowsWithWarning(t *testing.T) {
	// R53-A-1：provider/config 行级坏数据（空 Name/Provider/DirectoryURL，
	// 仅 v1 导入残留/直改库可达）整包硬拒会让 rules/users 等无关节同步一并
	// 瘫痪——与 R51 发现3/R52 N3 同型 fail-open：逐行 warn+continue，坏行
	// 照常镜像落库，主节点修复后随后续同步自愈。
	// Given：一条空字段 provider 行 + 一条空字段 config 行
	snapshot := models.ClusterSnapshot{SchemaVersion: 3, ACME: &models.ClusterACMEState{
		CAProviders:        []models.CAProvider{{ID: 7, Name: "", Provider: "", DirectoryURL: ""}},
		CertificateConfigs: []models.CertificateConfig{{ID: 8, Name: "", DNSProvider: ""}},
		DNSOwnership:       json.RawMessage(`{"version":1,"records":[]}`),
	}}

	// When
	err := validateSnapshotACMEState(snapshot)

	// Then
	if err != nil {
		t.Fatalf("broken provider/config rows must not reject the whole snapshot: %v", err)
	}
}

func TestClusterService_Snapshot_prefersLaterExpiryBeforeExactDomainMatch(t *testing.T) {
	// Given：exact 证书（24h 后到期）updated_at 更晚；覆盖证书（90 天后到期）
	// updated_at 更早——updated_at 顺序与 NotAfter 顺序相反，必须真正按
	// NotAfter 降序选择覆盖证书，而不是靠种子巧合按 updated_at 选中
	service, database := newClusterTestService(t)
	now := time.Now().UTC()
	service.snapshotNow = func() time.Time { return now }
	exactCert, exactKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "example.com")
	coveringCert, coveringKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "example.com", "www.example.com")
	seedSnapshotCertificate(t, database, "lb_selection", "example.com", "example.com", exactCert, exactKey, now.Add(24*time.Hour), 1)
	seedSnapshotCertificateJob(t, database, "lb_selection", "example.com,www.example.com", coveringCert, coveringKey, now.Add(90*24*time.Hour), 2)
	if _, err := database.Exec("UPDATE cert_jobs SET updated_at=? WHERE id=2", now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

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
	if _, err := database.Exec(`INSERT OR IGNORE INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'snapshot CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO certificate_configs (id,name,dns_provider,enabled) VALUES (11,'snapshot DNS','dnspod',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled) VALUES ('lb_bad_candidate','bad','http','bad.example.com',443,1,'acme_dns',11,7,1)`); err != nil {
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

func TestNearestSnapshotCertificateExpiry_acmeWithEmptyExpiryUsesRebuildWindow(t *testing.T) {
	// Given
	now := time.Now().UTC()

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_acme", Domain: "example.com", CertPEM: "pem", ExpiresAt: ""},
	}, now)

	// Then
	if !got.Equal(now.Add(snapshotCertMissingExpiryWindow)) {
		t.Fatalf("expiry=%v, want rebuild window %v", got, now.Add(snapshotCertMissingExpiryWindow))
	}
}

func TestNearestSnapshotCertificateExpiry_manualCertWithoutExpirySkipped(t *testing.T) {
	// Given
	now := time.Now().UTC()

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_manual", CertPEM: "pem", ExpiresAt: ""},
	}, now)

	// Then
	if !got.IsZero() {
		t.Fatalf("expiry=%v, want zero (manual cert skipped)", got)
	}
}

func TestNearestSnapshotCertificateExpiry_returnsNearestFutureExpiry(t *testing.T) {
	// Given
	now := time.Now().UTC().Truncate(time.Second)
	near := now.Add(24 * time.Hour).Format(time.RFC3339)
	far := now.Add(90 * 24 * time.Hour).Format(time.RFC3339)

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_far", Domain: "far.example.com", ExpiresAt: far},
		{RuleID: "lb_near", Domain: "near.example.com", ExpiresAt: near},
	}, now)

	// Then
	if !got.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("expiry=%v, want nearest %v", got, now.Add(24*time.Hour))
	}
}
