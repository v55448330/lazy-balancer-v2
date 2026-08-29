package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func TestValidateDNSOwnership_rejectsIncompleteRecords_allowsLegacyEmptyValue(t *testing.T) {
	rejected := []struct {
		name string
		data string
	}{
		{name: "missing zone", data: `{"version":1,"records":[{"provider":"dnspod","fqdn":"_acme.example.com","value":"token","record_id":"1"}]}`},
		{name: "missing record_id", data: `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme.example.com","value":"token"}]}`},
	}
	for _, test := range rejected {
		t.Run(test.name, func(t *testing.T) {
			// When
			err := validateDNSOwnership([]byte(test.data))

			// Then
			if err == nil {
				t.Fatal("incomplete ownership record was accepted")
			}
		})
	}

	// When/Then: empty value records are store-supported legacy (see
	// ownership.Store.MatchingValue) and must not fail cluster snapshots
	legacy := `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme.example.com","record_id":"1"}]}`
	if err := validateDNSOwnership([]byte(legacy)); err != nil {
		t.Fatalf("legacy empty-value record rejected: %v", err)
	}
}

func TestClusterService_Snapshot_accepts_legacy_empty_value_ownership(t *testing.T) {
	// Given: a node whose ownership file still holds a pre-value-tracking
	// legacy record (empty value), as supported by the ownership store
	service, database := newClusterTestService(t)
	dataDir, err := clusterDatabaseDir(database)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","record_id":"100"}]}`)
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")

	// Then: snapshot building stays available instead of failing every
	// section (rules/certs/users) on one legacy record
	if err != nil {
		t.Fatalf("snapshot with legacy ownership: %v", err)
	}
	if snapshot.Fingerprint == "" {
		t.Fatal("snapshot missing fingerprint")
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

// captureApplicationLogs 把应用日志（Logf → log.Printf）重定向到缓冲区，供
// 断言 warn 输出；返回恢复函数由 t.Cleanup 挂接。
func captureApplicationLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	previousLevel := CurrentLogLevel()
	if err := ConfigureLogLevel("info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureLogLevel(previousLevel) })
	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &logs
}

func writeDNSOwnershipFile(t *testing.T, database *sql.DB, content []byte) {
	t.Helper()
	dataDir, err := clusterDatabaseDir(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), content, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotOwnershipHash_corruptFileFallsBackToEmptyCanonical(t *testing.T) {
	// Given：空闲主节点上所有权文件损坏（JSON 不可解码）——store 侧隔离要等
	// 下一次签发触碰才发生，快照读取必须先按空态自愈，不能让整个 Snapshot/
	// 从节点 Pull 失败
	_, database := newClusterTestService(t)
	writeDNSOwnershipFile(t, database, []byte(`{"version":1,"records":[`))
	logs := captureApplicationLogs(t)

	// When
	hash, err := snapshotOwnershipHash(context.Background(), database)

	// Then：回退空规范字节（与文件缺失分支同源），不报错，且告警一行
	if err != nil {
		t.Fatalf("corrupt ownership must not fail the snapshot hash: %v", err)
	}
	if want := sha256.Sum256([]byte(`{"version":1,"records":[]}`)); hash != want {
		t.Fatalf("hash=%x, want empty-canonical hash %x", hash, want)
	}
	if output := logs.String(); !strings.Contains(output, "WARNING") || !strings.Contains(output, "acme_dns_ownership.json") {
		t.Fatalf("expected one warn line with path+reason, got %q", output)
	}
}

func TestSnapshotOwnershipHash_structurallyInvalidFileFallsBackToEmptyCanonical(t *testing.T) {
	// Given：可解析但结构无效（缺 zone）——非解码类校验失败同属尽力而为缓存
	// 范畴，按同样口径回退，不阻断同步
	_, database := newClusterTestService(t)
	writeDNSOwnershipFile(t, database, []byte(`{"version":1,"records":[{"provider":"dnspod","fqdn":"_acme-challenge.example.com","record_id":"1"}]}`))

	// When
	hash, err := snapshotOwnershipHash(context.Background(), database)

	// Then
	if err != nil {
		t.Fatalf("structurally invalid ownership must not fail the snapshot hash: %v", err)
	}
	if want := sha256.Sum256([]byte(`{"version":1,"records":[]}`)); hash != want {
		t.Fatalf("hash=%x, want empty-canonical hash %x", hash, want)
	}
}

func TestClusterService_Snapshot_acmeStateWithCorruptOwnershipFallsBackEmpty(t *testing.T) {
	// Given：ACME 区段构建（快照侧第二处读取点）面对损坏所有权文件
	service, database := newClusterTestService(t)
	writeDNSOwnershipFile(t, database, []byte(`not json at all`))

	// When
	state, err := service.snapshotACME(context.Background(), database)

	// Then：空 records 分发，不报错
	if err != nil {
		t.Fatalf("corrupt ownership must not fail the ACME state build: %v", err)
	}
	if string(state.DNSOwnership) != `{"version":1,"records":[]}` {
		t.Fatalf("dns ownership=%q, want empty canonical", state.DNSOwnership)
	}
}

func TestClusterService_Snapshot_succeedsWithCorruptOwnershipFile(t *testing.T) {
	// Given：端到端——主节点 DB 完好但所有权文件损坏，从节点 Pull 依赖的
	// Snapshot 必须照常出片（损坏文件只降级 DNS-01 所有权清理，属可自愈缓存）
	service, database := newClusterTestService(t)
	writeDNSOwnershipFile(t, database, []byte(`{"version":2,"records":[]}`))

	// When
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "cluster-token")

	// Then
	if err != nil {
		t.Fatalf("snapshot with corrupt ownership file: %v", err)
	}
	if snapshot.Fingerprint == "" {
		t.Fatal("snapshot missing fingerprint")
	}
	if snapshot.ACME == nil || string(snapshot.ACME.DNSOwnership) != `{"version":1,"records":[]}` {
		t.Fatalf("snapshot acme ownership=%v, want empty canonical", snapshot.ACME)
	}
}

func TestSnapshotOwnershipHash_missingFileKeepsEmptyCanonicalSilently(t *testing.T) {
	// Given：无所有权文件（新装机/store 隔离后）——既有语义必须保持：按空
	// 规范字节哈希且不告警
	_, database := newClusterTestService(t)
	logs := captureApplicationLogs(t)

	// When
	hash, err := snapshotOwnershipHash(context.Background(), database)

	// Then
	if err != nil {
		t.Fatalf("missing ownership file must not fail: %v", err)
	}
	if want := sha256.Sum256([]byte(`{"version":1,"records":[]}`)); hash != want {
		t.Fatalf("hash=%x, want empty-canonical hash %x", hash, want)
	}
	if output := logs.String(); strings.Contains(output, "WARNING") {
		t.Fatalf("missing file must stay silent, got %q", output)
	}
}

func TestSnapshotOwnershipHash_realReadErrorStillFails(t *testing.T) {
	// Given：路径被目录占据（EISDIR，非 ErrNotExist 的真实 I/O 故障）——
	// 真实读取错误保持报错语义，不被空态回退掩盖
	_, database := newClusterTestService(t)
	dataDir, err := clusterDatabaseDir(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dataDir, "acme_dns_ownership.json"), 0700); err != nil {
		t.Fatal(err)
	}

	// When
	_, err = snapshotOwnershipHash(context.Background(), database)

	// Then
	if err == nil {
		t.Fatal("real I/O read error must not be masked by the empty-state fallback")
	}
}

// C2-S1 回归：损坏文件的快照侧回退告警必须经 60s 限流（throttledAuditFailureLogf）。
// 该读取点在每次全量快照构建（主节点 ticker + 每个从节点 Pull）都会执行，坏文件
// 在 store 侧被实际隔离前会持续存在——无限流时每个周期都刷一条 warn。
func TestSnapshotOwnershipHash_corruptFileWarnThrottled(t *testing.T) {
	_, database := newClusterTestService(t)
	writeDNSOwnershipFile(t, database, []byte(`{"version":1,"records":[`))
	logs := captureApplicationLogs(t)

	// 隔离共享限流表：同文件中先前的损坏告警已占用同一归一化键（路径数字
	// 归一为 #），不重置会压制本测试的首条放行断言；defer 还原现场。
	auditFailureLogMu.Lock()
	saved := auditFailureLogTimes
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	defer func() {
		auditFailureLogMu.Lock()
		auditFailureLogTimes = saved
		auditFailureLogMu.Unlock()
	}()

	for i := 0; i < 3; i++ {
		if _, err := snapshotOwnershipHash(context.Background(), database); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logs.String(), "WARNING"); n != 1 {
		t.Fatalf("同一损坏文件 3 次读取应仅放行 1 条 warn（60s 窗口），got %d: %q", n, logs.String())
	}
}
