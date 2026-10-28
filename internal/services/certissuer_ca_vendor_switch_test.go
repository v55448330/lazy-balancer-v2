package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// 快速路径只比 provider id 时，「同一 provider 行改类型」（letsencrypt↔zerossl，
// id 不变、不触碰 cert_jobs）不会被发现——引用该 provider 的规则会继续服务旧
// 厂商签发的证书，直到下一次续期（最长一个证书寿命）。证书 issuer 与当前
// provider 类型矛盾时必须走完整重签。
func TestCertIssuer_Issue_fastPathReissuesWhenCertificateFromOtherCA(t *testing.T) {
	// Given：provider 行切到 ZeroSSL，任务里的证书仍是 Let's Encrypt 签发的
	jobID, ruleID, providerID := seedCrossCAFastPathJob(t, ProviderZeroSSL)
	certPEM := pemWithIssuer(t, time.Now().Add(90*24*time.Hour), "Let's Encrypt", "R11")
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key' WHERE id=?", certPEM, jobID); err != nil {
		t.Fatalf("seed cross-CA material: %v", err)
	}
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	issuer := NewCertIssuer(func() error { return nil })
	redeployed := make(chan struct{}, 1)
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error {
		redeployed <- struct{}{}
		return nil
	}

	// When：针对该 provider 触发一次（补偿重排队形态）
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID, Provider: ProviderZeroSSL})

	// Then：必须走完整签发（预检对不可达目录失败），不得重部署旧厂商证书
	if err == nil {
		t.Fatal("CA 厂商不匹配时必须重签（快速路径会重部署旧厂商证书并返回 nil）")
	}
	select {
	case <-redeployed:
		t.Fatal("CA 厂商不匹配时不得登记部署重试")
	default:
	}
	logData, readErr := os.ReadFile(CertJobLogPath(ruleID))
	if readErr != nil {
		t.Fatalf("read cert job log: %v", readErr)
	}
	if !strings.Contains(string(logData), "测试 CA 提供商") {
		t.Fatalf("job log=%q, want 完整签发链的预检记录", string(logData))
	}
}

// 回归形状：证书厂商与当前 provider 一致时，快速路径照旧（重部署、不重签）。
func TestCertIssuer_Issue_fastPathKeepsRedeployWhenVendorMatches(t *testing.T) {
	jobID, ruleID, providerID := seedCrossCAFastPathJob(t, ProviderZeroSSL)
	certPEM := pemWithIssuer(t, time.Now().Add(90*24*time.Hour), "ZeroSSL", "ZeroSSL RSA Domain Secure Site CA")
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key' WHERE id=?", certPEM, jobID); err != nil {
		t.Fatalf("seed same-CA material: %v", err)
	}
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	issuer := NewCertIssuer(func() error { return nil })

	if err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID, Provider: ProviderZeroSSL}); err != nil {
		t.Fatalf("同厂商证书必须走快速路径重部署，err=%v", err)
	}
	logData, readErr := os.ReadFile(CertJobLogPath(ruleID))
	if readErr != nil {
		t.Fatalf("read cert job log: %v", readErr)
	}
	if strings.Contains(string(logData), "测试 CA 提供商") {
		t.Fatalf("job log=%q, 同厂商不得重签", string(logData))
	}
}

// certIssuedByOtherCA 只做正向识别：明确来自另一个已知厂商才拦，其余一律放行。
func TestCertIssuedByOtherCA_table(t *testing.T) {
	le := pemWithIssuer(t, time.Now().Add(time.Hour), "Let's Encrypt", "R11")
	zero := pemWithIssuer(t, time.Now().Add(time.Hour), "ZeroSSL", "ZeroSSL RSA Domain Secure Site CA")
	self := pemWithIssuer(t, time.Now().Add(time.Hour), "Internal CA", "internal")
	cases := []struct {
		name     string
		certPEM  string
		provider string
		want     bool
	}{
		{"LE 证书 + ZeroSSL provider", le, ProviderZeroSSL, true},
		{"LE 证书 + LE provider", le, ProviderLetsEncrypt, false},
		{"ZeroSSL 证书 + LE provider", zero, ProviderLetsEncrypt, true},
		{"ZeroSSL 证书 + ZeroSSL provider", zero, ProviderZeroSSL, false},
		{"自建 CA + ZeroSSL provider（无法识别）", self, ProviderZeroSSL, false},
		{"自建 CA + LE provider（无法识别）", self, ProviderLetsEncrypt, false},
		{"空 provider 类型（未知）", le, "", false},
		{"空材料", "", ProviderZeroSSL, false},
		{"坏 PEM", "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----", ProviderZeroSSL, false},
	}
	for _, tc := range cases {
		if got := certIssuedByOtherCA(tc.certPEM, tc.provider); got != tc.want {
			t.Errorf("%s: certIssuedByOtherCA=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// seedCrossCAFastPathJob 播一个「provider 存在且可达性由测试桩控制」的 downloaded
// 任务：规则与任务都指向同一 provider 行（id 不变），满足旧判据。
func seedCrossCAFastPathJob(t *testing.T, providerType string) (int, string, int) {
	t.Helper()
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "no acme here", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	result, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('cross-ca',?,?,'{}',1,0,1)`, providerType, server.URL+"/directory")
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID64, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	providerID := int(providerID64)
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id=?", providerID, ruleID); err != nil {
		t.Fatalf("bind rule CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET ca_provider_id=? WHERE id=?", providerID, jobID); err != nil {
		t.Fatalf("bind job CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='admin@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed ACME email: %v", err)
	}
	return jobID, ruleID, providerID
}

// pemWithIssuer 生成自签证书（issuer=subject），用 Organization/CommonName
// 模拟某厂商签发的证书。真实链路里 issuer 由 CA 决定，测试只需可识别的文案。
func pemWithIssuer(t *testing.T, notAfter time.Time, organization, commonName string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.UnixNano()),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		DNSNames:  []string{"example.com"},
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
