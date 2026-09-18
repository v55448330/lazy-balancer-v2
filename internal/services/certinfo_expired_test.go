package services

// CERT40-1(第 40 轮):ACME 规则证书信息对「已过期证书」不得误报「尚未签发
// 或不存在」——cert_jobs 存在 PEM 但已过期时按 expired 呈现(解析真实
// NotAfter),运维可从规则列表直接看到过期状态。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// expiredShapeCertAndKey 生成指定域名/有效期外的证书+私钥 PEM 对。
func expiredShapeCertAndKey(t *testing.T, domain string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func TestGetRuleCertInfo_reportsExpiredACMECert(t *testing.T) {
	_, database := newClusterTestService(t)

	// Given:ACME 规则 + cert_jobs 携带已过期证书(SelectCertificate 因过期跳过)
	certPEM, keyPEM := expiredShapeCertAndKey(t, "expired.test", time.Now().Add(-24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_expired','expired','expired.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_expired', 'expired.test', 'issued', ?, ?, datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	// When
	info := GetRuleCertInfo("lb_expired")

	// Then:expired 而非「尚未签发」
	if info == nil {
		t.Fatal("info is nil")
	}
	if info.Status != "expired" {
		t.Fatalf("status=%q, want expired (must not report 尚未签发)", info.Status)
	}
	if !strings.Contains(info.Error, "已过期") {
		t.Fatalf("error=%q, want ACME 证书已过期", info.Error)
	}
}
