package handlers

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

// generateR41CAChain 生成「测试 CA → 叶子」证书对,返回叶子 PEM/私钥与含
// 测试 CA 的根池(经 tlsCertSystemRoots 注入,模拟系统根信任)。
func generateR41CAChain(t *testing.T, dnsNames []string) (certPEM, keyPEM string, roots *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "R41 Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	leafTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}))
	roots = x509.NewCertPool()
	roots.AddCert(caCert)
	return certPEM, keyPEM, roots
}

// injectR41Roots 用测试根池替换系统根源(验证链完整性判定),返回还原函数。
func injectR41Roots(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	old := tlsCertSystemRoots
	tlsCertSystemRoots = func() (*x509.CertPool, error) { return roots, nil }
	t.Cleanup(func() { tlsCertSystemRoots = old })
}

// CERT41-4:自签单张——系统根不认可(unknown authority)→链不完整警告。
func TestTlsCertificateWarnings_selfSignedSingleWarnsIncompleteChain(t *testing.T) {
	// Given
	certPEM, keyPEM, err := generateTestCert("self.example.test", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// When
	warnings := tlsCertificateWarnings(certPEM, keyPEM, "self.example.test")

	// Then
	joined := strings.Join(warnings, "；")
	if !strings.Contains(joined, "证书链可能不完整") {
		t.Fatalf("warnings=%v, want incomplete-chain warning", warnings)
	}
}

// CERT41-4:链可信但证书不覆盖规则域名→域名不匹配警告(不阻断)。
func TestTlsCertificateWarnings_domainMismatchWarns(t *testing.T) {
	// Given
	certPEM, keyPEM, roots := generateR41CAChain(t, []string{"cert.example.test"})
	injectR41Roots(t, roots)

	// When
	warnings := tlsCertificateWarnings(certPEM, keyPEM, "rule.example.test")

	// Then
	joined := strings.Join(warnings, "；")
	if !strings.Contains(joined, "证书域名与规则域名不匹配") {
		t.Fatalf("warnings=%v, want domain-mismatch warning", warnings)
	}
	if strings.Contains(joined, "证书链可能不完整") {
		t.Fatalf("warnings=%v, chain must verify against injected roots", warnings)
	}
}

// CERT41-4:链可信且域名覆盖(精确与通配)→无警告返回 nil。
func TestTlsCertificateWarnings_validChainAndCoveredDomainReturnsNil(t *testing.T) {
	tests := []struct {
		name     string
		dnsNames []string
		domain   string
	}{
		{name: "精确匹配", dnsNames: []string{"app.example.test"}, domain: "app.example.test"},
		{name: "通配覆盖单段", dnsNames: []string{"*.example.test"}, domain: "api.example.test"},
		{name: "多 SAN 命中其一", dnsNames: []string{"a.example.test", "b.example.test"}, domain: "b.example.test"},
		{name: "规则多域名全覆盖", dnsNames: []string{"example.test", "www.example.test"}, domain: "example.test,www.example.test"},
		{name: "空域名跳过域名检查", dnsNames: []string{"app.example.test"}, domain: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			certPEM, keyPEM, roots := generateR41CAChain(t, tt.dnsNames)
			injectR41Roots(t, roots)

			// When
			warnings := tlsCertificateWarnings(certPEM, keyPEM, tt.domain)

			// Then
			if warnings != nil {
				t.Fatalf("warnings=%v, want nil", warnings)
			}
		})
	}
}

// CERT41-4:通配符语义边界——*.example.test 不覆盖裸域与二级以上子域。
func TestTlsCertificateWarnings_wildcardBoundary(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{name: "裸域不被通配覆盖", domain: "example.test"},
		{name: "二级子域不被单段通配覆盖", domain: "a.b.example.test"},
		{name: "无关域名", domain: "other.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			certPEM, keyPEM, roots := generateR41CAChain(t, []string{"*.example.test"})
			injectR41Roots(t, roots)

			// When
			warnings := tlsCertificateWarnings(certPEM, keyPEM, tt.domain)

			// Then
			joined := strings.Join(warnings, "；")
			if !strings.Contains(joined, "证书域名与规则域名不匹配") {
				t.Fatalf("warnings=%v, want domain-mismatch warning for %q", warnings, tt.domain)
			}
		})
	}
}

// CERT41-4:无法解析的证书材料由 validateTLSCertificate 硬校验负责,
// 警告侧防御性返回 nil(不重复报错)。
func TestTlsCertificateWarnings_invalidMaterialReturnsNil(t *testing.T) {
	// When
	warnings := tlsCertificateWarnings("not-a-cert", "not-a-key", "app.example.test")

	// Then
	if warnings != nil {
		t.Fatalf("warnings=%v, want nil for unparseable material", warnings)
	}
}
