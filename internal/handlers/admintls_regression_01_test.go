package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

// days_left 与证书信息同口径向零截断（services/certinfo.go int(hours/24)）：
// 此前未过期用 Ceil（23h→1）、已过期用 Floor（过期 1天3h→-2），两处对同一
// 剩余期给出不同天数。统一为向零截断：23h→0、过期 1天3h→-1。
func TestParseAdminTLSCertInfo_daysLeftTruncates(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		notAfter time.Time
		wantDays int
		expired  bool
	}{
		{name: "23h remaining truncates to 0", notAfter: now.Add(23 * time.Hour), wantDays: 0, expired: false},
		{name: "expired 1d3h truncates to -1", notAfter: now.Add(-27 * time.Hour), wantDays: -1, expired: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			certPEM, _, err := generateTestCert("admintls.test", now.Add(-48*time.Hour), tt.notAfter)
			if err != nil {
				t.Fatalf("generate cert: %v", err)
			}

			// When
			info, err := parseAdminTLSCertInfo(certPEM)

			// Then
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if info.DaysLeft != tt.wantDays {
				t.Fatalf("days_left=%d, want %d(历史截断口径)", info.DaysLeft, tt.wantDays)
			}
			if info.Expired != tt.expired {
				t.Fatalf("expired=%v, want %v", info.Expired, tt.expired)
			}
		})
	}
}

func adminTLSTestCertWithIssuer(t *testing.T, commonName string, dnsNames []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Let's Encrypt"},
		},
		DNSNames:    dnsNames,
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseAdminTLSCertInfo_matchesRuleCertificateDisplay(t *testing.T) {
	tests := []struct {
		name       string
		commonName string
		dnsNames   []string
	}{
		{name: "SAN 不含 CN 时仍保留 CN", commonName: "cn.example.test", dnsNames: []string{"san.example.test"}},
		{name: "仅 CN", commonName: "only-cn.example.test"},
		{name: "多 SAN 且 CN 去重", commonName: "api.example.test", dnsNames: []string{"www.example.test", "api.example.test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM := adminTLSTestCertWithIssuer(t, tt.commonName, tt.dnsNames)
			adminInfo, err := parseAdminTLSCertInfo(certPEM)
			if err != nil {
				t.Fatalf("parse admin certificate: %v", err)
			}
			ruleInfo := services.FormatRuleCertInfo(certPEM, "manual", "", "", 30, time.Now())
			if adminInfo.Issuer != ruleInfo.Issuer {
				t.Fatalf("issuer admin=%q rule=%q, want 同一显示口径", adminInfo.Issuer, ruleInfo.Issuer)
			}
			if adminInfo.Domain != ruleInfo.Domains {
				t.Fatalf("domains admin=%q rule=%q, want SAN+CN 去重单源", adminInfo.Domain, ruleInfo.Domains)
			}
		})
	}
}
