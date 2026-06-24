package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// generateTestCert creates a test certificate and key pair
func generateTestCert(domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	// Encode certificate to PEM
	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode key to PEM
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return string(certPEMBlock), string(keyPEMBlock), nil
}

// generateMismatchedCert creates a certificate with a different key
func generateMismatchedCert() (certPEM, keyPEM string, err error) {
	// Generate first key pair
	certPEM, _, err = generateTestCert("example.com", time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		return "", "", err
	}

	// Generate different key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	return certPEM, keyPEM, nil
}

// generateECDSACert creates an ECDSA certificate
func generateECDSACert(domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	return certPEM, keyPEM, nil
}

func TestParseTLSCertificate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		certPEM     string
		keyPEM      string
		wantValid   bool
		wantDomain  string
		wantWarning bool
		wantErr     bool
		errContains string
	}{
		{
			name:      "empty cert and key",
			certPEM:   "",
			keyPEM:    "",
			wantValid: false,
			wantErr:   false,
		},
		{
			name:       "valid RSA certificate",
			wantValid:  true,
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:        "invalid cert PEM",
			certPEM:     "not a valid pem",
			keyPEM:      "not a valid key",
			wantErr:     true,
			errContains: "invalid certificate or key pair",
		},
		{
			name:        "expired certificate",
			wantValid:   true,
			wantDomain:  "expired.example.com",
			wantWarning: true,
			wantErr:     false,
		},
		{
			name:        "not yet valid certificate",
			wantValid:   true,
			wantDomain:  "future.example.com",
			wantWarning: true,
			wantErr:     false,
		},
		{
			name:        "mismatched cert and key",
			wantErr:     true,
			errContains: "private key does not match public key",
		},
		{
			name:       "valid ECDSA certificate",
			wantValid:  true,
			wantDomain: "ecdsa.example.com",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM := tt.certPEM
			keyPEM := tt.keyPEM
			var err error

			// Generate test certificates for specific test cases
			switch tt.name {
			case "valid RSA certificate":
				certPEM, keyPEM, err = generateTestCert("example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate test cert: %v", err)
				}
			case "expired certificate":
				certPEM, keyPEM, err = generateTestCert("expired.example.com", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate test cert: %v", err)
				}
			case "not yet valid certificate":
				certPEM, keyPEM, err = generateTestCert("future.example.com", now.Add(24*time.Hour), now.Add(48*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate test cert: %v", err)
				}
			case "mismatched cert and key":
				certPEM, keyPEM, err = generateMismatchedCert()
				if err != nil {
					t.Fatalf("failed to generate mismatched cert: %v", err)
				}
			case "valid ECDSA certificate":
				certPEM, keyPEM, err = generateECDSACert("ecdsa.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate ECDSA cert: %v", err)
				}
			}

			info, err := parseTLSCertificate(certPEM, keyPEM)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseTLSCertificate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseTLSCertificate() error = %v, want containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("parseTLSCertificate() unexpected error = %v", err)
				return
			}

			if info == nil {
				t.Error("parseTLSCertificate() returned nil info")
				return
			}

			if info.Valid != tt.wantValid {
				t.Errorf("parseTLSCertificate() Valid = %v, want %v", info.Valid, tt.wantValid)
			}

			if tt.wantDomain != "" && info.Domain != tt.wantDomain {
				t.Errorf("parseTLSCertificate() Domain = %v, want %v", info.Domain, tt.wantDomain)
			}

			if tt.wantWarning && info.Warning == "" {
				t.Errorf("parseTLSCertificate() Warning = empty, want non-empty warning")
			}

			if !tt.wantWarning && info.Warning != "" {
				t.Errorf("parseTLSCertificate() Warning = %v, want empty", info.Warning)
			}
		})
	}
}

func TestParseTLSCertificate_ExtractsSANs(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := generateTestCert("san.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	info, err := parseTLSCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseTLSCertificate() error = %v", err)
	}

	if info.Domain != "san.example.com" {
		t.Errorf("parseTLSCertificate() Domain = %v, want san.example.com", info.Domain)
	}
}

func TestParseTLSCertificate_DaysUntilExpiry(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := generateTestCert("days.example.com", now.Add(-1*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	info, err := parseTLSCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseTLSCertificate() error = %v", err)
	}

	// Should be approximately 7 days (might be 6 due to time elapsed during test)
	if info.DaysUntilExpiry < 5 || info.DaysUntilExpiry > 8 {
		t.Errorf("parseTLSCertificate() DaysUntilExpiry = %v, want approximately 7", info.DaysUntilExpiry)
	}
}

func TestValidateTLSCertificate(t *testing.T) {
	now := time.Now()

	t.Run("valid certificate", func(t *testing.T) {
		certPEM, keyPEM, err := generateTestCert("valid.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatalf("failed to generate test cert: %v", err)
		}

		if err := validateTLSCertificate(certPEM, keyPEM); err != nil {
			t.Errorf("validateTLSCertificate() error = %v", err)
		}
	})

	t.Run("empty certificate", func(t *testing.T) {
		if err := validateTLSCertificate("", ""); err != nil {
			t.Errorf("validateTLSCertificate() error = %v, want nil", err)
		}
	})

	t.Run("mismatched certificate", func(t *testing.T) {
		certPEM, keyPEM, err := generateMismatchedCert()
		if err != nil {
			t.Fatalf("failed to generate mismatched cert: %v", err)
		}

		if err := validateTLSCertificate(certPEM, keyPEM); err == nil {
			t.Error("validateTLSCertificate() error = nil, want error")
		}
	})
}
