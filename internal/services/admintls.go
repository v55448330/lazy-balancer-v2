package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

// AdminTLSConfig holds the admin-panel HTTPS settings stored in global_config.
type AdminTLSConfig struct {
	Enabled bool
	Mode    string // selfsigned | upload | acme
	Cert    string
	Key     string
}

type adminTLSFingerprint struct {
	Enabled     bool
	Mode        string
	Certificate [sha256.Size]byte
}

var runtimeAdminTLS atomic.Pointer[adminTLSFingerprint]

func fingerprintAdminTLS(cfg AdminTLSConfig) adminTLSFingerprint {
	return adminTLSFingerprint{
		Enabled:     cfg.Enabled,
		Mode:        cfg.Mode,
		Certificate: sha256.Sum256([]byte(cfg.Cert + cfg.Key)),
	}
}

// RecordRuntimeAdminTLS captures the state the process actually started with;
// the sync applier compares later states against it.
func RecordRuntimeAdminTLS(cfg AdminTLSConfig) {
	fingerprint := fingerprintAdminTLS(cfg)
	runtimeAdminTLS.Store(&fingerprint)
}

// RuntimeAdminTLSChanged reports whether the given config differs from the
// state the process started with, meaning a restart is required to apply it.
func RuntimeAdminTLSChanged(cfg AdminTLSConfig) bool {
	v := runtimeAdminTLS.Load()
	if v == nil {
		return false
	}
	return *v != fingerprintAdminTLS(cfg)
}

func LoadAdminTLSConfig() AdminTLSConfig {
	cfg := AdminTLSConfig{Mode: "selfsigned"}
	if db.DB == nil {
		return cfg
	}
	var enabled int
	var mode, cert, key string
	err := db.DB.QueryRow(`SELECT COALESCE(admin_tls_enabled,0), COALESCE(admin_tls_mode,'selfsigned'),
		COALESCE(admin_tls_cert,''), COALESCE(admin_tls_key,'')
		FROM global_config WHERE id=1`).Scan(&enabled, &mode, &cert, &key)
	if err != nil {
		return cfg
	}
	cfg.Enabled = enabled == 1
	cfg.Mode = mode
	cfg.Cert = cert
	cfg.Key = key
	return cfg
}

// ResolveCertificate returns the TLS certificate for the admin panel,
// generating a self-signed one on first use when configured so.
func (c AdminTLSConfig) ResolveCertificate(dataDir string) (tls.Certificate, error) {
	switch c.Mode {
	case "upload":
		if c.Cert == "" || c.Key == "" {
			return tls.Certificate{}, fmt.Errorf("上传证书模式但未提供证书内容")
		}
		return tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
	default:
		return selfSignedCert(dataDir)
	}
}

// selfSignedCert loads or generates a self-signed admin certificate so it is
// stable across restarts; cluster peers skip verification for it anyway.
func selfSignedCert(dataDir string) (tls.Certificate, error) {
	certPath := filepath.Join(dataDir, "admin_tls.crt")
	keyPath := filepath.Join(dataDir, "admin_tls.key")
	if certPEM, err1 := os.ReadFile(certPath); err1 == nil {
		if keyPEM, err2 := os.ReadFile(keyPath); err2 == nil {
			return tls.X509KeyPair(certPEM, keyPEM)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成自签名私钥失败: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Lazy Balancer V2", Organization: []string{"XiaoBao"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(50, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成自签名证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("编码私钥失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeAdminTLSCertPair(certPath, keyPath, certPEM, keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存自签名证书: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writeAdminTLSCertPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	return writeCertPair(certPath, keyPath, string(certPEM), string(keyPEM))
}
