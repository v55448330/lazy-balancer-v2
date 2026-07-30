package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/models"

	"golang.org/x/crypto/acme"
)

// Logger receives progress updates during issuance.
type Logger interface {
	Log(stage, message string)
}

// Client wraps golang.org/x/crypto/acme.Client with convenience methods.
type Client struct {
	DirectoryURL   string
	Email          string
	acme           *acme.Client
	accountKey     crypto.Signer
	eab            *acme.ExternalAccountBinding
	finalizedMu    sync.Mutex
	finalizedCerts map[string][][]byte
}

// NewClientForProvider creates an ACME client based on a CA provider configuration.
func NewClientForProvider(provider models.CAProvider, email string) (*Client, error) {
	var eab *acme.ExternalAccountBinding
	if provider.Provider == "zerossl" {
		var creds models.CAProviderCredentials
		if provider.Credentials != "" {
			if err := json.Unmarshal([]byte(provider.Credentials), &creds); err != nil {
				return nil, fmt.Errorf("invalid ZeroSSL credentials JSON: %w", err)
			}
		}
		if creds.EABKID == "" || creds.EABHMACKey == "" {
			return nil, fmt.Errorf("ZeroSSL requires eab_kid and eab_hmac_key")
		}
		hmacKey, err := base64.RawURLEncoding.DecodeString(creds.EABHMACKey)
		if err != nil {
			hmacKey, err = base64.URLEncoding.DecodeString(creds.EABHMACKey)
			if err != nil {
				hmacKey, err = base64.StdEncoding.DecodeString(creds.EABHMACKey)
				if err != nil {
					return nil, fmt.Errorf("invalid ZeroSSL EAB HMAC key: %w", err)
				}
			}
		}
		eab = &acme.ExternalAccountBinding{
			KID: creds.EABKID,
			Key: hmacKey,
		}
	}
	return newClient(provider.DirectoryURL, email, eab)
}

func newClient(directoryURL, email string, eab *acme.ExternalAccountBinding) (*Client, error) {
	eabKID := ""
	if eab != nil {
		eabKID = eab.KID
	}
	key, err := loadOrCreateAccountKey(directoryURL, email, eabKID)
	if err != nil {
		return nil, err
	}
	return &Client{
		DirectoryURL: directoryURL,
		Email:        email,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: directoryURL,
			HTTPClient:   &http.Client{Timeout: 30 * time.Second},
			RetryBackoff: func(n int, r *http.Request, resp *http.Response) time.Duration {
				if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
					return 0
				}
				return 2 * time.Second
			},
		},
		accountKey:     key,
		eab:            eab,
		finalizedCerts: make(map[string][][]byte),
	}, nil
}

// 账户密钥按 CA+邮箱+EAB KID 维度持久化复用；EAB 密钥本身不参与文件名计算。
const acmeAccountDir = "/app/data/acme_accounts"

var acmeAccountKeyMu sync.Mutex

func acmeAccountKeyPath(directoryURL, email, eabKID string) string {
	sum := sha256.Sum256([]byte(directoryURL + "|" + email + "|" + eabKID))
	return filepath.Join(acmeAccountDir, hex.EncodeToString(sum[:])+".key")
}

func loadOrCreateAccountKey(directoryURL, email, eabKID string) (*ecdsa.PrivateKey, error) {
	acmeAccountKeyMu.Lock()
	defer acmeAccountKeyMu.Unlock()
	keyPath := acmeAccountKeyPath(directoryURL, email, eabKID)
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
		log.Printf("ACME 账户密钥 %s 无法解析，将重新生成", keyPath)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(acmeAccountDir, 0755); err != nil {
		return nil, fmt.Errorf("创建 ACME 账户目录: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	tmp := keyPath + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, fmt.Errorf("写入 ACME 账户密钥: %w", err)
	}
	if err := os.Rename(tmp, keyPath); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("部署 ACME 账户密钥: %w", err)
	}
	return key, nil
}

// RegisterAccount registers a new ACME account or returns nil if already registered.
func (c *Client) RegisterAccount(ctx context.Context) error {
	acct := &acme.Account{
		Contact: []string{"mailto:" + c.Email},
	}
	if c.eab != nil {
		acct.ExternalAccountBinding = c.eab
	}
	_, err := c.acme.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "account already exists") || strings.Contains(lower, "already registered") {
			return nil
		}
	}
	return err
}

// AuthorizeOrder creates a new order for the given domains.
func (c *Client) AuthorizeOrder(ctx context.Context, domains []string) (*acme.Order, error) {
	return c.acme.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
}

// GetAuthorization fetches an authorization by URL.
func (c *Client) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.acme.GetAuthorization(ctx, url)
}

func (c *Client) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.acme.WaitAuthorization(ctx, url)
}

// AcceptChallenge accepts a DNS-01 challenge.
func (c *Client) AcceptChallenge(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	return c.acme.Accept(ctx, chal)
}

// GetChallenge fetches the current status of a challenge by URL.
func (c *Client) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	return c.acme.GetChallenge(ctx, url)
}

// WaitOrder polls the order until it is ready or valid.
func (c *Client) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	return c.acme.WaitOrder(ctx, url)
}

// DNS01ChallengeRecord computes the TXT record value for a DNS-01 challenge.
func (c *Client) DNS01ChallengeRecord(token string) (string, error) {
	return c.acme.DNS01ChallengeRecord(token)
}

// CreateCertRequest finalizes an order with a CSR and returns the order with CertURL.
func (c *Client) CreateCertRequest(ctx context.Context, finalizeURL string, csr []byte) (*acme.Order, error) {
	certDER, certURL, err := c.acme.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil {
		return nil, err
	}
	c.finalizedMu.Lock()
	if c.finalizedCerts == nil {
		c.finalizedCerts = make(map[string][][]byte)
	}
	c.finalizedCerts[certURL] = certDER
	c.finalizedMu.Unlock()
	return &acme.Order{CertURL: certURL}, nil
}

// FetchCert downloads the certificate chain from the given URL.
func (c *Client) FetchCert(ctx context.Context, url string) ([][]byte, error) {
	c.finalizedMu.Lock()
	certDER, ok := c.finalizedCerts[url]
	if ok {
		delete(c.finalizedCerts, url)
	}
	c.finalizedMu.Unlock()
	if ok {
		return certDER, nil
	}
	return c.acme.FetchCert(ctx, url, true)
}

// CreateCSR generates a private key and CSR for the given domains.
func CreateCSR(domains []string) ([]byte, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{DNSNames: domains}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return csrDER, key, nil
}

// EncodeCertPEM converts DER certificate chain to PEM string.
func EncodeCertPEM(derChain [][]byte) string {
	var b strings.Builder
	for _, der := range derChain {
		b.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return b.String()
}

// EncodeKeyPEM converts a private key to PEM string.
func EncodeKeyPEM(key crypto.Signer) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	case *ecdsa.PrivateKey:
		der, _ := x509.MarshalECPrivateKey(k)
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}
	return ""
}
