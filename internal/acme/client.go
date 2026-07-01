package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/acme"
)

// Logger receives progress updates during issuance.
type Logger interface {
	Log(stage, message string)
}

// Client wraps golang.org/x/crypto/acme.Client with convenience methods.
type Client struct {
	DirectoryURL string
	Email        string
	acme         *acme.Client
	accountKey   crypto.Signer
}

// NewClient creates a new ACME client with a fresh ECDSA account key.
func NewClient(directoryURL, email string) (*Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Client{
		DirectoryURL: directoryURL,
		Email:        email,
		acme:         &acme.Client{
			Key:          key,
			DirectoryURL: directoryURL,
		},
		accountKey: key,
	}, nil
}

// RegisterAccount registers a new ACME account or returns nil if already registered.
func (c *Client) RegisterAccount(ctx context.Context) error {
	_, err := c.acme.Register(ctx, &acme.Account{
		Contact: []string{"mailto:" + c.Email},
	}, acme.AcceptTOS)
	if err != nil {
		if strings.Contains(err.Error(), "Account already exists") || strings.Contains(err.Error(), "already registered") {
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

// AcceptChallenge accepts a DNS-01 challenge.
func (c *Client) AcceptChallenge(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	return c.acme.Accept(ctx, chal)
}

// WaitAuthorization polls the authorization until it is in a final state.
func (c *Client) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return c.acme.WaitAuthorization(ctx, url)
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
	_, certURL, err := c.acme.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil {
		return nil, err
	}
	return &acme.Order{CertURL: certURL}, nil
}

// FetchCert downloads the certificate chain from the given URL.
func (c *Client) FetchCert(ctx context.Context, url string) ([][]byte, error) {
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