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
	"errors"
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
	accountKeyPath string
	eabKID         string
	eab            *acme.ExternalAccountBinding
	finalizedMu    sync.Mutex
	finalizedCerts map[string][][]byte
}

// NewClientForProvider creates an ACME client based on a CA provider configuration.
func NewClientForProvider(provider models.CAProvider, email, dataDir string) (*Client, error) {
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
	return newClient(provider.DirectoryURL, email, dataDir, eab)
}

func newClient(directoryURL, email, dataDir string, eab *acme.ExternalAccountBinding) (*Client, error) {
	eabKID := ""
	if eab != nil {
		eabKID = eab.KID
	}
	var eabKey []byte
	if eab != nil {
		eabKey = eab.Key
	}
	key, err := loadOrCreateAccountKey(dataDir, directoryURL, email, eabKID, eabKey)
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
		accountKeyPath: acmeAccountKeyPath(dataDir, directoryURL, email, eabKID, eabKey),
		eabKID:         eabKID,
		eab:            eab,
		finalizedCerts: make(map[string][][]byte),
	}, nil
}

var acmeAccountKeyMu sync.Mutex

func acmeAccountKeyPath(dataDir, directoryURL, email, eabKID string, eabKey []byte) string {
	eabKeySum := sha256.Sum256(eabKey)
	eabKeyDigest := hex.EncodeToString(eabKeySum[:])
	sum := sha256.Sum256([]byte(directoryURL + "|" + email + "|" + eabKID + "|" + eabKeyDigest))
	return filepath.Join(dataDir, "acme_accounts", hex.EncodeToString(sum[:])+".key")
}

type accountKeyMetadata struct {
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	EABKID       string `json:"eab_kid"`
	// R71 F-A2：密钥路径由 (directory|email|KID|hmac摘要) 决定但元数据此前缺 hmac
	// 摘要——同三元组双 HMAC 配置（EAB 轮换）会被闲置清理互删密钥，后续注册以新
	// 密钥撞旧账户，签发持续失败直至人工恢复。
	EABKeyDigest string `json:"eab_key_digest,omitempty"`
}

func loadOrCreateAccountKey(dataDir, directoryURL, email, eabKID string, eabKey []byte) (*ecdsa.PrivateKey, error) {
	acmeAccountKeyMu.Lock()
	defer acmeAccountKeyMu.Unlock()
	keyPath := acmeAccountKeyPath(dataDir, directoryURL, email, eabKID, eabKey)
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				fi, _ := os.Stat(keyPath)
				created := ""
				if fi != nil {
					created = fmt.Sprintf("，首次注册时间: %s", fi.ModTime().Format("2006-01-02 15:04:05"))
				}
				log.Printf("ACME 账户密钥 %s 已加载%s", filepath.Base(keyPath), created)
				if err := writeAccountKeyMetadata(keyPath, directoryURL, email, eabKID, eabKeyDigestOf(eabKey)); err != nil {
					return nil, err
				}
				return key, nil
			}
		}
		log.Printf("ACME 账户密钥 %s 无法解析，将重新生成", keyPath)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
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
	if err := writeAccountKeyMetadata(keyPath, directoryURL, email, eabKID, eabKeyDigestOf(eabKey)); err != nil {
		return nil, err
	}
	return key, nil
}

// eabKeyDigestOf 计算原始 EAB key 的 sha256 摘要（与 acmeAccountKeyPath 的路径
// 公式同源）；空 key 产空串（无 EAB 场景的元数据统一形态）。
func eabKeyDigestOf(eabKey []byte) string {
	if len(eabKey) == 0 {
		return ""
	}
	sum := sha256.Sum256(eabKey)
	return hex.EncodeToString(sum[:])
}

// accountEABKeyDigest 计算 EAB HMAC 密钥摘要（无 EAB 时为空——路径公式对空 key
// 亦产生确定摘要，但元数据统一记空串以与「无 EAB」want 匹配；空/非空恒一致）。
func (c *Client) accountEABKeyDigest() string {
	if c.eab == nil {
		return ""
	}
	return eabKeyDigestOf(c.eab.Key)
}

func writeAccountKeyMetadata(keyPath, directoryURL, email, eabKID, eabKeyDigest string) error {
	data, err := json.Marshal(accountKeyMetadata{DirectoryURL: directoryURL, Email: email, EABKID: eabKID, EABKeyDigest: eabKeyDigest})
	if err != nil {
		return fmt.Errorf("编码 ACME 账户密钥元数据: %w", err)
	}
	metadataPath := keyPath + ".json"
	tmp := metadataPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("写入 ACME 账户密钥元数据: %w", err)
	}
	if err := os.Rename(tmp, metadataPath); err != nil {
		removeErr := os.Remove(tmp)
		return fmt.Errorf("部署 ACME 账户密钥元数据: %w", errors.Join(err, removeErr))
	}
	return nil
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
		if !strings.Contains(lower, "account already exists") && !strings.Contains(lower, "already registered") {
			return err
		}
		log.Printf("ACME 账户已注册，复用现有账户（directory: %s）", c.DirectoryURL)
	} else {
		log.Printf("ACME 账户注册成功（directory: %s）", c.DirectoryURL)
	}
	return c.removeStaleAccountKeys()
}

// staleAccountKeyIdleThreshold 是 removeStaleAccountKeys 清理密钥前的最小闲置时长，
// 必须显著大于单次签发执行上限（caExecutionTimeout 30min），取 1h。
const staleAccountKeyIdleThreshold = time.Hour

func (c *Client) removeStaleAccountKeys() error {
	acmeAccountKeyMu.Lock()
	defer acmeAccountKeyMu.Unlock()
	entries, err := os.ReadDir(filepath.Dir(c.accountKeyPath))
	if err != nil {
		return fmt.Errorf("读取 ACME 账户目录: %w", err)
	}
	want := accountKeyMetadata{DirectoryURL: c.DirectoryURL, Email: c.Email, EABKID: c.eabKID, EABKeyDigest: c.accountEABKeyDigest()}
	// 多 CA 提供商各有独立队列、可并发签发：其他任务（元数据≠本任务）的账户密钥
	// 可能正在使用。密钥元数据在每次加载/创建时都会重写，其 mtime 即最近使用时间；
	// 在途签发全程有 30min 执行上限，mtime 必然新于 1h 阈值——仅清理闲置超 1h 的
	// 密钥，避免误删并发任务密钥导致重试/重启后密钥反复再生（R44-3）。
	// 备查（R45 发现5）：系统时钟回拨 >1h 时在途密钥 mtime 会早于 cutoff 而被误删，
	// 后果仅是账户密钥换新并重新注册（账户 churn），无证书/数据损失，无安全影响。
	cutoff := time.Now().Add(-staleAccountKeyIdleThreshold)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key.json") {
			continue
		}
		metadataPath := filepath.Join(filepath.Dir(c.accountKeyPath), entry.Name())
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			// R71 F-A3：单条目读/解析失败不再中止整轮清理——与下方 stat 失败的
			// 「跳过+日志」同口径（原口径会使任一损坏元数据永久阻塞该提供商注册）。
			log.Printf("acme: 读取账户密钥元数据 %s 失败，跳过: %v", entry.Name(), err)
			continue
		}
		var metadata accountKeyMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			log.Printf("acme: 解析账户密钥元数据 %s 失败，跳过: %v", entry.Name(), err)
			continue
		}
		keyPath := strings.TrimSuffix(metadataPath, ".json")
		if metadata != want || keyPath == c.accountKeyPath {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			// 单条目 stat 失败（权限/外部并发删除）不应中止整轮清理（R45 发现4）：
			// 跳过该条目并记日志，下一轮注册时自愈。
			log.Printf("清理 ACME 账户密钥：读取元数据状态失败，跳过 %s: %v", entry.Name(), err)
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("删除失效 ACME 账户密钥 %s: %w", filepath.Base(keyPath), err)
		}
		if err := os.Remove(metadataPath); err != nil {
			return fmt.Errorf("删除失效 ACME 账户密钥元数据 %s: %w", entry.Name(), err)
		}
	}
	return nil
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
