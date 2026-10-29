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
	mathrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/atomicfile"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/retryafter"

	"golang.org/x/crypto/acme"
)

// Logger receives progress updates during issuance.
type Logger interface {
	Log(stage, message string)
}

// logf 是包级日志接缝（镜像 services/certjoblog.go certJobLogWarnf
// 先例）：默认落到标准 log（stdout）；acme 是独立 module 边界（services 反向
// 依赖 acme，acme 不得回依赖），故由 cmd/server/main.go 装配时注入
// services.Logf，使告警进入统一日志级别链（level 语义同 services.Logf）。
var logf = func(level, format string, args ...any) { log.Printf(format, args...) }

// SetLogf 装配包级日志函数（main 启动早期调用；nil 忽略）。
func SetLogf(f func(level, format string, args ...any)) {
	if f != nil {
		logf = f
	}
}

// Client wraps golang.org/x/crypto/acme.Client with convenience methods.
type Client struct {
	DirectoryURL   string
	Email          string
	acme           *acme.Client
	accountKeyPath string
	eabKID         string
	eab            *acme.ExternalAccountBinding
	finalizedMu    sync.Mutex
	finalizedCerts map[string][][]byte
	finalizedOrder []string // FIFO 插入序（上限逐出最旧）
}

// maxFinalizedCerts finalize 缓存上限（此前无界——finalize 成功后
// 走 FetchCert 之外的失败路径（wait-valid 超时/订单非 valid/下载失败/任务
// 取消）留下的证书字节永不释放）。FIFO 逐出最旧兜底；失败路径另由
// DiscardFinalizedCert 显式清理。
const maxFinalizedCerts = 16

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
					// 429：库内立即放弃重试（返回 0），让错误上抛给上层
					// waiting_ca 记账按 CA 的统一退避——语义保持不变。
					return 0
				}
				// 非 429 重试（5xx 等）：截断指数退避 1,2,4,8s、封顶 10s，对齐
				// x/crypto defaultBackoff 曲线（1<<(n-1)s+jitter、封顶 10s）。
				// 此前固定 2s 在 CA 5xx 过载时维持约 5 倍请求压力。
				// 注：自定义 RetryBackoff 的返回值即重试延迟本身（x/crypto 不会
				// 再叠加默认曲线或解析），故曲线在此显式给出——也因此库默认
				// 「优先采用 Retry-After」的语义会随自定义实现丢失，必须在此
				// 自行补回（见下）。
				// 自定义曲线会丢失默认实现的 jitter——多规则
				// 并发签发（max_concurrent>1）在同一 CA 5xx 窗口会以相同延迟同步
				// 重试（thundering herd）。补 0~1s 均匀抖动（同默认曲线量级）。
				// x/crypto 文档「The value of n for the
				// first call on failure is 1」（acme.go），实际序列必须从 n=1
				// 起跳为 1s——原实现 1<<min(n,4) 使首召即 2s，整条曲线右移一档
				// 且提前封顶。n<1 仅防御（生产不出现）。
				attempt := max(n, 1)
				base := min(time.Duration(1<<min(attempt-1, 4))*time.Second, 10*time.Second)
				// CA 用 Retry-After 明确要求等待（5xx 过载常见）时取较大值，
				// 与 x/crypto 默认实现「Retry-After 优先」及本仓 DNS 重试层
				// （internal/retryafter 单源）口径一致；上限沿用 10s（分段预算不变）。
				if resp != nil {
					if hinted := retryafter.Parse(resp.Header.Get("Retry-After"), time.Now()); hinted > 0 {
						base = max(base, min(hinted, 10*time.Second))
					}
				}
				return base + time.Duration(mathrand.IntN(1000))*time.Millisecond
			},
		},
		accountKeyPath: acmeAccountKeyPath(dataDir, directoryURL, email, eabKID, eabKey),
		eabKID:         eabKID,
		eab:            eab,
		finalizedCerts: make(map[string][][]byte),
	}, nil
}

var acmeAccountKeyMu sync.Mutex

// eabKeyDigestRaw 原始 EAB key 的 sha256 摘要（空 key 亦有确定值——路径公式
// 需要它）；路径公式与元数据共用同一实现，此前两份内联
// sha256+hex。
func eabKeyDigestRaw(eabKey []byte) string {
	sum := sha256.Sum256(eabKey)
	return hex.EncodeToString(sum[:])
}

func acmeAccountKeyPath(dataDir, directoryURL, email, eabKID string, eabKey []byte) string {
	eabKeyDigest := eabKeyDigestRaw(eabKey)
	sum := sha256.Sum256([]byte(directoryURL + "|" + email + "|" + eabKID + "|" + eabKeyDigest))
	return filepath.Join(dataDir, "acme_accounts", hex.EncodeToString(sum[:])+".key")
}

// accountKeyMetadata 是账户密钥的溯源旁注（落盘为 <keyPath>.json）：记录密钥
// 属于哪个 directory|email|KID|HMAC 摘要组合，供运维人工比对历史密钥的账户
// 身份；产品代码不消费它（本包不做陈旧密钥自动回收）。
//
// 裁定：轮换后的旧 HMAC 密钥必须保留（字节级残留无害；删除会让旧账户身份无法
// 恢复）。路径公式含 HMAC 摘要（见 acmeAccountKeyPath），同 directory+email+KID
// 不同 HMAC 是不同的账户身份，按「metadata 与当前配置不同」选出的陈旧密钥同样
// 不得删除。本包曾有的 removeStaleAccountKeys 删除分支在当前路径公式下恒不可
// 达（metadata 与当前配置相同的唯一文件就是本账户密钥本身），该清理机制已整体
// 退役——不得按「长时间未使用/配置不匹配」等判据复活它。
type accountKeyMetadata struct {
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	EABKID       string `json:"eab_kid"`
	// 密钥路径由 (directory|email|KID|hmac摘要) 决定但元数据此前缺 hmac
	// 摘要——同三元组双 HMAC 配置（EAB 轮换）会被闲置清理互删密钥，后续注册以新
	// 密钥撞旧账户，签发持续失败直至人工恢复。
	EABKeyDigest string `json:"eab_key_digest,omitempty"`
}

// accountKeyWrite 是账户密钥/元数据落盘的测试缝（默认持久化原子写：
// fsync + 父目录同步）。用于覆盖「落盘持久化失败」的失败路径——默认实现
// 见 internal/atomicfile.WriteAtomic。
var accountKeyWrite = atomicfile.WriteAtomic

func loadOrCreateAccountKey(dataDir, directoryURL, email, eabKID string, eabKey []byte) (*ecdsa.PrivateKey, error) {
	// dataDir 为空时密钥路径退化为 CWD 相对路径（曾使 handlers 测试
	// 在仓库内堆积数千个账户私钥），入口直接拒绝，对齐 dnsprovider/factory.go
	// 的 dataDir 必填校验。
	if dataDir == "" {
		return nil, errors.New("ACME dataDir 未配置，拒绝生成/加载账户密钥")
	}
	acmeAccountKeyMu.Lock()
	defer acmeAccountKeyMu.Unlock()
	keyPath := acmeAccountKeyPath(dataDir, directoryURL, email, eabKID, eabKey)
	data, err := os.ReadFile(keyPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取 ACME 账户密钥 %s: %w", keyPath, err)
	}
	if err == nil {
		// 密钥文件存在但无法解析 → fail-closed：静默再生新密钥会覆盖既有文件，
		// 且再生密钥对 CA 是陌生账户（或撞既有 email/EAB 账户被 400 拒绝），
		// 造成后续签名请求持续 403 且难以定位。再生仅允许用于文件缺失。
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("ACME 账户密钥 %s 无法解析（非有效 PEM）：为避免覆盖既有账户，请手动修复或删除该文件后重试", keyPath)
		}
		key, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("ACME 账户密钥 %s 无法解析（%v）：为避免覆盖既有账户，请手动修复或删除该文件后重试", keyPath, parseErr)
		}
		fi, _ := os.Stat(keyPath)
		created := ""
		if fi != nil {
			created = fmt.Sprintf("，首次注册时间: %s", fi.ModTime().Format("2006-01-02 15:04:05"))
		}
		logf("info", "ACME 账户密钥 %s 已加载%s", filepath.Base(keyPath), created)
		// 元数据是账户密钥的溯源旁注（见 accountKeyMetadata），产品代码不消费；
		// 刷新失败（只读挂载/权限漂移）不得连坐签发主路径。
		if err := writeAccountKeyMetadata(keyPath, directoryURL, email, eabKID, eabKeyDigestOf(eabKey)); err != nil {
			logf("warn", "acme: 刷新账户密钥元数据失败（密钥可用，不影响本次签发）: %v", err)
		}
		return key, nil
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
	// 账户密钥必须持久化落盘（fsync + 父目录同步，与仓内其他簿记文件同一
	// 契约）：掉电/硬杀落在写入窗口时，非持久写会留下「不存在」或截断的密钥
	// ——前者导致下次注册生成新账户（CA 账户 churn），后者 fail-closed 直到
	// 人工删除文件。落盘失败不得当作成功注册（密钥未持久 = 账户无法复用）。
	if err := accountKeyWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, fmt.Errorf("写入 ACME 账户密钥: %w", err)
	}
	// 密钥已落盘即可用，元数据（溯源旁注）写失败只记 warn。
	if err := writeAccountKeyMetadata(keyPath, directoryURL, email, eabKID, eabKeyDigestOf(eabKey)); err != nil {
		logf("warn", "acme: 写入账户密钥元数据失败（密钥可用，不影响本次签发）: %v", err)
	}
	return key, nil
}

// eabKeyDigestOf 计算原始 EAB key 的 sha256 摘要（与 acmeAccountKeyPath 的路径
// 公式同源——eabKeyDigestRaw）；空 key 产空串（无 EAB 场景的元数据统一形态）。
func eabKeyDigestOf(eabKey []byte) string {
	if len(eabKey) == 0 {
		return ""
	}
	return eabKeyDigestRaw(eabKey)
}

func writeAccountKeyMetadata(keyPath, directoryURL, email, eabKID, eabKeyDigest string) error {
	data, err := json.Marshal(accountKeyMetadata{DirectoryURL: directoryURL, Email: email, EABKID: eabKID, EABKeyDigest: eabKeyDigest})
	if err != nil {
		return fmt.Errorf("编码 ACME 账户密钥元数据: %w", err)
	}
	metadataPath := keyPath + ".json"
	if err := accountKeyWrite(metadataPath, data, 0600); err != nil {
		return fmt.Errorf("写入 ACME 账户密钥元数据: %w", err)
	}
	return nil
}

// RegisterAccount registers a new ACME account or verifies reuse of an existing one.
func (c *Client) RegisterAccount(ctx context.Context) error {
	acct := &acme.Account{
		Contact: []string{"mailto:" + c.Email},
	}
	if c.eab != nil {
		acct.ExternalAccountBinding = c.eab
	}
	_, err := c.acme.Register(ctx, acct, acme.AcceptTOS)
	switch {
	case err == nil:
		logf("info", "ACME 账户注册成功（directory: %s）", c.DirectoryURL)
	case errors.Is(err, acme.ErrAccountAlreadyExists):
		// 200 + JWK 匹配：x/crypto registerRFC 已缓存账户 KID，服务端确认
		// 本密钥持有该账户，复用成立。
		logf("info", "ACME 账户已注册，复用现有账户（directory: %s）", c.DirectoryURL)
	default:
		lower := strings.ToLower(err.Error())
		if !strings.Contains(lower, "account already exists") && !strings.Contains(lower, "already registered") {
			return err
		}
		// 400 "already exists/registered" 不必然表示本密钥持有账户：新密钥撞
		// 既有 email/EAB 账户同样得到该错误，且此时 KID 未被缓存，静默当成功
		// 会让后续签名请求 403 accountDoesNotExist。用 onlyReturnExisting 探测
		// 验证本密钥确实持有账户后再复用。
		if _, regErr := c.acme.GetReg(ctx, ""); regErr != nil {
			if errors.Is(regErr, acme.ErrNoAccount) {
				return fmt.Errorf("acme: 账户密钥与已注册账户不匹配（CA 拒绝注册: %v）：请手动删除 %s 或修正邮箱/EAB 配置后重试", err, c.accountKeyPath)
			}
			return fmt.Errorf("acme: 验证复用现有账户失败: %w", regErr)
		}
		logf("info", "ACME 账户已注册，复用现有账户（directory: %s）", c.DirectoryURL)
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
	c.rememberFinalizedCert(certURL, certDER)
	return &acme.Order{CertURL: certURL}, nil
}

// rememberFinalizedCert 记录 finalize 阶段已下载的证书（cap 内 FIFO 逐出
// 最旧；重复 URL 原位更新不推进序）。
func (c *Client) rememberFinalizedCert(certURL string, certDER [][]byte) {
	c.finalizedMu.Lock()
	defer c.finalizedMu.Unlock()
	if c.finalizedCerts == nil {
		c.finalizedCerts = make(map[string][][]byte)
	}
	if _, exists := c.finalizedCerts[certURL]; !exists {
		c.finalizedOrder = append(c.finalizedOrder, certURL)
	}
	c.finalizedCerts[certURL] = certDER
	for len(c.finalizedOrder) > maxFinalizedCerts {
		oldest := c.finalizedOrder[0]
		c.finalizedOrder = c.finalizedOrder[1:]
		delete(c.finalizedCerts, oldest)
	}
}

// DiscardFinalizedCert 显式丢弃 finalize 缓存条目——finalize 后的失败路径
// （wait-valid/状态非 valid/下载失败）调用，不等待 FIFO 上限逐出。
func (c *Client) DiscardFinalizedCert(certURL string) {
	c.finalizedMu.Lock()
	defer c.finalizedMu.Unlock()
	if _, ok := c.finalizedCerts[certURL]; !ok {
		return
	}
	delete(c.finalizedCerts, certURL)
	for i, u := range c.finalizedOrder {
		if u == certURL {
			c.finalizedOrder = append(c.finalizedOrder[:i], c.finalizedOrder[i+1:]...)
			break
		}
	}
}

// FetchCert downloads the certificate chain from the given URL.
func (c *Client) FetchCert(ctx context.Context, url string) ([][]byte, error) {
	c.finalizedMu.Lock()
	certDER, ok := c.finalizedCerts[url]
	if ok {
		delete(c.finalizedCerts, url)
		for i, u := range c.finalizedOrder {
			if u == url {
				c.finalizedOrder = append(c.finalizedOrder[:i], c.finalizedOrder[i+1:]...)
				break
			}
		}
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
// 未知密钥类型必须 fail-loud——静默返回空串会把「keyPEM=""」交给部署层，
// 落成一条无私钥的规则（生产密钥恒来自 CreateCSR 的 RSA-2048，ecdsa 分支
// 是防御性覆盖）。
func EncodeKeyPEM(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("marshal EC private key: %w", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
	}
	return "", fmt.Errorf("unsupported private key type %T", key)
}
