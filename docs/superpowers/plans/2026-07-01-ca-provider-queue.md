# CA Provider 配置与排队调度实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Lazy Balancer V2 中引入可配置的 CA Provider（Let's Encrypt / ZeroSSL），并用按 CA 排队的调度器替代全局互斥锁，使大量规则并发申请证书时能够按官方限流策略顺序执行。

**Architecture:** 新增 `ca_providers` 表与 `CAQueueManager` 单例，每个启用的 CA 拥有独立队列；规则保存/重试/续期时只把任务标记为 `queued` 并入队，调度器按 `max_concurrent` 与 `min_interval_ms` 控制实际签发；ACME client 通过 provider 类型选择是否携带 EAB。

**Tech Stack:** Go 1.26, `golang.org/x/crypto/acme`, SQLite, Vue 3 + Element Plus, Docker Compose.

---

## 文件结构

| 文件 | 职责 |
|------|------|
| `internal/db/db.go` | `ca_providers` 表、字段扩展、默认数据、迁移 |
| `internal/models/models.go` | `CAProvider`、`GlobalConfig` 等模型字段 |
| `internal/acme/client.go` | 按 provider 创建 ACME client（含 EAB） |
| `internal/acme/issuer.go` | 无需改动，继续接收 client 与 provider |
| `internal/services/caqueue.go` | 新增 `CAQueueManager` 与 `caQueue` |
| `internal/services/certissuer.go` | `CertIssuer.Issue` 接收 `models.CAProvider`，移除全局 `issuingMu` |
| `internal/services/certificates.go` | 续期时入队，不再直接启动 goroutine 调用 `Issue` |
| `internal/handlers/caproviders.go` | 新增 CA Provider 列表/更新/测试接口 |
| `internal/handlers/rules.go` | 规则创建/更新时解析 CA 并入队 |
| `internal/handlers/certjobs.go` | 重试时校验状态并入队 |
| `internal/handlers/handlers.go` | 注册 CA Provider 路由 |
| `web/src/views/settings/FreeCertificates.vue` | CA Provider 配置卡片、默认 CA 选择 |
| `web/src/views/Rules.vue` | 规则 wizard TLS 步骤选择 CA Provider |
| `web/src/views/settings/CertJobs.vue` | 显示 `queued` 状态，禁用非终态重签 |

---

### Task 1: 数据库 schema 与默认数据

**Files:**
- Modify: `internal/db/db.go`

- [ ] **Step 1: 新增 `ca_providers` 表并在 `createTables` 中创建**

在 `createTables()` 的 `CREATE TABLE IF NOT EXISTS upstreams` 之前插入：

```go
	CREATE TABLE IF NOT EXISTS ca_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		provider VARCHAR(50) NOT NULL,
		directory_url VARCHAR(255) NOT NULL,
		credentials TEXT,
		max_concurrent INTEGER DEFAULT 1,
		min_interval_ms INTEGER DEFAULT 2000,
		enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);
```

- [ ] **Step 2: 扩展 `lb_rules`、`cert_jobs`、`global_config`**

在 `runMigrations()` 中 `// Create upstreams table if not exists` 之前插入：

```go
	// ca_providers columns are created by createTables; here we only add columns to existing tables.
	newColumns := map[string]string{
		"lb_rules.ca_provider_id":      "INTEGER DEFAULT 0",
		"cert_jobs.ca_provider_id":     "INTEGER DEFAULT 0",
		"global_config.default_ca_provider_id": "INTEGER DEFAULT 0",
	}
	for col, dtype := range newColumns {
		parts := strings.Split(col, ".")
		if len(parts) != 2 {
			continue
		}
		table, name := parts[0], parts[1]
		DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, name).Scan(&colCount)
		if colCount == 0 {
			DB.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + dtype)
		}
	}
```

注意需要在 `db.go` 顶部确认 `strings` 已 import（通常已有）。

- [ ] **Step 3: 种子默认 CA Provider 并设置默认**

在 `runMigrations()` 末尾、`return nil` 之前插入：

```go
	// Seed default CA providers if table is empty.
	var caCount int
	DB.QueryRow("SELECT COUNT(*) FROM ca_providers").Scan(&caCount)
	if caCount == 0 {
		res, err := DB.Exec(`
			INSERT INTO ca_providers (name, provider, directory_url, credentials, max_concurrent, min_interval_ms, enabled)
			VALUES
				('ZeroSSL', 'zerossl', 'https://acme.zerossl.com/v2/DV90', '{}', 1, 10000, 1),
				('Let''s Encrypt', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory', '{}', 2, 5000, 1)
		`)
		if err != nil {
			log.Printf("Warning: failed to seed CA providers: %v", err)
		} else {
			zid, _ := res.LastInsertId()
			// ZeroSSL is the first inserted row.
			DB.Exec("UPDATE global_config SET default_ca_provider_id = ? WHERE id = 1", zid)
		}
	}
```

- [ ] **Step 4: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output (success).

- [ ] **Step 5: Commit**

```bash
git add internal/db/db.go
git commit -m "feat(db): add ca_providers table, default ZeroSSL/LetsEncrypt, related columns"
```

---

### Task 2: 数据模型

**Files:**
- Modify: `internal/models/models.go`

- [ ] **Step 1: 新增 `CAProvider` 模型**

在 `models.go` 中 `GlobalConfig` 之前插入：

```go
// CAProvider represents an ACME certificate authority configuration.
type CAProvider struct {
	ID              int       `json:"id"`
	Name            string    `json:"name"`
	Provider        string    `json:"provider"`
	DirectoryURL    string    `json:"directory_url"`
	Credentials     string    `json:"credentials,omitempty"`
	MaxConcurrent   int       `json:"max_concurrent"`
	MinIntervalMS   int       `json:"min_interval_ms"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CAProviderCredentials holds typed credential fields for ZeroSSL.
type CAProviderCredentials struct {
	EABKID     string `json:"eab_kid,omitempty"`
	EABHMACKey string `json:"eab_hmac_key,omitempty"`
}
```

- [ ] **Step 2: 扩展 `GlobalConfig`、`LbRule`、`CertJob`、`CreateRuleRequest`、`UpdateRuleRequest`**

在 `GlobalConfig` 结构体中添加：

```go
	DefaultCAProviderID int `json:"default_ca_provider_id"`
```

在 `LbRule` 结构体中 `ACMEConfigID` 下方添加：

```go
	CAProviderID                  int          `json:"ca_provider_id"`
```

在 `CertJob` 结构体中 `ACMEConfigID` 或合适位置添加：

```go
	CAProviderID int `json:"ca_provider_id"`
```

在 `CreateRuleRequest` 与 `UpdateRuleRequest` 中 `ACMEConfigID` 下方添加：

```go
	CAProviderID                  int        `json:"ca_provider_id"`
```

- [ ] **Step 3: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add internal/models/models.go
git commit -m "feat(models): add CAProvider model and related fields"
```

---

### Task 3: ACME Client 工厂支持 EAB

**Files:**
- Modify: `internal/acme/client.go`

- [ ] **Step 1: 修改 `NewClient` 签名以支持 EAB**

将 `NewClient` 改为内部辅助函数，并新增 `NewClientForProvider`：

```go
// NewClient creates a Let's Encrypt compatible ACME client.
func NewClient(directoryURL, email string) (*Client, error) {
	return newClient(directoryURL, email, nil)
}

// NewClientForProvider creates an ACME client based on a CA provider configuration.
func NewClientForProvider(provider models.CAProvider, email string) (*Client, error) {
	var eab *acme.ExternalAccountBinding
	if provider.Provider == "zerossl" {
		var creds models.CAProviderCredentials
		if provider.Credentials != "" {
			_ = json.Unmarshal([]byte(provider.Credentials), &creds)
		}
		if creds.EABKID == "" || creds.EABHMACKey == "" {
			return nil, fmt.Errorf("ZeroSSL requires eab_kid and eab_hmac_key")
		}
		eab = &acme.ExternalAccountBinding{
			KID: creds.EABKID,
			Key: []byte(creds.EABHMACKey),
		}
	}
	return newClient(provider.DirectoryURL, email, eab)
}

func newClient(directoryURL, email string, eab *acme.ExternalAccountBinding) (*Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Client{
		DirectoryURL: directoryURL,
		Email:        email,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: directoryURL,
		},
		accountKey: key,
		eab:        eab,
	}, nil
}
```

- [ ] **Step 2: 更新 `Client` 结构与 `RegisterAccount`**

```go
type Client struct {
	DirectoryURL string
	Email        string
	acme         *acme.Client
	accountKey   crypto.Signer
	eab          *acme.ExternalAccountBinding
}

func (c *Client) RegisterAccount(ctx context.Context) error {
	acct := &acme.Account{
		Contact: []string{"mailto:" + c.Email},
	}
	if c.eab != nil {
		acct.ExternalAccountBinding = c.eab
	}
	_, err := c.acme.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		if strings.Contains(err.Error(), "Account already exists") || strings.Contains(err.Error(), "already registered") {
			return nil
		}
	}
	return err
}
```

- [ ] **Step 3: 添加 import**

确保 `client.go` 顶部包含：

```go
import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"lazy-balancer-v2/internal/models"

	"golang.org/x/crypto/acme"
)
```

- [ ] **Step 4: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add internal/acme/client.go
git commit -m "feat(acme): support EAB and provider-based ACME client factory"
```

---

### Task 4: CAQueueManager 调度器

**Files:**
- Create: `internal/services/caqueue.go`

- [ ] **Step 1: 创建 `internal/services/caqueue.go`**

```go
package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CAQueueManager schedules ACME issuance jobs per CA provider.
type CAQueueManager struct {
	mu          sync.Mutex
	queues      map[int]*caQueue
	reloader    func() error
	initialized bool
}

var (
	caQueueManager     *CAQueueManager
	caQueueManagerOnce sync.Once
)

// GetCAQueueManager returns the singleton queue manager.
func GetCAQueueManager(reloader func() error) *CAQueueManager {
	caQueueManagerOnce.Do(func() {
		caQueueManager = &CAQueueManager{
			queues:   make(map[int]*caQueue),
			reloader: reloader,
		}
	})
	return caQueueManager
}

// SetCAReloader updates the reloader used by new issuers.
func (m *CAQueueManager) SetCAReloader(reloader func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloader = reloader
}

// Enqueue adds or re-enqueues a cert job.
func (m *CAQueueManager) Enqueue(providerID int, jobID int, ruleID, domains string) error {
	provider, err := loadCAProvider(providerID)
	if err != nil {
		failJob(jobID, fmt.Sprintf("CA Provider 不可用: %v", err))
		return err
	}

	m.mu.Lock()
	q, ok := m.queues[provider.ID]
	if !ok {
		q = newCAQueue(provider, m.reloader)
		m.queues[provider.ID] = q
		go q.loop()
	}
	m.mu.Unlock()

	q.enqueue(queueItem{
		jobID:   jobID,
		ruleID:  ruleID,
		domains: domains,
	})
	return nil
}

type queueItem struct {
	jobID   int
	ruleID  string
	domains string
}

type caQueue struct {
	provider  models.CAProvider
	pending   []queueItem
	running   int
	lastOrder time.Time
	reloader  func() error
	mu        sync.Mutex
	stopCh    chan struct{}
}

func newCAQueue(provider models.CAProvider, reloader func() error) *caQueue {
	return &caQueue{
		provider: provider,
		reloader: reloader,
		stopCh:   make(chan struct{}),
	}
}

func (q *caQueue) enqueue(item queueItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = append(q.pending, item)
}

func (q *caQueue) loop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			q.tick()
		}
	}
}

func (q *caQueue) tick() {
	q.mu.Lock()
	if q.running >= q.provider.MaxConcurrent || len(q.pending) == 0 {
		q.mu.Unlock()
		return
	}
	interval := time.Duration(q.provider.MinIntervalMS) * time.Millisecond
	if time.Since(q.lastOrder) < interval {
		q.mu.Unlock()
		return
	}

	item := q.pending[0]
	q.pending = q.pending[1:]
	q.running++
	q.lastOrder = time.Now()
	q.mu.Unlock()

	go q.execute(item)
}

func (q *caQueue) execute(item queueItem) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CA queue panic for job %d: %v", item.jobID, r)
			failJob(item.jobID, fmt.Sprintf("调度器异常: %v", r))
		}
		q.mu.Lock()
		q.running--
		q.mu.Unlock()
	}()

	_, _ = db.DB.Exec("UPDATE cert_jobs SET status='creating_account', message='开始申请证书', updated_at=datetime('now') WHERE id=?", item.jobID)

	issuer := NewCertIssuer(q.reloader)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := issuer.Issue(ctx, item.ruleID, item.domains, q.provider); err != nil {
		log.Printf("CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
	}
}

func loadCAProvider(id int) (models.CAProvider, error) {
	var p models.CAProvider
	if id == 0 {
		// Use system default.
		var defaultID int
		err := db.DB.QueryRow("SELECT COALESCE(default_ca_provider_id,0) FROM global_config WHERE id=1").Scan(&defaultID)
		if err != nil || defaultID == 0 {
			// Fallback to first enabled provider.
			err = db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&defaultID)
			if err != nil {
				return p, fmt.Errorf("no enabled CA provider")
			}
		}
		id = defaultID
	}

	err := db.DB.QueryRow(`
		SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled
		FROM ca_providers WHERE id=? AND enabled=1
	`, id).Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled)
	if err != nil {
		return p, fmt.Errorf("load CA provider %d: %w", id, err)
	}
	return p, nil
}

// failJob marks a job as failed and writes an error log.
func failJob(jobID int, message string) {
	_, _ = db.DB.Exec("INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'error', ?)", jobID, message)
	_, _ = db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, updated_at=datetime('now') WHERE id=?", message, jobID)
}
```

- [ ] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/services/caqueue.go
git commit -m "feat(services): add CAQueueManager with per-provider scheduling"
```

---

### Task 5: CertIssuer 接入 CA Provider 并移除全局锁

**Files:**
- Modify: `internal/services/certissuer.go`

- [ ] **Step 1: 删除全局 `issuingMu` 并修改 `Issue` 签名**

删除：

```go
// issuingMu serializes ACME issuance to avoid rate limits and concurrent DNS conflicts.
var issuingMu sync.Mutex
```

修改 `Issue` 签名：

```go
func (s *CertIssuer) Issue(ctx context.Context, ruleID, domains string, provider models.CAProvider) error {
```

- [ ] **Step 2: 使用 `NewClientForProvider` 创建 client**

在 `CertIssuer.Issue` 中，替换原有 `acme.NewClient` 调用：

```go
	// Create ACME client for the selected provider
	if strings.TrimSpace(acmeEmail) == "" {
		s.failJob(jobID, "ACME 邮箱未配置，请在「系统设置 / 免费证书」中填写邮箱")
		return fmt.Errorf("ACME 邮箱未配置")
	}
	client, err := acme.NewClientForProvider(provider, acmeEmail)
	if err != nil {
		s.failJob(jobID, err.Error())
		return err
	}
```

- [ ] **Step 3: 移除 `Issue` 开头的 `issuingMu.Lock()`**

删除：

```go
	issuingMu.Lock()
	defer issuingMu.Unlock()
```

- [ ] **Step 4: 更新 job 创建/查询逻辑以兼容 domain 列表**

`primaryDomain` 仍取自 `domainList[0]`；查询已存在 job 时使用 `primaryDomain`。

- [ ] **Step 5: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/services/certissuer.go
git commit -m "refactor(certissuer): accept CAProvider, remove global mutex, use provider client"
```

---

### Task 6: CertificateService 续期入队

**Files:**
- Modify: `internal/services/certificates.go`

- [ ] **Step 1: 修改 `renewExpiringCertificates` 使用队列**

在 `renewExpiringCertificates` 中，把 goroutine 内直接调用 `issuer.Issue` 改为入队：

```go
	for _, j := range jobs {
		var currentStatus string
		err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", j.ID).Scan(&currentStatus)
		if err != nil {
			log.Printf("Renewal: failed to read job %d status: %v", j.ID, err)
			continue
		}
		if isCertJobActive(currentStatus) {
			continue
		}

		// Reset to queued and enqueue.
		_, _ = db.DB.Exec("UPDATE cert_jobs SET status='queued', message='等待排队续期', updated_at=datetime('now') WHERE id=?", j.ID)
		qm := GetCAQueueManager(s.caddyReloader)
		if err := qm.Enqueue(j.CAProviderID, j.ID, j.RuleID, j.Domain); err != nil {
			log.Printf("Renewal: failed to enqueue job %d: %v", j.ID, err)
		}
	}
```

并移除原 `go func(j models.CertJob) { ... }(j)` 块。

- [ ] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/services/certificates.go
git commit -m "refactor(certificates): enqueue renewals instead of direct issuance"
```

---

### Task 7: 规则创建时入队

**Files:**
- Modify: `internal/handlers/rules.go`

- [ ] **Step 1: 替换规则创建后的自动签发 goroutine**

在 `CreateRule` 中，找到：

```go
			// Trigger ACME issuance if needed
			if req.TLSSource == "acme_dns" && req.Domain != "" {
				go func() {
					issuer := services.NewCertIssuer(func() error {
						fullConfig := services.GenerateCaddyConfig(h.cfg)
						return h.caddyService.ApplyConfig(fullConfig)
					})
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
					defer cancel()
					if err := issuer.Issue(ctx, caddyID, req.Domain); err != nil {
						log.Printf("Auto cert issuance failed for %s: %v", req.Domain, err)
					}
				}()
			}
```

替换为：

```go
			// Trigger ACME issuance if needed
			if req.TLSSource == "acme_dns" && req.Domain != "" {
				go func() {
					qm := services.GetCAQueueManager(func() error {
						fullConfig := services.GenerateCaddyConfig(h.cfg)
						return h.caddyService.ApplyConfig(fullConfig)
					})
					if err := services.CreateOrRequeueCertJob(caddyID, req.Domain, req.CAProviderID, qm); err != nil {
						log.Printf("Auto cert enqueue failed for %s: %v", req.Domain, err)
					}
				}()
			}
```

- [ ] **Step 2: 新增 `CreateOrRequeueCertJob` 辅助函数**

在 `internal/services/certificates.go` 末尾或 `certissuer.go` 中添加：

```go
// CreateOrRequeueCertJob creates a pending cert job for the rule and enqueues it.
func CreateOrRequeueCertJob(ruleID, domains string, caProviderID int, qm *CAQueueManager) error {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return fmt.Errorf("invalid ACME domains: %s", domains)
	}
	primary := list[0]
	joined := strings.Join(list, ",")

	var jobID int
	err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id=? AND domain=?", ruleID, primary).Scan(&jobID)
	if err != nil {
		res, err := db.DB.Exec(
			"INSERT INTO cert_jobs (rule_id, domain, status, message, ca_provider_id) VALUES (?, ?, 'queued', '等待排队签发', ?)",
			ruleID, joined, caProviderID,
		)
		if err != nil {
			return fmt.Errorf("create cert job: %w", err)
		}
		id64, _ := res.LastInsertId()
		jobID = int(id64)
	} else {
		_, _ = db.DB.Exec(
			"UPDATE cert_jobs SET status='queued', message='重新排队签发', updated_at=datetime('now'), ca_provider_id=? WHERE id=?",
			caProviderID, jobID,
		)
	}
	return qm.Enqueue(caProviderID, jobID, ruleID, joined)
}
```

注意需要 import `lazy-balancer-v2/internal/db`、`lazy-balancer-v2/internal/models`（若使用）、`strings`、`fmt` 已在 `certissuer.go` 中。

- [ ] **Step 3: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add internal/handlers/rules.go internal/services/certissuer.go
git commit -m "feat(rules): enqueue ACME issuance on rule creation"
```

---

### Task 8: 规则更新时入队

**Files:**
- Modify: `internal/handlers/rules.go`

- [ ] **Step 1: 替换规则更新后的自动签发 goroutine**

在 `UpdateRule` 中，找到：

```go
			// Trigger ACME issuance if needed
			if req.TLSSource == "acme_dns" && req.EnableTLS && domain != "" {
				if !services.IsACMECertIssued(caddyID, domain) {
					go func() {
						issuer := services.NewCertIssuer(func() error {
							fullConfig := services.GenerateCaddyConfig(h.cfg)
							return h.caddyService.ApplyConfig(fullConfig)
						})
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
						defer cancel()
						if err := issuer.Issue(ctx, caddyID, domain); err != nil {
							log.Printf("Auto cert issuance failed for %s: %v", domain, err)
						}
					}()
				}
			}
```

替换为：

```go
			// Trigger ACME issuance if needed
			if req.TLSSource == "acme_dns" && req.EnableTLS && domain != "" {
				if !services.IsACMECertIssued(caddyID, domain) {
					go func() {
						qm := services.GetCAQueueManager(func() error {
							fullConfig := services.GenerateCaddyConfig(h.cfg)
							return h.caddyService.ApplyConfig(fullConfig)
						})
						if err := services.CreateOrRequeueCertJob(caddyID, domain, req.CAProviderID, qm); err != nil {
							log.Printf("Auto cert enqueue failed for %s: %v", domain, err)
						}
					}()
				}
			}
```

- [ ] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/handlers/rules.go
git commit -m "feat(rules): enqueue ACME issuance on rule update"
```

---

### Task 9: 手动重试入队

**Files:**
- Modify: `internal/handlers/certjobs.go`

- [ ] **Step 1: 修改 `RetryCertJob` 入队而非直接签发**

将 `RetryCertJob` 中 `go func() { ... issuer.Issue(...) ... }()` 替换为：

```go
	go func() {
		qm := services.GetCAQueueManager(func() error {
			fullConfig := services.GenerateCaddyConfig(h.cfg)
			return h.caddyService.ApplyConfig(fullConfig)
		})
		if err := services.CreateOrRequeueCertJob(ruleID, domain, 0, qm); err != nil {
			log.Printf("Manual retry enqueue failed for job %d: %v", id, err)
		}
	}()
```

注意：`CreateOrRequeueCertJob` 的 `caProviderID=0` 会让队列管理器根据系统默认/规则当前配置解析。

- [ ] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/handlers/certjobs.go
git commit -m "feat(certjobs): retry enqueues job instead of blocking"
```

---

### Task 10: CA Provider API 与默认设置

**Files:**
- Create: `internal/handlers/caproviders.go`
- Modify: `internal/handlers/handlers.go`

- [ ] **Step 1: 创建 `internal/handlers/caproviders.go`**

```go
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) ListCAProviders(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled, created_at, updated_at
		FROM ca_providers ORDER BY id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to list CA providers"})
		return
	}
	defer rows.Close()

	var list []models.CAProvider
	for rows.Next() {
		var p models.CAProvider
		var createdAt, updatedAt sql.NullTime
		rows.Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled, &createdAt, &updatedAt)
		if createdAt.Valid {
			p.CreatedAt = createdAt.Time
		}
		if updatedAt.Valid {
			p.UpdatedAt = updatedAt.Time
		}
		list = append(list, p)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: list})
}

func (h *Handlers) UpdateCAProvider(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req models.CAProvider
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}
	if req.Provider != "letsencrypt" && req.Provider != "zerossl" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unsupported provider"})
		return
	}
	if req.DirectoryURL == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Directory URL is required"})
		return
	}
	if req.MaxConcurrent <= 0 {
		req.MaxConcurrent = 1
	}
	if req.MinIntervalMS <= 0 {
		req.MinIntervalMS = 1000
	}

	_, err := db.DB.Exec(`
		UPDATE ca_providers SET name=?, provider=?, directory_url=?, credentials=?, max_concurrent=?, min_interval_ms=?, enabled=?, updated_at=datetime('now')
		WHERE id=?
	`, req.Name, req.Provider, req.DirectoryURL, req.Credentials, req.MaxConcurrent, req.MinIntervalMS, req.Enabled, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update CA provider: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA provider updated"})
}

func (h *Handlers) TestCAProvider(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var p models.CAProvider
	err := db.DB.QueryRow(`
		SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled
		FROM ca_providers WHERE id=? AND enabled=1
	`, id).Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found or disabled"})
		return
	}

	// Validate credentials by attempting ACME account registration.
	client, err := services.NewACMEClientForProvider(p, "test@example.com")
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid CA provider config: " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.RegisterAccount(ctx); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ACME registration failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA provider configuration is valid"})
}
```

注意：`services.NewACMEClientForProvider` 需要在 `internal/services/certissuer.go` 或 `caqueue.go` 中包装暴露：

```go
// NewACMEClientForProvider exposes the ACME client factory for handlers.
func NewACMEClientForProvider(provider models.CAProvider, email string) (*acme.Client, error) {
	return acme.NewClientForProvider(provider, email)
}
```

如果放在 `certissuer.go`，需要 import `lazy-balancer-v2/internal/acme`。

- [ ] **Step 2: 在 `handlers.go` 注册路由**

在 `SetupRoutes`（或路由注册处）添加：

```go
	api.GET("/ca-providers", h.ListCAProviders)
	api.PUT("/ca-providers/:id", h.UpdateCAProvider)
	api.POST("/ca-providers/:id/test", h.TestCAProvider)
```

- [ ] **Step 3: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add internal/handlers/caproviders.go internal/handlers/handlers.go internal/services/certissuer.go
git commit -m "feat(api): add CA provider list/update/test endpoints"
```

---

### Task 11: 全局默认 CA Provider 保存

**Files:**
- Modify: `internal/handlers/certificates.go`（全局设置保存）

- [x] **Step 1: 读取并保存 `default_ca_provider_id`**

在 `GetGlobalConfig`/`SaveGlobalConfig` 相关 handler 中，把 `default_ca_provider_id` 加入查询与更新。

例如若保存逻辑在 `SaveGlobalConfig`：

```go
	_, err = db.DB.Exec(`
		UPDATE global_config SET
			acme_email = ?,
			cert_expiry_days = ?,
			default_ca_provider_id = ?,
			updated_at = datetime('now')
		WHERE id = 1
	`, req.ACMEEmail, req.CertExpiryDays, req.DefaultCAProviderID)
```

并在读取时返回该字段。

- [x] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [x] **Step 3: Commit**

```bash
git add internal/handlers/certificates.go
git commit -m "feat(settings): persist default CA provider selection"
```

---

### Task 12: 规则删除级联删除 cert_jobs

**Files:**
- Modify: `internal/handlers/rules.go`

- [ ] **Step 1: 在 `DeleteRule` 中删除关联任务与日志**

在删除 `lb_rules` 记录之前插入：

```go
	_, _ = db.DB.Exec("DELETE FROM cert_job_logs WHERE job_id IN (SELECT id FROM cert_jobs WHERE rule_id = ?)", caddyID)
	_, _ = db.DB.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID)
```

- [ ] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/handlers/rules.go
git commit -m "fix(rules): cascade delete cert_jobs and logs when deleting rule"
```

---

### Task 13: 启动时重新入队非终态任务

**Files:**
- Modify: `internal/services/caqueue.go` 或 `internal/services/services.go`

- [ ] **Step 1: 在 `NewCertificateService` 或应用启动时调用重入队**

在 `services.go` 或 `certificates.go` 中新增：

```go
// RequeueNonTerminalJobs scans cert_jobs and re-enqueues jobs that are not in a terminal state.
func RequeueNonTerminalJobs(qm *CAQueueManager) {
	rows, err := db.DB.Query(`
		SELECT id, rule_id, domain, ca_provider_id FROM cert_jobs
		WHERE status NOT IN ('issued','failed')
	`)
	if err != nil {
		log.Printf("Failed to requeue non-terminal jobs: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var jobID, caProviderID int
		var ruleID, domain string
		if err := rows.Scan(&jobID, &ruleID, &domain, &caProviderID); err != nil {
			continue
		}
		if err := qm.Enqueue(caProviderID, jobID, ruleID, domain); err != nil {
			log.Printf("Failed to requeue job %d: %v", jobID, err)
		} else {
			_, _ = db.DB.Exec("UPDATE cert_jobs SET status='queued', message='等待排队签发' WHERE id=?", jobID)
		}
	}
}
```

在 `CertificateService.Start()` 开头调用：

```go
func (s *CertificateService) Start() {
	qm := GetCAQueueManager(s.caddyReloader)
	RequeueNonTerminalJobs(qm)
	// ... existing code
}
```

- [ ] **Step 2: 编译验证**

```bash
go build ./...
go vet ./...
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/services/caqueue.go internal/services/certificates.go
git commit -m "feat(queue): re-enqueue non-terminal cert jobs on startup"
```

---

### Task 14: 前端 CA Provider 配置卡片

**Files:**
- Modify: `web/src/views/settings/FreeCertificates.vue`

- [ ] **Step 1: 添加 CA Provider 列表与默认选择**

在 `<template>` 中，在「ACME 全局设置」与「DNS 提供商配置」之间新增：

```vue
    <el-card class="settings-card" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>CA 提供商</span>
        </div>
      </template>
      <el-table v-if="caProviders.length > 0" :data="caProviders" size="small">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="provider" label="类型" />
        <el-table-column prop="directory_url" label="Directory URL" show-overflow-tooltip />
        <el-table-column prop="max_concurrent" label="最大并发" width="90" />
        <el-table-column prop="min_interval_ms" label="最小间隔(ms)" width="120" />
        <el-table-column prop="enabled" label="状态" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="authStore.nodeMode === 'master'" label="操作" width="140" align="center">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :loading="testingCAId === row.id" @click="testCAProvider(row)">测试</el-button>
            <el-button link type="primary" size="small" @click="openCAProviderDialog(row)">编辑</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
```

在「ACME 全局设置」表单中增加默认选择：

```vue
        <el-form-item label="默认 CA 提供商">
          <el-select v-model="global.default_ca_provider_id" style="width: 100%">
            <el-option v-for="p in enabledCAProviders" :key="p.id" :label="p.name" :value="p.id" />
          </el-select>
        </el-form-item>
```

- [ ] **Step 2: 添加数据与函数**

在 `<script setup>` 中：

```ts
const caProviders = ref<CAProvider[]>([])
const testingCAId = ref<number | null>(null)
const caDialogVisible = ref(false)
const editingCAProvider = ref<CAProvider | null>(null)
const caForm = reactive<CAProvider>({
  id: 0,
  name: '',
  provider: 'zerossl',
  directory_url: 'https://acme.zerossl.com/v2/DV90',
  credentials: '{}',
  max_concurrent: 1,
  min_interval_ms: 10000,
  enabled: true,
} as CAProvider)

const enabledCAProviders = computed(() => caProviders.value.filter(p => p.enabled))

interface CAProvider {
  id: number
  name: string
  provider: string
  directory_url: string
  credentials: string
  max_concurrent: number
  min_interval_ms: number
  enabled: boolean
}

const fetchCAProviders = async () => {
  try {
    const res = await request.get('/ca-providers')
    caProviders.value = res.data || []
  } catch (error) {
    console.error('Failed to fetch CA providers:', error)
  }
}

const openCAProviderDialog = (p: CAProvider) => {
  editingCAProvider.value = p
  Object.assign(caForm, {
    ...p,
    credentials: typeof p.credentials === 'string' ? p.credentials : JSON.stringify(p.credentials || {}),
  })
  caDialogVisible.value = true
}

const saveCAProvider = async () => {
  if (!caForm.name || !caForm.directory_url) {
    ElMessage.warning('请填写名称和 Directory URL')
    return
  }
  try {
    await request.put(`/ca-providers/${editingCAProvider.value!.id}`, caForm)
    ElMessage.success('配置已更新')
    caDialogVisible.value = false
    fetchCAProviders()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || '保存失败')
  }
}

const testCAProvider = async (p: CAProvider) => {
  const domain = await promptTestDomain(false)
  if (!domain) return
  testingCAId.value = p.id
  try {
    await request.post(`/ca-providers/${p.id}/test`, { domain })
    ElMessage.success('CA 配置有效')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || '测试失败')
  } finally {
    testingCAId.value = null
  }
}
```

在 `onMounted` 中调用 `fetchCAProviders()`。

- [ ] **Step 3: 编译验证**

```bash
cd web && npm run build
```

Expected: build succeeds.

- [ ] **Step 4: Commit**

```bash
git add web/src/views/settings/FreeCertificates.vue
git commit -m "feat(ui): CA provider config card and default selector"
```

---

### Task 15: 规则 Wizard 选择 CA Provider

**Files:**
- Modify: `web/src/views/Rules.vue`

- [ ] **Step 1: 在 Rule 接口与表单中添加 `ca_provider_id`**

在 `interface Rule` 中 `acme_config_id` 下方添加：

```ts
  ca_provider_id?: number | undefined
```

在 `wizardForm` 初始化、`openWizard`、`submitWizard` 中同步该字段。

- [ ] **Step 2: 在 TLS 步骤表单增加选择器**

在 TLS 相关表单项中增加：

```vue
            <el-form-item label="CA 提供商">
              <el-select v-model="wizardForm.ca_provider_id" placeholder="系统默认" clearable style="width: 100%">
                <el-option label="系统默认" :value="0" />
                <el-option v-for="p in enabledCAProviders" :key="p.id" :label="p.name" :value="p.id" />
              </el-select>
            </el-form-item>
```

- [ ] **Step 3: 加载 CA Provider 列表**

在 `Rules.vue` 中：

```ts
const caProviders = ref<Array<{ id: number; name: string; enabled: boolean }>>([])
const enabledCAProviders = computed(() => caProviders.value.filter(p => p.enabled))

const fetchCAProviders = async () => {
  try {
    const res = await request.get('/ca-providers')
    caProviders.value = res.data || []
  } catch (e) {
    console.error('Failed to load CA providers:', e)
  }
}

onMounted(() => {
  fetchRules()
  fetchCAProviders()
})
```

- [ ] **Step 4: 编译验证**

```bash
cd web && npm run build
```

Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add web/src/views/Rules.vue
git commit -m "feat(ui): allow selecting CA provider per rule"
```

---

### Task 16: 签发任务列表显示 queued 状态

**Files:**
- Modify: `web/src/views/settings/CertJobs.vue`

- [x] **Step 1: 在状态标签与重签禁用中处理 queued**

`statusLabel` 中增加：

```ts
    case 'queued': return '排队中'
```

`statusType` 中增加：

```ts
    case 'queued': return 'info'
```

重签按钮保持仅 `issued`/`failed` 可点击。

- [x] **Step 2: 编译验证**

```bash
cd web && npm run build
```

Expected: build succeeds.

- [x] **Step 3: Commit**

```bash
git add web/src/views/settings/CertJobs.vue
git commit -m "feat(ui): show queued status in cert jobs list"
```

---

### Task 17: 文档清理

**Files:**
- Modify: `docs/superpowers/specs/2026-06-24-acme-dns-certificates-design.md`
- Modify: `docs/superpowers/specs/2-architecture.md`
- Modify: `docs/superpowers/specs/4-config-rules.md`

- [ ] **Step 1: 移除或标注 `tls_auto_cert` / `tls_email` / `TLSEmail` / `TLSAutoCert`**

使用 search 找出所有出现位置：

```bash
grep -n "tls_auto_cert\|tls_email\|TLSEmail\|TLSAutoCert" docs/superpowers/specs/*.md docs/caddy-config-rules.md
```

对每个出现：
- 若描述旧字段语义，改为说明已废弃，由 `tls_source` / `global_config.acme_email` / `ca_provider_id` 替代。
- 若出现在示例 JSON 中，删除对应字段。

- [ ] **Step 2: Commit**

```bash
git add docs/
git commit -m "docs: remove legacy tls_auto_cert/tls_email references"
```

---

### Task 18: 端到端验证

**Files:**
- N/A

- [ ] **Step 1: 构建并启动容器**

```bash
docker compose build --no-cache
docker compose up -d
```

- [ ] **Step 2: 验证 CA Provider 列表接口**

```bash
curl -s http://localhost:8000/api/ca-providers | jq
```

Expected: 返回 ZeroSSL 与 Let's Encrypt 两条记录，默认启用。

- [ ] **Step 3: 测试 ZeroSSL EAB 配置**

在 UI 中编辑 ZeroSSL，填入从 ZeroSSL 控制台生成的 `eab_kid` 与 `eab_hmac_key`，点击「测试」，输入可管理域名。

Expected: 提示 "CA 配置有效"。

- [ ] **Step 4: 创建单域名 ACME 规则**

创建 HTTP 规则，域名 `test.hifi029.com`，TLS 来源选择 ACME DNS，选择 ZeroSSL 或 Let's Encrypt，保存。

观察 `cert_jobs` 状态：`queued` → `creating_account` → ... → `issued`。

Expected: 最终状态 `issued`，`cert_pem` 与 `key_pem` 非空，HTTPS 可访问。

- [ ] **Step 5: 创建根域+www 规则**

域名填写 `hifi029.com,www.hifi029.com`，保存。

Expected: `cert_jobs.domain` 保存为 `hifi029.com,www.hifi029.com`，签发成功后证书包含两个域名。

- [ ] **Step 6: 并发规则测试**

同时创建 5-10 条 ACME 规则。

Expected: 任务状态大多为 `queued`，按 `max_concurrent` 与 `min_interval_ms` 逐个/逐批执行，不阻塞 UI。

- [ ] **Step 7: Commit 验证结果（可选）**

若验证通过，提交最终文档更新：

```bash
git add docs/
git commit -m "docs: verify CA provider queue design with end-to-end tests"
```

---

## 计划自检

- **Spec 覆盖：**
  - `ca_providers` 表与默认数据 → Task 1
  - 模型扩展 → Task 2
  - EAB 支持 → Task 3
  - QueueManager → Task 4
  - CertIssuer 改造 → Task 5
  - 续期入队 → Task 6
  - 规则创建/更新入队 → Task 7-8
  - 手动重试入队 → Task 9
  - CA Provider API → Task 10
  - 默认 CA 设置 → Task 11
  - 级联删除 → Task 12
  - 启动重入队 → Task 13
  - 前端配置 → Task 14
  - 规则 wizard → Task 15
  - queued 状态 → Task 16
  - 文档清理 → Task 17
  - 端到端验证 → Task 18
- **Placeholder 检查：** 无 TBD/TODO，所有步骤含具体文件路径与代码。
- **类型一致性：** `CAProvider` 字段、API 路径、`CreateOrRequeueCertJob` 签名在前后任务中一致。

## 执行方式

计划已保存到 `docs/superpowers/plans/YYYY-MM-DD-ca-provider-queue.md`。

两种执行方式：

1. **Subagent-Driven（推荐）**：每个 Task 派独立子代理执行，我负责审查与衔接。
2. **Inline Execution**：在当前会话中按 Task 顺序直接实现。

请选择执行方式。
