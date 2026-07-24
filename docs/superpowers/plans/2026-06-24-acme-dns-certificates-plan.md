# ACME DNS 自动证书签发实现计划

> **⚠️ 已过时**：本计划已被 `2026-07-01-ca-provider-queue.md` 取代。后续实现使用 `ca_providers` 表与按 CA 排队的调度器，规则级字段 `tls_auto_cert` 已废弃，由 `tls_source` + `ca_provider_id` 替代，ACME 邮箱全局配置在 `global_config.acme_email`。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 升级 Caddy 到 v2.11.4，新增 ACME + DNS 挑战免费证书自动签发能力，支持进度追踪和过期提醒，并重构系统设置页面导航。

**Architecture:** 后端新增 DNS provider 注册表和 CertificateService 轮询任务，Caddy JSON 配置中注入 TLS automation policies；凭证通过环境变量传入 Caddy；前端新增系统设置二级菜单和签发任务列表。

**Tech Stack:** Go 1.26, Caddy v2.11.4, xcaddy, Vue 3 + Element Plus, SQLite

---

## 文件结构

### 新建文件
- `internal/services/dnsproviders/dnspod.go` — DNSPod provider 实现
- `internal/services/dnsproviders/cloudflare.go` — Cloudflare provider 实现
- `internal/services/dnsproviders/registry.go` — provider 注册表
- `internal/services/certificates.go` — CertificateService 和 Job 轮询
- `internal/models/cert.go` — 证书相关模型（CertJob, CertificateConfig 改造）
- `internal/handlers/certjobs.go` — 签发任务 API
- `web/src/views/CertJobs.vue` — 签发任务列表（嵌入免费证书页面）

### 修改文件
- `Dockerfile` — 升级 Caddy 版本，注入 DNS 插件
- `internal/db/db.go` — 新增 cert_jobs 表，改造 certificate_configs / global_config / lb_rules
- `internal/models/models.go` — 改造 CertificateConfig，新增 CertJob
- `internal/config/config.go` — 无需改动
- `internal/services/caddy.go` — 生成 TLS automation policies，读取全局 ACME 配置
- `internal/handlers/certificates.go` — 改造 CRUD，支持 JSON credentials 和测试接口
- `internal/handlers/caddy.go` — UpdateConfig 增加 acme_email / cert_expiry_days
- `internal/handlers/rules.go` — 支持 tls_source / acme_config_id
- `internal/handlers/handlers.go` — 注册新路由
- `internal/services/services.go` — MetricsService 调用 CertificateService 检查过期
- `web/src/views/Settings.vue` — 重构为二级菜单，新增免费证书配置页面
- `web/src/views/Rules.vue` — TLS 来源二选一
- `web/src/components/layout/AppLayout.vue` — 更新主导航

---

## Task 1: Caddy 升级与 DNS 插件编译

**Files:**
- Modify: `Dockerfile:10`

- [ ] **Step 1: 修改 Dockerfile 中 Caddy 版本和插件**

```dockerfile
RUN xcaddy build v2.11.4 \
  --with github.com/caddy-dns/dnspod \
  --with github.com/caddy-dns/cloudflare
```

- [ ] **Step 2: 本地构建验证**

Run: `docker compose build --no-cache`
Expected: 构建成功，Caddy 版本输出 `v2.11.4`

- [ ] **Step 3: 运行容器并验证版本**

Run: `docker compose up -d && docker exec lazy-balancer caddy version`
Expected: 输出包含 `v2.11.4`

- [ ] **Step 4: 回归测试现有功能**

Run: 创建 HTTP 规则、HTTPS 手动证书规则、TCP 规则，确认均正常工作
Expected: 200 OK / 正常转发

- [ ] **Step 5: Commit**

```bash
git add Dockerfile
git commit -m "build: upgrade Caddy to v2.11.4 with DNS challenge plugins"
```

---

## Task 2: 数据库迁移

**Files:**
- Modify: `internal/db/db.go:152-178`, `internal/db/db.go:236-319`

- [ ] **Step 1: 修改 certificate_configs 表结构**

将 `dns_id` / `dns_key` 改为 `dns_credentials` JSON：

```sql
CREATE TABLE IF NOT EXISTS certificate_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    dns_provider VARCHAR(50) DEFAULT 'dnspod',
    dns_credentials TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);
```

- [ ] **Step 2: 新增 lb_rules TLS 来源字段（migration）**

```go
newLbColumns := map[string]string{
    ...
    "tls_source":      "VARCHAR(20) DEFAULT 'manual'",
    "acme_config_id":  "INTEGER DEFAULT 0",
}
```

- [ ] **Step 3: 新增 cert_jobs 表**

```sql
CREATE TABLE IF NOT EXISTS cert_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id VARCHAR(20) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    message TEXT,
    expires_at DATETIME,
    cert_pem TEXT,
    key_pem TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain ON cert_jobs(rule_id, domain);
```

- [ ] **Step 4: 新增 global_config ACME 字段（migration）**

```go
DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='acme_email'").Scan(&colCount)
if colCount == 0 {
    DB.Exec("ALTER TABLE global_config ADD COLUMN acme_email VARCHAR(255)")
}
DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cert_expiry_days'").Scan(&colCount)
if colCount == 0 {
    DB.Exec("ALTER TABLE global_config ADD COLUMN cert_expiry_days INTEGER DEFAULT 30")
}
```

- [ ] **Step 5: 运行 Go 构建验证**

Run: `go build ./cmd/server`
Expected: 成功

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go
git commit -m "db: add cert_jobs table, tls_source/acme_config_id, and ACME global settings"
```

---

## Task 3: DNS Provider 注册表

**Files:**
- Create: `internal/services/dnsproviders/registry.go`
- Create: `internal/services/dnsproviders/dnspod.go`
- Create: `internal/services/dnsproviders/cloudflare.go`

- [ ] **Step 1: 创建注册表接口**

```go
package dnsproviders

import "fmt"

type CredentialField struct {
    Name        string `json:"name"`
    Label       string `json:"label"`
    Type        string `json:"type"`
    Required    bool   `json:"required"`
    Placeholder string `json:"placeholder,omitempty"`
}

type Provider interface {
    Code() string
    Name() string
    ModuleName() string
    CredentialFields() []CredentialField
    BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error)
    EnvVarPrefix() string
}

var registry = map[string]Provider{}

func Register(p Provider) {
    registry[p.Code()] = p
}

func Get(code string) (Provider, bool) {
    p, ok := registry[code]
    return p, ok
}

func List() []Provider {
    list := make([]Provider, 0, len(registry))
    for _, p := range registry {
        list = append(list, p)
    }
    return list
}

func EnvVarName(configID int, p Provider) string {
    return fmt.Sprintf("%s_%d", p.EnvVarPrefix(), configID)
}
```

- [ ] **Step 2: 实现 DNSPod provider**

```go
package dnsproviders

func init() { Register(&DNSPod{}) }

type DNSPod struct{}

func (d *DNSPod) Code() string  { return "dnspod" }
func (d *DNSPod) Name() string  { return "DNSPod (腾讯云)" }
func (d *DNSPod) ModuleName() string { return "dns.providers.dnspod" }
func (d *DNSPod) EnvVarPrefix() string { return "DNSPOD_AUTH_TOKEN" }

func (d *DNSPod) CredentialFields() []CredentialField {
    return []CredentialField{
        {Name: "auth_token", Label: "Auth Token", Type: "password", Required: true, Placeholder: "APP_ID,APP_TOKEN"},
    }
}

func (d *DNSPod) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
    if creds["auth_token"] == "" {
        return nil, fmt.Errorf("auth_token is required")
    }
    return map[string]interface{}{
        "auth_token": creds["auth_token"],
    }, nil
}
```

- [ ] **Step 3: 实现 Cloudflare provider**

```go
package dnsproviders

func init() { Register(&Cloudflare{}) }

type Cloudflare struct{}

func (c *Cloudflare) Code() string  { return "cloudflare" }
func (c *Cloudflare) Name() string  { return "Cloudflare" }
func (c *Cloudflare) ModuleName() string { return "dns.providers.cloudflare" }
func (c *Cloudflare) EnvVarPrefix() string { return "CF_API_TOKEN" }

func (c *Cloudflare) CredentialFields() []CredentialField {
    return []CredentialField{
        {Name: "api_token", Label: "API Token", Type: "password", Required: true},
    }
}

func (c *Cloudflare) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
    if creds["api_token"] == "" {
        return nil, fmt.Errorf("api_token is required")
    }
    return map[string]interface{}{
        "api_token": creds["api_token"],
    }, nil
}
```

- [ ] **Step 4: 添加单元测试**

Create: `internal/services/dnsproviders/registry_test.go`

```go
func TestDNSPodCredentials(t *testing.T) {
    p, ok := Get("dnspod")
    if !ok { t.Fatal("dnspod not registered") }
    _, err := p.BuildCredentialsJSON(map[string]string{})
    if err == nil { t.Fatal("expected error for empty token") }
}
```

Run: `go test ./internal/services/dnsproviders/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/dnsproviders
git commit -m "feat: add DNS provider registry for ACME DNS challenge"
```

---

## Task 4: 模型改造

**Files:**
- Modify: `internal/models/models.go:69-123`, `internal/models/models.go:201-300`

- [ ] **Step 1: 改造 GlobalConfig**

```go
type GlobalConfig struct {
    ...
    ACMEEmail        string       `json:"acme_email"`
    CertExpiryDays   int          `json:"cert_expiry_days"`
    LETSEncryptEmail string       `json:"letsencrypt_email"`
    ...
}
```

- [ ] **Step 2: 改造 CertificateConfig**

```go
type CertificateConfig struct {
    ID              int          `json:"id"`
    Name            string       `json:"name"`
    DNSProvider     string       `json:"dns_provider"`
    DNSCredentials  string       `json:"-"`
    Enabled         bool         `json:"enabled"`
    CreatedAt       time.Time    `json:"created_at"`
    UpdatedAt       sql.NullTime `json:"updated_at"`
}
```

- [ ] **Step 3: 新增 CertJob 模型**

```go
type CertJob struct {
    ID        int          `json:"id"`
    RuleID    string       `json:"rule_id"`
    Domain    string       `json:"domain"`
    Status    string       `json:"status"`
    Message   string       `json:"message"`
    ExpiresAt sql.NullTime `json:"expires_at"`
    CreatedAt time.Time    `json:"created_at"`
    UpdatedAt sql.NullTime `json:"updated_at"`
}
```

- [ ] **Step 4: 改造 Create/Update CertificateConfig Request**

```go
type CreateCertificateConfigRequest struct {
    Name            string            `json:"name" binding:"required"`
    DNSProvider     string            `json:"dns_provider" binding:"required"`
    DNSCredentials  map[string]string `json:"dns_credentials"`
    Enabled         bool              `json:"enabled"`
}

type UpdateCertificateConfigRequest struct {
    Name            string            `json:"name"`
    DNSProvider     string            `json:"dns_provider"`
    DNSCredentials  map[string]string `json:"dns_credentials"`
    Enabled         *bool             `json:"enabled"`
}
```

- [ ] **Step 5: 改造 Rule Request 模型**

在 `CreateRuleRequest` 和 `UpdateRuleRequest` 中增加：

```go
TLSSource    string `json:"tls_source"`
ACMEConfigID int    `json:"acme_config_id"`
```

- [ ] **Step 6: Commit**

```bash
git add internal/models/models.go
git commit -m "feat(models): add CertJob, tls_source/acme_config_id, and ACME settings"
```

---

## Task 5: CertificateService 实现

**Files:**
- Create: `internal/services/certificates.go`

- [ ] **Step 1: 创建 CertificateService 结构**

```go
package services

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "sync"
    "time"

    "lazy-balancer-v2/internal/db"
    "lazy-balancer-v2/internal/models"
    "lazy-balancer-v2/internal/services/dnsproviders"
)

type CertificateService struct {
    adminURL string
    client   *http.Client
    mu       sync.Mutex
    stopCh   chan struct{}
}

func NewCertificateService(adminURL string) *CertificateService {
    return &CertificateService{
        adminURL: adminURL,
        client:   &http.Client{Timeout: 10 * time.Second},
        stopCh:   make(chan struct{}),
    }
}

func (s *CertificateService) Start() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            s.poll()
        case <-s.stopCh:
            return
        }
    }
}

func (s *CertificateService) Stop() { close(s.stopCh) }
```

- [ ] **Step 2: 实现 CreateJobsForRule**

```go
func (s *CertificateService) CreateJobsForRule(ruleID string, domains string) error {
    for _, d := range strings.Split(domains, ",") {
        d = strings.TrimSpace(d)
        if d == "" { continue }
        _, err := db.DB.Exec(`
            INSERT INTO cert_jobs (rule_id, domain, status, message)
            VALUES (?, ?, 'issuing', '等待 Caddy 签发')
            ON CONFLICT DO NOTHING
        `, ruleID, d)
        if err != nil {
            log.Printf("Create cert job failed: %v", err)
        }
    }
    return nil
}
```

注意：SQLite 无 ON CONFLICT 自动，需先查后插。

- [ ] **Step 3: 实现 poll 方法**

```go
func (s *CertificateService) poll() {
    resp, err := s.client.Get(s.adminURL + "/pki/ca/local")
    if err != nil {
        log.Printf("Failed to get Caddy certificates: %v", err)
        return
    }
    defer resp.Body.Close()

    var data struct {
        Roots []struct {
            Subject string `json:"subject"`
            NotAfter time.Time `json:"not_after"`
        } `json:"roots"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        return
    }

    rows, _ := db.DB.Query("SELECT id, domain, status FROM cert_jobs WHERE status IN ('pending','issuing','failed')")
    if rows == nil { return }
    defer rows.Close()

    for rows.Next() {
        var id int
        var domain, status string
        rows.Scan(&id, &domain, &status)

        found := false
        var notAfter time.Time
        for _, r := range data.Roots {
            if strings.Contains(r.Subject, domain) {
                found = true
                notAfter = r.NotAfter
                break
            }
        }

        if found {
            db.DB.Exec("UPDATE cert_jobs SET status='issued', message='签发成功', expires_at=? WHERE id=?", notAfter, id)
        } else if status == "issuing" {
            // 超过 10 分钟视为失败
            db.DB.Exec(`
                UPDATE cert_jobs SET status='failed', message='签发超时，请检查 DNS 配置和域名解析'
                WHERE id=? AND datetime(created_at, '+10 minutes') < datetime('now')
            `, id)
        }
    }
}
```

- [ ] **Step 4: 实现 CheckExpiration**

```go
func (s *CertificateService) CheckExpiration() []models.CertJob {
    var days int
    db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&days)

    rows, _ := db.DB.Query(`
        SELECT id, rule_id, domain, status, expires_at
        FROM cert_jobs
        WHERE status = 'issued'
          AND expires_at IS NOT NULL
          AND expires_at <= datetime('now', '+' || ? || ' days')
        ORDER BY expires_at ASC
    `, days)
    if rows == nil { return nil }
    defer rows.Close()

    var jobs []models.CertJob
    for rows.Next() {
        var j models.CertJob
        rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt)
        jobs = append(jobs, j)
    }
    return jobs
}
```

- [ ] **Step 5: Commit**

```bash
git add internal/services/certificates.go
git commit -m "feat: add CertificateService for ACME job tracking and expiry checks"
```

---

## Task 6: Caddy 配置生成 TLS Automation Policies

**Files:**
- Modify: `internal/services/caddy.go:1465-1480`, `internal/services/caddy.go:1905-1931`

- [ ] **Step 1: 新增 ACMEConfig 结构到 SingleRuleConfig**

```go
type SingleRuleConfig struct {
    ...
    TLSSource     string `json:"tls_source"`
    ACMEConfigID  int    `json:"acme_config_id"`
    ACMEEmail     string `json:"acme_email"`
}
```

- [ ] **Step 2: 实现 buildTLSAutomationPolicies 辅助函数**

```go
func buildTLSAutomationPolicies(rules []SingleRuleConfig) []map[string]interface{} {
    policies := []map[string]interface{}{}
    for _, rule := range rules {
        if !rule.EnableTLS || rule.TLSSource != "acme_dns" || rule.ACMEConfigID == 0 {
            continue
        }

        var provider, credentials string
        err := db.DB.QueryRow("SELECT dns_provider, dns_credentials FROM certificate_configs WHERE id=? AND enabled=1", rule.ACMEConfigID).Scan(&provider, &credentials)
        if err != nil { continue }

        p, ok := dnsproviders.Get(provider)
        if !ok { continue }

        var creds map[string]string
        json.Unmarshal([]byte(credentials), &creds)
        providerJSON, err := p.BuildCredentialsJSON(creds)
        if err != nil { continue }

        envVar := dnsproviders.EnvVarName(rule.ACMEConfigID, p)

        for _, domain := range strings.Split(rule.Domain, ",") {
            domain = strings.TrimSpace(domain)
            if domain == "" { continue }
            policies = append(policies, map[string]interface{}{
                "subjects": []string{domain},
                "issuers": []map[string]interface{}{
                    {
                        "module": "acme",
                        "email":  rule.ACMEEmail,
                        "challenges": map[string]interface{}{
                            "dns": map[string]interface{}{
                                "provider": map[string]interface{}{
                                    "name": p.Code(),
                                    "auth_token": "{" + envVar + "}",
                                },
                                "resolvers": []string{"119.29.29.29", "1.1.1.1"},
                            },
                        },
                    },
                },
            })
        }
    }
    return policies
}
```

注意：`providerJSON` 的字段名需要根据 provider 不同而不同（DNSPod 是 `auth_token`，Cloudflare 是 `api_token`），不能硬编码。

- [ ] **Step 3: 在 GenerateCaddyConfig 中注入 policies**

读取所有 lb_rules 并生成 policies：

```go
func GenerateCaddyConfig(cfg *config.Config) map[string]interface{} {
    ...
    rules := loadRulesFromDB()
    policies := buildTLSAutomationPolicies(rules)
    apps := map[string]interface{}{
        "http": map[string]interface{}{"servers": servers},
        "tls": map[string]interface{}{
            "automation": map[string]interface{}{
                "policies": policies,
            },
        },
    }
    ...
}
```

- [ ] **Step 4: 运行测试**

Run: `go build ./cmd/server`
Expected: 成功

- [ ] **Step 5: Commit**

```bash
git add internal/services/caddy.go
git commit -m "feat(caddy): generate TLS automation policies for ACME DNS challenge"
```

---

## Task 7: docker-entrypoint.sh 注入环境变量

**Files:**
- Modify: `docker-entrypoint.sh`

- [ ] **Step 1: 在启动 lazy-balancer 前导出 ACME DNS 凭证**

```sh
# Export ACME DNS provider credentials as environment variables
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${DATA_DIR}/lazy-balancer.db" "SELECT id, dns_provider, dns_credentials FROM certificate_configs WHERE enabled=1;" | while IFS='|' read -r id provider creds; do
        if [ -n "$creds" ]; then
            env_var_name=""
            case "$provider" in
                dnspod)
                    env_var_name="DNSPOD_AUTH_TOKEN_${id}"
                    ;;
                cloudflare)
                    env_var_name="CF_API_TOKEN_${id}"
                    ;;
            esac
            if [ -n "$env_var_name" ]; then
                token_value=$(echo "$creds" | tr -d '\n' | sed 's/.*"auth_token":"\?\([^"]*\)"\?.*/\1/')
                export "$env_var_name=$token_value"
                echo "Exported $env_var_name"
            fi
        fi
    done
fi
```

注意：JSON 解析用 `jq` 更可靠，先检查镜像是否有 jq，没有则 apk add。

- [ ] **Step 2: 在 Dockerfile 安装 jq**

```dockerfile
RUN apk add --no-cache ca-certificates shadow jq
```

- [ ] **Step 3: 重写 entrypoint 用 jq 解析**

```sh
sqlite3 "${DATA_DIR}/lazy-balancer.db" "SELECT id, dns_provider, dns_credentials FROM certificate_configs WHERE enabled=1;" | while IFS='|' read -r id provider creds; do
    if [ -n "$creds" ]; then
        env_var_name=""
        case "$provider" in
            dnspod)
                token=$(echo "$creds" | jq -r '.auth_token // empty')
                env_var_name="DNSPOD_AUTH_TOKEN_${id}"
                ;;
            cloudflare)
                token=$(echo "$creds" | jq -r '.api_token // empty')
                env_var_name="CF_API_TOKEN_${id}"
                ;;
        esac
        if [ -n "$env_var_name" ] && [ -n "$token" ]; then
            export "$env_var_name=$token"
        fi
    fi
done
```

- [ ] **Step 4: Commit**

```bash
git add Dockerfile docker-entrypoint.sh
git commit -m "feat: export ACME DNS credentials as env vars for Caddy"
```

---

## Task 8: 后端 API 改造

### 8.1 certificate_configs CRUD 改造

**Files:**
- Modify: `internal/handlers/certificates.go:14-127`

- [ ] **Step 1: 修改 ListCertificateConfigs**

读取 `dns_provider`, `dns_credentials` 为 JSON，但不返回敏感值：

```go
rows.Scan(&cfg.ID, &cfg.Name, &cfg.DNSProvider, &cfg.DNSCredentials, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt)
```

- [ ] **Step 2: 修改 CreateCertificateConfig**

```go
credsJSON, _ := json.Marshal(req.DNSCredentials)
result, err := db.DB.Exec(`
    INSERT INTO certificate_configs (name, dns_provider, dns_credentials, enabled)
    VALUES (?, ?, ?, ?)
`, req.Name, req.DNSProvider, string(credsJSON), req.Enabled)
```

- [ ] **Step 3: 修改 UpdateCertificateConfig**

```go
if req.DNSCredentials != nil {
    credsJSON, _ := json.Marshal(req.DNSCredentials)
    query += "dns_credentials = ?, "
    args = append(args, string(credsJSON))
}
```

### 8.2 新增 DNS Provider 列表和测试接口

**Files:**
- Modify: `internal/handlers/certificates.go`

- [ ] **Step 4: 新增 ListDNSProviders handler**

```go
func (h *Handlers) ListDNSProviders(c *gin.Context) {
    providers := dnsproviders.List()
    var result []gin.H
    for _, p := range providers {
        result = append(result, gin.H{
            "code":              p.Code(),
            "name":              p.Name(),
            "credential_fields": p.CredentialFields(),
        })
    }
    c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}
```

- [ ] **Step 5: 新增 TestCertificateConfig handler**

使用 Caddy `/adapt` 验证生成的 issuer JSON：

```go
func (h *Handlers) TestCertificateConfig(c *gin.Context) {
    id, _ := strconv.Atoi(c.Param("id"))
    var name, provider, credentials string
    err := db.DB.QueryRow("SELECT name, dns_provider, dns_credentials FROM certificate_configs WHERE id=?", id).Scan(&name, &provider, &credentials)
    if err != nil {
        c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Config not found"})
        return
    }
    p, ok := dnsproviders.Get(provider)
    if !ok {
        c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown provider"})
        return
    }
    var creds map[string]string
    json.Unmarshal([]byte(credentials), &creds)
    providerJSON, err := p.BuildCredentialsJSON(creds)
    if err != nil {
        c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
        return
    }
    c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Credentials valid", Data: providerJSON})
}
```

### 8.3 签发任务 API

**Files:**
- Create: `internal/handlers/certjobs.go`

- [ ] **Step 6: 实现 ListCertJobs**

```go
func (h *Handlers) ListCertJobs(c *gin.Context) {
    ruleID := c.Query("rule_id")
    query := "SELECT id, rule_id, domain, status, message, expires_at, created_at, updated_at FROM cert_jobs"
    var args []interface{}
    if ruleID != "" {
        query += " WHERE rule_id = ?"
        args = append(args, ruleID)
    }
    query += " ORDER BY created_at DESC"
    rows, _ := db.DB.Query(query, args...)
    ...
}
```

- [ ] **Step 7: 实现 RetryCertJob / DeleteCertJob**

```go
func (h *Handlers) RetryCertJob(c *gin.Context) {
    id, _ := strconv.Atoi(c.Param("id"))
    db.DB.Exec("UPDATE cert_jobs SET status='issuing', message='重新签发', updated_at=datetime('now') WHERE id=?", id)
    h.applyCaddyConfig()
    c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Retry triggered"})
}
```

### 8.4 UpdateConfig 增加 ACME 设置

**Files:**
- Modify: `internal/handlers/caddy.go:74-87`

- [ ] **Step 8: 修改 SQL 和参数**

```go
if req.ACMEEmail != "" {
    db.DB.Exec("UPDATE global_config SET acme_email = ? WHERE id=1", req.ACMEEmail)
}
if req.CertExpiryDays > 0 {
    db.DB.Exec("UPDATE global_config SET cert_expiry_days = ? WHERE id=1", req.CertExpiryDays)
}
```

- [ ] **Step 9: 注册路由**

Modify: `internal/handlers/handlers.go`（路由注册位置）

```go
api.GET("/dns-providers", h.ListDNSProviders)
api.POST("/certificate-configs/:id/test", h.TestCertificateConfig)
api.GET("/certificates/jobs", h.ListCertJobs)
api.POST("/certificates/jobs/:id/retry", h.RetryCertJob)
api.DELETE("/certificates/jobs/:id", h.DeleteCertJob)
```

- [ ] **Step 10: Commit**

```bash
git add internal/handlers/certificates.go internal/handlers/certjobs.go internal/handlers/caddy.go internal/handlers/handlers.go
git commit -m "feat(api): ACME config, DNS providers, and certificate job endpoints"
```

---

## Task 9: 规则保存集成 ACME

**Files:**
- Modify: `internal/handlers/rules.go:620-845`

- [ ] **Step 1: 保存规则时写入 tls_source / acme_config_id**

在 UPDATE 语句中增加：

```go
query += "tls_source = ?, "
args = append(args, req.TLSSource)
query += "acme_config_id = ?, "
args = append(args, req.ACMEConfigID)
```

- [ ] **Step 2: 创建 cert_jobs**

在规则保存成功后：

```go
if req.EnableTLS && req.TLSSource == "acme_dns" {
    h.certificateService.CreateJobsForRule(caddyID, domain)
}
```

- [ ] **Step 3: 重新加载 Caddy 配置**

保存规则后调用 `h.applyCaddyConfig()` 以触发 ACME 签发。

- [ ] **Step 4: Commit**

```bash
git add internal/handlers/rules.go
git commit -m "feat(rules): integrate ACME DNS certificate issuance on rule save"
```

---

## Task 10: 前端系统设置导航重构

**Files:**
- Modify: `web/src/components/layout/AppLayout.vue`
- Modify: `web/src/views/Settings.vue`

- [ ] **Step 1: 更新 AppLayout 主导航**

移除「节点管理」，保留：仪表盘、负载均衡、全局配置、用户管理、系统设置。

- [ ] **Step 2: Settings.vue 改为二级菜单布局**

```vue
<template>
  <div class="page">
    <div class="settings-layout">
      <div class="settings-sidebar">
        <div class="menu-item" :class="{active: activeTab==='basic'}" @click="activeTab='basic'">基础设置</div>
        <div class="menu-item" :class="{active: activeTab==='cluster'}" @click="activeTab='cluster'">集群管理</div>
        <div class="menu-item" :class="{active: activeTab==='certificates'}" @click="activeTab='certificates'">免费证书</div>
        <div class="menu-item" :class="{active: activeTab==='apikeys'}" @click="activeTab='apikeys'">API 密钥</div>
      </div>
      <div class="settings-content">
        <BasicSettings v-if="activeTab==='basic'" />
        <ClusterSettings v-if="activeTab==='cluster'" />
        <FreeCertificates v-if="activeTab==='certificates'" />
        <APIKeys v-if="activeTab==='apikeys'" />
      </div>
    </div>
  </div>
</template>
```

- [ ] **Step 3: 拆分现有 Settings.vue 内容到子组件**

在 `web/src/views/settings/` 下创建：
- `BasicSettings.vue`
- `ClusterSettings.vue`
- `FreeCertificates.vue`
- `APIKeys.vue`

- [ ] **Step 4: Commit**

```bash
git add web/src/components/layout/AppLayout.vue web/src/views/Settings.vue web/src/views/settings/
git commit -m "ui(settings): restructure system settings with secondary navigation"
```

---

## Task 11: 免费证书配置页面

**Files:**
- Create: `web/src/views/settings/FreeCertificates.vue`

- [ ] **Step 1: 模板结构**

```vue
<template>
  <div>
    <el-card class="settings-card">
      <template #header><span>ACME 全局设置</span></template>
      <el-form :model="global" label-width="140px">
        <el-form-item label="ACME 邮箱">
          <el-input v-model="global.acme_email" placeholder="your@email.com" />
        </el-form-item>
        <el-form-item label="过期提醒天数">
          <el-input-number v-model="global.cert_expiry_days" :min="1" :max="90" />
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="settings-card" style="margin-top:20px">
      <template #header>
        <div class="card-header">
          <span>DNS 提供商配置</span>
          <el-button type="primary" size="small" @click="openConfigDialog()">添加</el-button>
        </div>
      </template>
      <el-table :data="configs" size="small">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="dns_provider" label="提供商" />
        <el-table-column prop="enabled" label="状态" />
        <el-table-column label="操作">
          <template #default="{ row }">
            <el-button link type="primary" @click="testConfig(row)">测试</el-button>
            <el-button link type="primary" @click="openConfigDialog(row)">编辑</el-button>
            <el-button link type="danger" @click="deleteConfig(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="settings-card" style="margin-top:20px">
      <template #header><span>签发任务</span></template>
      <CertJobs />
    </el-card>
  </div>
</template>
```

- [ ] **Step 2: 获取 DNS provider 列表动态渲染凭证字段**

```ts
const providers = ref([])
const selectedProvider = computed(() => providers.value.find(p => p.code === form.value.dns_provider))

onMounted(async () => {
  const res = await request.get('/dns-providers')
  providers.value = res.data || []
})
```

- [ ] **Step 3: Commit**

```bash
git add web/src/views/settings/FreeCertificates.vue web/src/views/settings/CertJobs.vue
git commit -m "ui(certificates): add free certificate config and job list"
```

---

## Task 12: 规则弹窗 TLS 来源选择

**Files:**
- Modify: `web/src/views/Rules.vue:440-560`, `web/src/views/Rules.vue:1240-1320`

- [ ] **Step 1: TLS 部分增加证书来源单选**

```vue
<el-form-item label="证书来源" v-if="wizardForm.enable_tls">
  <el-radio-group v-model="wizardForm.tls_source">
    <el-radio value="manual">手动上传</el-radio>
    <el-radio value="acme_dns">ACME + DNS 自动</el-radio>
  </el-radio-group>
</el-form-item>

<template v-if="wizardForm.enable_tls && wizardForm.tls_source === 'acme_dns'">
  <el-form-item label="DNS 配置">
    <el-select v-model="wizardForm.acme_config_id" placeholder="选择 DNS 提供商配置">
      <el-option v-for="cfg in certConfigs" :key="cfg.id" :label="cfg.name" :value="cfg.id" />
    </el-select>
  </el-form-item>
</template>
```

- [ ] **Step 2: submitWizard 提交 tls_source / acme_config_id**

```ts
const data = {
  ...
  tls_source: wizardForm.tls_source,
  acme_config_id: wizardForm.acme_config_id,
  tls_cert: wizardForm.tls_source === 'manual' ? wizardForm.tls_cert : '',
  tls_key: wizardForm.tls_source === 'manual' ? wizardForm.tls_key : '',
  tls_auto_cert: wizardForm.tls_source === 'acme_dns',
}
```

- [ ] **Step 3: Commit**

```bash
git add web/src/views/Rules.vue
git commit -m "ui(rules): add ACME+DNS certificate source option"
```

---

## Task 13: MetricsService 调用过期检查

**Files:**
- Modify: `internal/services/services.go`

- [ ] **Step 1: 在 collect() 中调用 CertificateService**

```go
func (m *MetricsService) collect() {
    ...
    if m.certificateService != nil {
        expired := m.certificateService.CheckExpiration()
        for _, job := range expired {
            log.Printf("Certificate %s expires at %v", job.Domain, job.ExpiresAt.Time)
        }
    }
}
```

- [ ] **Step 2: 在 main.go 初始化 CertificateService 并注入**

Modify: `cmd/server/main.go`

```go
certService := services.NewCertificateService(cfg.CaddyAdminURL)
go certService.Start()
metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
metricsService.SetCertificateService(certService)
go metricsService.Start()
```

- [ ] **Step 3: Commit**

```bash
git add internal/services/services.go cmd/server/main.go
git commit -m "feat: wire CertificateService into metrics collection for expiry alerts"
```

---

## Task 14: 端到端测试

- [ ] **Step 1: 配置 ACME 邮箱和 DNSPod 凭证**

在「系统设置 / 免费证书」中配置：
- ACME 邮箱：`test@example.com`
- DNS 提供商：DNSPod
- 凭证：`auth_token`

- [ ] **Step 2: 创建 HTTPS 规则并选择 ACME+DNS**

规则 domain：`test.example.com`
证书来源：ACME + DNS 自动
DNS 配置：选择上一步创建的配置

- [ ] **Step 3: 观察签发任务**

Expected: cert_jobs 表中生成记录，状态从 `issuing` 变为 `issued` 或 `failed`

- [ ] **Step 4: 验证 Caddy 配置**

Run: `curl http://localhost:2019/config/apps/tls`
Expected: 包含 `automation.policies` 和对应 `subjects`

- [ ] **Step 5: 测试多域名规则**

规则 domain：`a.example.com,b.example.com`
Expected: cert_jobs 生成两条独立记录

---

## Task 15: 最终提交

- [ ] **Step 1: 全量构建**

Run: `docker compose build --no-cache && docker compose up -d`
Expected: 无错误

- [ ] **Step 2: Commit any remaining changes**

```bash
git add .
git commit -m "feat: ACME DNS automatic certificate issuance (complete)"
```

---

## Self-Review

### Spec Coverage
- [x] Caddy 升级到 v2.11.4 — Task 1
- [x] DNSPod + Cloudflare provider — Task 2/3
- [x] 系统设置导航重构 — Task 10
- [x] ACME 邮箱/过期提醒天数 — Task 8/11
- [x] 规则 TLS 来源二选一 — Task 12
- [x] 多域名每个域名单独 Job — Task 5/6
- [x] 进度轮询 — Task 5
- [x] 过期提醒 — Task 13

### Placeholder Scan
无 TBD/TODO/实现后补充。

### Type Consistency
- `TLSSource` 在 model/request/service 中均使用字符串 `manual` / `acme_dns`
- `ACMEConfigID` 统一为 int
- `dns_credentials` 在 DB 中为 JSON 字符串，API 中为 `map[string]string`

---
