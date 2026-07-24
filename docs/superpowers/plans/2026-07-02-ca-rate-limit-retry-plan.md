# CA 频率限制与重试策略 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 ACME 证书任务增加 CA 429 频率限制感知、冷却等待状态、可配置最大重试次数和递增重试间隔。

**Architecture:** 在 `CAQueueManager` 中捕获 429 并计算冷却时间；在 `cert_jobs` 中新增 `ca_available_after` 和 `last_error_code`；续签扫描时统一处理 `failed` 和 `waiting_ca`；前端展示新增状态和冷却时间。

**Tech Stack:** Go 1.26, Gin, SQLite, Vue 3 + TypeScript + Element Plus

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/db/db.go` | 新增 `cert_renewal_attempts`、`ca_available_after`、`last_error_code` 表字段及迁移 |
| `internal/models/models.go` | 更新 `GlobalConfig`、`UpdateConfigRequest`、`CertJob` 结构体 |
| `internal/handlers/caddy.go` | 读取/保存 `cert_renewal_attempts`，校验范围 |
| `internal/handlers/certjobs.go` | 返回 `ca_available_after`、`last_error_code` |
| `internal/services/certissuer.go` | ACME 失败时区分 429 与其他错误，计算冷却时间 |
| `internal/services/caqueue.go` | 根据错误类型更新任务状态为 `failed` 或 `waiting_ca` |
| `internal/services/certificates.go` | 续签扫描统一处理 `failed`/`waiting_ca`，达到最大次数转失败 |
| `web/src/views/Settings.vue` | 加载/保存 `cert_renewal_attempts` |
| `web/src/views/settings/FreeCertificates.vue` | 新增「最大续签重试次数」输入 |
| `web/src/views/settings/CertJobs.vue` | 显示 `waiting_ca` 状态、冷却时间 |

---

### Task 1: Schema and model updates

**Files:**
- Modify: `internal/db/db.go`
- Modify: `internal/models/models.go`
- Test: `go build ./...` and `go vet ./...`

- [ ] **Step 1: Add `cert_renewal_attempts` to `global_config` schema and migration**

In `internal/db/db.go`, add `cert_renewal_attempts INTEGER DEFAULT 5` to the `global_config` CREATE TABLE and add a migration:

```go
DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='cert_renewal_attempts'").Scan(&colCount)
if colCount == 0 {
    DB.Exec("ALTER TABLE global_config ADD COLUMN cert_renewal_attempts INTEGER DEFAULT 5")
}
```

- [ ] **Step 2: Add `ca_available_after` and `last_error_code` to `cert_jobs` schema and migration**

In `internal/db/db.go`, update `cert_jobs` CREATE TABLE:

```go
-- Certificate Jobs table for ACME issuance tracking
CREATE TABLE IF NOT EXISTS cert_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id VARCHAR(20) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    message TEXT,
    expires_at DATETIME,
    cert_pem TEXT,
    key_pem TEXT,
    ca_provider_id INTEGER DEFAULT 0,
    renewal_attempts INTEGER DEFAULT 0,
    ca_available_after DATETIME,
    last_error_code VARCHAR(20),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);
```

Add migration in `newColumns`:

```go
"cert_jobs.ca_available_after": "DATETIME",
"cert_jobs.last_error_code":    "VARCHAR(20)",
"global_config.cert_renewal_attempts": "INTEGER DEFAULT 5",
```

- [ ] **Step 3: Update Go models**

In `internal/models/models.go`:

```go
type GlobalConfig struct {
    // ... existing fields ...
    CertRenewalAttempts int `json:"cert_renewal_attempts"`
}

type UpdateConfigRequest struct {
    // ... existing fields ...
    CertRenewalAttempts int `json:"cert_renewal_attempts"`
}

type CertJob struct {
    // ... existing fields ...
    RenewalAttempts  int          `json:"renewal_attempts,omitempty"`
    CAAvailableAfter sql.NullTime `json:"ca_available_after,omitempty"`
    LastErrorCode    string       `json:"last_error_code,omitempty"`
}
```

- [ ] **Step 4: Build and vet**

Run: `gofmt -w internal/db/db.go internal/models/models.go && go build ./... && go vet ./...`
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add internal/db/db.go internal/models/models.go
git commit -m "feat(db): add cert_renewal_attempts, ca_available_after, last_error_code"
```

---

### Task 2: Backend error classification and backoff computation

**Files:**
- Modify: `internal/services/certissuer.go`
- Modify: `internal/services/caqueue.go`
- Test: `go build ./...` and `go vet ./...`

- [ ] **Step 1: Define 429-aware error type**

In `internal/services/certissuer.go`:

```go
// CAProviderRateLimitError indicates the CA rejected the request with 429.
type CAProviderRateLimitError struct {
    RetryAfter time.Duration
    Reason     string
}

func (e *CAProviderRateLimitError) Error() string {
    return fmt.Sprintf("CA rate limited (429), retry after %v: %s", e.RetryAfter, e.Reason)
}
```

- [ ] **Step 2: Add helper to extract Retry-After**

In `internal/services/certissuer.go`:

```go
func parseRetryAfter(header string) time.Duration {
    if header == "" {
        return 0
    }
    // Try seconds first
    if seconds, err := strconv.Atoi(header); err == nil {
        return time.Duration(seconds) * time.Second
    }
    // Try HTTP-date
    if t, err := http.ParseTime(header); err == nil {
        if d := time.Until(t); d > 0 {
            return d
        }
    }
    return 0
}

func defaultRetryAfter(provider string) time.Duration {
    switch provider {
    case ProviderZeroSSL:
        return 30 * time.Minute
    case ProviderLetsEncrypt:
        return time.Hour
    default:
        return time.Hour
    }
}
```

Add imports: `net/http`, `strconv`, `time` if not present.

- [ ] **Step 3: Add helper to compute retry backoff**

In `internal/services/certissuer.go`:

```go
func computeBackoff(attempts int, retryAfter time.Duration) time.Duration {
    var base time.Duration
    switch attempts {
    case 1:
        base = time.Hour
    case 2:
        base = 2 * time.Hour
    default:
        base = 3 * time.Hour
    }
    if retryAfter > base {
        return retryAfter
    }
    return base
}
```

- [ ] **Step 4: Update `Issue` to classify 429 errors**

In `internal/services/certissuer.go`, wrap ACME calls and detect 429:

```go
// Wrap the issuer.Issue call
certPEM, keyPEM, err := issuer.Issue(ctx, domainList)
if err != nil {
    if raErr := detectRateLimit(err, provider.Provider); raErr != nil {
        failJob(jobID, raErr.Error())
        // update is done by caller queue
        return raErr
    }
    failJob(jobID, err.Error())
    return err
}
```

Add `detectRateLimit`:

```go
func detectRateLimit(err error, providerType string) *CAProviderRateLimitError {
    if err == nil {
        return nil
    }
    // Check if error contains 429 or rate limit keywords
    msg := strings.ToLower(err.Error())
    if !strings.Contains(msg, "429") && !strings.Contains(msg, "rate limit") && !strings.Contains(msg, "too many") {
        return nil
    }
    retryAfter := defaultRetryAfter(providerType)
    return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
}
```

Note: ACME library may wrap HTTP errors; adjust detection based on actual error messages.

- [ ] **Step 5: Update `execute` in queue to set status based on error type**

In `internal/services/caqueue.go`:

```go
if err := issuer.Issue(ctx, item.jobID, item.ruleID, item.domains, q.provider); err != nil {
    log.Printf("CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
    if !isTerminalJobStatus(item.jobID) {
        var raErr *CAProviderRateLimitError
        if errors.As(err, &raErr) {
            markJobWaitingCA(item.jobID, raErr.RetryAfter)
        } else {
            failJob(item.jobID, fmt.Sprintf("CA 签发失败: %v", err))
        }
    }
}
```

Add import `errors` if missing.

- [ ] **Step 6: Implement `markJobWaitingCA`**

In `internal/services/caqueue.go`:

```go
func markJobWaitingCA(jobID int, retryAfter time.Duration) {
    available := time.Now().Add(retryAfter).UTC()
    if _, err := db.DB.Exec(
        "INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'warning', ?)",
        jobID, fmt.Sprintf("CA 频率限制，将在 %s 后重试", available.Format(time.RFC3339)),
    ); err != nil {
        log.Printf("CA queue: failed to insert waiting log for job %d: %v", jobID, err)
    }
    if _, err := db.DB.Exec(
        "UPDATE cert_jobs SET status='waiting_ca', message='等待 CA 频率限制冷却', ca_available_after=?, last_error_code='429', renewal_attempts = COALESCE(renewal_attempts,0) + 1, updated_at=datetime('now') WHERE id=?",
        available, jobID,
    ); err != nil {
        log.Printf("CA queue: failed to mark job %d as waiting_ca: %v", jobID, err)
    }
}
```

- [ ] **Step 7: Build and vet**

Run: `gofmt -w internal/services/certissuer.go internal/services/caqueue.go && go build ./... && go vet ./...`
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add internal/services/certissuer.go internal/services/caqueue.go
git commit -m "feat(queue): classify 429 errors and mark jobs as waiting_ca"
```

---

### Task 3: Renewal scan handles waiting_ca and retry limits

**Files:**
- Modify: `internal/services/certificates.go`
- Modify: `internal/services/certinfo.go` (helper for max attempts)
- Test: `go build ./...` and `go vet ./...`

- [ ] **Step 1: Add helper to read max retry attempts**

In `internal/services/certinfo.go`:

```go
// GetCertRenewalAttempts returns the configured max renewal attempts.
func GetCertRenewalAttempts() int {
    var attempts int
    err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_attempts, 5) FROM global_config WHERE id = 1").Scan(&attempts)
    if err != nil {
        log.Printf("GetCertRenewalAttempts: failed to read global_config, using default 5: %v", err)
        return 5
    }
    if attempts <= 0 {
        return 5
    }
    return attempts
}
```

- [ ] **Step 2: Update `renewExpiringCertificates` to handle waiting_ca and limits**

In `internal/services/certificates.go`:

```go
func (s *CertificateService) renewExpiringCertificates() {
    s.mu.Lock()
    defer s.mu.Unlock()

    maxAttempts := GetCertRenewalAttempts()
    jobs := s.CheckExpiration()
    if len(jobs) == 0 {
        return
    }

    for _, j := range jobs {
        if j.RenewalAttempts >= maxAttempts {
            if j.Status == "waiting_ca" {
                if _, err := db.DB.Exec(
                    "UPDATE cert_jobs SET status='failed', message='已达到最大重试次数，请检查 CA 配置后手动重签', updated_at=datetime('now') WHERE id=?",
                    j.ID,
                ); err != nil {
                    log.Printf("Renewal: failed to convert waiting_ca job %d to failed: %v", j.ID, err)
                }
            }
            continue
        }

        res, err := db.DB.Exec(
            "UPDATE cert_jobs SET status='queued', message='等待排队续期', updated_at=datetime('now') WHERE id=? AND status IN ('issued','failed','waiting_ca') AND (ca_available_after IS NULL OR ca_available_after <= datetime('now'))",
            j.ID,
        )
        if err != nil {
            log.Printf("Renewal: failed to update job %d status: %v", j.ID, err)
            continue
        }
        if rows, _ := res.RowsAffected(); rows == 0 {
            continue
        }
        qm := GetCAQueueManager(s.caddyReloader)
        if err := qm.Enqueue(0, j.ID, j.RuleID, j.Domain); err != nil {
            log.Printf("Renewal: failed to enqueue job %d: %v", j.ID, err)
        }
    }
}
```

- [ ] **Step 3: Update `CheckExpiration` query**

In `internal/services/certificates.go`:

```go
func (s *CertificateService) CheckExpiration() []models.CertJob {
    s.mu.Lock()
    defer s.mu.Unlock()

    var days int
    err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&days)
    if err != nil {
        days = 30
    }
    if days <= 0 {
        days = 30
    }

    rows, err := db.DB.Query(`
        SELECT id, rule_id, domain, status, expires_at, ca_provider_id, COALESCE(renewal_attempts,0) as renewal_attempts, ca_available_after, last_error_code
        FROM cert_jobs
        WHERE expires_at IS NOT NULL
          AND expires_at <= datetime('now', '+' || ? || ' days')
          AND status IN ('issued', 'failed', 'waiting_ca')
        ORDER BY expires_at ASC
    `, days)
    if err != nil {
        log.Printf("Failed to query expiring certificates: %v", err)
        return nil
    }
    defer rows.Close()

    var jobs []models.CertJob
    for rows.Next() {
        var j models.CertJob
        if err := rows.Scan(
            &j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt, &j.CAProviderID, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode,
        ); err != nil {
            continue
        }
        jobs = append(jobs, j)
    }
    return jobs
}
```

- [ ] **Step 4: Reset ca_available_after on successful issue**

In `internal/services/certissuer.go`, success update already resets `renewal_attempts=0`. Also clear `ca_available_after` and `last_error_code`:

```go
_, err = db.DB.Exec(
    "UPDATE cert_jobs SET status='issued', message='签发成功', cert_pem=?, key_pem=?, expires_at=?, ca_provider_id=?, renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?",
    certPEM, keyPEM, notAfter, provider.ID, jobID,
)
```

- [ ] **Step 5: Build and vet**

Run: `gofmt -w internal/services/certificates.go internal/services/certinfo.go internal/services/certissuer.go && go build ./... && go vet ./...`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add internal/services/certificates.go internal/services/certinfo.go internal/services/certissuer.go
git commit -m "feat(renewal): handle waiting_ca and configurable retry limits"
```

---

### Task 4: Backend config and job list APIs

**Files:**
- Modify: `internal/handlers/caddy.go`
- Modify: `internal/handlers/certjobs.go`
- Test: `go build ./...` and `go vet ./...`

- [ ] **Step 1: Update `GetConfig` to return `cert_renewal_attempts`**

In `internal/handlers/caddy.go`, add `COALESCE(cert_renewal_attempts,5) as cert_renewal_attempts` to SELECT and `&cfg.CertRenewalAttempts` to Scan.

- [ ] **Step 2: Update `UpdateConfig` to validate and save `cert_renewal_attempts`**

In `internal/handlers/caddy.go`:

```go
if req.CertRenewalAttempts < 1 || req.CertRenewalAttempts > 10 {
    c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "cert_renewal_attempts must be between 1 and 10"})
    return
}
```

Add `cert_renewal_attempts = COALESCE(?, cert_renewal_attempts),` to UPDATE and include `req.CertRenewalAttempts` in args.

- [ ] **Step 3: Update `ListCertJobs` to return new fields**

In `internal/handlers/certjobs.go`, update SELECT and Scan to include `ca_available_after` and `last_error_code`.

- [ ] **Step 4: Build and vet**

Run: `gofmt -w internal/handlers/caddy.go internal/handlers/certjobs.go && go build ./... && go vet ./...`
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add internal/handlers/caddy.go internal/handlers/certjobs.go
git commit -m "feat(api): expose cert_renewal_attempts and job cooling fields"
```

---

### Task 5: Frontend ACME settings

**Files:**
- Modify: `web/src/views/Settings.vue`
- Modify: `web/src/views/settings/FreeCertificates.vue`
- Test: `npm run build`

- [ ] **Step 1: Update `Settings.vue` model and fetch**

```typescript
const global = ref<any>({
  acme_email: '',
  cert_expiry_days: 30,
  cert_renewal_days: 30,
  cert_renewal_attempts: 5,
  default_ca_provider_id: 0,
  dns_provider: 'dnspod',
})
```

In `fetchSettings`:

```typescript
cert_renewal_attempts: res.data.cert_renewal_attempts ?? 5,
```

- [ ] **Step 2: Add input in `FreeCertificates.vue`**

Add after「自动续签时间」：

```vue
<el-form-item label="最大续签重试次数">
  <el-input-number v-model="global.cert_renewal_attempts" :min="1" :max="10" />
  <div class="form-tip">证书续签失败（包括 CA 频率限制）后的最大自动重试次数</div>
</el-form-item>
```

- [ ] **Step 3: Update save payload**

In `handleSave`:

```typescript
await emit('save', {
  acme_email: global.value.acme_email,
  cert_expiry_days: global.value.cert_expiry_days,
  cert_renewal_days: global.value.cert_renewal_days,
  cert_renewal_attempts: global.value.cert_renewal_attempts,
  default_ca_provider_id: global.value.default_ca_provider_id,
  dns_provider: global.value.dns_provider || 'dnspod',
})
```

- [ ] **Step 4: Build frontend**

Run: `cd web && npm run build`
Expected: builds successfully

- [ ] **Step 5: Commit**

```bash
git add web/src/views/Settings.vue web/src/views/settings/FreeCertificates.vue
git commit -m "feat(ui): add cert_renewal_attempts to ACME settings"
```

---

### Task 6: Frontend CertJobs list enhancements

**Files:**
- Modify: `web/src/views/settings/CertJobs.vue`
- Test: `npm run build`

- [ ] **Step 1: Update `CertJob` interface**

```typescript
interface CertJob {
  id: number
  rule_id: string
  domain: string
  status: CertJobStatus | 'waiting_ca'
  message: string
  expires_at?: string
  updated_at?: string
  cert_pem?: string
  renewal_attempts?: number
  ca_available_after?: string
  last_error_code?: string
}
```

- [ ] **Step 2: Add `waiting_ca` to status display**

Update `statusType`:

```typescript
case 'waiting_ca': return 'warning'
```

Update `statusLabel`:

```typescript
case 'waiting_ca': return '等待 CA 冷却'
```

- [ ] **Step 3: Add cooling time column**

Add before「剩余天数」：

```vue
<el-table-column label="冷却时间" min-width="140" show-overflow-tooltip>
  <template #default="{ row }">
    <span v-if="row.status === 'waiting_ca' && row.ca_available_after" class="cell-text">{{ formatCoolingTime(row.ca_available_after) }}</span>
    <span v-else class="cell-empty">-</span>
  </template>
</el-table-column>
```

Add helper:

```typescript
const formatCoolingTime = (iso: string): string => {
  const t = new Date(iso)
  const now = new Date()
  const diff = t.getTime() - now.getTime()
  if (diff <= 0) return '可重试'
  const hours = Math.floor(diff / (1000 * 60 * 60))
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
  return `${hours}小时${minutes}分钟后`
}
```

- [ ] **Step 4: Build frontend**

Run: `cd web && npm run build`
Expected: builds successfully

- [ ] **Step 5: Commit**

```bash
git add web/src/views/settings/CertJobs.vue
git commit -m "feat(ui): show waiting_ca status and cooling time"
```

---

### Task 7: Integration and deployment

**Files:**
- All modified files
- Docker build

- [ ] **Step 1: Full build verification**

Run:
```bash
go build ./... && go vet ./...
cd web && npm run build
```
Expected: both pass

- [ ] **Step 2: Deploy container**

Run: `docker compose up -d --build --force-recreate`
Expected: container rebuilt and started

- [ ] **Step 3: Verify runtime**

Run: `docker compose ps && docker compose logs --tail 10 lazy-balancer`
Expected: container running, no startup errors

- [ ] **Step 4: Commit design/plan docs**

```bash
git add docs/superpowers/specs/2026-07-02-ca-rate-limit-retry-design.md
git add docs/superpowers/plans/2026-07-02-ca-rate-limit-retry-plan.md
git commit -m "docs: add CA rate limit retry design and plan"
```

---

## Self-Review

1. **Spec coverage:** 所有设计点（429 检测、waiting_ca 状态、可配置重试次数、递增间隔、终止处理、UI 展示）均有对应任务。
2. **Placeholder scan:** 无 TBD/TODO/待实现。
3. **Type consistency:** `cert_renewal_attempts`、`ca_available_after`、`last_error_code` 在模型、数据库、API、UI 中命名一致。
4. **Scope:** 聚焦单实例主节点，未引入分布式协调，符合要求。

## Execution Choice

Plan complete and saved to `docs/superpowers/plans/2026-07-02-ca-rate-limit-retry-plan.md`.

Two execution options:

1. **Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration
2. **Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
