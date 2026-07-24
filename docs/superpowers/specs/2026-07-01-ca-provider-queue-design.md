# CA Provider 配置与排队调度设计

## 背景与目标

Lazy Balancer V2 的 ACME 证书签发目前仅支持 Let's Encrypt，且使用全局 `sync.Mutex` 串行所有签发请求。当大量规则同时申请证书时，请求会阻塞在互斥锁上，表现为“卡死”；同时无法利用多 CA 分流，也缺乏按 CA 官方限制进行频率控制的能力。

本设计引入：

1. **CA Provider 配置**：支持 Let's Encrypt、ZeroSSL，允许按 provider 类型填写不同的凭证字段（EAB 等）。
2. **按 CA Provider 排队的调度器**：任务入队后异步执行，按每个 CA 的并发与间隔限制调度，不限制排队长度。
3. **全局默认 CA 选择**：用户可在「免费证书」页面选择系统默认 CA，ZeroSSL 作为安装后的默认选项。
4. **规则级 CA 选择**：每个规则可指定使用哪个 CA Provider，未指定则跟随系统默认。
5. **任务状态扩展**：新增 `queued` 状态，UI 上可明确区分“排队中”。

## 范围

包含：

- 后端：数据模型、ACME client 工厂、CA Provider 管理 API、QueueManager 调度器、规则/重试/续期流程改造。
- 前端：「免费证书」页面增加 CA Provider 配置与默认选择、规则 wizard 增加 CA Provider 选择、签发任务列表显示 `queued` 状态。
- 文档：清理历史遗留的 `tls_auto_cert` / `tls_email` 引用。
- 验证：使用真实域名完成 Let's Encrypt / ZeroSSL 端到端签发验证（单域与根域+www）。

不包含：

- 单元/集成测试代码（当前阶段不加）。
- 通过 ZeroSSL REST API 自动申请 EAB（由用户手动在 ZeroSSL 控制台生成后填写）。
- 多个 CA Provider 之间的自动故障转移。

## 数据模型

### 新增表 `ca_providers`

```sql
CREATE TABLE IF NOT EXISTS ca_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    directory_url VARCHAR(255) NOT NULL,
    -- Provider-specific credentials stored as opaque JSON.
    -- Examples:
    --   letsencrypt: {}
    --   zerossl:     {"eab_kid":"...","eab_hmac_key":"..."}
    credentials TEXT,
    max_concurrent INTEGER DEFAULT 1,
    min_interval_ms INTEGER DEFAULT 2000,
    enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);
```

字段说明：

- `provider`：固定枚举 `letsencrypt`、`zerossl`。后续新增 CA 时扩展枚举值。
- `credentials`：JSON 字符串，按 provider 类型存放不同字段，避免为每个 CA 增加独立列。
- `max_concurrent`：该 CA 同时允许执行的 `newOrder` 数量。
- `min_interval_ms`：两次 `newOrder` 之间的最小间隔（毫秒）。
- `enabled`：是否可用。禁用后，已排队任务继续完成，新任务不能再选择该 CA。

### 扩展 `global_config`

```sql
ALTER TABLE global_config ADD COLUMN default_ca_provider_id INTEGER DEFAULT 0;
```

`0` 表示未明确设置，系统取第一个启用的 CA Provider（安装后默认指向 ZeroSSL）。

### 扩展 `lb_rules`

```sql
ALTER TABLE lb_rules ADD COLUMN ca_provider_id INTEGER DEFAULT 0;
```

`0` 表示使用系统默认 CA Provider。

### 扩展 `cert_jobs`

```sql
ALTER TABLE cert_jobs ADD COLUMN ca_provider_id INTEGER DEFAULT 0;
```

记录该任务实际使用的 CA Provider，便于排查与按 CA 统计。

## 默认配置

首次初始化数据库时插入两条默认记录：

```sql
INSERT INTO ca_providers (name, provider, directory_url, credentials, max_concurrent, min_interval_ms, enabled)
VALUES
    ('ZeroSSL', 'zerossl', 'https://acme.zerossl.com/v2/DV90', '{}', 1, 10000, 1),
    ('Let''s Encrypt', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory', '{}', 2, 5000, 1);
```

并将 `global_config.default_ca_provider_id` 设置为 ZeroSSL 的 `id`。

默认限流依据：

- Let's Encrypt 官方限制：每个账户每 3 小时最多 300 次 `newOrder`。保守设置 `max_concurrent=2`、`min_interval_ms=5000`。
- ZeroSSL 官方未公开明确频率，保守设置 `max_concurrent=1`、`min_interval_ms=10000`。

## 状态流转

证书任务状态扩展为：

```
queued → creating_account → creating_order → order_created → presenting_dns
       → dns_propagated → validating → finalizing → downloading → issued
       ↘ failed（任意阶段失败）
```

- `queued`：已创建任务，等待 CA 调度器分配执行资源。
- 只有 `issued` 和 `failed` 状态允许在 UI 点击「重签」。
- 规则在存在非 `issued`/`failed` 状态的任务时禁止编辑/删除。删除规则时级联删除关联的 `cert_jobs` 与 `cert_job_logs`。`queued` 状态的任务同样禁止编辑/删除规则，需等待其变为终态或删除规则。

## 调度器设计

### 组件：`CAQueueManager`

单例，维护每个启用 CA Provider 的独立队列：

```go
type CAQueueManager struct {
    mu     sync.Mutex
    queues map[int]*caQueue // key = ca_provider_id
}

type caQueue struct {
    provider  models.CAProvider
    pending   []queueItem
    running   int
    lastOrder time.Time
    mu        sync.Mutex
    stopCh    chan struct{}
}

type queueItem struct {
    jobID       int
    ruleID      string
    domains     string
    caProvider  models.CAProvider
}
```

### 入队

规则保存/更新/手动重试/自动续期时，执行：

1. 解析该规则应使用的 CA Provider（规则指定 → 系统默认 → 第一个启用）。
2. 在 `cert_jobs` 创建/更新记录，`status='queued'`，`ca_provider_id` 写入解析结果。
3. 调用 `QueueManager.Enqueue(providerID, item)`，立即返回，不阻塞 HTTP。

### 调度循环

每个 `caQueue` 启动一个 goroutine：

```go
func (q *caQueue) loop() {
    for {
        select {
        case <-q.stopCh:
            return
        default:
        }

        q.mu.Lock()
        if q.running >= q.provider.MaxConcurrent || len(q.pending) == 0 {
            q.mu.Unlock()
            time.Sleep(1 * time.Second)
            continue
        }
        elapsed := time.Since(q.lastOrder)
        if elapsed < time.Duration(q.provider.MinIntervalMS)*time.Millisecond {
            q.mu.Unlock()
            time.Sleep(time.Duration(q.provider.MinIntervalMS)*time.Millisecond - elapsed)
            continue
        }

        item := q.pending[0]
        q.pending = q.pending[1:]
        q.running++
        q.lastOrder = time.Now()
        q.mu.Unlock()

        go q.execute(item)
    }
}
```

### 执行

```go
func (q *caQueue) execute(item queueItem) {
    defer func() {
        q.mu.Lock()
        q.running--
        q.mu.Unlock()
    }()

    issuer := NewCertIssuer(q.caddyReloader)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    if err := issuer.Issue(ctx, item.ruleID, item.domains, item.caProvider); err != nil {
        log.Printf("CA queue execution failed for rule %s: %v", item.ruleID, err)
    }
}
```

执行过程沿用现有 `CertIssuer.Issue`，但传入 CA Provider 对象以决定使用哪个 directory URL 与凭证。

### 关键保证

- 不限制排队长度：超过并发/间隔限制的任务在 `pending` 中等待。
- 不同 CA Provider 之间互不阻塞。
- 同一 CA Provider 内部按限流策略串行/限流执行。
- HTTP 响应不等待签发完成，避免前端超时。

## ACME Client 工厂

`internal/acme/client.go` 增加按 provider 创建 client：

```go
func NewClientForProvider(provider models.CAProvider, email string) (*Client, error)
```

- `letsencrypt`：
  - `DirectoryURL = provider.DirectoryURL`
  - 注册账户时仅使用 `mailto:` contact。
- `zerossl`：
  - `DirectoryURL = provider.DirectoryURL`
  - 解析 `credentials` 中的 `eab_kid` 与 `eab_hmac_key`。
  - 注册账户时传入 `ExternalAccountBinding`。
  - 缺少 EAB 时返回明确错误。

`golang.org/x/crypto/acme` 已支持 EAB：

```go
account := &acme.Account{
    Contact: []string{"mailto:" + email},
    ExternalAccountBinding: &acme.ExternalAccountBinding{
        KID: eabKID,
        Key: []byte(eabHMACKey),
    },
}
```

## API 设计

### CA Provider 管理

CA Provider 仅内置两条记录（Let's Encrypt、ZeroSSL），不支持新增或删除，只允许修改配置与启用/禁用。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/ca-providers` | 列表 |
| PUT | `/api/ca-providers/:id` | 更新配置 |
| POST | `/api/ca-providers/:id/test` | 测试 EAB/Directory 是否可用 |

请求体示例：

```json
{
  "name": "ZeroSSL 主账户",
  "provider": "zerossl",
  "directory_url": "https://acme.zerossl.com/v2/DV90",
  "credentials": {
    "eab_kid": "kid-xxx",
    "eab_hmac_key": "hmac-yyy"
  },
  "max_concurrent": 1,
  "min_interval_ms": 10000,
  "enabled": true
}
```

### 全局默认 CA

通过现有「免费证书」保存接口扩展：

```json
{
  "acme_email": "admin@example.com",
  "cert_expiry_days": 30,
  "default_ca_provider_id": 1
}
```

### 规则级 CA 选择

`CreateRuleRequest` / `UpdateRuleRequest` 增加：

```go
CAProviderID int `json:"ca_provider_id"`
```

## 前端设计

### 「免费证书」页面

在现有「ACME 全局设置」与「DNS 提供商配置」之间新增「CA 提供商」卡片：

- 表格列：名称、类型、并发、间隔、状态、操作。
- 操作：编辑、测试（无新增/删除）。
- ACME 全局设置表单底部增加「默认 CA 提供商」下拉框。

弹窗表单字段：

- 名称
- 类型（只读，Let's Encrypt / ZeroSSL）
- Directory URL（按类型默认填充，可手动修改）
- 凭证字段（按类型动态显示）：
  - ZeroSSL：EAB KID、EAB HMAC Key
  - Let's Encrypt：无额外字段
- 最大并发
- 最小间隔（毫秒）
- 启用 switch

### 规则 Wizard TLS 步骤

在「DNS 提供商」选择下方增加「CA 提供商」选择：

- 选项包含「系统默认」+ 所有启用的 CA Provider。
- 默认选中「系统默认」。

### 签发任务列表

- 状态列新增 `queued` →「排队中」。
- 「重签」按钮仅在 `issued` / `failed` 时启用。

## 改造流程

### 规则创建/更新

1. 事务保存规则，`ca_provider_id` 写入规则表。
2. 若 `tls_source == 'acme_dns'` 且域名有效：
   - 解析实际 CA Provider。
   - 创建/重置 `cert_jobs`，`status='queued'`，`ca_provider_id` 写入。
   - 调用 `QueueManager.Enqueue(...)`。
3. 立即返回响应，不等待签发。

### 手动重试

1. 校验任务状态为 `issued` 或 `failed`。
2. 重置任务为 `queued`，`ca_provider_id` 保持原值（或重新解析规则当前指定）。
3. 入队。

### 自动续期

`CertificateService.renewExpiringCertificates` 不再直接 `go issuer.Issue(...)`，而是重置任务为 `queued` 并入队。

## 错误处理

- 无法解析 CA Provider（未启用、不存在）：任务直接标记为 `failed`，并写入日志。
- CA 注册/订单失败：由 `CertIssuer.Issue` 捕获，标记 `failed`，写入日志。
- 调度器自身 panic：单个任务 panic 不应影响队列循环，需 recover 并标记任务失败。

## 合并的遗留任务

| 遗留问题 | 处理方式 |
|---------|---------|
| 端到端 ACME 签发未验证 | 实现后使用真实域名分别验证 ZeroSSL / Let's Encrypt，单域与根域+www |
| `docs/` 中残留 `tls_auto_cert` / `TLSEmail` | 实现后统一清理或标注为历史字段 |
| 重签后卡在 creating_order | 通过调度器 + 详细日志 + failJob 落库解决，不再阻塞 UI；失败会明确显示 |
| 全局锁导致大量规则卡死 | 替换为按 CA Provider 排队调度，HTTP 立即返回，任务按限流执行 |

## 风险与回退

- **ZeroSSL EAB 凭证错误**：注册失败，任务标记 `failed`，日志明确提示。
- **CA Provider 被禁用**：已排队任务继续执行；新规则/重试若指向被禁用的 CA，解析时自动回退到系统默认的启用 CA，若系统默认也被禁用则标记失败。
- **调度器重启**：进程重启后，`cert_jobs` 中处于 `queued`/`creating_*` 等非终态的任务需要重新入队。启动时扫描 `status NOT IN ('issued','failed')` 的任务并重新入队。
- **并发调度器实现 bug**：保留现有全局 mutex 作为兜底方案的成本较高，新实现需仔细处理并发与 recover。

## 默认行为变更

- 新安装默认使用 ZeroSSL。
- 现有升级用户：数据库迁移后自动插入 ZeroSSL / Let's Encrypt 默认记录，并将全局默认设为 ZeroSSL。已有规则的 `ca_provider_id=0`，表示跟随系统默认。
- 原有全局 `sync.Mutex` 移除。

## 待决策确认项

1. 是否在首期支持「取消排队」功能？—— 不支持；删除规则时级联删除关联任务。
2. 是否允许删除被规则引用的 CA Provider？—— CA Provider 不提供删除功能，仅支持编辑配置与启用/禁用。
3. 任务执行超时是否可配置？—— 保持 10 分钟固定超时。
4. CA Provider 数量是否受限？—— 仅内置 Let's Encrypt 与 ZeroSSL 两种，用户只能修改其配置，不能新增或删除。

## 附录：EAB 说明

EAB（External Account Binding）是 ACME 协议扩展，用于把 ACME 账户与 CA 的现有账户绑定。ZeroSSL 要求新 ACME 账户必须提供 EAB，否则注册失败。

用户操作流程：

1. 登录 ZeroSSL 控制台 → Developer → EAB Credentials。
2. 生成一组 `eab_kid` 与 `eab_hmac_key`。
3. 在 Lazy Balancer「CA 提供商」页面添加 ZeroSSL，填入上述两项。
4. Lazy Balancer 注册 ACME 账户时自动携带 EAB。
