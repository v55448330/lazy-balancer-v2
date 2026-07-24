# CA 频率限制与重试策略设计

**Date:** 2026-07-02

## 背景

当前 `CAQueueManager` 已支持按 CA 提供商配置 `max_concurrent` 和 `min_interval_ms`，可在单实例主节点上控制 ACME `newOrder` 的并发和间隔。但以下场景仍可能导致证书签发失败：

- CA 返回 429（Rate Limited）时，当前实现直接标记任务失败，不会等待冷却。
- 重试次数固定为 3 次，且不可由用户配置。
- 重试间隔固定为 1 小时，没有按失败次数递增。
- 任务列表无法区分"普通失败"和"等待 CA 冷却"。

本设计在不引入分布式协调的前提下，增加 CA 频率限制感知、冷却等待状态和可配置重试策略。

## 目标

1. 当 CA 返回 429 时，读取 `Retry-After` 并按提供商默认值等待冷却。
2. 为 429 场景新增 `waiting_ca` 任务状态，UI 可显示剩余冷却时间。
3. 将最大重试次数放入 ACME 全局配置，默认 5 次，范围 1-10。
4. 重试间隔按次数递增：1h / 2h / 3h / 3h / 3h（第 4、5 次保持 3h）。
5. 每次失败（包括 429 冷却等待）都计入 `renewal_attempts`。
6. 当 `renewal_attempts >= cert_renewal_attempts` 时停止自动重试；若最后状态是 `waiting_ca`，自动转为 `failed`。
7. 续签扫描时同时检查 `failed` 和 `waiting_ca`，满足间隔且 `ca_available_after` 已过后重新入队。

## 非目标

- 不实现分布式限流（当前单主节点执行证书任务）。
- 不按账户维护 `newOrder` 计数器。
- 不处理除 429 以外的 CA 特定错误码退避。

## 数据模型变更

### `global_config` 表

新增字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `cert_renewal_attempts` | INTEGER | 5 | 最大自动重试次数，范围 1-10 |

### `cert_jobs` 表

新增字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `ca_available_after` | DATETIME | NULL | CA 可再次尝试的时间 |
| `last_error_code` | VARCHAR(20) | NULL | 最后错误码，如 `429` |

## 状态流转

```
queued -> processing
  -> issued
  -> waiting_ca (429)
       -> queued (冷却结束且未达最大重试次数)
       -> failed (达到最大重试次数)
  -> failed (其他错误)
       -> queued (续签周期到达且未达最大重试次数)
```

## 冷却时间计算

### 429 场景

1. 解析 ACME 响应中的 `Retry-After` header。
2. 若存在且为数字，视为秒数；若为 HTTP-date，解析为时间。
3. 若不存在，使用提供商默认值：
   - Let's Encrypt：1 小时
   - ZeroSSL：30 分钟
4. 计算 `ca_available_after = now + max(Retry-After, 按次数递增间隔)`。

### 非 429 场景

使用按 `renewal_attempts` 递增的间隔：

| renewal_attempts | 间隔 |
|------------------|------|
| 1 | 1 小时 |
| 2 | 2 小时 |
| 3 | 3 小时 |
| 4 | 3 小时 |
| 5 | 3 小时 |
| >5 | 3 小时 |

## 重试条件

续签扫描 `CheckExpiration` 查询满足以下条件的任务：

- `expires_at <= now + cert_renewal_days`
- 状态为 `issued`、`failed` 或 `waiting_ca`
- `renewal_attempts < cert_renewal_attempts`
- `ca_available_after IS NULL OR ca_available_after <= now`

对于 `waiting_ca` 且 `renewal_attempts >= cert_renewal_attempts` 的任务：
- 自动更新为 `failed`，message 为"已达到最大重试次数，请检查 CA 配置后手动重签"。

## UI 变更

### ACME 全局设置

- 新增「最大续签重试次数」输入框，范围 1-10，默认 5。
- 任务列表状态列增加 `waiting_ca` 显示："等待 CA 冷却"。
- 任务列表新增「冷却时间」列，显示 `ca_available_after` 的格式化时间或剩余时间。

## 接口变更

### `GET /api/config`

响应增加：

```json
{
  "cert_renewal_attempts": 5
}
```

### `PUT /api/config`

请求增加：

```json
{
  "cert_renewal_attempts": 5
}
```

校验：1-10 的整数。

### `GET /api/certificates/jobs`

响应增加：

```json
{
  "ca_available_after": "2026-07-02T10:00:00Z",
  "last_error_code": "429",
  "renewal_attempts": 2
}
```

## 错误处理

- `Retry-After` 解析失败时，记录 warning 日志并使用默认值。
- 无法识别的 CA 提供商使用默认冷却 1 小时。
- 达到最大重试次数的任务不再自动入队，避免无限循环。

## 测试建议

- 单元测试 `computeBackoff` 函数：验证不同 `renewal_attempts` 和 429 返回值。
- 手动测试：配置极低 `min_interval_ms` 触发 429，观察任务进入 `waiting_ca` 并在冷却后重新入队。

## 相关文件

- `internal/services/caqueue.go`
- `internal/services/certificates.go`
- `internal/services/certissuer.go`
- `internal/handlers/caddy.go`
- `internal/handlers/certjobs.go`
- `internal/db/db.go`
- `internal/models/models.go`
- `web/src/views/settings/FreeCertificates.vue`
- `web/src/views/settings/CertJobs.vue`
- `web/src/views/Settings.vue`
