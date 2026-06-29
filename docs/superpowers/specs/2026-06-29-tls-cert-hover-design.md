# TLS 证书详情 Hover 设计

**生成日期**: 2026-06-29
**范围**: 规则列表 TLS 标签 Hover 展示证书详情（后端独立接口 + 前端 Popover）

## 背景

当前规则列表的 TLS 列仅显示“自动/手动/禁用”标签，Hover 提示也只显示固定文本。用户希望在启用 HTTPS 后，Hover TLS 标签能展示证书的真实信息：域名、颁发者、生效时间、过期时间、剩余天数、状态。

## 设计原则

1. **数据必须由后端提供**：不依赖前端推导或解析，保证准确性。
2. **独立查询接口**：不在 ListRules / GetRule 中内联，避免列表查询变重。
3. **支持批量查询**：规则列表一次性拉取所有规则证书信息，减少请求数。
4. **统一数据源**：
   - 手动上传证书：解析 `lb_rules.tls_cert` PEM。
   - ACME 自动证书：解析 `cert_jobs.cert_pem` PEM。
5. **状态阈值使用系统设置**：从 `global_config.cert_expiry_days` 读取，不使用硬编码。

## 数据模型

### 后端响应结构

```go
type RuleCertInfo struct {
    CaddyID       string `json:"caddy_id"`
    Source        string `json:"source"`         // "manual" | "acme_dns"
    Domains       string `json:"domains"`        // 规则域名或证书域名（逗号分隔）
    Issuer        string `json:"issuer"`         // 颁发者 Common Name / Organization
    NotBefore     string `json:"not_before"`     // 生效时间，RFC3339 或 YYYY-MM-DD HH:mm:ss
    NotAfter      string `json:"not_after"`      // 过期时间
    DaysRemaining int    `json:"days_remaining"` // 剩余天数（已过期为负数）
    Status        string `json:"status"`         // "valid" | "expiring" | "expired" | "unknown"
    Error         string `json:"error,omitempty"` // 解析失败时的原因
}
```

### 状态判定

- `unknown`: 证书 PEM 为空或解析失败。
- `expired`: `NotAfter` 在当前时间之前。
- `expiring`: `NotAfter` 在未来，且剩余天数 ≤ `global_config.cert_expiry_days`。
- `valid`: 剩余天数 > 阈值。

## API 接口

### 1. 查询单条规则证书信息

```
GET /api/rules/:caddy_id/cert-info
```

响应：

```json
{
  "code": 0,
  "message": "",
  "data": {
    "caddy_id": "lb_xxx",
    "source": "manual",
    "domains": "test.local",
    "issuer": "CN=test.local",
    "not_before": "2026-06-29 08:00:00",
    "not_after": "2026-06-30 08:00:00",
    "days_remaining": 1,
    "status": "expiring"
  }
}
```

### 2. 批量查询规则证书信息

```
POST /api/rules/cert-info
Content-Type: application/json

{
  "caddy_ids": ["lb_xxx", "lb_yyy"]
}
```

响应：

```json
{
  "code": 0,
  "message": "",
  "data": {
    "lb_xxx": {
      "caddy_id": "lb_xxx",
      "source": "manual",
      "domains": "test.local",
      "issuer": "CN=test.local",
      "not_before": "2026-06-29 08:00:00",
      "not_after": "2026-06-30 08:00:00",
      "days_remaining": 1,
      "status": "expiring"
    },
    "lb_yyy": null
  }
}
```

未启用 TLS 或证书不可用的规则返回 `null`。

## 后端实现

### 新增文件

- `internal/handlers/certs.go`：证书信息查询处理器（可选，保持 handlers 拆分）或放在 `internal/handlers/rules.go`。
- `internal/services/certinfo.go`：证书解析服务，包含：
  - `ParseCertInfo(certPEM string, source string, domains string) (*models.RuleCertInfo, error)`
  - `GetRuleCertInfo(caddyID string) *models.RuleCertInfo`
  - `GetRulesCertInfo(caddyIDs []string) map[string]*models.RuleCertInfo`
  - `GetCertExpiryThreshold() int`

### 解析逻辑

1. 根据 `caddy_id` 读取规则：
   - `enable_tls == false`：返回 `nil`。
   - `tls_source == "manual"`：使用 `lb_rules.tls_cert`。
   - `tls_source == "acme_dns"`：查询 `cert_jobs`，取该 `rule_id` 对应 `status = 'issued'` 且 `cert_pem != ''` 的记录；若存在多个域名，按域名分别解析。
2. 解析 PEM → `x509.Certificate`。
3. 提取：
   - `Domains`: 优先使用证书 `DNSNames`，否则 `Subject.CommonName`。
   - `Issuer`: `Issuer.CommonName` 或 `Issuer.Organization[0]`。
   - `NotBefore` / `NotAfter`。
   - `DaysRemaining` = `int(NotAfter.Sub(now).Hours() / 24)`。
4. 与阈值比较得到 `Status`。

### 路由注册

在 `internal/middleware/middleware.go` 的认证路由下增加：

```go
api.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
api.POST("/rules/cert-info", h.GetRulesCertInfo)
```

## 前端实现

### 状态管理

在 `Rules.vue` 中新增：

```ts
const certInfoMap = ref<Record<string, RuleCertInfo | null>>({})
```

### 批量加载

`fetchRules` 成功后，如果规则中存在 `enable_tls` 的规则，调用批量接口：

```ts
const tlsRules = rules.value.filter(r => r.enable_tls)
if (tlsRules.length > 0) {
  const res = await request.post('/rules/cert-info', {
    caddy_ids: tlsRules.map(r => r.caddy_id)
  })
  certInfoMap.value = res.data || {}
}
```

### TLS 列展示

将 `Rules.vue` 中 TLS 列的 `el-tooltip` 替换为 `el-popover`：

```vue
<el-popover
  v-if="row.enable_tls"
  placement="top"
  trigger="hover"
  :width="280"
  :disabled="!certInfoMap[row.caddy_id]"
>
  <template #reference>
    <el-tag type="success" size="small" effect="plain">
      {{ row.tls_auto_cert ? '自动' : '手动' }}
    </el-tag>
  </template>
  <div class="cert-tooltip">
    <div class="tooltip-title">证书信息</div>
    <div class="cert-row">
      <span class="cert-label">来源</span>
      <el-tag size="small" :type="certInfoMap[row.caddy_id]?.source === 'manual' ? 'primary' : 'success'">
        {{ certInfoMap[row.caddy_id]?.source === 'manual' ? '手动上传' : "ACME 自动" }}
      </el-tag>
    </div>
    <div class="cert-row"><span class="cert-label">域名</span><span>{{ certInfoMap[row.caddy_id]?.domains || '-' }}</span></div>
    <div class="cert-row"><span class="cert-label">颁发者</span><span>{{ certInfoMap[row.caddy_id]?.issuer || '-' }}</span></div>
    <div class="cert-row"><span class="cert-label">生效时间</span><span>{{ certInfoMap[row.caddy_id]?.not_before || '-' }}</span></div>
    <div class="cert-row"><span class="cert-label">过期时间</span><span>{{ certInfoMap[row.caddy_id]?.not_after || '-' }}</span></div>
    <div class="cert-row">
      <span class="cert-label">剩余天数</span>
      <span :class="['cert-days', certInfoMap[row.caddy_id]?.status]">
        {{ certInfoMap[row.caddy_id]?.days_remaining }} 天
      </span>
    </div>
    <div class="cert-row" v-if="certInfoMap[row.caddy_id]?.error">
      <span class="cert-label">错误</span>
      <span class="cert-error">{{ certInfoMap[row.caddy_id]?.error }}</span>
    </div>
  </div>
</el-popover>
```

### 样式

新增 Tailwind / 自定义样式：

```css
.cert-tooltip .tooltip-title {
  font-weight: 600;
  margin-bottom: 8px;
  border-bottom: 1px solid #e5e7eb;
  padding-bottom: 6px;
}
.cert-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
  font-size: 13px;
}
.cert-label {
  color: #6b7280;
}
.cert-days.valid { color: #10b981; }
.cert-days.expiring { color: #f59e0b; font-weight: 600; }
.cert-days.expired { color: #ef4444; font-weight: 600; }
.cert-days.unknown { color: #9ca3af; }
.cert-error { color: #ef4444; }
```

## 错误处理

- 证书 PEM 为空：返回 `status: "unknown"`，`error: "证书不存在"`。
- PEM 解析失败：返回 `status: "unknown"`，`error` 包含具体错误。
- ACME 证书未签发：返回 `status: "unknown"`，`error: "ACME 证书尚未签发"`。
- 读取阈值失败：使用默认值 `30` 天并记录日志。

## 依赖与边界

- 依赖现有 `lb_rules` 和 `cert_jobs` 表结构。
- 不修改现有规则创建/更新流程。
- 前端保持对旧数据的兼容：当 `certInfoMap` 中无某条规则数据时，只显示 TLS 标签，不展示 Popover。

## 验收标准

1. 后端新增两个接口并能正确返回手动/ACME 证书信息。
2. 状态阈值从 `global_config.cert_expiry_days` 读取。
3. 规则列表启用 HTTPS 后，Hover TLS 标签展示：来源、域名、颁发者、生效时间、过期时间、剩余天数、状态颜色。
4. ACME 已签发证书也能展示完整信息。
5. 证书解析失败时显示友好错误提示。
6. `go test ./... && go vet ./...` 通过，前端构建无 TypeScript 错误。
