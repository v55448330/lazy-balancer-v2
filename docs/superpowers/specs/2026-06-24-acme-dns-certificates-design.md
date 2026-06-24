# ACME DNS 自动证书签发设计文档

**日期:** 2026-06-24  
**范围:** Caddy 升级、免费证书配置、ACME DNS 挑战、证书签发任务追踪、系统设置导航重构  
**状态:** 待实现

---

## 1. 背景与目标

### 1.1 当前状态
- Caddy 当前版本为 `v2.11.2`，项目需要升级到最新版 `v2.11.4`
- 系统设置页面已有「免费证书配置」UI 和 `certificate_configs` 表，但尚未把配置注入 Caddy
- 规则 TLS 目前只支持「手动上传证书」和「自动证书（tls_auto_cert）」，后者依赖 Caddy 内置 HTTP 挑战
- 缺少 ACME + DNS 挑战的自动签发能力
- 缺少签发进度追踪和证书过期时间展示

### 1.2 目标
- 升级 Caddy 到 v2.11.4
- 在系统设置中提供完整的免费证书配置：ACME 邮箱、过期提醒天数、DNS 提供商配置
- 允许规则在开启 TLS 时选择「ACME + DNS 自动签发」作为证书来源
- 支持多域名规则中每个域名单独追踪签发状态和过期时间
- 提供签发任务列表和进度展示
- 重构系统设置页面导航

---

## 2. 导航结构

### 2.1 主导航（左侧一级菜单）
- 仪表盘
- 负载均衡
- 全局配置
- 用户管理
- 系统设置（展开二级菜单）

### 2.2 系统设置二级菜单
- 基础设置（日志级别、访问日志）
- 集群管理（原节点管理，含主从配置）
- 免费证书（ACME 配置 + DNS 提供商 + 签发任务）
- API 密钥

---

## 3. Caddy 升级

### 3.1 Dockerfile 修改
```dockerfile
RUN xcaddy build v2.11.4 \
  --with github.com/caddy-dns/dnspod \
  --with github.com/caddy-dns/cloudflare
```

### 3.2 验证
- 升级后全量功能回归测试：HTTP/HTTPS 反向代理、动态上游、手动 TLS、TCP 规则
- 确认 Caddy admin API 行为未变

---

## 4. 数据模型

### 4.1 `global_config` 表扩展
新增/复用以下字段，用于存储 ACME 全局设置：

| 字段 | 类型 | 说明 |
|------|------|------|
| `acme_email` | TEXT | ACME 注册邮箱 |
| `cert_expiry_days` | INTEGER | 过期前提醒天数，默认 30 |

### 4.2 `certificate_configs` 表改造
保留现有表，字段改造为统一 JSON 凭证：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER PK | |
| `name` | TEXT | 配置名称 |
| `dns_provider` | TEXT | 提供商代码：`dnspod` / `cloudflare` |
| `dns_credentials` | TEXT | JSON 凭证，结构因 provider 而异 |
| `enabled` | BOOLEAN | 是否启用 |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |

**凭证 JSON 示例：**
- DNSPod: `{ "auth_token": "xxx" }`
- Cloudflare: `{ "api_token": "xxx" }`

### 4.3 `lb_rules` 表扩展
增加 TLS 来源字段，替代原有 `tls_auto_cert` 布尔值语义：

| 字段 | 类型 | 说明 |
|------|------|------|
| `tls_source` | TEXT | `manual` / `acme_dns` |
| `acme_config_id` | INTEGER FK | 引用的 certificate_configs.id |

保留 `tls_cert`, `tls_key` 用于手动模式。

### 4.4 `cert_jobs` 新建表
用于追踪每个域名的签发状态：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER PK | |
| `rule_id` | TEXT | 规则 caddy_id |
| `domain` | TEXT | 待签发域名 |
| `status` | TEXT | `pending` / `issuing` / `issued` / `failed` |
| `message` | TEXT | 进度信息或错误信息 |
| `expires_at` | DATETIME | 过期时间 |
| `cert_pem` | TEXT | 证书 PEM（可选，用于展示） |
| `key_pem` | TEXT | 私钥 PEM（可选） |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |

---

## 5. DNS 提供商架构

### 5.1 Provider 注册表
后端维护一个 provider 注册表，定义每个 provider 的：
- 代码名
- 显示名
- Caddy 模块名
- 凭证字段列表
- Caddy JSON 生成函数

```go
type DNSProvider interface {
    Code() string
    Name() string
    ModuleName() string
    CredentialFields() []CredentialField
    BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error)
}
```

### 5.2 新增 Provider 步骤
1. Dockerfile 添加 `--with github.com/caddy-dns/xxx`
2. 在 `internal/services/dnsproviders` 注册新的 provider 实现
3. 前端 provider 下拉选项增加对应项（由后端 `/dns-providers` 接口驱动）

---

## 6. Caddy 配置生成

### 6.1 手动证书
保持现有 `apps.tls.certificates.load_pem` 方式不变。

### 6.2 ACME + DNS 自动证书
在生成全局 Caddy 配置时，为每个启用了 `acme_dns` 的规则域名添加 TLS automation policy：

```json
{
  "apps": {
    "tls": {
      "automation": {
        "policies": [
          {
            "subjects": ["example.com"],
            "issuers": [
              {
                "module": "acme",
                "email": "user@email.com",
                "challenges": {
                  "dns": {
                    "provider": {
                      "name": "dnspod",
                      "auth_token": "{env.DNSPOD_AUTH_TOKEN_1}"
                    },
                    "resolvers": ["119.29.29.29"]
                  }
                }
              }
            ]
          }
        ]
      }
    }
  }
}
```

### 6.3 凭证注入
- 每个启用的 `certificate_configs` 记录映射为一个环境变量
- 在 `docker-entrypoint.sh` 中读取数据库并导出：
  - `DNSPOD_AUTH_TOKEN_1=xxx`
  - `CF_API_TOKEN_2=xxx`
- Caddy JSON 中引用对应环境变量，避免明文存储

### 6.4 多域名规则
规则 domain 按逗号拆分为多个域名，每个域名单独生成 automation policy 和 cert_job 记录。

---

## 7. 证书签发流程

### 7.1 触发时机
- 创建/更新规则并启用 `acme_dns` 时
- 保存后后端调用 `caddyService.ApplyConfig(fullConfig)`
- 同时为每个域名单独创建 `cert_jobs` 记录，状态 `issuing`

### 7.2 状态轮询
后端定时任务（可复用 MetricsService 的 ticker 或新增 CertificateService）：
1. 查询 Caddy `/pki/ca/local` 或证书存储目录
2. 匹配 `cert_jobs` 中的域名
3. 更新状态：
   - 找到证书 → `issued`，更新 `expires_at`
   - 超过超时阈值未找到 → `failed`，记录错误

### 7.3 前端轮询
前端 `/api/certificates/jobs?rule_id=xxx` 接口，每 5 秒轮询一次，展示进度。

---

## 8. 过期提醒

- 根据 `global_config.cert_expiry_days` 配置
- 后端每日检查 `cert_jobs.expires_at`
- 在证书过期前指定天数，在 Dashboard 或任务列表显示警告
- 支持手动重新签发/自动续期（Caddy 本身会自动续期，前端展示续期状态）

---

## 9. 前端改动

### 9.1 系统设置 / 免费证书页面
- ACME 邮箱输入框（必填）
- 过期提醒天数输入框（数字，默认 30）
- DNS 提供商配置列表
  - 添加/编辑弹窗：provider 下拉、动态凭证字段、启用开关、测试按钮
- 签发任务列表
  - 域名、所属规则、状态、过期时间、操作（查看日志/重试/删除）

### 9.2 规则弹窗 TLS 部分
- 证书来源二选一：
  - 手动上传
  - ACME + DNS 自动
- 选择 ACME + DNS 时：
  - 显示已启用的 DNS 提供商配置下拉
  - 显示待签发域名列表

### 9.3 全局配置页面
保持现有 Caddy 配置预览，增加 TLS automation policies 展示。

---

## 10. API 接口

### 10.1 DNS 提供商
- `GET /api/dns-providers` — 列出支持的 provider 及其凭证字段
- `POST /api/certificate-configs/:id/test` — 测试 DNS 凭证

### 10.2 免费证书配置
- `GET /api/certificate-configs` — 列表
- `POST /api/certificate-configs` — 创建
- `PUT /api/certificate-configs/:id` — 更新
- `DELETE /api/certificate-configs/:id` — 删除

### 10.3 签发任务
- `GET /api/certificates/jobs?rule_id=xxx` — 查询任务列表
- `POST /api/certificates/jobs/:id/retry` — 重试失败任务
- `DELETE /api/certificates/jobs/:id` — 删除任务

### 10.4 全局 ACME 设置
- `GET /api/config` — 返回包含 `acme_email`, `cert_expiry_days`
- `PUT /api/config` — 保存包含 ACME 设置

### 10.5 规则
- `POST /api/rules` 和 `PUT /api/rules/:caddy_id` 增加 `tls_source` 和 `acme_config_id` 字段

---

## 11. 错误处理

- DNS 凭证测试失败：返回具体错误信息
- ACME 签发失败：更新 `cert_jobs.status = failed`，`message` 记录 Caddy 返回的错误
- Caddy 配置应用失败：回滚到上一个有效配置

---

## 12. 安全考虑

- DNS 凭证以环境变量方式注入 Caddy，不写入 JSON 配置
- 数据库中 DNS 凭证可加密存储（MVP 可先明文，后续迭代加密）
- 私钥不返回给前端，仅在后端和 Caddy 之间传递

---

## 13. 实现阶段

### 阶段 1: 基础能力
- Caddy 升级到 v2.11.4
- 编译 DNSPod、Cloudflare 插件
- 改造 `certificate_configs` 表和 model
- 后端 provider 注册表
- ACME 全局设置接口

### 阶段 2: 规则集成
- `lb_rules` 增加 `tls_source` / `acme_config_id`
- Caddy 配置生成 automation policies
- docker-entrypoint.sh 注入环境变量
- 规则保存时创建 cert_jobs

### 阶段 3: 任务追踪与前端
- cert_jobs 轮询更新
- 前端签发任务页面
- 规则弹窗证书来源选择
- 过期提醒

### 阶段 4: 导航重构
- 系统设置改为二级菜单
- 集群管理移入系统设置
- 免费证书页面整合签发任务

---

## 14. 待确认事项

无。

---

## 15. 附录: Caddy ACME DNS 配置参考

```json
{
  "module": "acme",
  "email": "user@example.com",
  "challenges": {
    "dns": {
      "provider": {
        "name": "dnspod",
        "auth_token": "{env.DNSPOD_AUTH_TOKEN}"
      }
    }
  }
}
```

---
