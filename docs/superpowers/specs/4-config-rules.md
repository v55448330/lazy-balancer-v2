# Lazy Balancer V2 - 配置规则规范

> **已归档**：本文为历史设计文档，不代表当前实现（当前：首次访问初始化管理员、集群角色存于数据库、凭证在页面配置）。

**文档版本**: 1.0
**更新日期**: 2026-04-17
**目的**: Caddy 配置生成规范和操作流程，用于功能迭代和 Bug 修复

---

## 1. 核心原则

### 1.1 配置同步原则

1. **数据库为源**: 规则写端点先在数据库事务中完成变更，Caddy 配置只从数据库状态生成
2. **事务内生成**: 提交事务前通过 `ApplyConfigFromTx` 读取事务内可见数据并生成完整配置
3. **全量应用**: 完整配置通过 Caddy `/load` 校验并加载，不做单服务器或单路由增量写入
4. **原子性**: Caddy 应用失败则回滚事务；提交失败或后续步骤失败时恢复运行时快照并补偿

### 1.2 Caddy 写入顺序

| 操作 | 顺序 | 说明 |
|------|------|------|
| CreateRule | DB tx → full config → Caddy load → commit | 失败时回滚并恢复运行时快照 |
| UpdateRule | DB tx → full config → Caddy load → commit | 失败时回滚并恢复运行时快照 |
| EnableRule | DB tx → full config → Caddy load → commit | 后续 ACME 失败时补偿 |
| DisableRule | DB tx → full config → Caddy load → commit | 证书任务状态在同一事务更新 |
| DeleteRule | DB tx → full config → Caddy load → commit | 提交后清理运行文件 |

---

## 2. 端口检测策略

### 2.1 端口范围限制

- 端口必须在 1-65535 范围内
- 保留端口: 8000 (API), 2019 (Caddy Admin)

### 2.2 协议冲突检测

```
HTTP规则A(port=80) + HTTP规则B(port=80) → 允许（同协议共用端口）
HTTP规则(port=80) + TCP规则(port=80) → 冲突（不同协议不能共用端口）
TCP规则(port=8080) + TCP规则(port=8080) → 允许（同一端口可放多个TCP规则？）
```

### 2.3 服务器命名规则

| 协议 | 端口 | 服务器名 |
|------|------|----------|
| http | 80 | http_80 |
| https | 443 | https_443 |
| http | 其他 | http_{port} |
| https | 其他 | https_{port} |
| tcp | 任意 | tcp_{port} |

---

## 3. Caddy @id 机制

### 3.1 机制说明

使用 `@id` 实现精确路由管理：

- 每个规则有唯一的 `caddy_id`（13位随机字符串，格式 `lb_xxxxxxxxx`）
- 路由对象通过 `@id` 标识
- `@id` 用于在完整配置中稳定标识规则及关联运行数据
- 创建、更新、启用、禁用和删除均由数据库状态驱动全量配置重建
- Caddy 写入不依赖按 `@id` 操作单条路由的增量 API

### 3.2 @id 使用示例

```json
{
  "@id": "lb_abc123xyz12",
  "match": [{"host": ["example.com"]}],
  "handle": [
    {
      "handler": "encode",
      "encodings": {"gzip": {}}
    },
    {
      "handler": "reverse_proxy",
      "upstreams": [{"dial": "192.168.1.10:8080"}]
    }
  ]
}
```

---

## 4. 规则操作流程

### 4.1 CreateRule（创建规则）

```
1. 校验请求参数、端口冲突和完整规则配置
2. 开启数据库事务，写入 lb_rules、upstreams 和 path_rules
3. ApplyConfigFromTx(tx) 读取事务内状态，生成全量配置并调用 Caddy /load
4. Caddy 应用成功后提交事务
5. Caddy 应用或事务提交失败时回滚事务并恢复运行时快照
6. 提交后的 ACME 操作失败时补偿数据库、Caddy 和证书任务状态
```

### 4.2 UpdateRule（更新规则）

```
1. 校验请求参数、不可变字段和完整规则配置
2. 开启数据库事务，更新 lb_rules 并替换 upstreams、path_rules
3. ApplyConfigFromTx(tx) 读取事务内状态，生成全量配置并调用 Caddy /load
4. Caddy 应用成功后提交事务
5. Caddy 应用或事务提交失败时回滚事务并恢复运行时快照
6. 提交后的 ACME 操作失败时恢复规则、Caddy 和证书任务快照
```

### 4.3 EnableRule（启用规则）

```
1. 开启数据库事务并设置 enabled = 1
2. ApplyConfigFromTx(tx) 从事务内状态生成并加载完整 Caddy 配置
3. Caddy 应用成功后提交事务；应用或提交失败时回滚并恢复运行时快照
4. ACME 后续操作失败时恢复数据库、Caddy 和证书任务状态
```

### 4.4 DisableRule（禁用规则）

```
1. 开启数据库事务并设置 enabled = 0
2. 在同一事务中暂停关联的证书任务
3. ApplyConfigFromTx(tx) 从事务内状态生成并加载完整 Caddy 配置
4. Caddy 应用成功后提交事务；应用或提交失败时回滚并恢复运行时快照
```

### 4.5 DeleteRule（删除规则）

```
1. 开启数据库事务并删除 cert_jobs、upstreams 和 lb_rules 记录
2. ApplyConfigFromTx(tx) 从事务内状态生成不含该规则的完整 Caddy 配置并加载
3. Caddy 应用成功后提交事务；应用或提交失败时回滚并恢复运行时快照
4. 提交后清理指标历史、证书文件和规则日志文件
```

---

## 5. 系统启动流程

```
1. 等待 Caddy API 就绪
   └── 轮询 http://localhost:2019/config/ 直到返回非500状态

2. 查询启用的规则数量
   └── SELECT id FROM lb_rules WHERE enabled = 1

3. 生成完整 Caddy 配置
   └── GenerateCaddyConfig() 从数据库读取所有启用规则
   └── 内部调用 GenerateRouteObject() 生成每个路由（保证一致性）

4. 应用配置到 Caddy
   └── ApplyConfig() 将完整配置POST到 Caddy
   └── 这会替换整个 Caddy 配置

5. 添加兜底路由
   └── 如果存在 http_80 服务器，追加默认响应路由
   └── "Lazy Balancer V2 is running!"
```

---

## 6. 配置生成规则

### 6.1 域名处理

域名以逗号分隔字符串存储（如 `abc.com,def.com`），生成 Caddy 配置时必须分割为数组：

```go
domainHosts := strings.Split(rule.Domain, ",")
for i, d := range domainHosts {
    domainHosts[i] = strings.TrimSpace(d)
}
```

**结果**:
```json
{
  "match": [
    {
      "host": ["abc.com", "def.com"]
    }
  ]
}
```

### 6.2 路由结构

```json
{
  "@id": "lb_xxxxxxxxxxxx",
  "match": [{
    "host": ["abc.com", "def.com"]
  }],
  "handle": [handle_chain]
}
```

### 6.3 Handle Chain 顺序

1. **encode**（压缩）：如果启用压缩且有 gzip/zstd
2. **headers**（请求头）：如果设置了 HostHeader
3. **reverse_proxy**（反向代理）：主要处理逻辑

```go
// caddy.go:1881-1968 (approximately)
var handleChain []interface{}

// 1. 压缩
if rule.EnableCompress && rule.CompressTypes != "" {
    encodings := make(map[string]interface{})
    for _, ct := range splitAndTrim(rule.CompressTypes) {
        if ct == "gzip" || ct == "zstd" {
            encodings[ct] = map[string]interface{}{}
        }
    }
    handleChain = append(handleChain, map[string]interface{}{
        "handler":        "encode",
        "encodings":      encodings,
        "minimum_length": 512,
    })
}

// 2. Host 头
if rule.HostHeader != "" {
    handleChain = append(handleChain, map[string]interface{}{
        "handler": "headers",
        "request": map[string]interface{}{
            "set": map[string]interface{}{
                "Host": []string{rule.HostHeader},
            },
        },
    })
}

// 3. 反向代理
handleChain = append(handleChain, proxyConfig)
```

### 6.4 上游服务器配置

**静态上游（常规模式）**：
```json
{
  "dial": "192.168.1.1:8080"
}
```

**动态上游（DNS 模式）**：
```json
{
  "source": "a",
  "name": "example.com",
  "port": "443",
  "versions": {"ipv4": true, "ipv6": false}
}
```

### 6.5 负载均衡策略

**支持**: `round_robin`, `least_conn`, `random`, `ip_hash`, `weighted_random`

```go
// caddy.go:1908-1914
proxyConfig["load_balancing"] = map[string]interface{}{
    "selection_policy": map[string]interface{}{
        "policy": rule.Strategy,
    },
}
```

### 6.6 健康检查

**被动健康检查（HTTP 协议）**：
```json
{
  "passive": {
    "fail_duration": "30s",
    "max_fails": 3
  }
}
```

**主动健康检查**：
```json
{
  "active": {
    "uri": "/health",
    "timeout": "5s",
    "interval": "10s"
  }
}
```

**实现** (`caddy.go:1916-1933`):
```go
if rule.Protocol == "http" {
    healthChecks := map[string]interface{}{
        "passive": map[string]interface{}{
            "fail_duration": fmt.Sprintf("%ds", rule.HealthCheckInterval*3),
            "max_fails":     3,
        },
    }

    if rule.EnableActiveHealthCheck && rule.HealthCheckPath != "" {
        healthChecks["active"] = map[string]interface{}{
            "uri":      rule.HealthCheckPath,
            "timeout":  fmt.Sprintf("%ds", rule.HealthCheckTimeout),
            "interval": fmt.Sprintf("%ds", rule.HealthCheckInterval),
        }
    }

    proxyConfig["health_checks"] = healthChecks
}
```

### 6.7 TLS 配置

- 上游 HTTPS 时自动设置 `insecure_skip_verify: true`
- DNS 服务器用于动态上游解析

```go
// caddy.go:1935-1955
needsTransport := hasHTTPSUpstream || rule.EnableDnsServer
if needsTransport {
    transportConfig := map[string]interface{}{
        "protocol": "http",
    }
    if hasHTTPSUpstream {
        transportConfig["tls"] = map[string]interface{}{
            "insecure_skip_verify": true,
            "server_name":          rule.HostHeader,
        }
    }
    if rule.EnableDnsServer && rule.DnsServer != "" {
        transportConfig["resolver"] = map[string]interface{}{
            "addresses": []string{rule.DnsServer},
        }
        if rule.HealthCheckTimeout > 0 {
            transportConfig["dial_timeout"] = fmt.Sprintf("%ds", rule.HealthCheckTimeout)
        }
    }
    proxyConfig["transport"] = transportConfig
}
```

---

## 7. 关键函数说明

### 7.1 validateCaddyConfigBeforeSave

**位置**: `handlers.go` (约 500-600 行)

**功能**: 统一验证函数，在 Create/Update 规则时调用

```go
func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, uniqueID string, serverName string) error
```

**验证内容**:
- Protocol: http/https/tcp
- ListenPort: 1-65535
- Strategy: round_robin/ip_hash/least_conn/random/first/least_time
- Domain: 格式验证（调用 isValidDomain）
- Upstreams: 至少一个、host格式（IP或域名）、端口1-65535、去重、至少一个启用
- TLSHSTS: >= 0
- HealthCheckInterval/Timeout: >= 1

> **注意**：历史字段 `TLSEmail`（规则级 ACME 邮箱验证）已废弃。ACME 邮箱现全局配置在 `global_config.acme_email`，规则级 CA 选择通过 `ca_provider_id` 指定，CA Provider 在「系统设置 / 免费证书」的 CA Providers 卡片中管理。

### 7.2 ValidateRouteMergedConfig

**位置**: `caddy.go` (约 600-670 行)

**功能**: 模拟预置操作，验证合并后的完整服务器配置

```go
func (s *CaddyService) ValidateRouteMergedConfig(serverName string, routeConfig map[string]interface{}, uniqueID string) error
```

**流程**:
1. 获取当前服务器配置
2. 复制配置并将新路由预置到 routes 数组首位
3. 调用 `/load?validate=true` 验证
4. 验证失败返回具体错误信息

### 7.3 ApplyConfigFromTx

**功能**: 规则写端点在提交事务前，从事务内可见状态生成并加载完整配置

```go
func (s *CaddyService) ApplyConfigFromTx(tx *sql.Tx) error
```

**流程**:
1. 在 Caddy 配置写锁内读取事务中的启用规则及关联数据
2. 生成完整 Caddy 配置
3. 调用 Caddy `/load` 校验并加载完整配置
4. 失败时返回错误，由调用方回滚事务并恢复运行时快照

---

## 8. 错误处理

| 操作 | 失败处理 |
|------|---------|
| validateCaddyConfigBeforeSave | 返回 400，不写入数据库 |
| ValidateRouteMergedConfig | 返回 400，不写入数据库 |
| 事务内数据库写入 | 返回 500，回滚事务，不应用新配置 |
| ApplyConfigFromTx | 返回 400/500，回滚事务并恢复运行时快照 |
| 事务提交 | 返回 500，恢复运行时快照 |
| 提交后的 ACME 操作 | 执行数据库、Caddy 和证书任务补偿 |

---

## 9. Caddy 写入时机

### 9.1 CreateRule

```
验证 → 事务内写入 → 从 tx 生成并加载全量配置 → commit → 成功返回
                           ↓ 失败              ↓ 失败
                     rollback + 恢复运行时快照
```

### 9.2 UpdateRule

```
验证 → 事务内更新 → 从 tx 生成并加载全量配置 → commit → 成功返回
                           ↓ 失败              ↓ 失败
                     rollback + 恢复运行时快照
```

### 9.3 EnableRule

```
事务内 enabled=1 → 从 tx 生成并加载全量配置 → commit → 后续 ACME 操作
                           ↓ 失败              ↓ 失败
                     rollback + 恢复/补偿
```

### 9.4 DisableRule

```
事务内 enabled=0 → 从 tx 生成并加载全量配置 → commit → 返回
```

### 9.5 DeleteRule

```
事务内删除规则关联数据 → 从 tx 生成并加载全量配置 → commit → 清理运行文件
```

---

## 10. 相关文档

- [系统概述](./1-overview.md)
- [详细架构](./2-architecture.md)
- [API 参考](./3-api.md)
- [运维指南](./5-operations.md)
