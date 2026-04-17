# Lazy Balancer V2 - 配置规则规范

**文档版本**: 1.0
**更新日期**: 2026-04-17
**目的**: Caddy 配置生成规范和操作流程，用于功能迭代和 Bug 修复

---

## 1. 核心原则

### 1.1 配置同步原则

1. **验证优先**: 所有配置必须先通过 Caddy API 验证，才能写入数据库
2. **数据库为源**: 写入 Caddy 的配置必须从数据库重新读取，确保数据一致性
3. **原子性**: 数据库和 Caddy 配置必须保持同步

### 1.2 Caddy 写入顺序

| 操作 | 顺序 | 说明 |
|------|------|------|
| CreateRule | Caddy → 数据库 | Caddy 验证失败不写数据库 |
| UpdateRule | Caddy → 数据库 | Caddy 写入失败不更新数据库 |
| EnableRule | Caddy → 数据库 | - |
| DisableRule | 数据库 → Caddy | - |
| DeleteRule | 数据库 → Caddy | - |

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
- **更新时在原位置替换路由**（SetConfigByID）
- **启用时预置路由到服务器首位**（PrependRouteToServer）
- **禁用时从服务器移除路由**（RemoveRouteFromServer）

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
1. 请求参数验证
   ├── 必填字段检查（name, protocol, port, upstreams）
   ├── 端口冲突检查（validatePort）
   └── 设置默认值（strategy, health_check_interval 等）

2. 统一验证 validateCaddyConfigBeforeSave
   ├── 验证 Protocol（http/https/tcp）
   ├── 验证 ListenPort（1-65535）
   ├── 验证 Strategy（round_robin/ip_hash/least_conn/random/first/least_time）
   ├── 验证 Domain（格式验证）
   ├── 验证 Upstreams（至少一个、host格式、端口、去重、至少一个启用）
   ├── 验证 TLSEmail（必须包含 @）
   ├── 验证 TLSHSTS（>= 0）
   ├── 验证 HealthCheckInterval/Timeout（>= 1）
   └── 调用 ValidateRouteMergedConfig 验证合并后的完整配置

3. 写入 Caddy（Caddy 验证通过后才写数据库）
   ├── 创建服务器（如需要）CreateServerIfNotExists
   ├── 生成路由对象 GenerateSingleRuleCaddyConfig
   ├── 预置路由到服务器 PrependRouteToServer（路由添加到服务器首位）
   └── VerifyRouteExists 确认路由已写入 Caddy

4. 验证失败处理
   └── 如果 Caddy 验证失败，返回错误，不写入数据库

5. 写入数据库（Caddy 验证通过后才写入）
   ├── 写入 lb_rules 表
   └── 写入 upstreams 表

6. 数据库写入失败处理
   └── 如果数据库写入失败，回滚 Caddy（RemoveRouteFromServer）

7. 返回成功响应
```

### 4.2 UpdateRule（更新规则）

```
1. 请求参数验证
   ├── 端口不可更改检查
   └── validateCaddyConfigBeforeSave 统一验证

2. 获取现有规则信息
   ├── 从数据库读取 caddy_id
   └── 读取现有 protocol/domain/listen_port

3. 构建路由配置
   ├── 从请求和数据库合并完整 ruleConfig
   └── 生成路由对象 GenerateSingleRuleCaddyConfig

4. 写入 Caddy（关键：数据库更新在 Caddy 写入之后）
   ├── SetConfigByID 替换匹配 @id 的路由
   └── VerifyRouteExists 确认路由已正确替换

5. 更新数据库（Caddy 验证通过后才更新）
   ├── UPDATE lb_rules 表
   └── DELETE + INSERT upstreams 表

6. 返回成功响应
```

### 4.3 EnableRule（启用规则）

```
1. 检查路由是否已存在
   └── RouteExistsInServer 检查 @id 路由是否在服务器中
   └── 如果已存在，直接更新数据库 enabled=1

2. 从数据库读取完整规则配置

3. 创建服务器
   └── CreateServerIfNotExists（如需要）

4. 生成路由对象
   └── GenerateSingleRuleCaddyConfig

5. 写入 Caddy
   ├── PrependRouteToServer 预置路由到服务器
   └── VerifyRouteExists 确认写入

6. 更新数据库
   └── enabled = 1

注意：Enable 不需要验证逻辑，因为配置未改变
```

### 4.4 DisableRule（禁用规则）

```
1. 更新数据库
   └── enabled = 0

2. 写入 Caddy
   └── RemoveRouteFromServer 通过 @id 机制从服务器移除路由

注意：Disable 不需要验证逻辑
```

### 4.5 DeleteRule（删除规则）

```
1. 删除关联的上游服务器
   └── DELETE FROM upstreams WHERE rule_id = ?

2. 删除关联的指标历史
   └── DELETE FROM metrics_history WHERE rule_id = ?

3. 从 Caddy 移除路由（如有必要）
   └── RemoveRouteFromServer（如果 caddy_id 存在）

4. 删除规则
   └── DELETE FROM lb_rules WHERE caddy_id = ?
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
- TLSEmail: 必须包含 @
- TLSHSTS: >= 0
- HealthCheckInterval/Timeout: >= 1

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

### 7.3 VerifyRouteExists

**位置**: `caddy.go` (约 758-850 行)

**功能**: 验证路由是否已成功写入 Caddy

```go
func (s *CaddyService) VerifyRouteExists(caddyID string) error
```

**流程**:
1. 调用 `/config/` 获取当前完整配置
2. 遍历所有服务器的所有路由
3. 查找是否存在 @id 匹配的路由
4. 找到返回 nil，找不到返回错误

### 7.4 SetConfigByID

**位置**: `caddy.go` (约 374-450 行)

**功能**: 通过 @id 替换路由配置

```go
func (s *CaddyService) SetConfigByID(id string, config map[string]interface{}) error
```

**流程**:
1. 获取当前完整配置
2. 遍历所有服务器的所有路由
3. 找到 @id 匹配的路由，在原位置替换为新 config
4. 将完整配置 POST 到 `/config/`
5. 如果找不到对应 @id，返回错误

### 7.5 PrependRouteToServer

**位置**: `caddy.go` (约 674-730 行)

**功能**: 将路由预置到服务器首位（用于新路由优先级高于默认站点）

```go
func (s *CaddyService) PrependRouteToServer(serverName string, routeConfig map[string]interface{}) error
```

### 7.6 CreateServerIfNotExists

**位置**: `caddy.go` (约 550-600 行)

**功能**: 创建服务器（如果不存在）

```go
func (s *CaddyService) CreateServerIfNotExists(serverName string, listenPort int) error
```

### 7.7 RouteExistsInServer

**位置**: `caddy.go` (约 700-750 行)

**功能**: 检查路由是否已存在于服务器中

```go
func (s *CaddyService) RouteExistsInServer(serverName string, routeID string) bool
```

---

## 8. 错误处理

| 操作 | 失败处理 |
|------|---------|
| validateCaddyConfigBeforeSave | 返回 400，不写入数据库 |
| ValidateRouteMergedConfig | 返回 400，不写入数据库 |
| CreateServerIfNotExists | 返回 400，不写入数据库 |
| PrependRouteToServer | 返回 400，不写入数据库 |
| VerifyRouteExists | 返回 500，**回滚 Caddy 路由**，返回错误 |
| SetConfigByID | 返回 500，不更新数据库 |
| 数据库写入（Create） | 返回 500，**回滚 Caddy 路由** |
| 数据库更新（Update） | 返回 500，不更新 Caddy |
| RemoveRouteFromServer | 错误仅记录，不影响主流程 |
| DisableRule/DeleteRule | 错误仅记录，不影响主流程 |

---

## 9. Caddy 写入时机

### 9.1 CreateRule

```
验证 → Caddy 写入 → 验证 → 数据库写入 → 成功返回
                ↓ 失败
             返回错误（不写入数据库）
```

### 9.2 UpdateRule

```
验证 → Caddy 写入 → 验证 → 数据库更新 → 成功返回
           ↓ 失败
        返回错误（不更新数据库）
```

### 9.3 EnableRule

```
检查存在 → Caddy 写入 → 验证 → 数据库更新 → 成功返回
                ↓ 失败
             返回错误
```

### 9.4 DisableRule

```
数据库更新 → Caddy 移除 → 返回
```

### 9.5 DeleteRule

```
数据库删除（含 metrics_history） → Caddy 移除 → 返回
```

---

## 10. 相关文档

- [系统概述](./1-overview.md)
- [详细架构](./2-architecture.md)
- [API 参考](./3-api.md)
- [运维指南](./5-operations.md)