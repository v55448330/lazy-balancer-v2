# Caddy 配置管理规范

## 核心原则

1. **验证优先**：所有配置必须先通过 Caddy API 验证，才能写入数据库
2. **数据库为源**：写入 Caddy 的配置必须从数据库重新读取，确保数据一致性
3. **原子性**：数据库和 Caddy 配置必须保持同步

## 端口检测策略

### 端口范围限制
- 端口必须在 1-65535 范围内
- 8000、2019 端口保留给 admin 接口

### 协议冲突检测
- **HTTP/HTTPS 规则**：可以与其他 HTTP/HTTPS 规则共用端口（同协议）
- **TCP 规则**：独占端口，不能与 HTTP/HTTPS 规则共用端口

```
HTTP规则A(port=80) + HTTP规则B(port=80) → 允许（同协议）
HTTP规则(port=80) + TCP规则(port=80) → 冲突（不同协议）
TCP规则(port=8080) + TCP规则(port=8080) → 允许（同一规则重复）
```

### 特殊端口处理
- 80 端口：HTTP 专用，TCP 规则不能使用
- 443 端口：HTTPS 专用，TCP 规则不能使用

### 服务器命名规则

| 协议 | 端口 | 服务器名称 |
|------|------|----------|
| http | 80 | http_80 |
| https | 443 | https_443 |
| http | 其他 | http_{port} |
| https | 其他 | https_{port} |
| tcp | 任意 | tcp_{port} |

## 规则操作流程

### CreateRule（创建规则）

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
   ├── 验证 TLSHSTS（>= 0）
   ├── 验证 HealthCheckInterval/Timeout（>= 1）
   └── 调用 ValidateRouteMergedConfig 验证合并后的完整配置

3. 写入 Caddy（Caddy 验证通过后才写数据库）
   ├── 创建服务器（如需要）CreateServerIfNotExists
   ├── 生成路由对象 GenerateRouteObject
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
   ├── 验证 TLSHSTS（>= 0）
   ├── 验证 HealthCheckInterval/Timeout（>= 1）
   └── 调用 ValidateRouteMergedConfig 验证合并后的完整配置

3. 写入数据库
   ├── 写入 lb_rules 表
   └── 写入 upstreams 表

4. 从数据库读取
   └── 重新读取刚写入的数据作为规范数据

5. 写入 Caddy
   ├── 创建服务器（如需要）CreateServerIfNotExists
   ├── 生成路由对象 GenerateRouteObject
   └── 预置路由到服务器 PrependRouteToServer（路由添加到服务器首位）

6. 验证写入结果
   └── VerifyRouteExists 确认路由已写入 Caddy

7. 返回成功响应
```

### UpdateRule（更新规则）

```
1. 请求参数验证
   ├── 端口不可更改检查
   └── validateCaddyConfigBeforeSave 统一验证

2. 获取现有规则信息
   ├── 从数据库读取 caddy_id
   └── 读取现有 protocol/domain/listen_port

3. 构建路由配置
   ├── 从请求和数据库合并完整 ruleConfig
   └── 生成路由对象 GenerateRouteObject

4. 写入 Caddy（关键：数据库更新在 Caddy 写入之后）
   ├── SetConfigByID 替换匹配 @id 的路由
   └── VerifyRouteExists 确认路由已正确替换

5. 更新数据库（Caddy 验证通过后才更新）
   ├── UPDATE lb_rules 表
   └── DELETE + INSERT upstreams 表

6. 返回成功响应
```

### EnableRule（启用规则）

```
1. 检查路由是否已存在
   └── RouteExistsInServer 检查 @id 路由是否在服务器中
   └── 如果已存在，直接更新数据库 enabled=1

2. 从数据库读取完整规则配置

3. 创建服务器
   └── CreateServerIfNotExists（如需要）

4. 生成路由对象
   └── GenerateRouteObject

5. 写入 Caddy
   ├── PrependRouteToServer 预置路由到服务器
   └── VerifyRouteExists 确认写入

6. 更新数据库
   └── enabled = 1

注意：Enable 不需要验证逻辑，因为配置未改变
```

### DisableRule（禁用规则）

```
1. 更新数据库
   └── enabled = 0

2. 写入 Caddy
   └── RemoveRouteFromServer 通过 @id 机制从服务器移除路由

注意：Disable 不需要验证逻辑
```

### DeleteRule（删除规则）

```
1. 删除关联的上游服务器
   └── DELETE FROM upstreams WHERE rule_id = ?

2. 删除关联的指标历史
   └── DELETE FROM metrics_history WHERE rule_id = ?

3. 从 Caddy 移除路由（如有必要）
   └── RemoveRouteFromServer（如果 caddy_id 存在）

4. 删除规则
   └── DELETE FROM lb_rules WHERE id = ?
```

## 系统启动流程

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

### GenerateCaddyConfig 内部流程

```
1. 从数据库读取所有 enabled=1 的规则及其上游服务器

2. 按协议和端口分组
   ├── httpServersByPort: HTTP 规则按端口分组
   └── tcpServersByPort: TCP 规则按端口分组

3. 为每个服务器生成路由
   └── 对每个规则调用 GenerateRouteObject()
   └── GenerateRouteObject 内部处理域名分割、负载策略、健康检查等

4. 组装完整配置
   └── 包含 admin、apps.http.servers 等完整结构
```

## 配置生成规则

### 域名处理
域名以逗号分隔字符串存储（如 `abc.com,def.com`），生成 Caddy 配置时必须分割为数组：

```go
domainHosts := strings.Split(rule.Domain, ",")
for i, d := range domainHosts {
    domainHosts[i] = strings.TrimSpace(d)
}
```

### 路由结构

```json
{
  "@id": "lb_xxxxxxxxxxxx",
  "match": [{
    "host": ["abc.com", "def.com"]
  }],
  "handle": [handle_chain]
}
```

### Handle Chain 顺序
1. **encode**（压缩）：如果启用压缩且有 gzip/zstd
2. **headers**（请求头）：如果设置了 HostHeader
3. **reverse_proxy**（反向代理）：主要处理逻辑

### 上游服务器配置

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

### 负载均衡策略
支持：round_robin、least_conn、random、ip_hash、weighted_random

### 健康检查

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

### TLS 配置
- 上游 HTTPS 时自动设置 `insecure_skip_verify: true`
- DNS 服务器用于动态上游解析

## Caddy @id 机制

使用 `@id` 实现精确路由管理：

- 每个规则有唯一的 `caddy_id`（13位随机字符串）
- 路由对象通过 `@id` 标识
- **更新时在原位置替换路由**（SetConfigByID）
- 启用时预置路由到服务器首位（PrependRouteToServer）
- 禁用时从服务器移除路由（RemoveRouteFromServer）

## 兜底路由

当没有匹配的规则时，返回默认响应：

```json
{
  "handler": "static_response",
  "body": "Lazy Balancer V2 is running!"
}
```

## 配置验证

使用 Caddy `/load?validate=true` 接口验证配置（不实际应用）：

```bash
POST http://localhost:2019/load?validate=true
Content-Type: application/json

<full_config_json>
```

验证成功返回 200，失败返回 4xx 并包含错误信息。

## 关键函数说明

### validateCaddyConfigBeforeSave

统一验证函数，在 Create/Update 规则时调用：

```go
func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, uniqueID string, serverName string) error
```

验证内容：
- Protocol: http/https/tcp
- ListenPort: 1-65535
- Strategy: round_robin/ip_hash/least_conn/random/first/least_time
- Domain: 格式验证（调用 isValidDomain）
- Upstreams: 至少一个、host格式（IP或域名）、端口1-65535、去重、至少一个启用
- TLSHSTS: >= 0
- HealthCheckInterval/Timeout: >= 1

> **注意**：历史字段 `TLSEmail`（规则级 ACME 邮箱验证）已废弃。ACME 邮箱现全局配置在 `global_config.acme_email`，规则级 CA 选择通过 `ca_provider_id` 指定，CA Provider 在「系统设置 / 免费证书」的 CA Providers 卡片中管理。

### ValidateRouteMergedConfig

模拟预置操作，验证合并后的完整服务器配置：

```go
func (s *CaddyService) ValidateRouteMergedConfig(serverName string, routeConfig map[string]interface{}, uniqueID string) error
```

流程：
1. 获取当前服务器配置
2. 复制配置并将新路由预置到 routes 数组首位
3. 调用 `/load?validate=true` 验证
4. 验证失败返回具体错误信息

### VerifyRouteExists

验证路由是否已成功写入 Caddy：

```go
func (s *CaddyService) VerifyRouteExists(caddyID string) error
```

流程：
1. 调用 `/config/` 获取当前完整配置
2. 遍历所有服务器的所有路由
3. 查找是否存在 @id 匹配的路由
4. 找到返回 nil，找不到返回错误

### SetConfigByID

通过 @id 替换路由配置：

```go
func (s *CaddyService) SetConfigByID(id string, config map[string]interface{}) error
```

流程：
1. 获取当前完整配置
2. 遍历所有服务器的所有路由
3. 找到 @id 匹配的路由，在原位置替换为新 config
4. 将完整配置 POST 到 `/config/`
5. 如果找不到对应 @id，返回错误

### PrependRouteToServer

将路由预置到服务器首位（用于新路由优先级高于默认站点）：

```go
func (s *CaddyService) PrependRouteToServer(serverName string, routeConfig map[string]interface{}) error
```

### CreateServerIfNotExists

创建服务器（如果不存在）：

```go
func (s *CaddyService) CreateServerIfNotExists(serverName string, listenPort int) error
```

### RouteExistsInServer

检查路由是否已存在于服务器中：

```go
func (s *CaddyService) RouteExistsInServer(serverName string, routeID string) bool
```

## 错误处理

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

## Caddy 写入时机

### CreateRule
```
验证 → Caddy 写入 → 验证 → 数据库写入 → 成功返回
                ↓ 失败
             返回错误（不写入数据库）
```

### UpdateRule
```
验证 → Caddy 写入 → 验证 → 数据库更新 → 成功返回
           ↓ 失败
        返回错误（不更新数据库）
```

### EnableRule
```
检查存在 → Caddy 写入 → 验证 → 数据库更新 → 成功返回
                ↓ 失败
             返回错误
```

### DisableRule
```
数据库更新 → Caddy 移除 → 返回
```

### DeleteRule
```
数据库删除（含 metrics_history） → Caddy 移除 → 返回
```
