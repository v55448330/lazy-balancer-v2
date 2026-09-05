# Caddy 配置管理规范

## 核心原则

1. **数据库为源**：规则写端点先在数据库事务中完成变更，Caddy 配置只从数据库状态生成
2. **事务内生成**：提交事务前通过 `ApplyConfigFromTx` 读取事务内可见数据并生成完整配置
3. **全量应用**：完整配置通过 Caddy `/load` 校验并加载，不再对单个服务器或路由做增量写入
4. **原子性**：Caddy 应用失败则回滚事务；事务提交失败或后续步骤失败时恢复运行时快照并执行补偿

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
1. 校验请求参数、端口冲突和完整规则配置
2. 开启数据库事务，写入 lb_rules、upstreams 和 path_rules
3. ApplyConfigFromTx(tx) 读取事务内状态，生成全量配置并调用 Caddy /load
4. Caddy 应用成功后提交事务
5. Caddy 应用或事务提交失败时回滚事务并恢复运行时快照
6. 提交后的 ACME 操作失败时补偿数据库、Caddy 和证书任务状态
```

### UpdateRule（更新规则）

```
1. 校验请求参数、不可变字段和完整规则配置
2. 开启数据库事务，更新 lb_rules 并替换 upstreams、path_rules
3. ApplyConfigFromTx(tx) 读取事务内状态，生成全量配置并调用 Caddy /load
4. Caddy 应用成功后提交事务
5. Caddy 应用或事务提交失败时回滚事务并恢复运行时快照
6. 提交后的 ACME 操作失败时恢复规则、Caddy 和证书任务快照
```

### EnableRule（启用规则）

```
1. 开启数据库事务并设置 enabled = 1
2. ApplyConfigFromTx(tx) 从事务内状态生成并加载完整 Caddy 配置
3. Caddy 应用成功后提交事务；应用或提交失败时回滚并恢复运行时快照
4. ACME 后续操作失败时恢复数据库、Caddy 和证书任务状态
```

### DisableRule（禁用规则）

```
1. 开启数据库事务并设置 enabled = 0
2. 在同一事务中暂停关联的证书任务
3. ApplyConfigFromTx(tx) 从事务内状态生成并加载完整 Caddy 配置
4. Caddy 应用成功后提交事务；应用或提交失败时回滚并恢复运行时快照
```

### DeleteRule（删除规则）

```
1. 开启数据库事务并删除 cert_jobs、upstreams 和 lb_rules 记录
2. ApplyConfigFromTx(tx) 从事务内状态生成不含该规则的完整 Caddy 配置并加载
3. Caddy 应用成功后提交事务；应用或提交失败时回滚并恢复运行时快照
4. 提交后清理指标历史、证书文件和规则日志文件
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
1. **headers**（X-LB-Rule-ID 注入）：HTTP 规则绑定安全策略时链首注入归因头（供预检与 coraza 事务消费，reverse_proxy 前无条件剥离，不直达上游）
2. **IP 预检**：多策略绑定时合并全部绑定策略 deny 侧 IP 控制的极简 coraza 预检查器（先于全部 rate_limit/waf）
3. **rate_limit / waf**：按绑定策略 policy_id ASC 依次编入各策略的处理器组（限流先于 WAF）
4. **request_body**：配置了请求体上限时
5. **encode**（压缩）：如果启用压缩且有 gzip/zstd
6. **headers**（Server 头隐藏）：server_tokens_hidden 时 deferred 删除 Server 响应头（须推迟到上游响应写入之后）
7. **reverse_proxy**（反向代理）：主要处理逻辑；HostHeader 折入 reverse_proxy 的 request.headers（set Host），不再单独发射 headers 处理器

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
- `@id` 用于在完整配置中稳定标识规则及关联运行数据
- 创建、更新、启用、禁用和删除均由数据库状态驱动全量配置重建
- Caddy 写入不依赖按 `@id` 操作单条路由的增量 API

## 兜底路由

当没有匹配的规则时，返回默认响应：

```json
{
  "handler": "static_response",
  "body": "Lazy Balancer V2 is running!"
}
```

## 配置验证

Caddy admin `/load?validate=true` 并非只读校验——Caddy v2.11.4 的 handleLoad 无视 validate 参数、无条件执行 caddy.Load，请求成功即真实加载：

```bash
POST http://localhost:2019/load?validate=true
Content-Type: application/json

<full_config_json>
```

成功返回 200，失败返回 4xx 并包含错误信息，但请求体在成功后已成为运行配置。代码侧以清理/快照补偿该副作用：`ValidateConfig` 携带证书文件快照时验证后恢复快照；`ValidateRouteMergedConfig`/`ValidateTCPServerMergedConfig` 将候选路由/server 并入运行配置的副本后校验，避免运行面被单规则/单 server 配置整体替换。

## 关键函数说明

### validateCaddyConfigBeforeSave

统一验证函数，在 Create/Update 规则时调用：

```go
func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, features ruleFeatureInput, uniqueID string, serverName string) error
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
func (s *CaddyService) ValidateRouteMergedConfig(serverName string, routeConfig map[string]interface{}) error
```

流程：
1. 获取当前服务器配置
2. 复制配置并将新路由追加到非兜底路由末尾（识别并保留兜底路由在最后）
3. 调用 `/load?validate=true` 验证（validate 参数被 Caddy 忽略，实为真实加载；对副本操作以隔离运行面）
4. 验证失败返回具体错误信息

### ApplyConfigFromTx

规则写端点在提交事务前，从事务内可见状态生成并加载完整配置：

```go
func (s *CaddyService) ApplyConfigFromTx(tx *sql.Tx) error
```

流程：
1. 在 Caddy 配置写锁内读取事务中的启用规则及关联数据
2. 生成完整 Caddy 配置
3. 调用 Caddy `/load` 校验并加载完整配置
4. 失败时返回错误，由调用方回滚事务并恢复运行时快照

## 错误处理

| 操作 | 失败处理 |
|------|---------|
| validateCaddyConfigBeforeSave | 返回 400，不写入数据库 |
| ValidateRouteMergedConfig | 返回 400，不写入数据库 |
| 事务内数据库写入 | 返回 500，回滚事务，不应用新配置 |
| ApplyConfigFromTx | 返回 400/500，回滚事务并恢复运行时快照 |
| 事务提交 | 返回 500，恢复运行时快照 |
| 提交后的 ACME 操作 | 执行数据库、Caddy 和证书任务补偿 |

## Caddy 写入时机

### CreateRule
```
验证 → 事务内写入 → 从 tx 生成并加载全量配置 → commit → 成功返回
                           ↓ 失败              ↓ 失败
                     rollback + 恢复运行时快照
```

### UpdateRule
```
验证 → 事务内更新 → 从 tx 生成并加载全量配置 → commit → 成功返回
                           ↓ 失败              ↓ 失败
                     rollback + 恢复运行时快照
```

### EnableRule
```
事务内 enabled=1 → 从 tx 生成并加载全量配置 → commit → 后续 ACME 操作
                           ↓ 失败              ↓ 失败
                     rollback + 恢复/补偿
```

### DisableRule
```
事务内 enabled=0 → 从 tx 生成并加载全量配置 → commit → 返回
```

### DeleteRule
```
事务内删除规则关联数据 → 从 tx 生成并加载全量配置 → commit → 清理运行文件
```
