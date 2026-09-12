# Caddy 配置与规则管理

> 机制现状(2026-09-12 同步,SR11-F4):Caddy 层校验走 `caddy validate` CLI
> (真 validate-only)+ 事务内 `ApplyConfigFromTx` 终门;字段级校验
> (`validateRulePayloadBeforeSave`/`validateRuleFeatures`)仍活跃。v2.2.5 时代的
> 探针/合并校验函数已撤除(见「关键函数说明」)。

# Caddy 配置管理规范

## 核心原则

1. **数据库为源**：规则写端点先在数据库事务中完成变更，Caddy 配置只从数据库状态生成
2. **事务内生成**：提交事务前通过 `ApplyConfigFromTx` 读取事务内可见数据并生成完整配置
3. **全量应用**：完整配置通过 Caddy `/load` 校验并加载，不再对单个服务器或路由做增量写入
4. **原子性**：Caddy 应用失败则回滚事务；事务提交失败或后续步骤失败时恢复运行时快照并执行补偿

## 端口检测策略

### 端口范围限制
- 端口必须在 1-65535 范围内
- 8000、2019 端口保留给 admin 接口；创建/更新规则还会按部署实际配置拦截
  管理面板监听口（config 文件 `port`，admin TLS 与面板同口）与 Caddy admin
  端口（`caddy_admin_url` 解析），自定义部署不再只依赖硬编码默认值

### 协议冲突检测
- **HTTP/HTTPS 规则**：可以与其他 HTTP/HTTPS 规则共用端口（同协议）
- **TCP 规则**：独占端口，不能与 HTTP/HTTPS 规则共用端口

```
HTTP规则A(port=80) + HTTP规则B(port=80) → 允许（同协议）
HTTP规则(port=80) + TCP规则(port=80) → 冲突（不同协议）
TCP规则A(port=8080) + TCP规则B(port=8080) → 冲突（TCP 端口独占；同一规则自身更新除外）
```

### 特殊端口处理
- 80 端口：HTTP 专用，TCP 规则不能使用
- 443 端口：HTTPS 专用，TCP 规则不能使用

### 服务器命名规则

| 协议 | 端口 | 服务器名称 |
|------|------|----------|
| http（含启用 TLS 的 HTTPS） | 80 | http_80 |
| http（含启用 TLS 的 HTTPS） | 443 | http_443 |
| http（含启用 TLS 的 HTTPS） | 其他 | http_{port} |
| tcp | 任意 | tcp_{port} |

> 实现恒以 `http_{port}` 命名 HTTP 服务器（启用 TLS 不改变命名，caddy.go
> `servers[fmt.Sprintf("http_%d", port)]`）；不存在 `https_*` 命名。

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
   └── 内部对每个 HTTP 规则调用 generateHTTPRouteObjects()（经 SingleRuleConfig；
      GenerateRouteObject 仅用于保存前校验的包装形态）

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
   └── HTTP 规则经 generateHTTPRouteObjects()（与保存前校验同源）；TCP 规则
      经 buildTCPServer()/buildTCPProxyRoute()
   └── generateHTTPRouteObjects 处理域名分割、路径规则排序、健康检查、负载策略等

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
3. **encode**（压缩）：如果启用压缩且有 gzip/zstd——位于全部 waf 处理器之外侧（SR11-F3 同步：R1 裁定，coraza 响应拦截器需包在 encode 内侧）
4. **request_body**：配置了请求体上限时——先于全部 waf 处理器（新-1 裁定，body 解析需在 WAF 前）
5. **rate_limit / waf**：按绑定策略 policy_id ASC 依次编入各策略的处理器组（限流先于 WAF）
6. **headers**（Server 头隐藏）：server_tokens_hidden 时 deferred 删除 Server 响应头（须推迟到上游响应写入之后）。2026-09-06 裁定（T-3）：规则级 `server_tokens_hidden`（0=随全局 / 1=隐藏 / 2=显示）为 **API/MCP 预留字段，无 UI 入口、不作为产品功能维护**；管理面板仅提供全局开关（基础设置），UI 规则编辑仅透传保留 API 已设值
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
支持（与写侧白名单一致，rule_features.go/validateRulePayloadBeforeSave）：
- HTTP 规则：weighted_round_robin、least_conn、random、ip_hash、first、cookie
- TCP 规则：weighted_round_robin、least_conn、random、ip_hash、first（cookie 不支持）

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

`POST /config/validate`(handlers/caddy.go):真 validate-only——2026-09-06 裁定 ④' 后主径为 **`caddy validate` CLI**(provision 不运行、不绑端口、零运行时扰动),CLI 不可用回退 R69 C-N3-c 的 load+回弹口径(校验后恢复原配置)。此前经 Caddy admin `/load?validate=true` 的探针已撤除——v2.11.4 的 handleLoad 无视 validate 参数,成功即真实加载。

写路径(创建/更新/启用规则等)的四道关卡:前端表单校验 → 后端字段校验(`validateRuleFeatures`/`validateRulePayloadBeforeSave`)→ 事务内 CLI 校验(`ValidateTxRenderViaCLI`,输入=事务视图最终渲染)→ 事务内 `ApplyConfigFromTx` 终门(拒绝即回滚,DB 零变更)。

## 关键函数说明

### validateRulePayloadBeforeSave / validateRuleFeatures(handlers)

写侧字段校验(仍活跃):Protocol 白名单(http/tcp)、ListenPort 1-65535、Strategy 白名单(HTTP 含 cookie/TCP 不含)、Domain 格式、上游(host/端口/去重/至少一个启用)、body 上限等。历史 `validateCaddyConfigBeforeSave`(Caddy 级预校验探针)与 `ValidateRouteMergedConfig`/`ValidateTCPServerMergedConfig`(候选并入运行配置校验)已随 2026-09-06 裁定撤除,由「事务视图渲染 + CLI validate-only」取代。

> **注意**:历史字段 `TLSEmail` 已废弃。ACME 邮箱全局配置于 `global_config.acme_email`,规则级 CA 选择通过 `ca_provider_id` 指定。

### ApplyConfigFromTx(services/caddy.go)

家族 3 写路径的统一收尾(`applyFromTxNote` 咽喉点):事务内以最终渲染调用 Caddy /load,失败即回滚整个事务——「只有可渲染配置可落库」不变量。

## 错误处理

| 操作 | 失败处理 |
|------|---------|
| validateRulePayloadBeforeSave / validateRuleFeatures | 返回 400，不写入数据库 |
| ValidateTxRenderViaCLI(事务内 CLI 校验) | 拒绝即回滚，不写入数据库 |
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
