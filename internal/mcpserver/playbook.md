# Lazy Balancer V2 MCP 操作手册

面向通过 MCP 操作 Lazy Balancer V2 的 AI Agent。先读本手册，再调用工具。

## 1. 接入与认证

- 端点：`POST {面板地址}/api/v1/mcp`（Streamable HTTP，JSON-RPC 2.0）
- 认证：`X-API-Key: lb_sk_...` 头，或 `Authorization: Bearer lb_sk_...`
- 前提：该 Key 已开启 MCP 功能；面板为自签证书时客户端需跳过或信任证书
- 完整工具参数契约以 `tools/list` 返回的 `input_schema` 为准，不要凭猜测构造参数

## 2. 权限范围（Scope）

| 范围 | 说明 |
|---|---|
| 只读 Key（read_only） | 仅能调用 GET 查询类工具；调写工具返回 403 |
| 写工具（POST/PUT/DELETE） | 需非只读 Key，且**仅主节点可用**；从节点一律 403 |
| IP 白名单 | 配了白名单的 Key，请求来源 IP 必须命中（MCP 内部转发不受影响） |
| 生效方式 | 写操作校验后即时生效，失败自动回滚，无需手动 reload |

## 3. 工具分组速览（26 个）

- **规则**：list_rules、get_rule、create_rule、update_rule、delete_rule、enable_rule、disable_rule、duplicate_rule
- **证书**：list_cert_jobs、retry_cert_job、delete_cert_job、issue_certificate、list_certificates
- **配置**：get_config、update_config、reload_caddy、export_config
- **监控**：get_metrics_overview（轻量）、get_metrics_dashboard（全量聚合）、get_realtime_traffic、get_upstream_health
- **系统**：get_system_info、list_audit_logs、list_users、list_api_keys、get_cluster_status

## 4. 常用工作流

### 4.1 新建 HTTP 站点（含免费证书）

1. `create_rule`：`protocol=http` + `domain` + `listen_port`(80/443) + `upstreams[{host,port}]`；需 ACME 时加 `enable_tls=true`、`tls_source="acme"`
2. `issue_certificate` 传 `caddy_id` 触发签发（前提：系统已配 DNS 提供商与 CA）
3. `list_cert_jobs`（可按 `rule_id` 过滤）轮询直到 `success`；`failed` 看失败原因后 `retry_cert_job`
4. `get_upstream_health` 确认上游三态为正常，收尾

### 4.2 新建 TCP 四层代理

1. `create_rule`：`protocol=tcp` + `listen_port` + `upstreams[{host,port}]`，**不要填 domain**
2. 后端需要真实客户端 IP 时加 `tcp_proxy_protocol=true`（注意：后端必须支持 PROXY v2，否则连接会解析失败）
3. `get_upstream_health` 验证

### 4.3 修改规则（安全姿势：先读后写）

1. `get_rule` 取完整现状
2. `update_rule` 只传要改的字段（部分更新）；协议切换会自动迁移上游协议并清理对侧字段
3. `get_rule` 复查 + `get_upstream_health` 验证流量

### 4.4 排查流量异常

1. `get_upstream_health`：定位异常/不健康的上游
2. `get_metrics_dashboard`：看该规则请求数/状态码分布/流量（数据量大，只在需要明细时用）
3. `list_audit_logs`（`page`/`page_size`，page_size≤100）：查最近是否有变更操作
4. 怀疑配置漂移时 `reload_caddy` 强制从数据库收敛

### 4.5 快速巡检

`get_metrics_overview`（轻量汇总）+ `get_upstream_health`，避免每次都用全量 dashboard。

### 4.6 集群环境操作前

`get_cluster_status` 确认本节点角色：从节点全站只读，写工具一律 403——写操作必须对主节点地址发起。

## 5. 操作纪律

- `delete_rule` **不可恢复**：连带清理上游/证书任务/证书文件，调用前必须 `get_rule` 确认目标无误
- `duplicate_rule` 的副本默认禁用，需要时再 `enable_rule`
- `disable_rule` 会暂停进行中的签发任务，`enable_rule` 后按需恢复
- 写操作失败会自动回滚，报错时读错误信息修正参数重试，不要反复盲调

## 6. 性能建议

- 轻量优先：能 `get_metrics_overview` 就不用 `get_metrics_dashboard`；能 `get_rule` 就不用反复 `list_rules`
- 审计日志务必分页；单工具响应上限 4 MiB，超限请改分页或专用导出（`export_config`）
- 保持 HTTP 连接复用（一个 MCP 会话内不要每次新建连接）

## 7. 错误码速查

| 错误 | 含义与处理 |
|---|---|
| 401 | 密钥无效/缺失，或未开启 MCP → 核对 Key 与开关 |
| 403 | 只读 Key 调写工具 / 从节点写操作 / 来源 IP 不在白名单 → 换非只读 Key、对主节点调用、或放行来源 IP |
| -32602 | 参数不符合 `input_schema` → 重新读该工具 schema，按契约修正，不要猜字段名 |
| IsError + 4xx/5xx 文本 | 内部 REST 返回的业务错误，响应体里有具体 message |
