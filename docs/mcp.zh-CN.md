# MCP 服务文档

## 概述

Lazy Balancer V2 内置 **Model Context Protocol (MCP)** 服务，AI 代理可通过 127 个工具操作全部功能。

## 接入

| 配置项 | 值 |
|---|---|
| 端点 | `http://<host>:8000/api/v1/mcp` |
| 协议 | Streamable HTTP (POST) |
| 认证 | `X-API-Key: lb_sk_...` 或 `Authorization: Bearer lb_sk_...` |
| Content-Type | `application/json` |

## 快速验证

```bash
curl -s http://localhost:8000/api/v1/mcp \
  -H "X-API-Key: lb_sk_your_key" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

## 工具权限

| Key 类型 | 可用工具 |
|---|---|
| 管理员 Key（读写） | 全部 127 个工具 |
| 只读 Key（read_only） | GET 查询工具 + 5 个读探测 POST 工具（test_ca_provider / test_certificate_config / parse_certificate / validate_import / preview_config） |
| IP 白名单 Key | 请求来源 IP 必须命中白名单（MCP 内部转发不受影响） |

## 工具分组（节选）

| 分组 | 工具 |
|---|---|
| 负载规则 | list_rules、get_rule、create_rule、update_rule、delete_rule、enable_rule、disable_rule |
| 证书 | list_cert_jobs、retry_cert_job、issue_certificate、list_certificates |
| 安全策略 | list_security_policies、create_security_policy、update_security_policy |
| 自定义规则 | list_security_custom_rules、create_security_custom_rule |
| IP 名单 | list_ip_lists、create_ip_list、update_ip_list |
| 监控 | get_metrics_overview、get_metrics_dashboard、get_realtime_traffic、get_upstream_health |
| 集群 | get_cluster_status、generate_cluster_register_token |
| 配置 | get_config、update_config、reload_caddy |

完整工具列表通过 `tools/list` 方法获取。

## 操作手册

连接后可通过 `resources/read` 读取内置操作手册：

```
lazy-balancer://docs/ops-playbook
```

手册包含：接入指南、权限范围、常用工作流、排障手册、纪律约束、性能建议。

## 常用工作流示例

### 创建负载均衡规则

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_rule","arguments":{"name":"my-rule","protocol":"http","domain":"example.com","listen_port":80,"strategy":"weighted_round_robin","upstreams":[{"host":"10.0.0.1","port":8080,"weight":1}]}}}
```

### 查看安全事件

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_security_events","arguments":{"page":1,"page_size":20,"action":"blocked"}}}
```

### 触发证书签发

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_certificate","arguments":{"caddy_id":"lb_xxx"}}}
```

## 错误码

| 错误 | 含义 |
|---|---|
| 400 | 请求体不可读或超过 1 MiB |
| 401 | API Key 无效 |
| 403 | MCP 未启用 / IP 不在白名单 / 只读 Key 调写工具 |
