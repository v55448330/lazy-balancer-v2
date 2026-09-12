# API 文档

## 访问方式

部署后可通过以下方式访问：

- **Swagger UI**（交互调试）：`http://<host>:8000/api/v1/docs`
- **OpenAPI 规范**：`http://<host>:8000/api/v1/openapi.yaml`

## 认证

| 方式 | Header | 说明 |
|---|---|---|
| JWT | `Authorization: Bearer <token>` | 登录 `/api/v1/auth/login` 获取 |
| API Key | `X-API-Key: lb_sk_...` | 管理面板创建；非管理员 Key 强制只读 |

## 端点概览

| 域 | 前缀 | 说明 |
|---|---|---|
| 认证 | `/auth/*` | 登录、登出、MFA 两步验证 |
| 规则 | `/rules/*` | 负载均衡规则 CRUD、启停、复制、指标 |
| 安全策略 | `/security/*` | WAF 策略、自定义规则、IP 名单、事件 |
| 证书 | `/certificates/*`、`/certificate-configs/*` | 签发、任务、DNS 提供商 |
| 集群 | `/cluster/*` | 注册、同步、节点管理 |
| 配置 | `/config*` | 全局配置、备份导入导出、校验 |
| 用户 | `/users/*`、`/api-keys/*` | 用户管理、API 密钥 |
| MCP | `/mcp` | Model Context Protocol 端点 |
| 监控 | `/metrics/*` | 仪表盘、实时流量、上游健康 |

## 完整端点列表

完整端点文档（含请求/响应示例、错误码）由后端动态生成，部署后访问 `/api/v1/docs`（Swagger UI）获取。

## 错误格式

```json
{ "code": 400, "message": "错误描述" }
```

| 状态码 | 含义 |
|---|---|
| 400 | 参数校验失败 |
| 401 | 未认证 / 会话过期 |
| 403 | 无权限 / 从节点只读 / IP 白名单拒绝 |
| 404 | 资源不存在 |
| 409 | 冲突（重名、并发操作） |
| 428 | MFA 写操作验证 required |
| 429 | 请求过于频繁（登录/注册/集群公开端点限流、账户锁定） |
| 413 | 请求体超限 |
| 500 | 服务端错误 |
