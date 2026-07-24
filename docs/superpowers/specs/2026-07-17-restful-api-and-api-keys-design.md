# RESTful API v1 与 API 密钥功能设计

## 目标

在不中断现有 `/api` 接口的前提下，新增正式 RESTful 接口层 `/api/v1`，提供 OpenAPI 文档入口；完善 API 密钥能力，使当前用户可以在“系统设置 → API 密钥”页面创建、查看和删除自己的密钥，并确保 API Key 认证的写操作同样记录操作日志。

## 范围

### 包含

- `/api/v1` 正式接口层与 `/api` 兼容层并存
- OpenAPI 3.1 文档：`/api/v1/openapi.yaml` 与 `/api/v1/docs`
- API 密钥页面文档入口
- 当前用户 API Key：
  - `GET /api/v1/users/me/api-keys`
  - `POST /api/v1/users/me/api-keys`
  - `DELETE /api/v1/users/me/api-keys/:id`
- 管理 API Key：
  - `GET /api/v1/api-keys`
  - `POST /api/v1/api-keys`
  - `DELETE /api/v1/api-keys/:id`
- API Key 认证上下文与 `last_used` 更新
- API Key 写操作审计，detail 包含 `auth_type=api_key`、密钥 ID 和名称，不记录密钥本体

### 不包含

- 删除或立即重构现有 `/api` 兼容路由
- 将全部旧前端一次性迁移到 `/api/v1`
- 权限范围（scope）细粒度授权模型
- 请求体、密码、密钥、PEM、DNS 凭证进入审计详情

## 资源分类

- 认证：`auth`
- 用户：`users`
- API 密钥：`api-keys`
- 负载均衡规则：`rules`
- DNS 提供商配置：`certificate-configs`
- CA 提供商：`ca-providers`
- 证书与签发任务：`certificates`、`cert-jobs`
- 集群节点：`nodes`
- 全局配置：`config`
- Caddy：`caddy`
- 配置同步：`sync`
- 指标：`metrics`
- 系统：`system`
- 操作日志：`audit-logs`

## RESTful 命名原则

1. 集合资源使用复数名词。
2. 单个资源使用路径参数定位。
3. 状态修改优先使用 `PATCH`，不再使用动作路径。
4. 创建子资源使用集合路径。
5. 运维动作允许控制器式 POST，但必须在文档中明确。

## 兼容与迁移

- `/api/v1` 是唯一正式接口层。
- 旧 `/api` 不保留，前端、文档和审计统一使用 `/api/v1`。
- 外部调用方必须使用 `/api/v1`；系统不再提供旧接口兼容层。

## 核心接口

### 文档

- `GET /api/v1/openapi.yaml`：OpenAPI YAML
- `GET /api/v1/docs`：文档页面

### 当前用户 API Key

- `GET /api/v1/users/me/api-keys`：列出当前用户密钥
- `POST /api/v1/users/me/api-keys`：创建当前用户密钥，密钥只显示一次
- `DELETE /api/v1/users/me/api-keys/:id`：删除当前用户密钥

### 管理 API Key

- `GET /api/v1/api-keys`：admin 列出全部密钥
- `POST /api/v1/api-keys`：admin 为当前用户创建密钥
- `DELETE /api/v1/api-keys/:id`：admin 删除任意密钥

### 认证

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`

### 首批 v1 映射

优先映射现有稳定能力：

- `GET /api/v1/users/me`
- `PATCH /api/v1/users/me`
- `GET /api/v1/config`
- `PUT /api/v1/config`
- `POST /api/v1/config/preview`
- `POST /api/v1/config/reload`
- `GET /api/v1/audit-logs`

其余资源在 OpenAPI 中定义目标规范，分阶段映射实现。

## API Key 认证

请求头：

```http
Authorization: Bearer lb_sk_...
```

认证成功后在 Gin context 注入：

- `auth_type=api_key`
- `user_id`
- `username`
- `role`
- `api_key_id`
- `api_key_name`

同时更新 `last_used`。

## 审计策略

- API Key 认证的写操作进入操作日志。
- 操作人列显示密钥归属用户的显示名或用户名。
- 详情追加安全元数据：

```text
auth_type=api_key; api_key_id=12; key_name=ci-deploy
```

- 不记录密钥本体、hash、Authorization 头或请求体。

## 安全规则

- 密钥仅创建时显示一次。
- 数据库仅保存 SHA-256 hash 与前缀。
- 普通用户只能查看、创建、删除自己的密钥。
- admin 可以查看、创建、删除全部密钥。
- 过期密钥不得认证。
- 禁用用户的密钥不得认证。

## 错误处理

- 未认证：401
- 无权限：403
- 对象不存在：404
- 请求格式错误：400
- 响应格式沿用现有 `APIResponse`，兼容前端拦截器。

## 测试策略

- API Key 创建只返回一次明文密钥。
- 当前用户无法读取或删除他人的密钥。
- admin 可以读取和删除任意密钥。
- 正确 API Key 可认证，错误/过期/禁用用户密钥不可认证。
- API Key 写操作在独立审计库中生成一条操作日志，detail 不含密钥。
- OpenAPI YAML 可访问且包含核心路径。
- `/api` 兼容路由不受影响。

## 部署

- 不改变 Docker Compose 数据卷。
- SQLite 沿用现有 `api_keys` 表。
- 无需新依赖；OpenAPI YAML 可静态嵌入或 handler 返回。
