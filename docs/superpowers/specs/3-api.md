# Lazy Balancer V2 - API 参考

**文档版本**: 1.0
**更新日期**: 2026-04-17
**目的**: 详细 API 端点定义，支持功能迭代和 API 集成

---

## 1. 认证

### 1.1 登录

**端点**: `POST /api/auth/login`

**请求**:
```json
{
  "username": "admin",
  "password": "admin"
}
```

**响应** (200):
```json
{
  "code": 200,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "admin",
      "role": "admin",
      "display_name": "Administrator"
    }
  }
}
```

**响应** (401):
```json
{
  "code": 401,
  "message": "Invalid credentials"
}
```

### 1.2 登出

**端点**: `POST /api/auth/logout`

**Headers**: `Authorization: Bearer <token>`

**响应** (200):
```json
{
  "code": 200,
  "message": "Logged out"
}
```

---

## 2. 规则 (Rules)

### 2.1 列表

**端点**: `GET /api/rules`

**Headers**: `Authorization: Bearer <token>`

**响应** (200):
```json
{
  "code": 200,
  "data": [
    {
      "id": 1,
      "caddy_id": "lb_abc123xyz12",
      "name": "Web App",
      "protocol": "http",
      "domain": "example.com",
      "listen_port": 80,
      "strategy": "round_robin",
      "enabled": true,
      "upstreams": [
        {
          "id": 1,
          "host": "192.168.1.10",
          "port": 8080,
          "weight": 1,
          "enabled": true
        }
      ]
    }
  ]
}
```

### 2.2 详情

**端点**: `GET /api/rules/:caddy_id`

**示例**: `GET /api/rules/lb_abc123xyz12`

**响应** (200):
```json
{
  "code": 200,
  "data": {
    "id": 1,
    "caddy_id": "lb_abc123xyz12",
    "name": "Web App",
    "description": "Production web application",
    "protocol": "http",
    "domain": "example.com,www.example.com",
    "listen_port": 80,
    "strategy": "round_robin",
    "dynamic_dns": false,
    "enable_dns_server": false,
    "dns_server": "",
    "dns_family": "ipv4",
    "health_check_path": "/health",
    "health_check_interval": 10,
    "health_check_timeout": 5,
    "health_check_unhealthy_threshold": 3,
    "health_check_healthy_threshold": 2,
    "enable_active_health_check": true,
    "host_header": "",
    "enable_tls": false,
    "enable_compress": true,
    "compress_types": "gzip",
    "enabled": true,
    "upstreams": [
      {
        "id": 1,
        "rule_id": "lb_abc123xyz12",
        "host": "192.168.1.10",
        "port": 8080,
        "weight": 1,
        "enabled": true,
        "protocol": "http"
      }
    ]
  }
}
```

### 2.3 创建

**端点**: `POST /api/rules`

**Headers**: `Authorization: Bearer <token>`

**请求体**:
```json
{
  "name": "Web App",
  "description": "Production web application",
  "protocol": "http",
  "domain": "example.com",
  "listen_port": 80,
  "strategy": "round_robin",
  "upstreams": [
    {
      "host": "192.168.1.10",
      "port": 8080,
      "weight": 1,
      "enabled": true
    },
    {
      "host": "192.168.1.11",
      "port": 8080,
      "weight": 2,
      "enabled": true
    }
  ],
  "health_check_path": "/health",
  "health_check_interval": 10,
  "health_check_timeout": 5,
  "health_check_unhealthy_threshold": 3,
  "enable_active_health_check": true,
  "enable_compress": true,
  "compress_types": "gzip",
  "enabled": true
}
```

**响应** (200):
```json
{
  "code": 200,
  "message": "Rule created successfully",
  "data": {
    "caddy_id": "lb_abc123xyz12"
  }
}
```

**错误响应** (400):
```json
{
  "code": 400,
  "message": "Port 80 is already in use by another rule"
}
```

### 2.4 更新

**端点**: `PUT /api/rules/:caddy_id`

**示例**: `PUT /api/rules/lb_abc123xyz12`

**请求体**: (同创建，部分字段可选)

```json
{
  "name": "Updated Web App",
  "upstreams": [
    {
      "host": "192.168.1.20",
      "port": 9090,
      "weight": 1,
      "enabled": true
    }
  ]
}
```

**响应** (200):
```json
{
  "code": 200,
  "message": "Rule updated successfully"
}
```

### 2.5 删除

**端点**: `DELETE /api/rules/:caddy_id`

**示例**: `DELETE /api/rules/lb_abc123xyz12`

**响应** (200):
```json
{
  "code": 200,
  "message": "Rule deleted successfully"
}
```

### 2.6 启用

**端点**: `POST /api/rules/:caddy_id/enable`

**响应** (200):
```json
{
  "code": 200,
  "message": "Rule enabled successfully"
}
```

### 2.7 禁用

**端点**: `PUT /api/rules/:caddy_id/disable`

**响应** (200):
```json
{
  "code": 200,
  "message": "Rule disabled successfully"
}
```

### 2.8 复制

**端点**: `POST /api/rules/:caddy_id/duplicate`

**响应** (200):
```json
{
  "code": 200,
  "message": "Rule duplicated successfully",
  "data": {
    "caddy_id": "lb_new123xyz45"
  }
}
```

### 2.9 获取 Caddy 配置

**端点**: `GET /api/rules/:caddy_id/caddy-config`

**响应** (200):
```json
{
  "code": 200,
  "data": {
    "route": {
      "@id": "lb_abc123xyz12",
      "match": [
        {
          "host": ["example.com"]
        }
      ],
      "handle": [
        {
          "handler": "encode",
          "encodings": {
            "gzip": {}
          }
        },
        {
          "handler": "reverse_proxy",
          "upstreams": [
            {"dial": "192.168.1.10:8080"}
          ],
          "health_checks": {
            "passive": {
              "fail_duration": "30s",
              "max_fails": 3
            }
          }
        }
      ]
    }
  }
}
```

---

## 3. 用户管理 (Admin)

### 3.1 列表

**端点**: `GET /api/users` (Admin only)

**响应** (200):
```json
{
  "code": 200,
  "data": [
    {
      "id": 1,
      "username": "admin",
      "role": "admin",
      "display_name": "Administrator",
      "is_enabled": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### 3.2 创建

**端点**: `POST /api/users` (Admin only)

**请求体**:
```json
{
  "username": "newuser",
  "password": "password123",
  "role": "user",
  "display_name": "New User"
}
```

### 3.3 更新

**端点**: `PUT /api/users/:id` (Admin only)

**请求体**:
```json
{
  "display_name": "Updated Name",
  "role": "admin"
}
```

### 3.4 删除

**端点**: `DELETE /api/users/:id` (Admin only)

### 3.5 启用/禁用

**端点**: `PUT /api/users/:id/status` (Admin only)

**请求体**:
```json
{
  "is_enabled": true
}
```

### 3.6 重置密码

**端点**: `POST /api/users/:id/reset-password` (Admin only)

**请求体**:
```json
{
  "new_password": "newpassword123"
}
```

---

## 4. 节点管理 (多节点)

### 4.1 注册节点

**端点**: `POST /api/nodes/register`

**请求体**:
```json
{
  "name": "worker-1",
  "mode": "slave",
  "ip_address": "192.168.1.100",
  "port": 8000,
  "master_id": 1
}
```

### 4.2 心跳

**端点**: `POST /api/nodes/:id/heartbeat`

### 4.3 列表

**端点**: `GET /api/nodes` (Admin only)

### 4.4 审批节点

**端点**: `PUT /api/nodes/:id/approve` (Admin only)

### 4.5 拒绝节点

**端点**: `PUT /api/nodes/:id/reject` (Admin only)

### 4.6 删除节点

**端点**: `DELETE /api/nodes/:id` (Admin only)

---

## 5. 指标

### 5.1 概览

**端点**: `GET /api/metrics/overview`

**响应** (200):
```json
{
  "code": 200,
  "data": {
    "total_requests": 1000000,
    "active_connections": 150,
    "rules_count": 10,
    "upstreams_count": 25,
    "healthy_upstreams": 23,
    "unhealthy_upstreams": 2
  }
}
```

### 5.2 规则指标

**端点**: `GET /api/metrics/rule/:caddy_id`

### 5.3 历史指标

**端点**: `GET /api/metrics/history?rule_id=:caddy_id&from=&to=`

### 5.4 实时流量

**端点**: `GET /api/metrics/realtime`

### 5.5 连接统计

**端点**: `GET /api/metrics/connections`

---

## 6. Caddy 配置

### 6.1 获取状态

**端点**: `GET /api/caddy/status`

### 6.2 获取配置

**端点**: `GET /api/caddy/config`

### 6.3 更新配置

**端点**: `PUT /api/caddy/config`

**请求体**: (Caddy JSON 配置)

### 6.4 重新加载

**端点**: `POST /api/config/reload` (Admin only)

### 6.5 验证配置

**端点**: `POST /api/config/validate` (Admin only)

**请求体**: (Caddy JSON 配置)

**响应** (200):
```json
{
  "code": 200,
  "message": "Configuration is valid"
}
```

**响应** (400):
```json
{
  "code": 400,
  "message": "Configuration is invalid: ..."
}
```

### 6.6 上游健康状态

**端点**: `GET /api/config/health`

---

## 7. 全局配置

### 7.1 获取

**端点**: `GET /api/config`

### 7.2 更新

**端点**: `PUT /api/config` (Admin only)

---

## 8. API Key 管理 (Admin)

### 8.1 列表

**端点**: `GET /api/keys`

### 8.2 创建

**端点**: `POST /api/keys`

**请求体**:
```json
{
  "name": "CI/CD Key",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**响应** (200):
```json
{
  "code": 200,
  "data": {
    "id": 1,
    "name": "CI/CD Key",
    "key": "lb_key_xxxxxxxxxxxx_abcd1234",
    "key_prefix": "lb_key_xxxx",
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### 8.3 删除

**端点**: `DELETE /api/keys/:id`

---

## 9. 证书

### 9.1 列表

**端点**: `GET /api/certificates`

### 9.2 签发

**端点**: `POST /api/certificates/issue` (Admin only)

**请求体**:
```json
{
  "domain": "example.com",
  "provider": "dnspod",
  "email": "admin@example.com"
}
```

---

## 10. 系统信息

### 10.1 系统信息

**端点**: `GET /api/system/info`

**响应** (200):
```json
{
  "code": 200,
  "data": {
    "version": "1.0.0",
    "go_version": "1.21",
    "os": "linux",
    "arch": "amd64",
    "hostname": "lazy-balancer",
    "uptime": 3600,
    "memory": {
      "total": 2147483648,
      "used": 1073741824,
      "percent": 50
    },
    "disk": {
      "total": 107374182400,
      "used": 53687091200,
      "percent": 50
    },
    "cpu_count": 4
  }
}
```

### 10.2 系统指标

**端点**: `GET /api/system/metrics`

---

## 11. 同步 (多节点)

### 11.1 同步状态

**端点**: `GET /api/sync/status`

### 11.2 获取同步配置

**端点**: `GET /api/sync/config`

### 11.3 手动同步

**端点**: `POST /api/sync/pull`

---

## 12. 错误码

| 错误码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 / Caddy 验证失败 |
| 401 | 未认证 / Token 无效 |
| 403 | 无权限 (需要 Admin) |
| 404 | 资源不存在 |
| 409 | 资源冲突 (端口冲突等) |
| 500 | 服务器内部错误 |

---

## 13. 请求示例

### 使用 JWT Token

```bash
curl -X GET http://localhost:8000/api/rules \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 使用 API Key

```bash
curl -X GET http://localhost:8000/api/rules \
  -H "X-API-Key: lb_key_xxxxxxxxxxxx_abcd1234"
```

---

## 14. 相关文档

- [系统概述](./1-overview.md)
- [详细架构](./2-architecture.md)
- [配置规则规范](./4-config-rules.md)
- [运维指南](./5-operations.md)