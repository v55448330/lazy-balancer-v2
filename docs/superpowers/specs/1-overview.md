# Lazy Balancer V2 - 系统概述

**文档版本**: 1.0
**更新日期**: 2026-04-17
**目的**: AI 认知项目上下文，支持功能迭代和 Bug 修复

---

## 1. 项目简介

**Lazy Balancer V2** 是一个基于 Caddy 的负载均衡管理平台，通过 Go 后端生成 Caddy JSON 配置并推送到 Caddy Admin API，实现动态路由、健康检查和流量分发。

### 核心特点

- **动态配置**: 无需重启 Caddy，实时更新路由规则
- **健康检查**: 支持主动和被动健康检查
- **多协议**: HTTP/HTTPS/TCP 负载均衡
- **多节点**: Master/Slave 架构支持配置同步
- **TLS 自动证书**: 支持 Let's Encrypt 自动签发

---

## 2. 技术栈

| 层级 | 技术 | 版本 |
|------|------|------|
| 后端 | Go | 1.21+ |
| Web 框架 | Gin | latest |
| 数据库 | SQLite (WAL mode) | - |
| 负载均衡 | Caddy | v2.11.2 |
| 前端 | Vue 3 + TypeScript | - |
| 构建工具 | Vite | - |
| UI 框架 | Element Plus + Tailwind CSS | - |
| 容器 | Docker Compose | - |

---

## 3. 项目结构

```
.
├── cmd/server/
│   └── main.go                 # 后端入口
├── internal/
│   ├── config/
│   │   └── config.go           # 配置加载
│   ├── db/
│   │   └── db.go               # SQLite 数据库
│   ├── handlers/
│   │   └── handlers.go         # API 处理器 (~3200 行)
│   ├── middleware/
│   │   └── middleware.go       # JWT/API Key 认证
│   ├── models/
│   │   └── models.go           # 数据结构 (~400 行)
│   └── services/
│       ├── caddy.go            # Caddy 编排 (~2300 行)
│       └── services.go         # 其他服务
├── web/
│   └── src/
│       ├── views/              # Vue 页面组件
│       ├── stores/             # Pinia 状态管理
│       ├── api/                # API 客户端
│       └── utils/              # 工具函数
├── ui/                         # 前端构建产物
├── data/                       # SQLite 数据库文件
├── docs/                       # 文档
├── docker-compose.yml          # 容器编排
└── Dockerfile                  # 镜像构建

```

---

## 4. 核心概念

### 4.1 规则 (Rule)

**规则**是负载均衡的核心单元，定义如何将流量路由到上游服务器。

| 字段 | 类型 | 说明 |
|------|------|------|
| caddy_id | string | 唯一标识 (lb_xxxxxxxxx, 13位) |
| name | string | 规则名称 |
| protocol | string | http/https/tcp |
| domain | string | 域名 (逗号分隔) |
| listen_port | int | 监听端口 |
| strategy | string | 负载策略 |
| upstreams | []Upstream | 上游服务器列表 |

### 4.2 上游服务器 (Upstream)

定义后端服务器地址和权重。

| 字段 | 类型 | 说明 |
|------|------|------|
| host | string | IP 或域名 |
| port | int | 端口 |
| weight | int | 权重 (用于加权负载) |
| protocol | string | http/https |
| enabled | bool | 启用状态 |

### 4.3 健康检查

**被动健康检查** (始终启用):
- `fail_duration`: 失败持续时间 = `health_check_interval * 3`
- `max_fails`: 失败阈值 = `health_check_unhealthy_threshold`

**主动健康检查** (可选):
- `uri`: 检查路径
- `interval`: 检查间隔
- `timeout`: 超时时间 (与连接超时共用 `health_check_timeout`)

---

## 5. 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                     浏览器 (Vue 3 SPA)                       │
│         Dashboard / Rules / Nodes / Settings / Users        │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP/HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              lazy-balancer 容器 (:8000 API)                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    Gin API Server                     │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │  │  Handlers   │  │ Middleware  │  │   Models    │   │  │
│  │  │  (~3200行)  │  │  Auth/JWT   │  │  (~400行)   │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              CaddyService (caddy.go)            │  │  │
│  │  │  GenerateCaddyConfig / ApplyConfig / Validate    │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  SQLite Database                      │  │
│  │    lb_rules / upstreams / users / api_keys / nodes   │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────────┘
                          │ POST /load
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Caddy Server (:80, :443, :2019)                 │
│                                                              │
│   apps.http.servers:                                        │
│     http_80 ──► route [@id=lb_xxx] ──► upstream             │
│                                                              │
│   功能: 负载均衡 / TLS 终止 / 压缩 / 健康检查                │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. 关键标识

### 6.1 caddy_id 格式

```
lb_ + 10位随机字符 = 13位
示例: lb_abc123xyz12
```

**用途**:
- 数据库主键 (替代自增 ID)
- Caddy 路由的 `@id` 标识
- API 路径参数

### 6.2 服务器命名规则

| 协议 | 端口 | 服务器名 |
|------|------|----------|
| http | 80 | http_80 |
| https | 443 | https_443 |
| http | 其他 | http_{port} |
| https | 其他 | https_{port} |
| tcp | 任意 | tcp_{port} |

---

## 7. 配置同步流程

### 7.1 创建规则 (CreateRule)

```
1. 请求验证 (validateCaddyConfigBeforeSave)
2. Caddy 预验证 (ValidateRouteMergedConfig)
3. 写入 Caddy (CreateServerIfNotExists + PrependRouteToServer)
4. 验证路由 (VerifyRouteExists)
5. 写入数据库 (lb_rules + upstreams)
6. 失败回滚 (RemoveRouteFromServer)
```

### 7.2 更新规则 (UpdateRule)

```
1. 请求验证
2. 读取现有配置
3. 写入 Caddy (SetConfigByID - 按 @id 替换)
4. 验证路由
5. 更新数据库
```

### 7.3 启用/禁用规则

```
启用: PrependRouteToServer (添加) + 更新数据库
禁用: RemoveRouteFromServer (移除) + 更新数据库
```

---

## 8. 认证机制

### 8.1 JWT 认证

- 用户登录获取 Token
- Token 包含 user_id, username, role
- 有效期 24 小时 (可配置)

### 8.2 API Key 认证

- 机器间通信
- 使用 `X-API-Key` header
- 自动获得 admin 角色

---

## 9. 多节点架构

```
┌─────────────┐     同步      ┌─────────────┐
│   Master    │ ◄───────────► │   Slave     │
│  (写入)     │               │  (只读)     │
└──────┬──────┘               └─────────────┘
       │
       ▼
   Caddy Server
```

**环境变量**:
- `NODE_MODE=master|slave`
- `MASTER_URL=http://...`
- `NODE_NAME=...`

---

## 10. 已知约束

1. **无测试**: 整个项目没有测试覆盖 (backend 和 frontend)
2. **SQLite**: 使用文件数据库，不支持真正分布式写入
3. **端口独占**: TCP 协议规则独占端口，不与 HTTP/HTTPS 共用
4. **Caddy 版本**: 锁定 v2.11.2，未使用最新版本

---

## 11. 相关文档

- [架构详解](./2-architecture.md)
- [API 参考](./3-api.md)
- [配置规则规范](./4-config-rules.md)
- [运维指南](./5-operations.md)