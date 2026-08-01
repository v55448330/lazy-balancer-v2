# Lazy Balancer V2 - 文档索引

**文档版本**: 1.0
**更新日期**: 2026-04-17

---

## 文档概览

本项目文档分为 5 个层级，从概述到运维：

| 文档 | 层级 | 目的 | 读者 |
|------|------|------|------|
| [1-overview.md](./1-overview.md) | 概念层 | 系统概述和核心概念 | 所有读者 |
| [2-architecture.md](./2-architecture.md) | 架构层 | 函数级代码细节 | 开发人员 |
| [3-api.md](./3-api.md) | 参考层 | API 端点定义 | 开发/集成 |
| [4-config-rules.md](./4-config-rules.md) | 规范层 | Caddy 配置生成规范 | 开发/运维 |
| [5-operations.md](./5-operations.md) | 运维层 | 部署和故障排查 | 运维人员 |

---

## 快速导航

### 新成员 Onboarding

1. [系统概述](./1-overview.md) - 了解项目是什么
2. [技术栈和架构](./1-overview.md#2-技术栈) - 技术选型
3. [核心概念](./1-overview.md#4-核心概念) - 规则、上游、健康检查
4. [运维指南 - 快速开始](./5-operations.md#1-快速开始) - 本地运行

### 功能迭代

1. [详细架构](./2-architecture.md) - 理解代码结构
2. [API 参考](./3-api.md) - 了解端点定义
3. [配置规则规范](./4-config-rules.md) - 配置生成逻辑

### Bug 修复

1. [Caddy 编排详解](./2-architecture.md#4-caddy-编排-caddyservice) - CaddyService 函数
2. [API 处理器](./2-architecture.md#5-api-处理器-internalhandlershandlersgo) - Handler 函数
3. [配置规则规范](./4-config-rules.md#7-关键函数说明) - 关键函数位置

### 深度调试

1. [数据流图](./2-architecture.md#8-数据流图) - 创建/更新流程
2. [错误处理](./4-config-rules.md#8-错误处理) - 错误码和回滚机制
3. [Caddy @id 机制](./4-config-rules.md#3-caddy-id-机制) - 路由管理

---

## 关键文件位置

| 功能 | 文件 | 关键函数 |
|------|------|----------|
| 入口 | `cmd/server/main.go` | main |
| 数据库 | `internal/db/db.go` | Initialize, runMigrations |
| 数据模型 | `internal/models/models.go` | LbRule, Upstream |
| API 处理器 | `internal/handlers/handlers.go` | CreateRule, UpdateRule, EnableRule, DisableRule, DeleteRule |
| Caddy 编排 | `internal/services/caddy.go` | GenerateCaddyConfig, ApplyConfigFromTx, GenerateAndApplyConfig |
| 认证 | `internal/middleware/middleware.go` | jwtAuth, apiKeyAuth |
| 前端 | `web/src/views/Rules.vue` | 规则管理界面 |

---

## 核心概念速查

### caddy_id 格式
- 长度: 13 位
- 格式: `lb_` + 10 位随机字符
- 示例: `lb_abc123xyz12`

### 服务器命名
| 协议 | 端口 | 服务器名 |
|------|------|----------|
| http | 80 | http_80 |
| https | 443 | https_443 |
| http | 其他 | http_{port} |
| https | 其他 | https_{port} |
| tcp | 任意 | tcp_{port} |

### 配置写入顺序

**CreateRule**:
```
验证 → Caddy 写入 → 验证 → 数据库写入 → 成功返回
```

**UpdateRule**:
```
验证 → Caddy 写入 → 验证 → 数据库更新 → 成功返回
```

---

## 常见问题

### Q: 如何添加新字段到规则？
A:
1. `internal/models/models.go` - 添加字段到 LbRule 结构体
2. `internal/db/db.go` - 添加数据库列（迁移或 ALTER TABLE）
3. `internal/handlers/handlers.go` - 更新 SQL 查询和绑定
4. `internal/services/caddy.go` - 更新配置生成逻辑
5. `web/src/views/Rules.vue` - 更新前端表单

### Q: 如何修改健康检查逻辑？
A: 查看 `internal/services/caddy.go:1916-1933` (GenerateSingleRuleCaddyConfig 函数中的健康检查部分)

### Q: @id 机制是什么？
A: 查看 [配置规则规范 - Caddy @id 机制](./4-config-rules.md#3-caddy-id-机制)

---

## 相关资源

- [Caddy v2.11.2 文档](https://caddyserver.com/docs/)
- [Gin Web Framework](https://gin-gonic.com/)
- [SQLite 文档](https://www.sqlite.org/docs.html)
- [Vue 3 文档](https://vuejs.org/)
- [Element Plus](https://element-plus.org/)