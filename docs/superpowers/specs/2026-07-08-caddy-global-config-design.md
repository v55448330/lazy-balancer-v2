# Caddy 全局配置卡片设计

## 1. 概述

在“全局配置”页面（`CaddyConfig.vue`）新增一个 **Caddy 全局配置** 卡片，把与 Caddy 直接相关的配置项从“系统设置 / 基础设置”迁移过来，并增加一组常用的全局默认值。同时，把页面下方的 **Caddy 配置预览 (JSON)** 卡片改为默认折叠，展开后才实时请求并渲染完整 JSON 配置。

真正全局生效的配置项（Caddy 日志、HTTP server 超时）保留在全局卡片中；非全局生效但常用的配置项（请求体大小、上游 keepalive、Server 响应头）在全局卡片中提供**默认值**，并在规则向导的高级选项中允许按规则覆盖。

## 2. 目标

- 集中管理 Caddy 相关配置，减少用户在“系统设置”和“全局配置”之间切换。
- 支持全局默认值 + 规则级覆盖，兼顾易用性和灵活性。
- Caddy JSON 预览按需加载，避免默认页面加载过慢或暴露过多信息。

## 3. 非目标

- 本次不涉及 Caddy `admin`、`storage`、`auto_https` 等更底层的全局配置。
- 不修改菜单结构，保留“系统设置 / 基础设置”入口（仅精简内容）。
- 不引入新的第三方 Caddy 插件。

## 4. 全局配置页 UI

### 4.1 Caddy 全局配置卡片

使用 Element Plus `el-card` 承载，左侧表单 + 右侧操作区布局。

左侧表单字段：

| 字段 | 控件 | 单位 | 说明 |
|------|------|------|------|
| Caddy 日志路径 | `el-input` | - | 绝对路径，保存时校验 |
| Caddy 日志级别 | `el-select` | - | debug / info / warn / error |
| 日志滚动大小 | `el-input-number` | MB | 默认 100 |
| 请求体大小限制 | `el-input-number` | MB | 全局默认值，0 表示不限制 |
| HTTP 读取超时 | `el-input-number` | 秒 | 0 表示使用 Caddy 默认值 |
| HTTP 写入超时 | `el-input-number` | 秒 | 0 表示使用 Caddy 默认值 |
| HTTP 空闲超时 | `el-input-number` | 秒 | 0 表示使用 Caddy 默认值 |
| 上游 keepalive 超时 | `el-input-number` | 秒 | 全局默认值，0 表示 Caddy 默认 |
| 隐藏 Server 响应头 | `el-switch` | - | 默认关闭 |

右侧操作区：
- “保存”按钮：调用 `PUT /config` 保存全局配置。
- “重载 Caddy”按钮：从基础设置的危险操作卡片迁移过来，调用 `POST /config/reload`。

### 4.2 Caddy 配置预览 (JSON) 卡片

- 使用 `el-collapse` 包装，默认折叠（`v-model="activeCollapse"`，初始不含 `json-preview`）。
- 折叠时不请求 `/caddy/config`。
- 展开时通过 `watch` 或 `el-collapse` 的 `change` 事件触发 `fetchCaddyConfig()`，加载完整 JSON 并渲染 `VueJsonPretty`。
- 保留刷新按钮，仅当已展开时有效。

## 5. 基础设置页调整

`BasicSettings.vue` 中：
- 移除 **Caddy 日志路径**、**Caddy 日志级别**、**日志滚动大小** 三个字段。
- 移除 **重载 Caddy** 按钮（已迁移到全局配置卡片）。
- 移除 **危险操作** 卡片（仅保留重载按钮，迁移后此处无内容）。
- 保留 **Lazy Balancer 日志级别** 字段。
- 保留 **系统信息** 卡片。

## 6. 规则向导高级选项

在 `Rules.vue` 的规则向导“高级选项”步骤中，增加以下覆盖项：

| 字段 | 控件 | 说明 |
|------|------|------|
| 请求体大小限制 | `el-input-number` | 0 表示使用全局默认值 |
| 上游 keepalive 超时 | `el-input-number` | 0 表示使用全局默认值 |
| Server 响应头 | `el-select` | 使用全局默认值 / 隐藏 / 显示 |

HTTP 读取/写入/空闲超时是 per-server 属性，多个规则共享端口时无法按规则覆盖，因此不在规则向导中提供。

## 7. 数据模型

### 7.1 `global_config` 表

新增字段（SQLite）：

```sql
ALTER TABLE global_config ADD COLUMN request_body_max_size_mb INTEGER DEFAULT 0;
ALTER TABLE global_config ADD COLUMN http_read_timeout INTEGER DEFAULT 0;
ALTER TABLE global_config ADD COLUMN http_write_timeout INTEGER DEFAULT 0;
ALTER TABLE global_config ADD COLUMN http_idle_timeout INTEGER DEFAULT 0;
ALTER TABLE global_config ADD COLUMN upstream_keepalive_timeout INTEGER DEFAULT 0;
ALTER TABLE global_config ADD COLUMN server_tokens_hidden BOOLEAN DEFAULT FALSE;
```

### 7.2 `lb_rules` 表

新增字段（SQLite）：

```sql
ALTER TABLE lb_rules ADD COLUMN request_body_max_size_mb INTEGER DEFAULT 0;
ALTER TABLE lb_rules ADD COLUMN upstream_keepalive_timeout INTEGER DEFAULT 0;
ALTER TABLE lb_rules ADD COLUMN server_tokens_hidden INTEGER DEFAULT 0;  -- 0=默认, 1=隐藏, 2=显示
```

### 7.3 Go 模型

`GlobalConfig` / `UpdateConfigRequest` 增加：

```go
RequestBodyMaxSizeMB      int  `json:"request_body_max_size_mb"`
HTTPReadTimeout           int  `json:"http_read_timeout"`
HTTPWriteTimeout          int  `json:"http_write_timeout"`
HTTPIdleTimeout           int  `json:"http_idle_timeout"`
UpstreamKeepaliveTimeout  int  `json:"upstream_keepalive_timeout"`
ServerTokensHidden        bool `json:"server_tokens_hidden"`
```

`LbRule` / `CreateRuleRequest` / `UpdateRuleRequest` 增加：

```go
RequestBodyMaxSizeMB     int `json:"request_body_max_size_mb"`
UpstreamKeepaliveTimeout int `json:"upstream_keepalive_timeout"`
ServerTokensHidden       int `json:"server_tokens_hidden"` // 0=默认, 1=隐藏, 2=显示
```

## 8. 后端行为

### 8.1 配置读取

`internal/handlers/caddy.go` 的 `GetConfig` 和 `UpdateConfig` 增加新字段的读取、校验和保存。

`internal/handlers/rules.go` 的 `ListRules`、`GetRule`、`CreateRule`、`UpdateRule`、`DuplicateRule` 增加 `request_body_max_size_mb`、`upstream_keepalive_timeout`、`server_tokens_hidden` 的读写。

`internal/handlers/sync.go` 的 `GetSyncConfig` 和 `internal/services/services.go` 的 `applySyncData` 同步这些字段。

### 8.2 配置生成

`internal/services/caddy.go` 的 `GenerateCaddyConfig` 和 `GenerateSingleRuleCaddyConfig` 按以下规则应用：

1. **Caddy 日志**：沿用现有 `buildCaddyLogging` 函数。
2. **HTTP 服务器超时**：
   - 当全局值大于 0 时，写入每个 HTTP server 的 `read_timeout`、`write_timeout`、`idle_timeout`（Caddy 接受 Go duration 字符串，如 `"30s"`）。
3. **请求体大小限制**：
   - 全局值 > 0 或规则级值 > 0 时，在对应 HTTP 路由的 handler 链最前面插入 `{"handler": "request_body", "max_size": <bytes>}`。
   - 规则级值优先于全局值；0 表示不限制。
4. **上游 keepalive 超时**：
   - 全局值 > 0 或规则级值 > 0 时，在对应 HTTP 反向代理的 `transport http` 块中写入 `keepalive`（Caddy 接受 duration 字符串，如 `"60s"`）。
   - 规则级值优先于全局值；0 表示 Caddy 默认。
5. **Server 响应头**：
   - 规则级 `server_tokens_hidden`：
     - `1`（隐藏）→ 在路由响应处理中删除 `Server` 头，即 `header` handler 配置 `delete: ["Server"]`。
     - `2`（显示）→ 不处理，允许 Caddy 默认行为。
     - `0`（默认）→ 使用全局 `server_tokens_hidden` 的值。
   - 全局 `server_tokens_hidden` 为 true 时，所有未明确“显示”的规则统一删除 `Server` 头。

### 8.3 校验

- 路径必须绝对路径（`filepath.IsAbs`）。
- 日志级别必须是 `debug/info/warn/error`。
- 所有超时和大小字段必须 >= 0。
- 规则级 `server_tokens_hidden` 必须是 0/1/2。

## 9. 涉及文件

- `web/src/views/CaddyConfig.vue` — 新增 Caddy 全局配置卡片 + JSON 预览折叠。
- `web/src/views/settings/BasicSettings.vue` — 精简基础设置卡片内容。
- `web/src/views/Rules.vue` — 规则向导增加高级覆盖项。
- `internal/models/models.go` — 新增模型字段。
- `internal/db/db.go` — 新增表迁移。
- `internal/handlers/caddy.go` — 全局配置读写、校验。
- `internal/handlers/rules.go` — 规则 CRUD 读写。
- `internal/handlers/sync.go` — 同步配置读取。
- `internal/services/services.go` — 同步配置写入。
- `internal/services/caddy.go` — 生成 Caddy 配置时应用新字段。

## 10. 风险与后续

- `request_body` 是 Caddy 的 handler，需要放在路由 handler 链的最前面才能正确拦截大请求体。实现时要确保它在 `reverse_proxy` 之前。
- `server_tokens` 在 Caddy 中没有全局开关，通过 `header` handler 删除 `Server` 头会同时影响上游返回的 `Server` 头。如果业务依赖上游的 `Server` 头，需谨慎。
- HTTP 读取/写入/空闲超时是 per-server 属性，当前实现会对所有生成的 HTTP server 统一应用。未来如果支持多租户或不同端口不同策略，需要拆分到服务器级配置。
