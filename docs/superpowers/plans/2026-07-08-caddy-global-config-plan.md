注：本文档为历史设计稿，caddy_log_path 已于 v2.1.4 移除。

# Caddy 全局配置卡片实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在全局配置页面新增“Caddy 全局配置”卡片，集中管理 Caddy 日志、全局 HTTP 超时、请求体大小、上游 keepalive、Server 响应头默认值；在规则向导中提供规则级覆盖；并将 JSON 预览卡片改为默认折叠、按需加载。

**Architecture:** 后端在 `global_config` 和 `lb_rules` 表新增字段，通过 `internal/handlers/caddy.go` 和 `internal/handlers/rules.go` 读写；`internal/services/caddy.go` 在生成 Caddy JSON 时应用全局默认值，规则级字段覆盖默认值；前端在 `CaddyConfig.vue` 新增卡片和折叠预览，在 `BasicSettings.vue` 移除迁移字段，在 `Rules.vue` 增加高级选项覆盖。

**Tech Stack:** Go 1.26, Gin, SQLite, Vue 3 + TypeScript + Element Plus, Caddy v2.11.x

## Global Constraints

- 使用现有 API 风格：`/config` 用于全局配置，`/rules` 用于规则 CRUD。
- 所有新增数字字段必须 >= 0，布尔字段默认 false，规则级 `server_tokens_hidden` 使用 0/1/2（默认/隐藏/显示）。
- 后端使用 `COALESCE` 兼容旧数据，前端使用 `??` 或 `||` 提供默认值。
- 生成的 Caddy 配置中 duration 使用字符串格式如 `"30s"`，`request_body.max_size` 使用字节整数。
- 不引入新的 Caddy 插件或第三方依赖。

---

## Task 1: 数据库迁移

**Files:**
- Modify: `internal/db/db.go`
- Test: `go build ./cmd/server`（无专门测试，通过编译验证）

**Interfaces:**
- Consumes: 现有 `global_config` 和 `lb_rules` 表结构
- Produces: 新增列可被 `db.go` 的 `runMigrations` 创建

- [ ] **Step 1: 在 `createTables()` 的 `global_config` 表定义中新增字段**

在 `internal/db/db.go` 的 `global_config` 表 `CREATE TABLE` 语句中，找到 `caddy_log_size_mb INTEGER DEFAULT 100,` 之后追加：

```sql
request_body_max_size_mb INTEGER DEFAULT 0,
http_read_timeout INTEGER DEFAULT 0,
http_write_timeout INTEGER DEFAULT 0,
http_idle_timeout INTEGER DEFAULT 0,
upstream_keepalive_timeout INTEGER DEFAULT 0,
server_tokens_hidden BOOLEAN DEFAULT FALSE,
```

- [ ] **Step 2: 在 `runMigrations()` 中新增 `global_config` 列迁移**

在 `internal/db/db.go` 的 `runMigrations` 函数中，找到已有的 `caddy_log_size_mb` 迁移之后，追加：

```go
DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='request_body_max_size_mb'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE global_config ADD COLUMN request_body_max_size_mb INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='http_read_timeout'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE global_config ADD COLUMN http_read_timeout INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='http_write_timeout'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE global_config ADD COLUMN http_write_timeout INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='http_idle_timeout'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE global_config ADD COLUMN http_idle_timeout INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='upstream_keepalive_timeout'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE global_config ADD COLUMN upstream_keepalive_timeout INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='server_tokens_hidden'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE global_config ADD COLUMN server_tokens_hidden BOOLEAN DEFAULT FALSE")
}
```

- [ ] **Step 3: 在 `lb_rules` 表 `CREATE TABLE` 中新增规则级字段**

在 `internal/db/db.go` 的 `lb_rules` 表 `CREATE TABLE` 语句中，找到 `tcp_try_interval INTEGER DEFAULT 250,` 之后追加：

```sql
request_body_max_size_mb INTEGER DEFAULT 0,
upstream_keepalive_timeout INTEGER DEFAULT 0,
server_tokens_hidden INTEGER DEFAULT 0,
```

- [ ] **Step 4: 在 `runMigrations()` 中新增 `lb_rules` 列迁移**

在 `runMigrations` 中追加：

```go
DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='request_body_max_size_mb'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE lb_rules ADD COLUMN request_body_max_size_mb INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='upstream_keepalive_timeout'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE lb_rules ADD COLUMN upstream_keepalive_timeout INTEGER DEFAULT 0")
}

DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name='server_tokens_hidden'").Scan(&colCount)
if colCount == 0 {
	DB.Exec("ALTER TABLE lb_rules ADD COLUMN server_tokens_hidden INTEGER DEFAULT 0")
}
```

- [ ] **Step 5: 在 `migrateLbRulesPrimaryKey()` 中同步更新列清单**

在 `internal/db/db.go` 的 `migrateLbRulesPrimaryKey()` 中，创建新表时的列定义和 INSERT/SELECT 列清单都要包含上述三个字段。例如插入列中：

```sql
enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
host_header, ...
```

- [ ] **Step 6: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过，无错误。

- [ ] **Step 7: 提交**

```bash
git add internal/db/db.go
git commit -m "feat(db): add caddy global and rule-level config columns"
```

---

## Task 2: Go 数据模型更新

**Files:**
- Modify: `internal/models/models.go`
- Test: `go build ./cmd/server`

**Interfaces:**
- Consumes: 新增数据库列
- Produces: `GlobalConfig`、`UpdateConfigRequest`、`LbRule`、`CreateRuleRequest`、`UpdateRuleRequest` 的新字段

- [ ] **Step 1: 在 `GlobalConfig` 结构体中新增字段**

在 `internal/models/models.go` 的 `GlobalConfig` 结构体中，在 `CaddyLogSizeMB` 之后追加：

```go
RequestBodyMaxSizeMB     int  `json:"request_body_max_size_mb"`
HTTPReadTimeout          int  `json:"http_read_timeout"`
HTTPWriteTimeout         int  `json:"http_write_timeout"`
HTTPIdleTimeout          int  `json:"http_idle_timeout"`
UpstreamKeepaliveTimeout int  `json:"upstream_keepalive_timeout"`
ServerTokensHidden       bool `json:"server_tokens_hidden"`
```

- [ ] **Step 2: 在 `UpdateConfigRequest` 结构体中新增字段**

在 `UpdateConfigRequest` 结构体中，在 `CaddyLogSizeMB` 之后追加：

```go
RequestBodyMaxSizeMB     int  `json:"request_body_max_size_mb"`
HTTPReadTimeout          int  `json:"http_read_timeout"`
HTTPWriteTimeout         int  `json:"http_write_timeout"`
HTTPIdleTimeout          int  `json:"http_idle_timeout"`
UpstreamKeepaliveTimeout int  `json:"upstream_keepalive_timeout"`
ServerTokensHidden       bool `json:"server_tokens_hidden"`
```

- [ ] **Step 3: 在 `LbRule` 结构体中新增字段**

在 `LbRule` 结构体中，在 `TCPTryInterval` 之后追加：

```go
RequestBodyMaxSizeMB     int `json:"request_body_max_size_mb"`
UpstreamKeepaliveTimeout int `json:"upstream_keepalive_timeout"`
ServerTokensHidden       int `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
```

- [ ] **Step 4: 在 `CreateRuleRequest` 结构体中新增字段**

在 `CreateRuleRequest` 结构体中，在 `TCPTryInterval` 之后追加：

```go
RequestBodyMaxSizeMB     int `json:"request_body_max_size_mb"`
UpstreamKeepaliveTimeout int `json:"upstream_keepalive_timeout"`
ServerTokensHidden       int `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
```

- [ ] **Step 5: 在 `UpdateRuleRequest` 结构体中新增字段**

在 `UpdateRuleRequest` 结构体中，在 `TCPTryInterval` 之后追加：

```go
RequestBodyMaxSizeMB     int `json:"request_body_max_size_mb"`
UpstreamKeepaliveTimeout int `json:"upstream_keepalive_timeout"`
ServerTokensHidden       int `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
```

- [ ] **Step 6: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 7: 提交**

```bash
git add internal/models/models.go
git commit -m "feat(models): add caddy global and rule-level config fields"
```

---

## Task 3: 全局配置接口读写

**Files:**
- Modify: `internal/handlers/caddy.go`
- Test: `go build ./cmd/server`

**Interfaces:**
- Consumes: `GlobalConfig`、`UpdateConfigRequest` 的新字段
- Produces: `GET /config` 返回新字段，`PUT /config` 保存并校验新字段

- [ ] **Step 1: 在 `GetConfig` 的 SQL 查询中新增字段**

在 `internal/handlers/caddy.go` 的 `GetConfig` 函数中，把 SQL 查询扩展为：

```sql
SELECT id, caddy_config, dns_provider, COALESCE(dns_credentials,'') as dns_credentials,
       COALESCE(acme_email,'') as acme_email, COALESCE(cert_expiry_days,30) as cert_expiry_days,
       COALESCE(cert_renewal_days,30) as cert_renewal_days,
       COALESCE(cert_renewal_attempts,5) as cert_renewal_attempts,
       COALESCE(default_ca_provider_id,0) as default_ca_provider_id,
       log_level, access_log_enabled,
       COALESCE(caddy_log_path,'/app/logs/caddy.log') as caddy_log_path,
       COALESCE(caddy_log_level,'info') as caddy_log_level,
       COALESCE(caddy_log_size_mb,100) as caddy_log_size_mb,
       COALESCE(request_body_max_size_mb,0) as request_body_max_size_mb,
       COALESCE(http_read_timeout,0) as http_read_timeout,
       COALESCE(http_write_timeout,0) as http_write_timeout,
       COALESCE(http_idle_timeout,0) as http_idle_timeout,
       COALESCE(upstream_keepalive_timeout,0) as upstream_keepalive_timeout,
       COALESCE(server_tokens_hidden,FALSE) as server_tokens_hidden,
       is_master, COALESCE(master_url, '') as master_url, sync_interval,
       last_sync, updated_at
FROM global_config WHERE id = 1
```

并把 `Scan` 调用对应扩展为：

```go
&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider, &cfg.DNSCredentials,
&cfg.ACMEEmail, &cfg.CertExpiryDays, &cfg.CertRenewalDays, &cfg.CertRenewalAttempts, &cfg.DefaultCAProviderID,
&cfg.LogLevel, &cfg.AccessLogEnabled,
&cfg.CaddyLogPath, &cfg.CaddyLogLevel, &cfg.CaddyLogSizeMB,
&cfg.RequestBodyMaxSizeMB, &cfg.HTTPReadTimeout, &cfg.HTTPWriteTimeout, &cfg.HTTPIdleTimeout,
&cfg.UpstreamKeepaliveTimeout, &cfg.ServerTokensHidden,
&cfg.IsMaster, &cfg.MasterURL, &cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt
```

- [ ] **Step 2: 在 `UpdateConfig` 中增加校验**

在 `UpdateConfig` 的 `DefaultCAProviderID` 校验之后，追加：

```go
if req.RequestBodyMaxSizeMB < 0 {
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "request_body_max_size_mb must be >= 0"})
	return
}
if req.HTTPReadTimeout < 0 || req.HTTPWriteTimeout < 0 || req.HTTPIdleTimeout < 0 || req.UpstreamKeepaliveTimeout < 0 {
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "timeouts must be >= 0"})
	return
}
```

- [ ] **Step 3: 在 `UpdateConfig` 的 SQL 更新中新增字段**

在 `UPDATE global_config SET` 中，找到 `caddy_log_size_mb = COALESCE(?, caddy_log_size_mb),` 之后追加：

```sql
request_body_max_size_mb = COALESCE(?, request_body_max_size_mb),
http_read_timeout = COALESCE(?, http_read_timeout),
http_write_timeout = COALESCE(?, http_write_timeout),
http_idle_timeout = COALESCE(?, http_idle_timeout),
upstream_keepalive_timeout = COALESCE(?, upstream_keepalive_timeout),
server_tokens_hidden = COALESCE(?, server_tokens_hidden),
```

并把参数列表对应扩展，在 `req.CaddyLogSizeMB` 之后追加：

```go
req.RequestBodyMaxSizeMB, req.HTTPReadTimeout, req.HTTPWriteTimeout, req.HTTPIdleTimeout,
req.UpstreamKeepaliveTimeout, req.ServerTokensHidden,
```

- [ ] **Step 4: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 5: 提交**

```bash
git add internal/handlers/caddy.go
git commit -m "feat(handlers): read/write caddy global config fields"
```

---

## Task 4: 规则 CRUD 接口读写新字段

**Files:**
- Modify: `internal/handlers/rules.go`
- Test: `go build ./cmd/server`

**Interfaces:**
- Consumes: `LbRule`、`CreateRuleRequest`、`UpdateRuleRequest` 的新字段
- Produces: 规则列表/详情/创建/更新/复制接口包含新字段

- [ ] **Step 1: 在 `ListRules` 的 SQL 和 Scan 中新增字段**

在 `internal/handlers/rules.go` 的 `ListRules` 中，SELECT 列在 `COALESCE(tcp_try_interval,250)` 之后追加：

```sql
COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
```

声明变量：

```go
var requestBodyMaxSizeMB, upstreamKeepaliveTimeout, serverTokensHidden int
```

调整 `rows.Scan` 顺序，在读取 `tcpTryInterval` 之后读取这三个字段，并赋值给 `r`：

```go
r.TCPHealthCheckPort = tcpHealthCheckPort
r.TCPTryDuration = tcpTryDuration
r.TCPTryInterval = tcpTryInterval
r.RequestBodyMaxSizeMB = requestBodyMaxSizeMB
r.UpstreamKeepaliveTimeout = upstreamKeepaliveTimeout
r.ServerTokensHidden = serverTokensHidden
```

- [ ] **Step 2: 在 `GetRule` 中新增字段**

在 `GetRule` 的 SELECT 中，在 `COALESCE(tcp_try_interval,250)` 之后追加三个字段；在 Scan 中读取并赋值给 `r`。

- [ ] **Step 3: 在 `GetRuleCaddyConfig` 中新增字段**

在 `GetRuleCaddyConfig` 的匿名结构体中新增：

```go
RequestBodyMaxSizeMB     int
UpstreamKeepaliveTimeout int
ServerTokensHidden       int
```

SELECT 和 Scan 中对应添加。

- [ ] **Step 4: 在 `CreateRule` 中保存新字段**

INSERT 语句的列中增加：

```sql
request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
```

VALUES 中增加：

```go
req.RequestBodyMaxSizeMB, req.UpstreamKeepaliveTimeout, req.ServerTokensHidden,
```

创建 `ruleConfig` 时赋值：

```go
RequestBodyMaxSizeMB:     req.RequestBodyMaxSizeMB,
UpstreamKeepaliveTimeout: req.UpstreamKeepaliveTimeout,
ServerTokensHidden:       req.ServerTokensHidden,
```

- [ ] **Step 5: 在 `UpdateRule` 中读取和更新新字段**

在 `UpdateRule` 读取现有规则的 SELECT 中增加三个字段；在设置更新值时，如果请求值为 0 则保留现有值（参考现有 `if req.TCPHealthCheckPort == 0` 逻辑）。

UPDATE 动态 SQL 中追加：

```go
query += "request_body_max_size_mb = ?, "
args = append(args, req.RequestBodyMaxSizeMB)
query += "upstream_keepalive_timeout = ?, "
args = append(args, req.UpstreamKeepaliveTimeout)
query += "server_tokens_hidden = ?, "
args = append(args, req.ServerTokensHidden)
```

- [ ] **Step 6: 在 `DuplicateRule` 中复制新字段**

SELECT 中增加三个字段，读取后赋值给 `rule`，INSERT 中写入。

- [ ] **Step 7: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 8: 提交**

```bash
git add internal/handlers/rules.go
git commit -m "feat(rules): persist rule-level caddy config overrides"
```

---

## Task 5: 同步接口包含新字段

**Files:**
- Modify: `internal/handlers/sync.go`, `internal/services/services.go`
- Test: `go build ./cmd/server`

**Interfaces:**
- Consumes: `GlobalConfig` 和 `LbRule` 的新字段
- Produces: 主从同步数据包含新字段

- [ ] **Step 1: 在 `GetSyncConfig` 的 SQL 和 Scan 中新增字段**

在 `internal/handlers/sync.go` 的 `GetSyncConfig` 中，SELECT 的 `lb_rules` 列清单在 `COALESCE(tcp_try_interval,250)` 之后追加：

```sql
COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
```

声明变量并赋值给 `r`。

- [ ] **Step 2: 在 `applySyncData` 的 INSERT 中写入新字段**

在 `internal/services/services.go` 的 `applySyncData` 中，INSERT 列清单和 VALUES 参数都要包含 `request_body_max_size_mb`、`upstream_keepalive_timeout`、`server_tokens_hidden`。

- [ ] **Step 3: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 4: 提交**

```bash
git add internal/handlers/sync.go internal/services/services.go
git commit -m "feat(sync): include new caddy config fields in sync"
```

---

## Task 6: Caddy 配置生成 — 全局超时和日志

**Files:**
- Modify: `internal/services/caddy.go`
- Test: `go build ./cmd/server`；手动验证 JSON 生成

**Interfaces:**
- Consumes: `global_config` 全局字段
- Produces: 生成的 Caddy JSON 中每个 HTTP server 包含 `read_timeout`、`write_timeout`、`idle_timeout`；日志使用全局配置

- [ ] **Step 1: 在 `GenerateCaddyConfig` 中读取新字段**

在 `internal/services/caddy.go` 的 `GenerateCaddyConfig` 中，把查询 `global_config` 的 SQL 扩展为：

```sql
SELECT COALESCE(dns_provider,''), COALESCE(acme_email,''), is_master,
       COALESCE(caddy_log_path,'/app/logs/caddy.log'), COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
       COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,0), COALESCE(http_write_timeout,0),
       COALESCE(http_idle_timeout,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,FALSE)
FROM global_config WHERE id = 1
```

Scan 读取到对应变量：

```go
var requestBodyMaxSizeMB, httpReadTimeout, httpWriteTimeout, httpIdleTimeout, upstreamKeepaliveTimeout int
var serverTokensHidden bool
```

- [ ] **Step 2: 在生成 HTTP server 时应用全局超时**

在 `httpServersByPort` 循环中，创建 `server` 时加入超时字段：

```go
server := map[string]interface{}{
	"listen": []string{fmt.Sprintf(":%d", port)},
}
if httpReadTimeout > 0 {
	server["read_timeout"] = fmt.Sprintf("%ds", httpReadTimeout)
}
if httpWriteTimeout > 0 {
	server["write_timeout"] = fmt.Sprintf("%ds", httpWriteTimeout)
}
if httpIdleTimeout > 0 {
	server["idle_timeout"] = fmt.Sprintf("%ds", httpIdleTimeout)
}
```

- [ ] **Step 3: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 4: 提交**

```bash
git add internal/services/caddy.go
git commit -m "feat(caddy): apply global http timeouts and read config fields"
```

---

## Task 7: Caddy 配置生成 — 规则级 request_body、keepalive、server_tokens

**Files:**
- Modify: `internal/services/caddy.go`
- Test: `go build ./cmd/server`；手动验证规则配置 JSON

**Interfaces:**
- Consumes: 全局 `requestBodyMaxSizeMB`、`upstreamKeepaliveTimeout`、`serverTokensHidden` 和规则级字段
- Produces: 每个 HTTP 路由包含 `request_body` handler，每个 HTTP 反向代理 transport 包含 `keepalive`，`header` handler 按需删除 `Server`

- [ ] **Step 1: 在 `GenerateRouteObject` 中实现规则级应用**

`GenerateRouteObject` 接收 `SingleRuleConfig`，需要知道全局默认值。为简化，把全局默认值在调用处计算为 `effectiveRequestBodyMaxSizeMB`、`effectiveUpstreamKeepaliveTimeout`、`effectiveServerTokensHidden` 后传入 `SingleRuleConfig`。或者，在 `SingleRuleConfig` 中增加全局字段。

在 `SingleRuleConfig` 结构体中新增：

```go
RequestBodyMaxSizeMB     int
UpstreamKeepaliveTimeout int
ServerTokensHidden       int // 0=default, 1=hide, 2=show
// 全局默认值
GlobalRequestBodyMaxSizeMB     int
GlobalUpstreamKeepaliveTimeout int
GlobalServerTokensHidden       bool
```

- [ ] **Step 2: 在 `GenerateRouteObject` 中插入 request_body handler**

在 HTTP 路由 handler 链生成后，如果规则级或全局的请求体大小限制 > 0，则在 handler 链最前面插入：

```go
maxSize := rule.RequestBodyMaxSizeMB
if maxSize <= 0 {
	maxSize = rule.GlobalRequestBodyMaxSizeMB
}
if maxSize > 0 {
	handleChain = append([]interface{}{
		map[string]interface{}{
			"handler":  "request_body",
			"max_size": maxSize * 1024 * 1024,
		},
	}, handleChain...)
}
```

- [ ] **Step 3: 在 `GenerateRouteObject` 中设置 upstream keepalive**

在 HTTP 反向代理的 `transport http` 块中，如果规则级或全局 keepalive > 0，则写入：

```go
keepalive := rule.UpstreamKeepaliveTimeout
if keepalive <= 0 {
	keepalive = rule.GlobalUpstreamKeepaliveTimeout
}
if keepalive > 0 {
	transportConfig["keepalive"] = fmt.Sprintf("%ds", keepalive)
}
```

- [ ] **Step 4: 在 `GenerateRouteObject` 中处理 Server 响应头**

根据规则级 `server_tokens_hidden` 和全局默认值决定是否需要删除 `Server` 头：

```go
shouldHide := rule.GlobalServerTokensHidden
switch rule.ServerTokensHidden {
case 1:
	shouldHide = true
case 2:
	shouldHide = false
}
if shouldHide {
	handleChain = append(handleChain, map[string]interface{}{
		"handler": "headers",
		"response": map[string]interface{}{
			"delete": []string{"Server"},
		},
	})
}
```

- [ ] **Step 5: 在 `GenerateCaddyConfig` 中把全局默认值传入规则配置**

在 `httpServersByPort` 循环中，构建 `SingleRuleConfig` 时传入：

```go
ruleConfig := SingleRuleConfig{
	// ... existing fields ...
	RequestBodyMaxSizeMB:     r.RequestBodyMaxSizeMB,
	UpstreamKeepaliveTimeout: r.UpstreamKeepaliveTimeout,
	ServerTokensHidden:       r.ServerTokensHidden,
	GlobalRequestBodyMaxSizeMB:     requestBodyMaxSizeMB,
	GlobalUpstreamKeepaliveTimeout: upstreamKeepaliveTimeout,
	GlobalServerTokensHidden:       serverTokensHidden,
}
```

- [ ] **Step 6: 在 `GenerateSingleRuleCaddyConfig` 中传入相同默认值**

该函数用于单条规则预览，从调用者传入全局默认值或读取数据库一次后传入。

- [ ] **Step 7: 验证编译**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 8: 提交**

```bash
git add internal/services/caddy.go
git commit -m "feat(caddy): apply per-rule request_body, keepalive and server_tokens overrides"
```

---

## Task 8: 前端基础设置页精简

**Files:**
- Modify: `web/src/views/settings/BasicSettings.vue`
- Test: `npm run build`

**Interfaces:**
- Consumes: 现有 `settings` prop
- Produces: 移除 Caddy 日志和重载按钮后更精简的页面

- [ ] **Step 1: 移除 Caddy 日志字段**

在 `BasicSettings.vue` 的表单中删除以下字段：
- Caddy 日志路径
- Caddy 日志级别
- 日志滚动大小

- [ ] **Step 2: 移除重载 Caddy 按钮和危险操作卡片**

删除整个 `action-card` 卡片以及 `handleReloadCaddy` 函数和 `RefreshRight`、`WarningFilled` 图标引用。

- [ ] **Step 3: 移除 `handleSave` 中不再保存的字段**

`handleSave` 只提交：

```ts
{
  log_level: settings.value.log_level,
  access_log_enabled: settings.value.access_log_enabled,
}
```

- [ ] **Step 4: 验证构建**

```bash
cd web && npm run build
```

Expected: 构建成功。

- [ ] **Step 5: 提交**

```bash
git add web/src/views/settings/BasicSettings.vue
git commit -m "feat(ui): move caddy log and reload controls from basic settings"
```

---

## Task 9: 前端全局配置页新增 Caddy 全局配置卡片和折叠 JSON 预览

**Files:**
- Modify: `web/src/views/CaddyConfig.vue`
- Test: `npm run build`；在浏览器中验证展开/折叠

**Interfaces:**
- Consumes: `GET /config` 和 `PUT /config` 返回/接收的新字段，以及 `POST /config/reload`
- Produces: 可编辑的 Caddy 全局配置卡片和按需加载的 JSON 预览

- [ ] **Step 1: 新增全局配置表单状态**

在 `<script setup>` 中定义：

```ts
const caddySettings = ref({
  caddy_log_path: '/app/logs/caddy.log',
  caddy_log_level: 'info',
  caddy_log_size_mb: 100,
  request_body_max_size_mb: 0,
  http_read_timeout: 0,
  http_write_timeout: 0,
  http_idle_timeout: 0,
  upstream_keepalive_timeout: 0,
  server_tokens_hidden: false,
})

const saving = ref(false)
const activeCollapse = ref<string[]>([])
```

- [ ] **Step 2: 修改 `fetchCaddyConfig` 并新增全局配置获取**

```ts
const fetchCaddyConfig = async () => {
  loading.value = true
  try {
    const res = await request.get('/caddy/config')
    if (res.data) {
      caddyConfigData.value = res.data
    }
  } catch (e: any) {
    caddyConfigData.value = null
  } finally {
    loading.value = false
  }
}

const fetchGlobalConfig = async () => {
  try {
    const res = await request.get('/config')
    if (res.data) {
      caddySettings.value = {
        caddy_log_path: res.data.caddy_log_path || '/app/logs/caddy.log',
        caddy_log_level: res.data.caddy_log_level || 'info',
        caddy_log_size_mb: res.data.caddy_log_size_mb ?? 100,
        request_body_max_size_mb: res.data.request_body_max_size_mb ?? 0,
        http_read_timeout: res.data.http_read_timeout ?? 0,
        http_write_timeout: res.data.http_write_timeout ?? 0,
        http_idle_timeout: res.data.http_idle_timeout ?? 0,
        upstream_keepalive_timeout: res.data.upstream_keepalive_timeout ?? 0,
        server_tokens_hidden: res.data.server_tokens_hidden ?? false,
      }
    }
  } catch (e: any) {
    console.error('Failed to fetch global config:', e)
  }
}
```

- [ ] **Step 3: 新增保存和重载函数**

```ts
const handleSave = async () => {
  saving.value = true
  try {
    await request.put('/config', caddySettings.value)
    ElMessage.success('保存成功')
  } catch (e: any) {
    ElMessage.error('保存失败')
  } finally {
    saving.value = false
  }
}

const handleReloadCaddy = async () => {
  try {
    await ElMessageBox.confirm('此操作将重新加载 Caddy 配置，是否继续？', '确认重载', {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning',
    })
    await request.post('/config/reload')
    ElMessage.success('Caddy 配置已重载')
  } catch (error: any) {
    if (error !== 'cancel') {
      console.error('Failed to reload Caddy:', error)
    }
  }
}
```

- [ ] **Step 4: 在模板中新增 Caddy 全局配置卡片**

在 `<el-row>` 的最上方新增一个 `<el-col :span="24">` 卡片，包含左侧表单和右侧操作按钮。示例结构：

```vue
<el-card class="settings-card">
  <template #header>
    <div class="card-header">
      <div class="card-title"><el-icon><Setting /></el-icon><span>Caddy 全局配置</span></div>
    </div>
  </template>
  <el-row :gutter="24">
    <el-col :span="18">
      <el-form :model="caddySettings" label-width="160px">
        <!-- 表单字段 -->
      </el-form>
    </el-col>
    <el-col :span="6" class="action-col">
      <el-button type="primary" :loading="saving" @click="handleSave">保存</el-button>
      <el-button type="warning" @click="handleReloadCaddy">重载 Caddy</el-button>
    </el-col>
  </el-row>
</el-card>
```

- [ ] **Step 5: 将 JSON 预览改为折叠并按需加载**

把 JSON 预览卡片用 `el-collapse` 包裹：

```vue
<el-collapse v-model="activeCollapse" @change="onCollapseChange">
  <el-collapse-item name="json-preview" title="Caddy 配置预览 (JSON)">
    <el-card class="config-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Document /></el-icon>
            <span>Caddy 配置预览 (JSON)</span>
          </div>
          <div class="card-actions">
            <el-button size="small" @click="refreshConfig" :loading="loading" :disabled="!isJsonExpanded">
              <el-icon><RefreshRight /></el-icon>刷新
            </el-button>
          </div>
        </div>
      </template>
      <div v-loading="loading" class="config-preview">
        <VueJsonPretty v-if="caddyConfigData" :data="caddyConfigData" :collapsed="false" show-length copyable :show-line="false" />
        <pre v-else>{{ '点击展开以加载配置' }}</pre>
      </div>
    </el-card>
  </el-collapse-item>
</el-collapse>
```

并定义：

```ts
const isJsonExpanded = computed(() => activeCollapse.value.includes('json-preview'))

const onCollapseChange = (val: string[]) => {
  if (val.includes('json-preview') && !caddyConfigData.value) {
    fetchCaddyConfig()
  }
}

onMounted(() => {
  fetchGlobalConfig()
})
```

移除原来的 `onMounted(fetchCaddyConfig)`。

- [ ] **Step 6: 导入所需图标和组件**

确保导入 `Setting`、`ElMessage`、`ElMessageBox`。移除未使用的 `Cpu` 或保留（标题图标）。

- [ ] **Step 7: 验证构建**

```bash
cd web && npm run build
```

Expected: 构建成功。

- [ ] **Step 8: 提交**

```bash
git add web/src/views/CaddyConfig.vue
git commit -m "feat(ui): caddy global config card and collapsible json preview"
```

---

## Task 10: 前端规则向导增加高级覆盖字段

**Files:**
- Modify: `web/src/views/Rules.vue`
- Test: `npm run build`

**Interfaces:**
- Consumes: `GET /rules` 和 `POST /rules` 返回/接收的新字段
- Produces: 规则向导“高级选项”中可编辑的规则级覆盖字段

- [ ] **Step 1: 在 `Rule` 接口中新增字段**

在 `Rules.vue` 的 `interface Rule` 中追加：

```ts
request_body_max_size_mb?: number
upstream_keepalive_timeout?: number
server_tokens_hidden?: number
```

- [ ] **Step 2: 在 `wizardForm` 初始化中新增字段**

在 `wizardForm` 的 `reactive<Rule>({ ... })` 中追加：

```ts
request_body_max_size_mb: 0,
upstream_keepalive_timeout: 0,
server_tokens_hidden: 0,
```

- [ ] **Step 3: 在 `openWizard` 中回填规则值**

```ts
request_body_max_size_mb: (rule as any).request_body_max_size_mb || 0,
upstream_keepalive_timeout: (rule as any).upstream_keepalive_timeout || 0,
server_tokens_hidden: (rule as any).server_tokens_hidden || 0,
```

- [ ] **Step 4: 在规则向导的高级选项步骤中增加表单字段**

在 `<el-form>` 中合适位置（例如连接重试之后）添加：

```vue
<el-divider content-position="left" class="compact-divider">Caddy 全局覆盖</el-divider>

<el-form-item label="请求体大小">
  <el-input-number v-model="wizardForm.request_body_max_size_mb" :min="0" :max="10240" controls-position="right" style="width: 120px;" />
  <span class="form-tip-inline">MB，0 表示使用全局默认值</span>
</el-form-item>

<el-form-item label="上游 keepalive">
  <el-input-number v-model="wizardForm.upstream_keepalive_timeout" :min="0" :max="3600" controls-position="right" style="width: 120px;" />
  <span class="form-tip-inline">秒，0 表示使用全局默认值</span>
</el-form-item>

<el-form-item label="Server 响应头">
  <el-select v-model="wizardForm.server_tokens_hidden" style="width: 180px;">
    <el-option :value="0" label="使用全局默认值" />
    <el-option :value="1" label="隐藏" />
    <el-option :value="2" label="显示" />
  </el-select>
</el-form-item>
```

- [ ] **Step 5: 在 `submitWizard` 提交对象中包含新字段**

在 `submitWizard` 的 `payload` 中追加：

```ts
request_body_max_size_mb: wizardForm.request_body_max_size_mb || 0,
upstream_keepalive_timeout: wizardForm.upstream_keepalive_timeout || 0,
server_tokens_hidden: wizardForm.server_tokens_hidden || 0,
```

- [ ] **Step 6: 在规则详情弹窗中展示新字段**

在 `viewConfig` 或规则详情展示区域，增加 `request_body_max_size_mb`、`upstream_keepalive_timeout`、`server_tokens_hidden` 的描述项，例如：

```vue
<el-descriptions-item label="请求体大小">{{ (ruleConfig.request_body_max_size_mb || 0) > 0 ? ruleConfig.request_body_max_size_mb + 'MB' : '全局默认' }}</el-descriptions-item>
<el-descriptions-item label="上游 keepalive">{{ (ruleConfig.upstream_keepalive_timeout || 0) > 0 ? ruleConfig.upstream_keepalive_timeout + 's' : '全局默认' }}</el-descriptions-item>
<el-descriptions-item label="Server 头">{{ serverTokensLabel(ruleConfig.server_tokens_hidden) }}</el-descriptions-item>
```

- [ ] **Step 7: 验证构建**

```bash
cd web && npm run build
```

Expected: 构建成功。

- [ ] **Step 8: 提交**

```bash
git add web/src/views/Rules.vue
git commit -m "feat(ui): rule-level overrides for request body, keepalive and server tokens"
```

---

## Task 11: 端到端验证

**Files:**
- 全部已修改文件
- Test: 手动或半自动验证

- [ ] **Step 1: 后端构建**

```bash
go build ./cmd/server
```

Expected: 编译通过。

- [ ] **Step 2: 前端构建**

```bash
cd web && npm run build
```

Expected: 构建成功。

- [ ] **Step 3: 手动验证全局配置卡片**

1. 打开“全局配置”页面。
2. 确认“Caddy 全局配置”卡片显示新字段。
3. 修改“请求体大小限制”并保存，确认接口返回成功。
4. 刷新页面，确认字段值已持久化。
5. 确认 JSON 预览默认折叠，展开后加载完整 JSON。

- [ ] **Step 4: 手动验证规则向导覆盖**

1. 创建/编辑一条 HTTP 规则。
2. 在高级选项中设置“请求体大小”和“上游 keepalive”。
3. 保存后查看规则配置 JSON 预览，确认包含 `request_body` 和 `transport http.keepalive`。

- [ ] **Step 5: 手动验证 server_tokens**

1. 在全局配置中开启“隐藏 Server 响应头”。
2. 创建一条 HTTP 规则，不修改 Server 头选项。
3. 查看生成的 Caddy 配置，确认包含删除 `Server` 的 `headers` handler。

- [ ] **Step 6: 提交最终验证状态**

如果一切正常，可以推送或告知用户已完成。若需要提交，执行：

```bash
git status
# 确保工作区干净
```

---

## 自我检查

- **Spec 覆盖**：每个 spec 要求都对应到任务：数据库迁移（Task 1）、模型（Task 2）、全局配置接口（Task 3）、规则接口（Task 4）、同步（Task 5）、Caddy 生成超时（Task 6）、Caddy 生成规则覆盖（Task 7）、基础设置页精简（Task 8）、全局配置页卡片和折叠预览（Task 9）、规则向导覆盖（Task 10）、验证（Task 11）。
- **Placeholder 扫描**：无 TBD/TODO；每个步骤包含代码片段和命令。
- **类型一致性**：`request_body_max_size_mb`、`http_read_timeout` 等字段在后端为 int（秒/MB），前端为 number；`server_tokens_hidden` 在后端规则级为 int（0/1/2），全局为 bool。
