# Lazy Balancer V2 - 详细架构

> **已归档**：本文为历史设计文档，不代表当前实现（当前：首次访问初始化管理员、集群角色存于数据库、凭证在页面配置）。

**文档版本**: 1.0
**更新日期**: 2026-04-17
**目的**: 函数级代码细节，支持复杂 Bug 调试和深度修改

---

## 1. 入口点 (cmd/server/main.go)

### 1.1 main 函数流程

```go
func main() {
    // 1. 解析命令行参数
    configPath := flag.String("config", "", "Config file path")
    initDB := flag.Bool("init", false, "Initialize database")
    flag.Parse()

    // 2. 加载配置
    cfg := config.Load(*configPath)

    // 3. 初始化数据库
    if err := db.Initialize(cfg.DataDir); err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }

    // 4. 初始化服务
    caddyService := services.NewCaddyService(cfg.CaddyAdminURL)
    metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
    nodeService := services.NewNodeService()
    syncService := services.NewSyncService()

    // 5. 初始化处理器
    h := handlers.NewHandlers(cfg, caddyService, metricsService, nodeService, syncService)

    // 6. 应用启动时配置
    if err := h.ApplyConfigOnStartup(); err != nil {
        log.Printf("Warning: Failed to apply Caddy config on startup: %v", err)
    }

    // 7. 设置路由
    router := middleware.SetupRouter(h, cfg)

    // 8. 启动后台服务
    go metricsService.Start()
    go nodeService.StartHeartbeat(cfg)
    go syncService.Start()

    // 9. 启动 HTTP 服务器
    addr := fmt.Sprintf(":%d", cfg.Port)
    log.Printf("Starting lazy-balancer-v2 %s on %s", version, addr)
    if err := router.Run(addr); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
```

---

## 2. 数据库 (internal/db/db.go)

### 2.1 核心变量

```go
var DB *sql.DB  // 全局数据库连接
```

### 2.2 Initialize 函数

**位置**: `db.go:16-54`

**功能**: 初始化数据库连接和表结构

```go
func Initialize(dataDir string) error {
    // 创建数据目录
    os.MkdirAll(dataDir, 0755)

    // SQLite 连接参数: WAL 模式, 外键启用
    db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_foreign_keys=on")

    // 创建表
    createTables()

    // 运行迁移
    runMigrations()

    // 确保全局配置行存在
    DB.QueryRow("SELECT COUNT(*) FROM global_config")
    if configCount == 0 {
        DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')")
    }
}
```

### 2.3 表结构

#### lb_rules (负载规则表)

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | - | 旧主键 (迁移中) |
| caddy_id | VARCHAR(20) | **PRIMARY KEY** | 新主键 (lb_xxxxxxxxx) |
| name | VARCHAR(100) | NOT NULL | 规则名称 |
| protocol | VARCHAR(10) | NOT NULL | http/https/tcp |
| domain | VARCHAR(255) | - | 域名 (逗号分隔) |
| listen_port | INTEGER | NOT NULL | 监听端口 |
| strategy | VARCHAR(20) | DEFAULT 'round_robin' | 负载策略 |
| health_check_timeout | INTEGER | DEFAULT 5 | 超时时间 (秒) |
| health_check_unhealthy_threshold | INTEGER | DEFAULT 3 | 失败阈值 |
| enable_active_health_check | BOOLEAN | DEFAULT FALSE | 启用主动检查 |
| enabled | BOOLEAN | DEFAULT TRUE | 启用状态 |

#### upstreams (上游服务器表)

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY | - |
| rule_id | VARCHAR(20) | FOREIGN KEY → lb_rules.caddy_id | 关联规则 |
| host | VARCHAR(255) | NOT NULL | 地址 (IP/域名) |
| port | INTEGER | NOT NULL | 端口 |
| weight | INTEGER | DEFAULT 1 | 权重 |
| enabled | BOOLEAN | DEFAULT TRUE | 启用状态 |

### 2.4 迁移 (runMigrations)

**位置**: `db.go:237-354`

关键迁移:
1. `display_name` 列添加 (users 表)
2. `is_enabled` 列添加 (users 表)
3. `caddy_id` 列添加 (lb_rules 表)
4. **表重建**: `migrateLbRulesPrimaryKey` - 将主键从 `id` 改为 `caddy_id`

### 2.5 migrateLbRulesPrimaryKey 函数

**位置**: `db.go:357-517`

**功能**: 将 lb_rules 和 upstreams 表的主键从自增 ID 改为 caddy_id

**流程**:
1. 禁用外键检查
2. 创建新表 lb_rules_new (caddy_id 作为主键)
3. 复制数据
4. 删除旧表，重命名新表
5. 同样处理 upstreams 表
6. 提交事务，启用外键

---

## 3. 数据模型 (internal/models/models.go)

### 3.1 LbRule 结构体

**位置**: `models.go:32-68`

```go
type LbRule struct {
    ID                            int
    CaddyID                       string       `json:"caddy_id"`
    Name                          string       `json:"name"`
    Description                   string       `json:"description"`
    Protocol                      string       `json:"protocol"`
    Domain                        string       `json:"domain"`
    ListenPort                    int          `json:"listen_port"`
    Strategy                      string       `json:"strategy"`
    DynamicDNS                    bool         `json:"dynamic_dns"`
    EnableDnsServer               bool         `json:"enable_dns_server"`
    DnsServer                     string       `json:"dns_server"`
    DnsFamily                     string       `json:"dns_family"`
    HealthCheckPath               string       `json:"health_check_path"`
    HealthCheckInterval           int          `json:"health_check_interval"`
    HealthCheckTimeout            int          `json:"health_check_timeout"`
    HealthCheckUnhealthyThreshold int          `json:"health_check_unhealthy_threshold"`
    HealthCheckHealthyThreshold   int          `json:"health_check_healthy_threshold"`
    EnableActiveHealthCheck       bool         `json:"enable_active_health_check"`
    Upstreams                     []Upstream    `json:"upstreams"`
    HostHeader                    string       `json:"host_header"`
    EnableTLS                     bool         `json:"enable_tls"`
    TLSSource                     string       `json:"tls_source"`
    ACMEConfigID                  int          `json:"acme_config_id"`
    CAProviderID                  int          `json:"ca_provider_id"`
    TLSCert                       string       `json:"tls_cert,omitempty"`
    TLSKey                        string       `json:"tls_key,omitempty"`
    TLSHTTPRedirect               bool         `json:"tls_http_redirect"`
    TLSHSTS                       int          `json:"tls_hsts"`
    EnableCompress                bool         `json:"enable_compress"`
    CompressTypes                 string       `json:"compress_types"`
    Enabled                       bool         `json:"enabled"`
    CreatedBy                     int          `json:"created_by"`
    UpdatedBy                     int          `json:"updated_by"`
    CreatedAt                     time.Time    `json:"created_at"`
    UpdatedAt                     sql.NullTime `json:"updated_at"`
}
```

**TLS 字段说明（当前行为）**:
- `enable_tls`: 是否启用 TLS。
- `tls_source`: 证书来源，`manual`（手动上传）或 `acme_dns`（ACME + DNS 自动签发）。
- `acme_config_id`: 引用的 DNS 提供商配置（`certificate_configs.id`）。
- `ca_provider_id`: 选择的 CA Provider（`ca_providers.id`），`0` 表示使用系统默认。
- `tls_cert` / `tls_key`: 手动模式下的证书与私钥。
- 历史字段 `tls_auto_cert`（布尔值）与 `tls_email`（规则级邮箱）已废弃：ACME 邮箱现在全局配置在 `global_config.acme_email`，CA Provider 在「系统设置 / 免费证书」的 CA Providers 卡片中管理。

### 3.2 Upstream 结构体

**位置**: `models.go:86-98`

```go
type Upstream struct {
    ID         int    `json:"id"`
    RuleID     string `json:"rule_id"`
    Host       string `json:"host"`
    Port       int    `json:"port"`
    Weight     int    `json:"weight"`
    Domain     string `json:"domain"`
    DynamicDNS bool   `json:"dynamic_dns"`
    Enabled    bool   `json:"enabled"`
    Protocol   string `json:"protocol"`
    DnsServer  string `json:"dns_server"`
}
```

---

## 4. Caddy 编排 (internal/services/caddy.go)

### 4.1 CaddyService 结构体

**位置**: `caddy.go:20-26`

```go
type CaddyService struct {
    adminURL     string                    // Caddy Admin API URL
    client       *http.Client              // HTTP 客户端 (30s timeout)
    mu           sync.Mutex               // 互斥锁 (ApplyConfig/Rollback)
    backupConfig map[string]interface{}   // 备份配置 (用于回滚)
}
```

### 4.2 GenerateCaddyID 函数

**位置**: `caddy.go:37-51`

**功能**: 生成唯一的 caddy_id

```go
func GenerateCaddyID() (string, error) {
    // 格式: lb_ + 10位随机字符 = 13位
    // 字符集: abcdefghijklmnopqrstuvwxyz0123456789
}
```

### 4.3 GenerateCaddyConfig 函数

**位置**: `caddy.go:500-600` (approximately)

**功能**: 从数据库生成完整 Caddy 配置

```go
func GenerateCaddyConfig() map[string]interface{} {
    // 1. 从数据库读取所有 enabled=1 的规则
    // 2. 按协议和端口分组
    //    - httpServersByPort: HTTP 规则
    //    - tcpServersByPort: TCP 规则
    // 3. 为每个服务器生成路由 (调用 GenerateRouteObject)
    // 4. 组装完整配置 (包含 admin, apps.http.servers 等)
}
```

### 4.4 GenerateSingleRuleCaddyConfig 函数

**位置**: `caddy.go:1822-2000` (approximately)

**功能**: 为单个规则生成 Caddy 路由配置

**流程**:

```go
func GenerateSingleRuleCaddyConfig(rule SingleRuleConfig) map[string]interface{} {
    // 1. 默认策略为 round_robin
    if rule.Strategy == "" {
        rule.Strategy = "round_robin"
    }

    // 2. 分割域名
    domainHosts := strings.Split(rule.Domain, ",")

    // 3. 过滤启用的上游
    enabledUpstreams := filter(u => u.Enabled)

    // 4. 构建 handle chain
    //    - encode (压缩)
    //    - headers (Host 头)
    //    - reverse_proxy (负载均衡)

    // 5. 构建健康检查配置
    //    - passive: fail_duration = interval * 3, max_fails = threshold
    //    - active: (可选) uri, timeout, interval

    // 6. 构建 transport (如果需要 TLS 或 DNS)
}
```

### 4.5 ApplyConfigFromTx 函数

**功能**: 从未提交事务的可见状态生成并加载完整 Caddy 配置

```go
func (s *CaddyService) ApplyConfigFromTx(tx *sql.Tx) error {
    // 1. 获取 Caddy 配置写锁
    // 2. 从 tx 读取启用规则及关联数据并生成完整配置
    // 3. POST 完整配置到 /load，由 Caddy 校验并加载
    // 4. 失败时返回错误，由处理器回滚事务并恢复运行时快照
}
```

### 4.6 ValidateRouteMergedConfig 函数

**位置**: `caddy.go:600-670` (approximately)

**功能**: 验证路由配置合法性 (不实际应用)

```go
func (s *CaddyService) ValidateRouteMergedConfig(serverName string, routeConfig map[string]interface{}, uniqueID string) error {
    // 1. 获取当前服务器配置
    // 2. 复制配置并将新路由预置到 routes 数组首位
    // 3. POST 到 /load?validate=true 验证
    // 4. 验证失败返回具体错误
}
```

---

## 5. API 处理器 (internal/handlers/handlers.go)

### 5.1 Handlers 结构体

**位置**: `handlers.go` (approx line 100-150)

```go
type Handlers struct {
    cfg            *config.Config
    caddyService   *services.CaddyService
    metricsService *services.MetricsService
    nodeService    *services.NodeService
    syncService    *services.SyncService
}
```

### 5.2 NewHandlers 函数

**位置**: `handlers.go` (approx)

```go
func NewHandlers(cfg *config.Config, caddyService *services.CaddyService, ...) *Handlers {
    return &Handlers{
        cfg:            cfg,
        caddyService:   caddyService,
        metricsService: metricsService,
        nodeService:    nodeService,
        syncService:    syncService,
    }
}
```

### 5.3 规则写端点

`CreateRule`、`UpdateRule`、`EnableRule`、`DisableRule` 和 `DeleteRule` 使用同一事务内全量应用流程：

```go
tx, err := db.DB.BeginTx(c.Request.Context(), nil)
// 1. 在 tx 中写入、更新状态或删除规则关联数据
// 2. 捕获当前运行时快照
// 3. ApplyConfigFromTx(tx) 从事务内状态生成并加载完整 Caddy 配置
// 4. Caddy 应用成功后提交 tx
// 5. 应用或提交失败时回滚 tx 并恢复运行时快照
```

创建和更新端点在事务中同时维护 `lb_rules`、`upstreams` 和 `path_rules`。启用和禁用端点在事务中更新 `enabled` 及相关证书任务状态。删除端点在事务中删除规则关联数据，提交后再清理指标与运行文件。提交后的 ACME 操作失败时执行数据库、Caddy 和证书任务补偿。

### 5.7 validateCaddyConfigBeforeSave 函数

**位置**: `handlers.go` (约 500-600 行)

**功能**: 统一配置验证

```go
func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, uniqueID string, serverName string) error {
    // 验证内容:
    // - Protocol: http/https/tcp
    // - ListenPort: 1-65535
    // - Strategy: round_robin/ip_hash/least_conn/random/first/least_time
    // - Domain: 格式验证 (调用 isValidDomain)
    // - Upstreams: 至少一个、host 格式、端口 1-65535、去重、至少一个启用
    // - TLSHSTS: >= 0
    // - HealthCheckInterval/Timeout: >= 1

    // 调用 ValidateRouteMergedConfig 验证完整配置
    return h.caddyService.ValidateRouteMergedConfig(serverName, routeConfig, uniqueID)
}
```

---

## 6. 中间件 (internal/middleware/middleware.go)

### 6.1 SetupRouter 函数

**位置**: `middleware.go:16-153`

**功能**: 设置 Gin 路由

```go
func SetupRouter(h *handlers.Handlers, cfg *config.Config) *gin.Engine {
    r := gin.Default()

    // CORS
    r.Use(corsMiddleware())

    // 静态文件
    r.Static("/assets", cfg.StaticDir+"/assets")
    r.GET("/", func(c *gin.Context) { c.File(cfg.StaticDir + "/index.html") })
    r.Static("/ui", cfg.StaticDir)

    // 健康检查
    r.GET("/health", ...)

    // API 路由
    api := r.Group("/api")
    {
        // 公开接口
        api.POST("/auth/login", h.Login)
        api.Use(apiKeyAuth(cfg))  // API Key 认证 (机器间通信)

        // 受保护接口
        api.Use(jwtAuth(cfg))  // JWT 认证
        {
            // Admin 专用
            admin := api.Group("")
            admin.Use(adminOnly())
            {
                admin.GET("/users", h.ListUsers)
                admin.POST("/users", h.CreateUser)
                // ... 其他管理接口
            }

            // 用户/Admin 共用
            api.GET("/rules", h.ListRules)
            api.GET("/rules/:caddy_id", h.GetRule)
            api.POST("/rules", h.CreateRule)
            api.PUT("/rules/:caddy_id", h.UpdateRule)
            api.DELETE("/rules/:caddy_id", h.DeleteRule)
            // ... 其他接口
        }
    }

    return r
}
```

### 6.2 jwtAuth 函数

**位置**: `middleware.go:170-208`

**功能**: JWT 认证

```go
func jwtAuth(cfg *config.Config) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 1. 获取 Authorization header
        // 2. 解析 Bearer token
        // 3. 验证签名和过期时间
        // 4. 提取 claims: user_id, username, role
        // 5. 设置到 context
        c.Set("user_id", claims["user_id"])
        c.Set("username", claims["username"])
        c.Set("role", claims["role"])
        c.Next()
    }
}
```

---

## 7. 配置 (internal/config/config.go)

### 7.1 Config 结构体

**位置**: `config/config.go`

```go
type Config struct {
    Port           int    // API 端口 (默认 8000)
    DataDir        string // 数据目录
    StaticDir      string // 静态文件目录
    CaddyAdminURL  string // Caddy Admin API URL (默认 http://localhost:2019)
    CaddyMetricsURL string // Caddy 指标 URL
    MetricsInterval int    // 指标收集间隔 (秒)
    JWTSecret      string  // JWT 密钥
}
```

---

## 8. 数据流图

### 8.1 创建规则完整流程

```
客户端                  服务端数据库事务                    Caddy
  │ POST /api/v1/rules         │                               │
  │───────────────────────────►│                               │
  │                            │ 校验并写入规则关联数据         │
  │                            │ 捕获运行时快照                 │
  │                            │ ApplyConfigFromTx(tx)          │
  │                            │──────── POST /load ───────────►│
  │                            │◄────── 校验并加载结果 ─────────│
  │                            │ 成功：commit                   │
  │                            │ 失败：rollback + 恢复快照      │
  │◄────────── 响应 ───────────│                               │
```

### 8.2 更新规则完整流程

```
客户端                  服务端数据库事务                    Caddy
  │ PUT /api/v1/rules/lb_xxx   │                               │
  │───────────────────────────►│                               │
  │                            │ 校验并更新规则关联数据         │
  │                            │ 捕获运行时快照                 │
  │                            │ ApplyConfigFromTx(tx)          │
  │                            │──────── POST /load ───────────►│
  │                            │◄────── 校验并加载结果 ─────────│
  │                            │ 成功：commit                   │
  │                            │ 失败：rollback + 恢复快照      │
  │◄────────── 响应 ───────────│                               │
```

---

## 9. 关键常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `caddy_id` 长度 | 13 | lb_ + 10 字符 |
| 默认端口 | 80, 443, 8000, 2019 | 保留端口 |
| 健康检查默认间隔 | 10 秒 | health_check_interval |
| 健康检查默认超时 | 5 秒 | health_check_timeout |
| 失败阈值默认 | 3 | health_check_unhealthy_threshold |
| JWT 有效期 | 24 小时 | 可配置 |
| API Key 前缀长度 | 12 字符 | 用于快速验证 |

---

## 10. 相关文档

- [系统概述](./1-overview.md)
- [API 参考](./3-api.md)
- [配置规则规范](./4-config-rules.md)
- [运维指南](./5-operations.md)
