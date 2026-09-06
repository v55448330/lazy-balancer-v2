# API 与 MCP 审计报告（2026-09-05）

> 审计域：API 与 MCP（再次全项目审计的功能域切片之一）。只读代码审计，未修改任何源码/配置/测试文件，未触碰运行中的服务与数据目录。

## 一、概览

### 1.1 范围文件清单

| 文件 | 规模 | 说明 |
|---|---|---|
| `internal/handlers/apidocs.go` | 445 行 / 63KB | `apiDocRoutes` 文档表、`apiDocContracts` 契约表、OpenAPI YAML 生成器、Swagger UI HTML |
| `internal/handlers/mcp_apidocs.go` | 22 行 | `init()` 向 `apiDocRoutes` 追加 `GET /mcp/tools`、`GET /mcp/ops-playbook` 两条文档 |
| `internal/handlers/mcp.go` | 23 行 | `GetMCPTools` / `GetMCPOpsPlaybook`（REST 镜像端点） |
| `internal/mcpserver/server.go` | 477 行 | `tools` 注册表（121 个工具）、JSON Schema 常量、`forward()` 内部转发器、initialize instructions |
| `internal/mcpserver/tools.go` | 161 行 | `ListToolSpecs()` 公开注册表、`toolUsage` 用法文案（121 条） |
| `internal/mcpserver/tool_visibility.go` | 128 行 | 只读 Key 的 `tools/list` 可见性过滤、`resolveAPIKeyReadOnly` |
| `internal/mcpserver/playbook.md` | 85 行 | 内嵌 MCP 操作手册（同时经 MCP 资源与 REST 端点下发） |
| `internal/mcpserver/*_test.go` | 5 个文件 | server_test / tools_test / metrics_dashboard_test / mcp_routes_parity_test / apidocs_routes_test |
| `internal/middleware/middleware.go` | 898 行 | `SetupRouter` 路由总装、`apiKeyAuth`/`apiKeyReadOnlyGuard`/`mfaStepUpGuard`、MCP 端点挂载与 1 MiB 限流 |
| `internal/middleware/mcp.go` | 38 行 | `mcpAccessGuard`（MCP 认证门）、`loopbackAPIClient` |
| `internal/middleware/mcp_test.go` | — | MCP 端点认证/白名单/审计 IP/体积限制测试 |
| `internal/middleware/readonly.go` | 78 行 | `readOnlyGuard`（从节点/非管理员写拦截），MCP 写工具转发的最终裁决层 |
| `internal/services/auditpolicy.go`（节选） | — | `readOnlyWriteRoutes`（只读 Key 可调用的只读语义 POST） |

对照取证时实际读码的相关 handler：`rules.go`、`certificates.go`、`certjobs.go`、`caddy.go`、`metrics.go`、`security.go`、`admintls.go`、`config_backup.go`、`config_import_v1.go`、`cluster_ticket.go`、`auditlog.go`、`system.go`、`internal/models/models.go`。

### 1.2 方法

1. 从 `middleware.SetupRouter`（`internal/middleware/middleware.go:167`）机械提取全部 166 条注册路由（含 `/api/v1/docs`、`/api/v1/openapi.yaml`）。
2. 从 `apidocs.go` + `mcp_apidocs.go` 提取 164 条文档收录（排除 docs/openapi.yaml 自身），从 `mcpserver/server.go:34-161` 的 `tools` 切片提取 121 个工具的 (method, path)。
3. 三方 join 比对（`:param` ↔ `{param}` 归一化），并用脚本核验工具数/用法文案数一致。
4. 运行既有 parity 测试与 `internal/mcpserver` 整包单测（结果见 1.3）。
5. 对每个可疑点读对应 REST handler 源码核实（如 `fmt.Sprint` 科学计数法问题用独立 Go 程序实测复现）。

### 1.3 结论摘要

**总体健康**。本域核心承诺均成立：

- **REST ↔ apidocs parity 完整且双向有测试绊线**：`TestOpenAPIDocumentation_covers_registeredGinAPIRoutes`（`internal/mcpserver/apidocs_routes_test.go:19`）双向比对路由注册与生成的 OpenAPI `paths`，本会话实测通过。文档分散在 `apidocs.go` + `mcp_apidocs.go`（`init()` 追加），单一 grep 会漏看（审计过程中已甄别）。
- **MCP → REST parity 完整**：121 个工具的 (method, path) 全部命中注册路由，1:1 无重复；`TestMCPToolSpecs_cover_registeredGinRoutes`（`internal/mcpserver/mcp_routes_parity_test.go:16`）单向绊线实测通过。43 条无 MCP 工具的路由均为可解释的取舍（认证/自助/集群机器接口/SSE 流/批量便捷端点，详见第二节备注），其中约 12 条属于「值得补工具或显式豁免」的缺口（发现 F12）。
- **权限三链一致**：`tools/list` 可见性过滤（`tool_visibility.go`）→ `apiKeyReadOnlyGuard`（重入守卫）→ `readOnlyGuard`（从节点/管理员）语义互相咬合：只读 Key 调写工具在 HTTP 层 403；`export_config` 在可见性层隐藏 + HTTP 层 403 双卡（M8 注释）；从节点上非集群写工具 403 与 instructions/playbook 表述一致。
- **schema 与 REST clamp 对齐良好**：`auditLogsSchema` page_size≤100、`listCertJobsSchema` page≤1e6/page_size≤200、`listCRSRulesSchema` page_size≤100、`securityEventsSchema` page_size≤100 均与 handler 实际 clamp 一致（R68 B-F2 修复后）。
- `internal/mcpserver` 整包测试与两个 parity 测试本会话运行全部通过（`go test ./internal/mcpserver -count=1` → ok）。

**主要问题**：2 个中严重度——MCP 的 `update_admin_tls`/`inspect_admin_tls` 两个工具指向 multipart 端点而转发层只会发 JSON，属于注册即可用承诺落空的死工具（F2）；`update_rule` 上游 `enabled` 语义与 `create_rule` 的 MCP 层注入不对称，Agent 按部分更新心智传 `upstreams` 会静默禁用全部上游（F3）。另有 1 个真实逻辑缺陷（路径参数 ≥1e6 变科学计数法，F1，低概率触发）与若干文档漂移/冗余/待裁定项。

### 1.4 发现统计

| 维度 | 数量 |
|---|---|
| 总发现 | **15** |
| 按分类 | 逻辑 bug/缺陷 3（F1、F2、F11）｜不合理逻辑 2（F9、F13）｜设计漂移 7（F3、F4、F5、F6、F7、F12、F15）｜冗余代码 2（F8、F14）｜表述歧义 1（F10） |
| 按严重度 | 高 0｜**中 2**（F2、F3）｜低 13 |
| 按判定 | 有意设计 2（F8、F13 倾向）｜设计漂移 9（F3、F4、F5、F6、F7、F9、F10、F12、F15）｜缺陷 4（F1、F2、F11、F14 中 F14 属风格冗余归冗余类） |
| 待裁定 | 5（F9、F10、F11、F12、F15） |

（分类与判定存在交叉计数口径，以第三节总表每条唯一归类为准；本表仅示意分布。）

## 二、三方 parity 对照表（REST 路由 | apidocs | MCP 工具 | 备注）

- REST = `SetupRouter` 注册（前缀 `/api/v1` 省略）；apidocs ✓/✗ = 是否收录于 `apiDocRoutes`（含 `mcp_apidocs.go` 追加项）；MCP 工具 = `tools` 切片对应工具名，「—」= 无工具。
- 121 个有工具的路由与工具严格 1:1；43 条无工具路由逐条给出归属判断（有意豁免 vs 缺口）。

### 2.1 认证与自助（JWT 专属，MCP 按设计不覆盖）

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| POST /auth/login | ✓ | — | 有意：MCP 仅 API Key（mcp.go:13） |
| POST /auth/ticket-login | ✓ | — | 有意：从节点票据登录 |
| POST /auth/mfa/verify | ✓ | — | 有意 |
| GET/POST /auth/setup | ✓ | — | 有意：首次初始化 |
| POST /auth/logout | ✓ | — | 有意 |
| GET /auth/mfa/status | ✓ | — | 有意：JWT 自助 |
| POST /auth/mfa/setup / activate / disable / recovery-codes / verify-step | ✓ | — | 有意：JWT 自助 |
| GET /users/me、PATCH /users/me | ✓ | — | 有意：JWT 自助 |
| GET/POST /users/me/api-keys、PATCH/DELETE /users/me/api-keys/:id | ✓ | — | 有意：JWT 自助 |
| POST /users/:id/mfa/reset | ✓ | — | **缺口候选**（管理员重置 MFA，MCP 不可达，见 F12） |
| GET /branding | ✓ | — | 有意：公开品牌信息 |

### 2.2 MCP 自身

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| POST /mcp | ✓ | —（端点本体） | 契约完整：400/401/403/413 与实现一致 |
| GET /mcp/tools | ✓（mcp_apidocs.go:6） | — | REST 镜像；描述有歧义（F10） |
| GET /mcp/ops-playbook | ✓（mcp_apidocs.go:15） | — | REST 镜像，与 MCP 资源同源（`OpsPlaybook()`） |
| GET /docs、GET /openapi.yaml | ✗（测试显式豁免自身） | — | 有意：文档端点本体 |

### 2.3 用户 / API Key

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /users | ✓ | list_users | |
| POST /users | ✓ | create_user | |
| PUT /users/:id | ✓ | update_user | |
| PUT /users/:id/status | ✓ | toggle_user_status | |
| POST /users/:id/reset-password | ✓ | reset_user_password | MCP 层注入随机密码并回显（已测） |
| DELETE /users/:id | ✓ | delete_user | |
| GET /api-keys | ✓ | list_api_keys | |
| POST /api-keys | ✓ | create_api_key | |
| PATCH /api-keys/:id/status | ✓ | update_api_key_status | |
| DELETE /api-keys/:id | ✓ | delete_api_key | |

### 2.4 规则

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /rules | ✓ | list_rules | |
| POST /rules | ✓ | create_rule | MCP 层注入 upstreams[].enabled=true（F3 关联） |
| GET/PUT/DELETE /rules/:caddy_id | ✓ | get_rule / update_rule / delete_rule | update_rule 上游语义陷阱（F3） |
| POST /rules/:caddy_id/enable / disable / duplicate | ✓ | enable_rule / disable_rule / duplicate_rule | |
| GET /rules/:caddy_id/caddy-config | ✓ | get_rule_caddy_config | |
| GET /rules/:caddy_id/metrics-history | ✓ | get_rule_metrics_history | **MCP 工具缺 `range` 参数**（F5） |
| GET /rules/:caddy_id/logs | ✓ | get_rule_logs | |
| GET /rules/:caddy_id/log-stream | ✓ | — | 有意：SSE 增量流，MCP 无流式语义 |
| GET /rules/:caddy_id/cert-info | ✓ | get_rule_cert_info | |
| POST /rules/cert-info（批量） | ✓ | — | 缺口候选（批量便捷端点，见 F12） |

### 2.5 证书 / DNS / CA

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /certificates | ✓ | list_certificates | |
| POST /certificates/issue | ✓ | issue_certificate | schema oneOf 与「body 可省略/必须 caddy_id」一致 |
| POST /certificates/parse | ✓ | parse_certificate | |
| GET /certificates/jobs | ✓ | list_cert_jobs | 分页 clamp 对齐 |
| GET /certificates/jobs/:id、/:id/logs | ✓ | get_cert_job / get_cert_job_logs | |
| POST /certificates/jobs/:id/retry | ✓ | retry_cert_job | |
| DELETE /certificates/jobs/:id | ✓ | delete_cert_job | |
| POST /certificates/jobs/current（批量） | ✓ | — | 缺口候选（见 F12） |
| GET/POST/PUT/DELETE /certificate-configs(/:id) | ✓ | list/create/update/delete_certificate_config | |
| POST /certificate-configs/:id/test | ✓ | test_certificate_config | R72 F2 修复后 schema 含 domain（server.go:116-119 注释与 schema） |
| POST /certificate-configs/test（未保存配置） | ✓ | — | 有意：MCP 仅测已保存配置 |
| GET /dns-providers | ✓ | list_dns_providers | |
| GET /ca-providers(/:id)、PUT /:id、POST /:id/test | ✓ | list/get/update/test_ca_provider | |

### 2.6 配置

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /config | ✓ | get_config | |
| PUT /config | ✓ | update_config | schema 34 字段与 `UpdateConfigRequest` 全对齐（含 github_proxy_url enum=3 与 `ValidateGitHubProxyURL` 白名单一致） |
| POST /config/reload | ✓ | reload_caddy | |
| POST /config/preview | ✓ | preview_config | 只读语义 POST（readOnlyWriteRoutes） |
| POST /config/validate | ✓ | validate_config | 已移出只读豁免（auditpolicy.go:126 注释），三守卫一致 |
| GET /config/export | ✓ | export_config | 只读 Key：可见性隐藏 + HTTP 403 双卡；>4MiB 提示误导（F15） |
| POST /config/import、/import/v1、/import/validate | ✓ | import_config / import_v1_config / validate_import | **MCP 网关 1 MiB 上限 vs REST 16 MiB**（F6） |
| GET /config/health | ✓ | get_upstream_health | |
| GET /logs/stats | ✓ | — | 缺口候选（日志存储状态，见 F12） |

### 2.7 安全

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /security/overview、rate-limit-blocks、events | ✓ | get_security_overview / get_rate_limit_blocks / list_security_events | events schema 12 参数与 handler/文档一致（含 rule_triggered_exclude） |
| GET/POST/PUT/DELETE /security/policies(/:id) | ✓ | list/get/create/update/delete_security_policy | |
| POST /security/policies/:id/bind、DELETE …/bind/:caddy_id | ✓ | bind/unbind_security_policy | unbind 用 bodySchema（F14 风格） |
| PUT /security/rules/:caddy_id/policies | ✓ | set_rule_security_policies | maxItems=5 与后端校验对齐（server.go:243 注释） |
| GET /security/rules/:caddy_id/policy、/security/bindings | ✓ | get_rule_security_policy / list_security_bindings | |
| GET/POST/PUT/DELETE /security/custom-rules(/:id) | ✓ | list/create/update/delete_custom_rule | |
| GET/POST/PUT/DELETE /security/block-pages(/:id) | ✓ | list/create/update/delete_block_page | |
| GET/POST/PUT/DELETE /security/ip-lists(/:id) | ✓ | list/create/update/delete_ip_list | |
| POST /security/ip-lists/:id/ips（单条追加） | ✓ | — | **缺口候选**（安全事件处置工作流，见 F12） |
| GET /security/crs、update/status、update/logs | ✓ | get_crs_info / get_crs_update_status / get_crs_update_logs | |
| GET /security/crs/rules(/:filename) | ✓ | list_crs_rules / get_crs_rule | 分页 clamp 对齐 |
| GET /security/crs/rule-index | ✓ | — | **缺口候选**（排除规则选择器数据源，见 F12） |
| GET /security/crs/setup | ✓ | — | 缺口候选（低价值） |
| PUT /security/crs/auto-update、POST /security/crs/update | ✓ | toggle_crs_auto_update / trigger_crs_update | |
| GET /security/ip2region 及四条 | ✓ | get_ip2region_info / regions / update_status / update_logs | |
| PUT /security/ip2region/auto-update、POST /security/ip2region/update | ✓ | toggle_ip2region_auto_update / trigger_ip2region_update | |
| GET /audit-logs | ✓ | list_audit_logs | 参数/clamp 对齐 |
| GET /audit-logs/options | ✓ | — | 缺口候选（筛选可选值，见 F12） |

### 2.8 集群

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /cluster/status、/cluster/nodes | ✓ | get_cluster_status / list_cluster_nodes | |
| POST /cluster/register-tokens | ✓ | create_register_token | |
| POST /cluster/nodes/:id/approve / reject / login-ticket | ✓ | approve/reject_cluster_node、create_login_ticket | login-ticket 描述与 handler MFA 语义逐条一致（cluster_ticket.go:20-44） |
| PUT /cluster/nodes/:id/access-url、DELETE /cluster/nodes/:id | ✓ | update_node_access_url / delete_cluster_node | |
| POST /cluster/mode、/cluster/promote、/cluster/sync/pull | ✓ | set_cluster_mode / promote_cluster / pull_sync | 从节点可用（readOnlyGuard 白名单） |
| PUT /cluster/settings | ✓ | update_cluster_settings | |
| POST /cluster/forget-pins | ✓ | — | **缺口候选**（从节点补救操作，见 F12） |
| POST /cluster/nodes/:id/service | ✓ | — | **缺口候选**（主节点遥控从节点服务，见 F12） |
| POST /cluster/register、GET /cluster/register/:id/status | ✓（机器接口 tag） | — | 有意：registration-secret 认证 |
| GET /cluster/sync/snapshot、/sync/waf-files | ✓（机器接口 tag） | — | 有意：cluster-token 认证 |
| POST /cluster/registration/confirm、/cluster/nodes/report、/cluster/service-control | ✓（机器接口 tag） | — | 有意：机器对机器 |

### 2.9 监控 / 系统 / Caddy

| REST | apidocs | MCP 工具 | 备注 |
|---|---|---|---|
| GET /metrics/dashboard、overview、realtime、connections、history | ✓ | get_metrics_dashboard / get_metrics_overview / get_realtime_traffic / get_connections / get_metrics_history | history 的 rule_id/interval 齐 |
| GET /metrics/rule/:caddy_id | ✓ | get_rule_metrics | |
| GET /caddy/status、/caddy/config、/caddy/logs | ✓ | get_caddy_status / get_caddy_config / get_caddy_logs | logs schema enum 含 runtime；apidocs 描述漏 runtime（F7） |
| GET /caddy/metrics | ✓ | — | 有意：Prometheus 抓取 |
| GET /caddy/host-metrics | ✓ | — | 缺口候选（按域名统计，见 F12） |
| PUT /caddy/config、POST /caddy/start / stop / restart | ✓ | update_caddy_config / start_caddy / stop_caddy / restart_caddy | |
| GET /admin-tls | ✓ | get_admin_tls | |
| PUT /admin-tls | ✓ | update_admin_tls | **multipart 端点，MCP JSON 转发必败（F2）** |
| POST /admin-tls/inspect | ✓ | inspect_admin_tls | 同上（F2） |
| GET /system/info、/system/metrics、/system/logs | ✓ | get_system_info / get_system_metrics / get_system_logs | |
| POST /system/restart | ✓ | restart_system | |

## 三、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| F1 | internal/mcpserver/server.go:285 | 逻辑 bug | 低 | 缺陷 |
| F2 | internal/mcpserver/server.go:153-154（工具注册）+ internal/handlers/admintls.go:114-118,177-181 | 逻辑 bug | **中** | 缺陷 |
| F3 | internal/mcpserver/server.go:300-312 vs internal/handlers/rules.go:1614,1640-1642 | 逻辑 bug（跨层语义） | **中** | 设计漂移（MCP 层不一致构成缺陷面） |
| F4 | internal/mcpserver/server.go:205；internal/mcpserver/playbook.md:82 | 设计漂移（文档） | 低 | 设计漂移 |
| F5 | internal/mcpserver/server.go:142（get_rule_metrics_history 条目 queryArgs=nil） | 设计漂移 | 低 | 设计漂移 |
| F6 | internal/middleware/middleware.go:213 vs internal/handlers/config_import_v1.go:496-503 | 设计漂移 | 低 | 设计漂移 |
| F7 | internal/handlers/apidocs.go:131 | 设计漂移（文档） | 低 | 设计漂移 |
| F8 | internal/middleware/mcp.go:34-36 + internal/mcpserver/server.go:370-374 | 冗余代码 | 低 | 有意设计（防御性重复） |
| F9 | internal/mcpserver/tool_visibility.go:80-87 vs internal/services/auditpolicy.go:117-131 | 不合理逻辑（可见性收敛方向） | 低 | 设计漂移（待裁定） |
| F10 | internal/handlers/mcp_apidocs.go:11 | 设计漂移（文档歧义） | 低 | 设计漂移（待裁定） |
| F11 | internal/mcpserver/tool_visibility.go:67-105 | 逻辑 bug（潜在/休眠） | 低 | 缺陷（待裁定） |
| F12 | internal/mcpserver/mcp_routes_parity_test.go:16-33；server.go tools 切片缺项 | 设计漂移（覆盖缺口） | 低 | 设计漂移（待裁定） |
| F13 | internal/mcpserver/tool_visibility.go:48-64 vs internal/middleware/middleware.go:699-712 | 不合理逻辑（口径） | 低 | 有意设计（弱化防御深度） |
| F14 | internal/mcpserver/server.go:83（unbind_security_policy 条目） | 冗余代码（风格） | 低 | 缺陷（微） |
| F15 | internal/mcpserver/server.go:413-416 | 设计漂移（提示文案） | 低 | 设计漂移（待裁定） |

## 四、逐条详述

### F1 路径参数经 `fmt.Sprint` 替换，整型 ≥1,000,000 变科学计数法

- **位置**：`internal/mcpserver/server.go:281-287`（对照 `:292-296`；`fmt.Sprint` 在 `:286`）
- **代码证据**：
  ```go
  for _, name := range spec.pathArgs {
      value, ok := arguments[name]
      if !ok {
          return nil, fmt.Errorf("缺少参数 %s", name)
      }
      path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(fmt.Sprint(value)))   // :285
  }
  ...
  for _, name := range spec.queryArgs {
      if value, ok := arguments[name]; ok && fmt.Sprint(value) != "" {
          query.Set(name, scalarString(value))                                            // :293
      }
  }
  ```
  以及 `scalarString`（`server.go:464-472`）：
  ```go
  func scalarString(value any) string {
      switch value := value.(type) {
      case float64:
          if value == float64(int64(value)) {
              return strconv.FormatInt(int64(value), 10)
          }
      }
      return fmt.Sprint(value)
  }
  ```
- **分类**：逻辑 bug。**判定**：缺陷。
- **依据**：MCP 工具参数经 JSON 反序列化为 `float64`。本会话用独立 Go 程序实测：`fmt.Sprint(float64(1000000)) == "1e+06"`、`fmt.Sprint(float64(12345678901)) == "1.2345678901e+10"`。因此路径 ID ≥ 1e6 时 URL 变为 `/certificates/jobs/1e+06/retry`，REST handler `strconv.Atoi` 失败返回 400（或匹配不到资源）。`scalarString` 正是为该问题而生，但只用于 query 参数，路径替换未复用——同函数内两处口径不一致是明确的实现疏漏，而非有意设计。触发概率低（自增 ID 需达百万级，`cert_jobs` 长期自增最可能触达），故定低。
- **影响**：`retry_cert_job`/`get_cert_job`/`delete_cert_job` 等所有以整型 ID 为路径参数的 30+ 个工具在 ID ≥ 1e6 时恒失败，且报错形态（400 invalid id parameter）会误导 Agent 认为参数格式错。
- **建议**：路径替换改用 `url.PathEscape(scalarString(value))`；可顺手为 `fmt.Sprint(value) != ""` 的 query 跳过判断同样换 `scalarString`（空串判断不受影响）。
- **是否待裁定**：否（修复无副作用）。

### F2 `update_admin_tls` / `inspect_admin_tls` 工具指向 multipart 端点，MCP 调用必败

- **位置**：工具注册 `internal/mcpserver/server.go:153-154`；转发层 Content-Type `internal/mcpserver/server.go:343-345,388-390`；REST 端 `internal/handlers/admintls.go:177-181`（Update）、`:114-118`（Inspect）、`:139-142`（readAdminTLSFiles）。
- **代码证据**：
  ```go
  // server.go:153-154 —— 工具以 JSON bodySchema 暴露
  {"update_admin_tls", "更新管理面板 HTTPS 配置", http.MethodPut, "/admin-tls", nil, nil, bodySchema},
  {"inspect_admin_tls", "检查管理面板 HTTPS 证书", http.MethodPost, "/admin-tls/inspect", nil, nil, bodySchema},
  ```
  ```go
  // server.go:357-359 —— forward 只会以 application/json 发送
  if body != nil {
      request.Header.Set("Content-Type", "application/json")
  }
  ```
  ```go
  // admintls.go:177-181 —— REST 端强制 multipart
  func (h *Handlers) UpdateAdminTLS(c *gin.Context) {
      c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
      if err := c.Request.ParseMultipartForm(2 << 20); err != nil {
          c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "表单解析失败: " + err.Error()})
          return
      }
  ```
  ```go
  // admintls.go:139-142 —— Inspect 依赖 FormFile
  read := func(field string) (string, error) {
      f, _, err := c.Request.FormFile(field)
      if err != nil {
          return "", &adminTLSError{"请上传" + field + " 文件"}
      }
  ```
- **分类**：逻辑 bug。**判定**：缺陷。
- **依据**：`forward()` 对 PUT/POST 只能发送 JSON body（`bodyBytes` 由 `json.Marshal` 生成），而这两个 REST 端点第一步就是 `ParseMultipartForm` / `FormFile`——JSON body 必然解析失败，返回 400「表单解析失败」/「请上传 cert_file 文件」。即无论 Agent 传什么参数，这两个工具 100% 失败。工具注册表是对 Agent 的可用性承诺（tools/list 可见、toolUsage 还给出指引文案），注册了不可用的工具属于实现与承诺脱节的缺陷。apidocs 侧契约是正确的（`apiDocContracts` 中 `"PUT /admin-tls": {requestContentType: "multipart/form-data"}`），说明文档层知道差异而工具层未跟进。
- **影响**：Agent 尝试更新/检查管理面板 HTTPS 时必然 400，浪费交互轮次并产生错误归因；`inspect_admin_tls` 还被列入 `readOnlyWriteRoutes`（只读 Key 可调），但只读 Key 连可见性都被收敛（见 F9），双重不一致。
- **建议**：三选一：① 移除这两个 MCP 工具并在 playbook/instructions 注明「管理面板 TLS 请走面板 UI」；② 给 REST 端点增加 JSON 兼容入参（cert/key 以 PEM 字符串传入，与 `parse_certificate` 同风格）；③ 在工具 description 中显式标注「仅面板 UI 可用，MCP 调用必失败」。推荐 ②（与 `parse_certificate` 已有形态一致）。
- **是否待裁定**：否（现状明确是坏契约）；修复方案可裁定。

### F3 `create_rule` 注入 `upstreams[].enabled=true` 而 `update_rule` 不注入——Agent 语义陷阱

- **位置**：注入逻辑 `internal/mcpserver/server.go:300-312`；REST 更新侧 `internal/handlers/rules.go:1614`（全删）、`:1640-1642`（重插，直接取 `u.Enabled`）。
- **代码证据**：
  ```go
  // server.go:300-312 —— 仅 create_rule 注入默认 enabled（enabled=true 赋值在 :307）
  bodyArguments := make(map[string]any, len(arguments))
  maps.Copy(bodyArguments, arguments)
  if spec.name == "create_rule" {
      if upstreams, ok := bodyArguments["upstreams"].([]any); ok {
          for _, upstream := range upstreams {
              if fields, ok := upstream.(map[string]any); ok {
                  if _, exists := fields["enabled"]; !exists {
                      fields["enabled"] = true
                  }
              }
          }
      }
  }
  ```
  ```go
  // rules.go:1614 —— update 全删后重插
  if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
  // rules.go:1640-1646 —— 直接使用请求里的 u.Enabled（Go bool 零值 false）
  if _, err := tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      caddyID, u.Host, u.Port, u.Weight, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections); err != nil {
  ```
  `Upstream` 模型（`internal/models/models.go:249-259`）中 `Enabled bool` 为非指针布尔。
- **分类**：逻辑 bug（跨 MCP/REST 的语义不一致）。**判定**：设计漂移（REST「upstreams 全量替换、enabled 缺省即 false」是有意设计；MCP 层只对 create 补默认、未对 update 补，属同层不对称的实现漂移，构成缺陷面）。
- **依据**：`update_rule` 的 toolUsage 文案是「修改现有规则的任意字段（部分更新）」，`updateRuleSchema` 中 `upstreams` 仅为 `{"type":"object"}`（无字段提示）。Agent 若遵循「部分更新」心智，传 `upstreams:[{host,port}]` 调整后端列表，则每个上游 `enabled` 反序列化为 false，规则更新成功但全部上游被禁用、流量中断——静默且与文案预期相反。create 侧注入默认值的行为（有测试 `TestCreateRuleToolForwardsBodyAndAPIKey` 固化）恰恰证明 MCP 层已认识到该陷阱，却只在 create 修了一半。
- **影响**：中。Agent 通过 MCP 修改规则上游（常见操作）存在静默禁用全部上游的生产风险；REST 直接调用者同样受「enabled 缺省=false」影响，但 apidocs 对 PUT /rules/:caddy_id 也未警示（仅说明 path_rules 整体替换）。
- **建议**：① `forward()` 将 `enabled` 注入同样应用于 `update_rule`（与 create 对称）；② 在 `update_rule` 的 usage/描述中明确「upstreams 为全量替换，须带完整字段（含 enabled）」；③ REST 文档同步补一句。
- **是否待裁定**：修复语义（注入 vs 文档警示）可由用户裁定，问题本身成立。

### F4 serverInstructions 与 playbook 的 401/403 错误码表述与实现相反

- **位置**：`internal/mcpserver/server.go:205`；`internal/mcpserver/playbook.md:82`；实现 `internal/middleware/mcp.go:11-19`；apidocs 正确记载 `internal/handlers/apidocs.go:40`（`403 mcp_disabled_or_ip_denied`）。
- **代码证据**：
  ```go
  // server.go:205
  错误约定：401=密钥无效或未开启 MCP；403=只读 Key 调写工具/从节点非集群写工具/IP 白名单拦截；…
  ```
  ```
  // playbook.md:82
  | 401 | 密钥无效/缺失，或未开启 MCP → 核对 Key 与开关 |
  ```
  ```go
  // mcp.go:11-19 ——「未开启 MCP」实际返回 403
  if c.GetString("auth_type") != "api_key" {
      c.AbortWithStatusJSON(http.StatusUnauthorized, ...)   // 401
  if !c.GetBool("api_key_mcp_enabled") {
      c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "MCP 功能未开启"})
  ```
- **分类**：设计漂移（文档与实现不符）。**判定**：设计漂移。
- **依据**：apidocs 的 POST /mcp 错误清单（401 api_key_required / 403 mcp_disabled_or_ip_denied）与代码一致；instructions 与 playbook 把「未开启 MCP」并入 401 与代码相反。Agent 按错误码分流重试策略时会被误导（401 → 换 Key，403 → 查开关——语义正好错位一半）。
- **影响**：低。仅误导诊断，不造成安全或数据问题。
- **建议**：两处文案改为「401=密钥无效/缺失或使用 JWT；403=未开启 MCP/白名单拦截/只读越权…」。
- **是否待裁定**：否。

### F5 `get_rule_metrics_history` 缺 `range` 查询参数

- **位置**：`internal/mcpserver/server.go:142`（`{"get_rule_metrics_history", …, []string{"caddy_id"}, nil, idSchema(…)}`，queryArgs 为 nil）；REST 侧 `internal/handlers/metrics.go:241`（`metricsHistoryRange(c.DefaultQuery("range", "24h"))`）；apidocs 已文档化（`internal/handlers/apidocs.go:292` contract：`range` 参数 1h/6h/24h/7d 默认 24h）。
- **代码证据**：
  ```go
  // metrics.go:241 —— REST 支持 range
  modifier, bucketSeconds, bucketCount := metricsHistoryRange(c.DefaultQuery("range", "24h"))
  ```
  ```go
  // server.go:142 —— 工具只声明 path 参数
  {"get_rule_metrics_history", "获取指定规则的历史指标", http.MethodGet, "/rules/{caddy_id}/metrics-history", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
  ```
- **分类**：设计漂移。**判定**：设计漂移。
- **依据**：REST 与文档均支持/记载 `range`，工具 schema 因 `additionalProperties:false` 主动拒绝该参数（传了会 -32602），Agent 只能永远拿默认 24h。同类的 `get_metrics_history` 就带齐了 `rule_id`/`interval`，可见这是遗漏而非取舍。
- **影响**：低。排查「7 天趋势」类需求在 MCP 内不可达。
- **建议**：queryArgs 加 `range`，schema 增加 `{"range":{"type":"string","enum":["1h","6h","24h","7d"],"default":"24h"}}`（与 `metricsHistoryRange` 支持集对齐）。
- **是否待裁定**：否。

### F6 MCP 网关 1 MiB 请求上限与 REST 导入 16 MiB 契约不匹配

- **位置**：`internal/middleware/middleware.go:213`；REST 限制 `internal/handlers/config_import_v1.go:496-503`（`maxConfigImportBytes`=16MB）；apidocs `internal/handlers/apidocs.go`（`/config/import/validate` 条目明确 413 body_exceeds_16_MiB）。
- **代码证据**：
  ```go
  // middleware.go:211-213 —— MCP 端点统一 1 MiB
  v1.POST("/mcp", apiKeyAuth(cfg), mcpAccessGuard(), func(c *gin.Context) {
      c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
  ```
  ```go
  // config_import_v1.go:496-498
  func limitConfigImportBody(c *gin.Context) bool {
      if c.Request.ContentLength > maxConfigImportBytes {
          c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
  ```
- **分类**：设计漂移。**判定**：设计漂移。
- **依据**：`import_config`/`import_v1_config`/`validate_import` 三个工具的载荷是整份备份 JSON。真实备份（含规则、证书任务、用户、密钥哈希）超过 1 MiB 完全正常（含证书材料时更甚），此时 MCP 请求在网关就被 413 截断，而 REST 端点承诺 16 MiB。工具的 usage 文案（「导入 v2 配置备份（覆盖式，先验证后写入）」）未提示体积上限。1 MiB 网关上限对 JSON-RPC 信封本身是合理防线，但对这三个特定工具构成能力缺口。
- **影响**：低-中（取决于部署规模）：大配置的备份恢复在 MCP 通道不可用，且错误信息（413 请求体过大）不会告诉 Agent「这是 MCP 通道限制而非备份无效」。
- **建议**：① 在三个导入类工具的 usage 中注明「备份 >1 MiB 请走 REST/面板」；或 ② 网关按 method 区分限额（tools/call 且工具为导入类时放宽至 16 MiB——实现成本较高，不推荐）；或 ③ 接受现状并写入 playbook 排障节。
- **是否待裁定**：是（选择文案提示 vs 通道放宽属产品决策）。

### F7 apidocs `GET /caddy/logs` 描述遗漏 `runtime` 类型（恰为默认值）

- **位置**：`internal/handlers/apidocs.go:131`；实现 `internal/handlers/caddy.go:710-722`。
- **代码证据**：
  ```go
  // apidocs.go:131
  {"GET", "/caddy/logs", "Caddy", "Caddy 日志", "", `{"content":"..."}`, []string{"401 unauthenticated"}, "query: type（server/proxy/tls）。"},
  ```
  ```go
  // caddy.go:710-715 —— runtime 是默认值
  logType := c.DefaultQuery("type", "runtime")
  pathMap := map[string]string{
      "runtime": "/app/logs/caddy.log",
  ```
- **分类**：设计漂移（文档不全）。**判定**：设计漂移。
- **依据**：MCP 的 `caddyLogsSchema`（server.go:240）enum 为 `["runtime","server","proxy","tls"]` 四值齐全；apidocs 描述只列三值且漏掉的恰是不传参时的默认类型。两侧文档对同一参数的口径不一致。
- **影响**：低。REST 使用者不知默认行为与 runtime 日志的存在。
- **建议**：描述改为「query: type（runtime 默认/server/proxy/tls）」。
- **是否待裁定**：否。

### F8 重定向禁用策略在两处重复设置

- **位置**：`internal/middleware/mcp.go:34-36`；`internal/mcpserver/server.go:370-374`。
- **代码证据**：
  ```go
  // mcp.go:34-36 —— loopbackAPIClient
  CheckRedirect: func(*http.Request, []*http.Request) error {
      return http.ErrUseLastResponse
  },
  ```
  ```go
  // server.go:370-374 —— forward 内再复制一份客户端并覆盖
  redirectlessClient := *client
  redirectlessClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
      return http.ErrUseLastResponse
  }
  ```
- **分类**：冗余代码。**判定**：有意设计（防御性冗余）。
- **依据**：生产装配传入的 `loopbackAPIClient()` 已设置同样的 `CheckRedirect`；`forward()` 为兼容测试注入任意 client（`New()` 路径）再次覆写。`forward` 的覆写是实际生效方，`mcp.go` 的设置在生产路径上是重复的，但它让 `loopbackAPIClient` 的语义自含（注释也说明了意图），删掉任何一处都不改变行为。
- **影响**：无行为影响；读者需要理解两处谁是权威。
- **建议**：保留 `forward` 内覆写（它覆盖所有 client 来源），`mcp.go` 注释可补一句「forward 层还会再覆写，此处为客户端自含语义」。可不改。
- **是否待裁定**：否。

### F9 只读 Key 的 `tools/list` 可见性把「只读语义 POST 工具」一并隐藏，与 HTTP 层放行口径不同

- **位置**：`internal/mcpserver/tool_visibility.go:77-87`；对照 `internal/services/auditpolicy.go:117-131`（readOnlyWriteRoutes）。
- **代码证据**：
  ```go
  // tool_visibility.go:77-87 —— 只保留 GET 工具（除显式隐藏的 export_config）
  readOnlyHiddenTools := map[string]struct{}{"export_config": {}}
  readOnlyNames := make(map[string]struct{}, len(tools))
  for _, spec := range tools {
      if spec.method == http.MethodGet {
          if _, hidden := readOnlyHiddenTools[spec.name]; !hidden {
              readOnlyNames[spec.name] = struct{}{}
          }
      }
  }
  ```
  ```go
  // auditpolicy.go:118-131 —— HTTP 层对只读 Key 放行这些 POST
  var readOnlyWriteRoutes = map[string]struct{}{
      "POST /api/v1/admin-tls/inspect":            {},
      "POST /api/v1/ca-providers/:id/test":        {},
      "POST /api/v1/certificate-configs/:id/test": {},
      "POST /api/v1/certificates/jobs/current":    {},
      "POST /api/v1/certificate-configs/test":     {},
      "POST /api/v1/certificates/parse":           {},
      "POST /api/v1/config/import/validate":       {},
      "POST /api/v1/config/preview":               {},
      "POST /api/v1/rules/cert-info":              {},
  }
  ```
- **分类**：不合理逻辑（可见性收敛与执行权限的口径差）。**判定**：设计漂移（更准确说是「有意的保守策略未文档化」，倾向设计漂移并待裁定）。
- **依据**：`readOnlyWriteRoutes` 声明这些 POST 语义为读（只读 Key 可调），但工具可见性按「method==GET」一刀切，于是只读 Key 的 `tools/list` 看不到 `preview_config`、`parse_certificate`、`test_ca_provider`、`test_certificate_config`、`validate_import`、`inspect_admin_tls`——尽管直接 `tools/call` 它们会被放行成功。方向是安全的（隐藏不会放大权限），且 serverInstructions 明确写「只读 Key 仅能调用 GET 查询类工具」，文案与可见性自洽、与 HTTP 层宽口径不一致。`readOnlyHiddenTools` 机制本身证明作者知道需要例外清单，只是只登记了 export_config 一项。
- **影响**：低。只读观察型 Agent（监控巡检、配置核对）无法发现预览/测试类工具，能力被不必要收窄；两层口径不一致增加维护者认知成本（若未来 readOnlyWriteRoutes 增项，可见性不会跟随）。
- **建议**：以 `readOnlyWriteRoutes` 为单一事实源生成 `readOnlyNames`（GET 工具 ∪ 只读语义 POST 工具 − export_config），并同步修 instructions 文案；或维持现状但在 tool_visibility.go 注释中显式声明「有意隐藏只读语义 POST」。
- **是否待裁定**：是（收敛策略是产品选择）。

### F10 apidocs `GET /mcp/tools` 描述「不包含内部参数 schema」与实际响应含 `input_schema` 相悖（表述歧义）

- **位置**：`internal/handlers/mcp_apidocs.go:11`；实现 `internal/mcpserver/tools.go:31-33`。
- **代码证据**：
  ```go
  // mcp_apidocs.go:11
  Description: "所有已登录用户可读；返回 MCP 工具名称、描述、映射的 REST 请求与读写分类，不包含内部参数 schema。",
  ```
  ```go
  // tools.go:31-33 —— InputSchema 实际随响应返回
  if spec.schema != "" && spec.schema != emptySchema {
      item.InputSchema = json.RawMessage(spec.schema)
  }
  ```
- **分类**：设计漂移（文档表述）。**判定**：设计漂移（待裁定：可能本意是「不含 path_args/query_args 内部字段」）。
- **依据**：`tools_test.go` 的绊线明确防的是泄露 `path_args`/`query_args` 内部字段；而 `input_schema` 是对外契约的一部分，`ListToolSpecs` 对非空 schema 的工具都会返回。文档字面「不包含内部参数 schema」按常读理解即 input_schema，与响应不符。
- **影响**：低。API 使用者可能误以为需要另外途径获取参数契约。
- **建议**：改为「不包含内部路由参数注记（path_args/query_args）；含各工具 input_schema」。
- **是否待裁定**：是（若作者坚持原意，改措辞即可）。

### F11 `filterReadOnlyTools` 反序列化-重序列化丢弃 `result` 未知字段（休眠缺陷）

- **位置**：`internal/mcpserver/tool_visibility.go:66-105`。
- **代码证据**：
  ```go
  var payload struct {
      JSONRPC string `json:"jsonrpc"`
      ID      any    `json:"id"`
      Result  struct {
          Tools []json.RawMessage `json:"tools"`
      } `json:"result"`
  }
  if err := json.Unmarshal(response, &payload); err != nil { … }
  …
  payload.Result.Tools = filtered
  data, err := json.Marshal(payload)
  ```
- **分类**：逻辑 bug（当前休眠）。**判定**：缺陷（待裁定——当前无触发路径）。
- **依据**：本会话核对依赖的 mcp-go v0.58.0（go.mod:11）`server.go` 分页逻辑：`paginationLimit == nil` 时 `nextCursor` 恒为空串，而本项目 `NewMCPServer` 未传 `WithPaginationLimit`，故当前 `tools/list` 响应的 `result` 只有 `tools`，无字段丢失。但该过滤器只保留结构体已声明字段，一旦未来启用分页（`nextCursor`）或 mcp-go 升级添加 `result._meta`，这些字段会被静默剥离——只读 Key 的客户端将永远拿不到游标，分页永远不可达，且无任何报错。属埋雷式实现而非有意设计（无任何注释声明「只支持无分页响应」）。
- **影响**：当前零影响；升级/启用分页时成为静默故障。
- **建议**：改为对 `result.tools` 数组的定点 JSON 改写（如用 `json.RawMessage` 保留 result 原文、仅替换 tools 字段），或在注释中声明约束并加测试。
- **是否待裁定**：是（是否现在修）。

### F12 parity 绊线单向：REST→MCP 无显式豁免清单，12 条路由覆盖缺口无守门

- **位置**：`internal/mcpserver/mcp_routes_parity_test.go:16-33`（仅 tools→routes 方向）；`internal/mcpserver/server.go:34-161`（tools 切片）；对照第二节 43 条无工具路由。
- **代码证据**：
  ```go
  // mcp_routes_parity_test.go:22-30 —— 只验证工具指向的路由存在
  specs := mcpserver.ListToolSpecs()
  for _, spec := range specs {
      ginPath := openAPIToGinPath(spec.Path)
      if _, ok := registered[spec.Method+" "+ginPath]; !ok {
          t.Errorf("工具 %s 指向未注册路由 %s %s——…", spec.Name, spec.Method, spec.Path)
      }
  }
  ```
- **分类**：设计漂移（测试覆盖缺口/暴露决策无守门）。**判定**：设计漂移。
- **依据**：反向（某 REST 路由是否应暴露为 MCP 工具）确实不可机械断言，但当前连「显式豁免清单」都没有——新增 REST 路由（如 `POST /security/ip-lists/:id/ips`，其 remark 固定「事件处置」明显面向安全事件处置工作流）时没有任何机制提醒决策者考虑 MCP 暴露。经逐条核对，以下 12 条属于值得补工具或显式记录豁免的缺口（其余 31 条为明确的认证/自助/机器接口/SSE/批量镜像类合理豁免）：
  1. `POST /security/ip-lists/:id/ips` — 单条追加 IP（幂等），Agent 安全响应工作流（封禁 IP）只能走「读全表-改-全量替换 `update_ip_list`」，存在读改写竞态；
  2. `POST /cluster/forget-pins` — 从节点 PinMismatch 补救，instructions 引导集群运维走 MCP 却缺此工具；
  3. `POST /cluster/nodes/:id/service` — 主节点遥控从节点服务（start/stop/restart caddy/app），集群运维闭环缺一角；
  4. `POST /users/:id/mfa/reset` — 管理员重置 MFA；
  5. `GET /security/crs/rule-index` — 6 位规则 ID 索引，Agent 配 CRS 排除规则时无数据源（`list_crs_rules` 只有文件级）；
  6. `GET /audit-logs/options` — `list_audit_logs` 筛选可选值（用户名/操作/对象）；
  7. `GET /logs/stats` — 9 类日志存储状态（排障视角）；
  8. `GET /caddy/host-metrics` — 按域名统计指标；
  9. `GET /security/crs/setup` — CRS setup 文件内容（低价值）；
  10. `POST /certificates/jobs/current` — 批量查询规则当前任务（MCP 只能逐规则 `list_cert_jobs`）；
  11. `POST /rules/cert-info` — 批量证书信息（MCP 只能逐规则）；
  12. `GET /caddy/metrics` — Prometheus 原始指标（可选，JSON 聚合已有 dashboard）。
- **影响**：低。能力缺口本身渐进累积；「该不该暴露」无决策留痕。
- **建议**：在 `mcp_routes_parity_test.go` 增加显式豁免清单（`mcpUncoveredRoutes` map + 反向断言「无工具的路由必须在清单中」），新路由落进来时测试强迫开发者做一次显式取舍；同时按需补充上表 1-5 号工具。
- **是否待裁定**：是（哪些补工具、哪些记录豁免）。

### F13 `resolveAPIKeyReadOnly` 与 `apiKeyAuth` 的取数口径不一致（无 key_prefix、不校验 mcp_enabled）

- **位置**：`internal/mcpserver/tool_visibility.go:48-64`；对照 `internal/middleware/middleware.go:699-712`（apiKeyAuth 查询）。
- **代码证据**：
  ```go
  // tool_visibility.go:54-62 —— 仅按 key_hash 查询，无 key_prefix 预筛、无 mcp_enabled
  err := db.DB.QueryRow(`
      SELECT COALESCE(k.read_only,0)
      FROM api_keys k
      JOIN users u ON u.id = k.created_by
      WHERE k.key_hash = ?
        AND k.is_enabled = 1
        AND u.is_enabled = 1
        AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))
  `, fmt.Sprintf("%x", hash[:])).Scan(&readOnly)
  ```
  ```go
  // middleware.go:701-710 —— apiKeyAuth 带 key_prefix 前缀索引与全字段
  WHERE k.key_prefix = ? AND k.key_hash = ?
  ```
- **分类**：不合理逻辑（口径漂移）。**判定**：有意设计（该函数只服务可见性过滤，鉴权由网关与重入守卫承担——`serveWithToolVisibility` 仅在 method==tools/list 时调用，且调用前已经过 apiKeyAuth+mcpAccessGuard）。
- **依据**：即便该函数漏判（例如返回 err→按非只读处理），后果只是 tools/list 多显示写工具，真正调用仍会被 `apiKeyReadOnlyGuard` 403 拦截——fail-safe 方向。但不带 `key_prefix` 使该查询无法走前缀索引（api_keys 表若以 key_prefix 建索引），且不校验 `mcp_enabled` 依赖「网关已先行 mcpAccessGuard」这一隐含前置条件，两层间是隐式契约而非显式参数传递。
- **影响**：低。性能（全表 hash 匹配，量级小）与可维护性（隐式前置条件）层面。
- **建议**：查询补 `AND k.key_prefix = ?`（apiKey[:12]）与 `AND COALESCE(k.mcp_enabled,0)=1`，消除隐式依赖；或在函数注释中写明前置条件。
- **是否待裁定**：否（低风险加固）。

### F14 `unbind_security_policy`（DELETE）注册了宽松 bodySchema

- **位置**：`internal/mcpserver/server.go:83`。
- **代码证据**：
  ```go
  {"unbind_security_policy", "解除安全策略与规则的绑定", http.MethodDelete, "/security/policies/{id}/bind/{caddy_id}", []string{"id", "caddy_id"}, nil, bodySchema},
  ```
  `bodySchema = {"type":"object","additionalProperties":true}`（server.go:164）。
- **分类**：冗余代码（风格不一致）。**判定**：缺陷（微）。
- **依据**：DELETE 请求在 `forward()` 中永不携带 body（server.go:336-338 仅 POST/PUT/Patch 序列化 body），schema 的 `additionalProperties:true` 形同虚设且与其余「纯路径参数工具」统一使用 `idSchema(...)` 的风格相悖（对照 `delete_security_policy`/`delete_ip_list` 等均为 idSchema）。Agent 侧会误以为可传 body 字段。
- **影响**：无功能影响；schema 语义噪音。
- **建议**：换成与参数匹配的显式 schema（`{"type":"object","required":["id","caddy_id"],"properties":{…}}` 或 idSchema 变体）。
- **是否待裁定**：否。

### F15 响应超 4 MiB 的提示文案对 `export_config` 误导

- **位置**：`internal/mcpserver/server.go:413-416`；工具 `export_config`（server.go:51），`maxResponseSize`（server.go:165）。
- **代码证据**：
  ```go
  if len(responseBody) > maxResponseSize {
      result := mcp.NewToolResultText("内部 API 响应超过 4 MiB 上限，请改用分页或专用导出工具")
      result.IsError = true
      return result, nil
  }
  ```
- **分类**：设计漂移（提示文案）。**判定**：设计漂移（待裁定）。
- **依据**：该提示对所有工具统一生效，但 `export_config` 恰好是「导出」本身——它没有任何分页参数，也不存在「专用导出工具」（REST `/config/export` 对 MCP Agent 不可达）。大配置（多规则+证书材料）导出超 4 MiB 时，Agent 收到的自救指引是死路。`maxResponseSize=4<<20`（server.go:165）的护栏本身合理。
- **影响**：低。大配置场景下 Agent 陷入无解循环重试或放弃。
- **建议**：按工具区分提示：export_config 超限时提示「配置过大，请由管理员经面板/REST 下载备份」；或在 usage 中预注明体积限制。
- **是否待裁定**：是（也可选择放宽 export 的响应上限）。

## 五、待裁定项汇总

| 编号 | 事项 | 需要裁定的点 |
|---|---|---|
| F6 | MCP 网关 1 MiB vs 导入 16 MiB | 导入类工具走「文案提示走面板」还是「通道按工具放宽限额」 |
| F9 | 只读 Key 可见性隐藏只读语义 POST 工具 | 可见性是否改为以 `readOnlyWriteRoutes` 为事实源（并同步 instructions 文案），还是维持保守并注释声明 |
| F10 | `GET /mcp/tools` 「不包含内部参数 schema」表述 | 确认原意（防 path_args/query_args 泄露）后修正措辞 |
| F11 | `filterReadOnlyTools` 丢未知字段 | 是否现在改为定点改写以消除未来分页启用时的静默故障 |
| F12 | REST→MCP 覆盖缺口 12 条 | 哪些补工具（建议优先 1-5：ip-lists/:id/ips、forget-pins、nodes/:id/service、users/:id/mfa/reset、crs/rule-index），哪些写入显式豁免清单 |
| F15 | export_config 超限提示死路 | 文案区分 vs 放宽导出响应上限 |

---

### 附：本会话验证记录

- `go test ./internal/mcpserver -run 'TestOpenAPIDocumentation_covers_registeredGinAPIRoutes|TestMCPToolSpecs_cover_registeredGinRoutes' -count=1` → ok（两绊线通过）。
- `go test ./internal/mcpserver -count=1`（整包）→ ok。
- F1 用独立 Go 程序（/tmp，仓库外）实测 `fmt.Sprint` 对 float64 1e6/1.2345678901e10 的输出为科学计数法。
- 三方对照数据由脚本从 `SetupRouter`/`apiDocRoutes`(+`mcp_apidocs.go`)/`tools` 切片机械提取后 join 比对（121 工具 ↔ 121 路由 1:1；43 路由无工具；apidocs 覆盖 164/164，双向零差）。
