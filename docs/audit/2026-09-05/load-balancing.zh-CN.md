# 负载均衡模块审计报告（2026-09-05）

## 一、概览

### 1.1 范围文件清单

| 文件 | 规模 | 说明 |
|---|---|---|
| `internal/services/caddy.go` | 3348 行 | 配置生成（全量/单规则）、HTTP/TCP 路由构建、健康检查、负载策略、权重、Caddy admin 交互 |
| `internal/handlers/rules.go` | 2704 行 | 规则 CRUD/启用/禁用/复制、校验、事务与回滚、ACME 任务联动 |
| `internal/handlers/rule_features.go` | 853 行 | 特性校验（协议/策略/健康检查/路径规则/超时）、列清单、行扫描、启用前校验 |
| `internal/handlers/handlers.go`（相关段） | 171-722 | validateCaddyConfigBeforeSave、validatePortFromDB、启动应用 |
| `internal/models/models.go`（相关段） | 109-162, 248-277, 390-485 | LbRule/Upstream/PathRule 与 Create/Update 请求模型 |
| `docs/caddy-config-rules.md` | 337 行 | 设计意图文档（找实现漂移） |
| `config/Caddyfile` | 10 行 | 启动引导模板 |
| `web/src/views/Rules.vue` | 3775 行 | 规则页（列表、六步向导、配置查看、日志） |
| `web/src/components/rules/PathRulesEditor.vue` | 233 行 | 自定义路径规则编辑器 |
| `web/src/components/rules/ProxyTimeoutFields.vue` | 65 行 | 代理超时字段组 |
| `web/src/types/rules.ts` | 157 行 | 前端类型 |
| `web/src/utils/ruleValidation.ts` | 96 行 | 路径规则校验（与后端同源归一） |
| `web/src/utils/upstreamWeights.ts` | 69 行 | 权重百分比分摊/再分配 |
| `web/src/utils/caddyDefaults.ts` | 5 行 | 仅含访问日志格式模板（`DEFAULT_ACCESS_LOG_FORMAT`），与规则字段默认值无关 |

### 1.2 方法

- 全量读码（caddy.go / rules.go / rule_features.go 逐行；Rules.vue 模板+脚本分段全读）。
- 与本机 Go module 缓存中的**实际构建版本源码**逐项比对生成 JSON 的字段契约：
  - Caddy core `v2.11.4`（`caddyserver/caddy/v2@v2.11.4`）：`selection_policy.weights`、`max_requests`（simultaneous 语义）、`cookie` 策略 `name` 字段、`unhealthy_status` 类码语义。
  - `mholt/caddy-l4@v0.1.2`（Dockerfile xcaddy `--with` 固定版本）：`health_checks.{passive.fail_duration/max_fails, active.rise/fall/port}`、`load_balancing.{selection.policy, try_duration, try_interval}`、upstream `{dial[], weight, max_connections, tls}`、指标名 `caddy_layer4_proxy_upstream_healthy`（namespace `caddy` + subsystem `layer4_proxy`）、TryInterval 默认 250ms。
- 按「UI 文案 → 请求载荷 → DB → caddy.go 生成 JSON → Caddy 实际行为」四链对照核查关键字段。
- 只读审计：未修改任何源码/配置；未运行测试（全部发现以读码与上游源码比对核实）。

### 1.3 结论摘要

- **总体质量高**。本模块历经多轮审计修订，注释中保留了完整的决策链（R43/R63/R69/R72 等）。L4/L7 双链的字段映射（passive fail_duration=3×interval、active passes/fails ↔ rise/fall、`max_requests`/`max_connections` 分链、动态 DNS 仅 L7）与 UI 文案基本一致；规则保存的「校验→事务→ApplyConfigFromTx→失败恢复快照」回滚链完整，与 `docs/caddy-config-rules.md` 描述的原子性契约相符（详见 §3.18）。
- **主要问题集中在「部分更新（PATCH 式）契约」与「UI 语义」两个断层**：
  1. UI 复制向导提交的 `enabled:false` 被后端 CreateRule 丢弃（硬编码 `enabled=1`），「副本已禁用」语义断裂（LB-01）；
  2. UpdateRule 对非指针整型做「0=未提供」合并，导致 TCP 重试窗口「0=不重试」等有意义的零值无法写回（LB-02）；
  3. UpdateRule 的 443 端口默认值先于存量合并执行，部分更新会静默改写监听端口（LB-03）。
- 权重链路存在一个 UI 展示与实际流量分配不一致的边角：启用态上游权重 0 显示 0% 但落库/渲染为 1（LB-05）。
- 设计文档 `docs/caddy-config-rules.md` 存在多处与实现漂移（服务器命名、策略清单等，LB-06）。
- 无高严重度发现；中严重度 3 条，其余为低。

### 1.4 前端默认值 ↔ 后端默认值契约（caddyDefaults.ts 说明）

`caddyDefaults.ts` 只承载访问日志格式模板，**不包含任何规则字段默认值**；规则默认值的前端事实源是 `Rules.vue` 的 `wizardForm`（1771-1817 / 2235-2281），后端事实源分散在写侧（rules.go / handlers.go）与读/渲染侧（SQL COALESCE + caddy.go 兜底）：

| 字段 | 前端默认 | 后端写侧默认 | 后端读/渲染默认 | 一致性 |
|---|---|---|---|---|
| strategy | `weighted_round_robin`（1777） | 同（rules.go:672-674、handlers.go:341-343） | 同（caddy.go:1119-1121） | ✅ |
| health_check_interval | 10（1783） | 0→10（rules.go:675-677） | COALESCE 10；渲染 ≤0→10 | ✅ |
| health_check_timeout | 2（1784） | 0→2（rules.go:678-680、handlers.go:347-349） | **COALESCE 5**（rule_features.go:506/517）；渲染 ≤0→**5**（caddy.go:3094-3097） | ❌ LB-04 |
| unhealthy_threshold | 3（1786） | 校验副本 0→3（handlers.go:350-352） | 渲染 ≤0→3（caddy.go:3069-3072） | ✅ |
| healthy_threshold | 2（1785） | 校验副本 0→2（handlers.go:353-355） | 渲染 ≤0→2（caddy.go:3088-3091） | ✅ |
| tcp_try_interval | 250（1791） | 无（存原值） | 渲染 ≤0→250（caddy.go:3286-3290，与 l4 默认一致） | ✅ |
| 单上游 weight | 100（1732） | 0→1（rules.go:834-836） | ≤0→1（caddy.go:1508-1511 等） | △ LB-05 |
| compress_types | `['gzip']`（1802） | ""→"gzip"（rules.go:697-699） | 'gzip' | ✅ |

### 1.5 L4(TCP) 与 L7(HTTP) 双链差异对照（读码核实）

| 维度 | L7 (HTTP) | L4 (TCP) | 判定 |
|---|---|---|---|
| 上游形态 | `upstreams:[{dial:"h:p", max_requests?}]`（caddy.go:3006-3011） | `upstreams:[{dial:["h:p"], weight?, tls?, max_connections?}]`（caddy.go:3234-3255） | ✅ 与两插件契约一致 |
| 权重 | `load_balancing.selection_policy.weights`（GCD 归一，3054-3055） | `upstream.weight` 仅 >1 时发射（3243-3246；l4 源码确认 `<=0 视为 1`） | ✅ |
| 策略白名单 | wrr/least_conn/ip_hash/cookie/random/first（rule_features.go:222-226） | wrr/least_conn/ip_hash/random/first（227-231） | ✅ 两端策略均存在于对应插件（l4 另有 round_robin/random_choose 未暴露） |
| cookie | 发射 `{"policy":"cookie","name":"lb_sticky"}`（3042-3044）；Caddy `CookieHashSelection.Name` 确认 | 校验拒绝 + 渲染兜底降级 wrr（3262-3264，双保险） | ✅ |
| 重试 | `try_duration:"5s"/try_interval:"250ms"` **硬编码**（3057-3061），UI 无入口 | 规则级 `tcp_try_duration/tcp_try_interval`（3284-3292），0=不重试 | △ 待裁定 T-2 |
| 被动健康 | `fail_duration=3×interval`、`max_fails`、`unhealthy_status:[5]`（3073-3081） | `fail_duration=3×interval`、`max_fails`（3305-3310） | ✅ 与 UI 文案「被动失败记忆窗口为其 3 倍」一致 |
| 主动健康 | `uri/timeout/interval/passes/fails(+Host 头)`（3098-3108） | `interval/timeout/rise/fall(+port)`（3320-3329） | ✅ 字段名与两插件 JSON 契约逐一核对一致 |
| 动态 DNS | `dynamic_upstreams`（A 记录 + versions + resolver；单上游强制；wrr→random 降级 3052-3056） | 保存拒绝（rule_features.go:290-292）+ 渲染跳过（caddy.go:1698-1707）双保险 | ✅ |
| TLS 上游 | `transport.tls{insecure_skip_verify, server_name=host_header}`（3126-3131） | `upstream.tls{insecure_skip_verify}`（3247-3251，无 SNI） | ✅ |
| 健康指标名 | `caddy_reverse_proxy_upstreams_healthy` | `caddy_layer4_proxy_upstream_healthy`（caddy.go:763；l4 metrics.go:55-75 确认） | ✅ |
| 仅 L7 能力 | 压缩、自定义路由、Host 头、请求体上限、Server 隐藏、代理超时 | 协议切换时清零 + 校验拒绝（rules.go:1174-1209、rule_features.go:293-298） | ✅ |

---

## 二、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| LB-01 | rules.go:816 + Rules.vue:2777/2635 + models.go:390-435 | 逻辑 bug（契约断裂） | 中 | 缺陷 |
| LB-02 | rules.go:1106-1114 + Rules.vue:694-701/617 | 逻辑 bug（零值合并） | 中 | 缺陷 |
| LB-03 | rules.go:984-988 vs 1074-1076 | 逻辑 bug（合并顺序） | 中 | 缺陷 |
| LB-04 | rules.go:678-680 / handlers.go:347-349 vs rule_features.go:506 / caddy.go:3094-3097 | 设计漂移（默认值分裂） | 低 | 设计漂移 |
| LB-05 | Rules.vue:483 + upstreamWeights.ts:8 vs rules.go:834-836/1626-1628 + caddy.go:2978-2981 | 逻辑 bug（权重 0 语义） | 低 | 缺陷 |
| LB-06 | docs/caddy-config-rules.md:23/32-38/102/183/259 | 设计漂移（文档过期） | 低 | 设计漂移 |
| LB-07 | caddy.go:244-248（231-243 同型） | 不合理逻辑（校验放行） | 低 | 设计缺口（待裁定 T-1） |
| LB-08 | Rules.vue:1654/1691 vs caddy.go:2686-2688/589 | 逻辑 bug（IPv6 健康键） | 低 | 缺陷 |
| LB-09 | Rules.vue:616-617 | 不合理逻辑（UI 约束 vs 文案） | 低 | 缺陷 |
| LB-10 | rules.go:844-848 / 1636-1639 | 冗余代码（不可达检查） | 低 | 有意设计（纵深防御） |
| LB-11 | caddy.go:1123-1125 | 冗余代码（死分支） | 低 | 有意设计（防御遗留） |
| LB-12 | rules.go:729-742 | 冗余代码（等价分支） | 低 | 设计漂移 |
| LB-13 | rules.go:140 + caddy.go:2661 | 不合理逻辑（展示链不完整） | 低 | 设计漂移 |
| LB-14 | Rules.vue:488-493 | 不合理逻辑（文案不准） | 低 | 设计漂移 |
| LB-15 | models.go:413 + caddy.go:2218-2223 + Rules.vue 全文无入口 | 待裁定（UI 未暴露） | 低 | 待裁定 T-3 |
| LB-16 | caddy.go:2428-2461 | 已弃用代码（不可达分支，自注） | 低 | 有意保留 |
| LB-17 | rules.go:118-125 | 冗余代码（仅 debug 用的查询） | 低 | 设计漂移 |
| LB-18 | Rules.vue:2533-2536 vs rule_features.go:243-246 | 不合理逻辑（前后端校验门控不一致） | 低 | 缺陷（轻微） |

统计：**18 条**。按分类：逻辑 bug 6（LB-01/02/03/05/08/18）、不合理逻辑 4（LB-07/09/13/14）、冗余代码 3（LB-10/11/12）、设计漂移 3（LB-04/06/17）、已弃用代码 1（LB-16）、待裁定 1（LB-15）。按严重度：**高 0、中 3（LB-01/02/03）、低 15**。待裁定项另见 §四（T-1/T-2/T-3）。

---

## 三、逐条详述

### LB-01【中】UI 复制向导创建的规则被硬编码为启用，「副本已禁用」语义断裂

**位置**：`internal/handlers/rules.go:816`、`web/src/views/Rules.vue:2777、2611、2632-2636`、`internal/models/models.go:390-435`

**代码证据**：

前端复制向导（`openCopyWizard`）明确将副本置为禁用态，且预览页展示「状态：禁用」：

```ts
// Rules.vue:2777（openCopyWizard 的表单回填）
    enabled: false,
```
```html
<!-- Rules.vue:789-791（预览步骤） -->
<el-descriptions-item label="状态">
  <el-tag :type="wizardForm.enabled ? 'success' : 'info'">{{ wizardForm.enabled ? '启用' : '禁用' }}</el-tag>
</el-descriptions-item>
```

提交时 `enabled` 随载荷发送且走 POST 创建（编辑态才走 PUT）：

```ts
// Rules.vue:2611 / 2632-2636
  enabled: wizardForm.enabled,
...
  if (editingRule.value) {
    await request.put<APIResponse>(`/rules/${editingRule.value.caddy_id}`, data)
  } else {
    await request.post<APIResponse>('/rules', data)
  }
```

但后端 `CreateRuleRequest` **没有 `Enabled` 字段**（models.go:390-435 全文核对），且 INSERT 硬编码 `1`：

```go
// rules.go:806-816（INSERT 列含 enabled，值硬编码 1）
		enable_compress, compress_types, enabled, created_by, updated_at, caddy_id, log_enabled)
VALUES (?, ..., ?, ?, ?, ?, ?)
	`, ..., req.TLSHTTPRedirect, req.EnableCompress, req.CompressTypes, 1, userIDInt, ...)

// rules.go:833-836（同段，供参考）
	for _, u := range req.Upstreams {
```

而仓库内实现「禁用副本」语义的是另一个端点 `DuplicateRule`（`POST /rules/:caddy_id/duplicate`），其响应文案为：

```go
// rules.go:2314
c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "副本已创建（已禁用）：域名与源规则相同，启用前请修改域名或端口", Data: gin.H{"caddy_id": newCaddyID}})
```

grep 核实：`/rules/:caddy_id/duplicate` 仅由 API 文档（apidocs.go:74）与 MCP（mcpserver/server.go:42）注册，**web 前端从不调用**；UI「复制」按钮走向导（Rules.vue:235 按钮 → `duplicateRule`（2685）→ `openCopyWizard`（2696））。

**分类**：逻辑 bug（UI 意图与后端契约断裂）。
**判定**：缺陷。依据：前端代码明确表达「副本=禁用」意图（与后端 DuplicateRule 端点语义一致），CreateRule 丢弃 `enabled` 并硬编码 1 属于两套复制路径（端点 vs 向导）演化的契约断裂，无注释声明该差异为有意。
**影响**：
1. 复制**已启用**的 HTTP 规则且未改域名 → 保存必 400「域名已被其他 HTTP/HTTPS 规则使用」（`ruleDomainConflict` 只统计 enabled=1 规则，源规则命中）；复制已启用 TCP 规则未改端口 → 400「端口已被其他规则占用」。向导式复制在「先复制再慢慢改」的预期路径上直接死路。
2. 用户按提示改了域名/端口后保存 → 副本**立即启用上线**接收流量，与预览展示的「禁用」相反。
**建议**：`CreateRuleRequest` 增加 `Enabled` 字段（或 CreateRule 读取可选 `enabled`，默认 true），使向导复制落库为禁用；或 UI 复制按钮改调 `/duplicate` 端点。
**是否待裁定**：否（证据充分）。

---

### LB-02【中】UpdateRule 非指针整型「0=沿用存量」合并吞掉显式 0——TCP 重试窗口/重试间隔/检查端口无法清零

**位置**：`internal/handlers/rules.go:1106-1114`；UI 语义 `web/src/views/Rules.vue:694-701、615-618`；消费 `internal/services/caddy.go:3284-3292、3326-3328`

**代码证据**：

```go
// rules.go:1106-1114
	if req.TCPHealthCheckPort == 0 {
		req.TCPHealthCheckPort = existingRule.TCPHealthCheckPort
	}
	if req.TCPTryDuration == 0 {
		req.TCPTryDuration = existingRule.TCPTryDuration
	}
	if req.TCPTryInterval == 0 {
		req.TCPTryInterval = existingRule.TCPTryInterval
	}
```

这三个字段在 `UpdateRuleRequest` 中均为**非指针 int**（models.go:456-459），「未提供」与「显式 0」在 JSON 反序列化后不可区分，合并逻辑统一按 0=未提供处理。而 UI 文案为 0 赋予了明确语义：

```html
<!-- Rules.vue:694-695 -->
<el-input-number v-model="wizardForm.tcp_try_duration" :min="0" :max="60000" ... />
<span class="form-tip-inline">毫秒，0 表示不重试；连接失败后在窗口期内尝试其他上游</span>
<!-- Rules.vue:699-700 -->
<el-input-number v-model="wizardForm.tcp_try_interval" :min="0" :max="10000" ... />
<span class="form-tip-inline">毫秒，每次重试间隔；0 表示使用 Caddy 默认间隔</span>
<!-- Rules.vue:616-617 -->
<el-input-number v-model="wizardForm.tcp_health_check_port" :min="1" :max="65535" ... />
<span class="form-tip-inline">0 表示使用第一个上游端口</span>
```

渲染端对 0 有真实、可区分的行为（caddy.go:3284-3292：`tryDuration > 0` 才发射 `try_duration`，否则完全不发射=关闭故障切换窗口；3326-3328：`TCPHealthCheckPort > 0` 才发射 `active.port`）。

MCP 工具描述将 UpdateRule 明确定位为部分更新契约（`internal/mcpserver/tools.go:43`）：

```go
	"update_rule":                  "修改现有规则的任意字段（部分更新）。协议切换会自动迁移上游协议并清理对侧字段",
```

**分类**：逻辑 bug（零值合并吞语义）。
**判定**：缺陷。依据：`tcp_try_duration=0` 是 UI 明示、渲染端明确消费的状态；存量非零时该状态经任何更新入口（UI/MCP/API）均不可达，保存返回成功但值回弹。
**影响**：曾配置过重试窗口（如 5000ms）的 TCP 规则永远无法改回「不重试」；`tcp_try_interval`/`tcp_health_check_port` 同理（后者还叠加 LB-09 的 UI min=1）。用户在预览看到「禁用」、保存成功，实际运行仍按旧值重试。
**设计合理性评估**：M16 审计已将 `HostHeader/Description/DnsServer/HealthCheckPath` 指针化以解决同型问题，但 TCP 整型字段未跟进；修复方向一致（指针化或引入「显式 0」哨兵）。
**建议**：`TCPTryDuration/TCPTryInterval/TCPHealthCheckPort` 改为 `*int` 并沿用 M16 合并口径。
**是否待裁定**：否。

---

### LB-03【中】UpdateRule 的 443 默认端口先于存量合并执行——部分更新会静默改写监听端口

**位置**：`internal/handlers/rules.go:984-988`（默认先执行）vs `rules.go:1074-1076`（存量合并后执行）

**代码证据**：

```go
// rules.go:984-988（在读库合并之前执行）
	// When TLS is enabled on HTTP, default the port to 443 if the user didn't explicitly set one.
	// For updates the port is fixed, so we only apply the default when an explicit port was not supplied.
	if req.Protocol == "http" && req.EnableTLS != nil && *req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}
...
// rules.go:1074-1076（存量合并）
	if req.ListenPort == 0 {
		req.ListenPort = existingRule.ListenPort
	}
```

注释自称「only apply the default when an explicit port was not supplied」，但实际效果相反：对监听 8080 的规则发送部分更新 `{"protocol":"http","enable_tls":true}`（不含 listen_port），`req.ListenPort` 被先改成 443，后续合并 `== 0` 不成立 → **8080 被静默改写为 443**。若 443 已被占用则报 400「端口已被其他规则占用」，否则规则监听端口被迁移、原端口监听消失。

CreateRule 的同型代码（rules.go:598-601）作用于新规则，无此问题；MCP `update_rule` 宣称「部分更新」（tools.go:43），该路径契约成立。

**分类**：逻辑 bug（合并顺序错误）。
**判定**：缺陷。依据：与函数内显式存在的「未提供字段沿用存量」合并设计（1068 起）直接矛盾，且打脸自身注释。
**影响**：API/MCP 部分更新启用 TLS 时静默迁移监听端口（8080→443），或因端口占用意外 400；原端口流量中断。
**建议**：将 443 默认值逻辑移到存量合并之后，且仅当「存量端口为 80 且本次未显式提供端口」时才应用（或仅信任显式端口）。
**是否待裁定**：否。

---

### LB-04【低】health_check_timeout 默认值三处分裂：写侧 2、读侧/渲染侧 5

**位置**：`internal/handlers/rules.go:678-680`、`internal/handlers/handlers.go:347-349`（写侧 2）vs `internal/handlers/rule_features.go:506、517`（`COALESCE(health_check_timeout,5)`）、`internal/services/caddy.go:3094-3097`（渲染 ≤0→5）

**代码证据**：

```go
// rules.go:678-680（CreateRule）
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = 2
	}
```
```go
// rule_features.go:506（lbRuleListColumns/lbRuleColumns 读取口径）
	COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5), ...
```
```go
// caddy.go:3094-3097（渲染兜底）
		hcTimeout := rule.HealthCheckTimeout
		if hcTimeout <= 0 {
			hcTimeout = 5
		}
```

**分类**：设计漂移。
**判定**：设计漂移。依据：三处默认值均为「兜底空值」性质且互不引用，2 与 5 的差异无任何注释解释；UI 默认 2（Rules.vue:1784）与写侧一致，说明 5 是旧口径残留。
**影响**：仅影响 NULL/0 值行（导入备份、直改 DB）：此类规则实际探测超时为 5s，而 UI 编辑回填显示 `|| 2` 兜底（Rules.vue:2187）会把表单值显示为 2，保存后落库 2——即一次无害的「打开即改写」。运行行为正确性不受影响（timeout<interval 校验两侧都会再跑）。
**建议**：统一为单一常量（建议 2，与 UI 一致），或读取侧改 COALESCE(...,2)。
**是否待裁定**：否。

---

### LB-05【低】启用态上游权重 0：UI 显示 0%，后端一律强改为 1，实际仍分得流量

**位置**：`web/src/views/Rules.vue:483` + `web/src/utils/upstreamWeights.ts:8-9` vs `internal/handlers/rules.go:834-836、1626-1628` + `internal/services/caddy.go:1508-1511、1746-1749、2978-2981`

**代码证据**：

UI 权重输入允许 0，且权重分摊算法对「启用」行的最小权重取 0（即允许启用行权重为 0）：

```html
<!-- Rules.vue:483 -->
<el-input-number v-model="row.weight" :min="0" :max="100" ... />
```
```ts
// upstreamWeights.ts:8-9
const minimumWeight = (item: WeightedItem): number => item.enabled === undefined ? 1 : 0
const normalizedWeight = (item: WeightedItem): number => Math.max(minimumWeight(item), Math.round(item.weight || 0))
```

（例：两上游，用户把 A 权重改为 0 → `redistributeWeight` 保持 A=0、B=100，`validateEnabledUpstreams` 的总和校验 `0+100===100` 通过。）预览/列表按占比显示 0%（Rules.vue:2331-2337 `weightPercent`）。

后端写侧与渲染侧一律把 0 当「未设置」强改为 1：

```go
// rules.go:834-836（CreateRule；1626-1628 同型）
	if u.Weight == 0 {
		u.Weight = 1
	}
```
```go
// caddy.go:2978-2981（buildHTTPHandleChain；1508-1511/1746-1749 同型）
	weight := upstream.Weight
	if weight <= 0 {
		weight = 1
	}
```

**分类**：逻辑 bug（UI 语义与存储/渲染不一致）。
**判定**：缺陷。依据：UI 的 `:min="0"` 与分摊算法共同产出「启用但权重 0」的合法形态，展示层（0%）与执行层（weight=1）语义分裂；后端 0→1 是历史「0=未设置」约定，未随百分比权重 UI 收敛。
**影响**：用户设 0% 期望零流量的上游实际获得 ≈1/(其余权重和+1) 的流量（如 [0,100]→存 [1,100]→GCD 后 [1,100]，约 1% 请求）。功能上应用「启用」开关来表达摘流，此为边角语义。
**建议**：UI `:min` 改 1（启用行），或后端保留 0 并在渲染侧将 weight 0 的启用上游按 0 参与（Caddy weights 支持 0：`weights [0,100]` 时 0 权重主机不获流量）。二选一，保持三链一致。
**是否待裁定**：否（低严重度、影响明确）。

---

### LB-06【低】docs/caddy-config-rules.md 多处与实现漂移

**位置**：`docs/caddy-config-rules.md:32-38、23、102、183、259`

**代码证据与逐项对照**：

1. **服务器命名**（doc:32-38 表格）：

   ```markdown
   | http | 80 | http_80 |
   | https | 443 | https_443 |
   | http | 其他 | http_{port} |
   | https | 其他 | https_{port} |
   ```

   实现恒为 `http_{port}`（caddy.go:1579 `servers[fmt.Sprintf("http_%d", port)]`；TCP 为 `tcp_{port}`，1756）。不存在 `https_*` 命名。

2. **负载策略清单**（doc:183）：「支持：round_robin、least_conn、random、ip_hash、weighted_random」；doc:259：「Strategy: round_robin/ip_hash/least_conn/random/first/least_time」。实现白名单为 `weighted_round_robin/least_conn/ip_hash/cookie/random/first`（rule_features.go:222-231、handlers.go:368-376）——文档列的 `round_robin/weighted_random/least_time` 均不在实现内，实现的 `weighted_round_robin/cookie` 未列。

3. **启动流程**（doc:102）：「内部调用 GenerateRouteObject() 生成每个路由（保证一致性）」——全量生成实际调用 `generateHTTPRouteObjects`（caddy.go:1523，经 `SingleRuleConfig`）；`GenerateRouteObject` 仅用于保存前校验的包装形态（handlers.go:594）。

4. **端口示例**（doc:23）：「TCP规则(port=8080) + TCP规则(port=8080) → 允许（同一规则重复）」——`validatePortFromDB` 按 `caddy_id != exclude` 排除自身（handlers.go:702），**另一条**启用中 TCP 规则同端口会被拒（渲染侧亦整体跳过该端口，caddy.go:1713-1723），示例表述容易误读为同端口双 TCP 规则可行。

**分类**：设计漂移。
**判定**：设计漂移。依据：文档描述的是旧/设想形态，实现与注释（如 R43/R44 修订记录）已多轮演进，文档未同步。
**影响**：按文档对接 API/排障会得到错误的 server 名与策略集合；`https_443` 命名在 Caddy admin API 排查时不存在。
**建议**：以实现为准更新文档四节。
**是否待裁定**：否。

---

### LB-07【低】ValidateRouteMergedConfig 在目标 server 不存在时直接放行，候选路由未经 Caddy 校验

**位置**：`internal/services/caddy.go:244-248`（apps/http/servers 缺失的 231-243 分支同型）

**代码证据**：

```go
	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		// Server doesn't exist, so prepend won't cause merge issues
		return nil
	}
```

该函数是 HTTP 规则保存前的唯一 Caddy 侧预校验入口（handlers.go:598）。当候选规则监听端口在运行配置中尚无 server（典型：非 80/443 端口的**首条**规则，或 Caddy 刚启动只有 http_80 兜底站时）时，直接 `return nil`，**候选路由本身没有经过 `/load?validate=true` 的任何校验**。注释只考虑了「合并不会产生冲突」，未考虑「候选自身合法性未被验证」。

**分类**：不合理逻辑（校验缺口）。
**判定**：设计缺口（介于有意与缺陷之间）。依据：无注释声明有意跳过；但后果有兜底——真正非法的配置会在随后的 `ApplyConfigFromTx` 阶段被 Caddy 拒绝并触发事务回滚+运行时快照恢复（rules.go:878-882），数据库与运行面仍一致，只是错误暴露时机从「校验阶段 400、零副作用」推迟到「应用阶段 400、多付一次快照/恢复周期」。
**影响**：非默认端口首条规则的保存错误延迟暴露，错误信息一致性略差；正确性不受损。
**建议**：server 不存在时也应构造 `{"apps":{"http":{"servers":{serverName:{listen:[...],routes:[候选]}}}}}` 的最小合并副本送验。
**是否待裁定**：**是**（T-1：该放行是否有意为之——例如刻意避免对空配置发请求——请维护者裁定）。

---

### LB-08【低】上游健康状态键 IPv6 不匹配：后端带方括号、前端不带

**位置**：后端 `internal/services/caddy.go:2686-2688（joinUpstreamAddress→net.JoinHostPort）、589/3007`；前端 `web/src/views/Rules.vue:1654、1691`

**代码证据**：

```go
// caddy.go:2686-2688
func joinUpstreamAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
```

`net.JoinHostPort("2001:db8::1", 80)` → `"[2001:db8::1]:80"`；健康详情 map 与 Caddy 指标 label 均以此为键（caddy.go:580、664-678）。

```ts
// Rules.vue:1654（getUpstreamHealthStatus）；1691（fetchHealthStatus）同型
  const upstreamKey = `${upstream.host}:${upstream.port}`
```

前端键为 `"2001:db8::1:80"`，永远匹配不到后端的 `"[2001:db8::1]:80"`。

**分类**：逻辑 bug（键口径不一致）。
**判定**：缺陷。依据：两侧无共享键构造函数，IPv6 主机上游的健康态在 UI 恒落 `unknown` 分支（`getUpstreamHealthStatus` 返回 `{healthy:false, unknown:true}`），显示「未知」。
**影响**：仅影响 IPv6 上游（或含冒号主机名）的健康展示与规则级健康汇总（`unknown>0` 会拉低标签为「降级/未知」），不影响代理转发本身。
**建议**：前端用与 `net.JoinHostPort` 等价的归一（host 含 `:` 时加方括号），或后端在 `/config/health` 响应中直接携带 host/port 结构化字段。
**是否待裁定**：否。

---

### LB-09【低】TCP 主动健康检查端口：UI `:min="1"` 与「0 表示使用第一个上游端口」文案矛盾

**位置**：`web/src/views/Rules.vue:616-617`

**代码证据**：

```html
<el-input-number v-model="wizardForm.tcp_health_check_port" :min="1" :max="65535" controls-position="right" style="width: 120px;" />
<span class="form-tip-inline">0 表示使用第一个上游端口</span>
```

后端 0 有真实语义（caddy.go:3326-3328：`if rule.TCPHealthCheckPort > 0 { active["port"] = ... }`，0=不发射 port，l4 按上游自身地址探测）。但输入框最小值 1，用户无法主动输入 0；另外开启主动检查的 watch 会自动把端口填成第一个上游端口（Rules.vue:1925-1929），使「跟随上游端口」状态在实践中几乎不可达。叠加 LB-02 的零值合并，即使 API 客户端想清 0 也写不回。

**分类**：不合理逻辑（UI 约束与文案/后端语义矛盾）。
**判定**：缺陷（UI 层）。依据：文案承诺的状态在 UI 内不可达，属输入约束未随语义更新。
**影响**：用户无法把自定义检查端口恢复为「跟随上游端口」；文案误导。
**建议**：`:min="0"`（并保留 0 的显示），或改文案说明端口为必填。
**是否待裁定**：否。

---

### LB-10【低】事务内上游循环中的「HTTP 规则上游协议 tls」400 检查不可达且位置不当

**位置**：`internal/handlers/rules.go:844-848`（CreateRule）、`rules.go:1636-1639`（UpdateRule）

**代码证据**：

```go
// rules.go:833-848（位于 DB 事务内的上游 INSERT 循环）
	for _, u := range req.Upstreams {
		...
		// Round 37 I-11: HTTP 规则上游 protocol=tls 静默当 http 处理（与 TCP 行为不对称），显式拒绝。
		if req.Protocol == "http" && u.Protocol == "tls" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP 规则的上游协议不支持 tls，请使用 http 或 https"})
			return
		}
```

同样的拒绝在保存前的 `validateCaddyConfigBeforeSave` 已按协议族完成（handlers.go:413-420：「上游 #d：协议 'tls' 无效（HTTP 规则仅支持 http/https）」），该校验先于事务执行（rules.go:763 vs 778），因此事务内的重复检查在正常流程不可达；若真触发，也是在部分 upstream 已 INSERT 之后于事务中返回 400（依赖 `defer tx.Rollback()` 收尾，正确性无虞但位置违反「全部校验先于写库」的自述契约，见 rules.go:554-559 注释）。

**分类**：冗余代码。
**判定**：有意设计（纵深防御，注释标明 R37 I-11 背景）。评估：防御本身合理，但应移到事务外与其他校验同址，避免事务内早退依赖 defer 回滚。
**影响**：无功能影响；维护时易误以为存在两条不同校验口径。
**建议**：上移至 `validateCaddyConfigBeforeSave` 之后、`BeginTx` 之前的统一校验段。
**是否待裁定**：否。

---

### LB-11【低】generateCaddyConfigFromStore 中 `if !r.Enabled { continue }` 死分支

**位置**：`internal/services/caddy.go:1119-1125`

**代码证据**：

```go
	if r.Strategy == "" {
		r.Strategy = "weighted_round_robin"
	}

	if !r.Enabled {
		continue
	}
```

查询本身为 `FROM lb_rules WHERE enabled = 1`（caddy.go:1094），且扫描列是 `IIF(enabled IN ('1',1),1,0)`——进入循环的行 `r.Enabled` 恒为 true，`continue` 不可达。

**分类**：冗余代码。
**判定**：有意设计（防御式遗留：IIF 兼容文本 '1' 的历史脏数据，分支是 IIF 引入前的残留）。评估：无害；对读码者是噪音，且与上游加载查询（1146-1150，SQL 侧已过滤 enabled）双保险不对称。
**建议**：可删除（渲染侧真正的「零启用上游跳过」在 1429-1432 另有实现）。
**是否待裁定**：否。

---

### LB-12【低】CreateRule 的 serverName 四分支全部产出 `http_{port}`，与 UpdateRule 单行写法不对称

**位置**：`internal/handlers/rules.go:729-742` vs `rules.go:1346`

**代码证据**：

```go
// rules.go:729-742
	var serverName string
	if req.Protocol == "http" {
		if req.EnableTLS && req.ListenPort == 443 {
			serverName = "http_443"
		} else if req.ListenPort == 80 {
			serverName = "http_80"
		} else if req.EnableTLS {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
		} else {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
		}
	} else {
		serverName = fmt.Sprintf("tcp_%d", req.ListenPort)
	}
```

四个 HTTP 分支的字符串结果完全相同（`"http_443"` ≡ `fmt("http_%d",443)`）。UpdateRule 已收敛为单行：`validationServerName := fmt.Sprintf("%s_%d", req.Protocol, req.ListenPort)`（rules.go:1346）。

**分类**：冗余代码。
**判定**：设计漂移（TLS 分端口命名的历史方案残留，与 LB-06 文档漂移同源）。评估：无功能影响；误导读码者以为 TLS 规则有独立 server 命名。
**建议**：收敛为与 UpdateRule 相同的单行写法。
**是否待裁定**：否。

---

### LB-13【低】「查看 Caddy 配置」对话框对启用自定义路由的规则只展示主路由，路径路由缺失

**位置**：`internal/handlers/rules.go:140`（GetConfigByID）+ `internal/services/caddy.go:2661`（路径路由 @id 命名）

**代码证据**：

```go
// rules.go:140-141（仅按规则主 @id 取单个对象）
	caddyActualConfig, err := h.caddyService.GetConfigByID(r.CaddyID)
```

全量渲染中，启用自定义路由的规则会产出扁平的多条路由：GeoIP pass（无 @id）、各路径路由 `@id = caddyID_path_N`、主路由 `@id = caddyID`：

```go
// caddy.go:2656-2662
		pathRoute := map[string]interface{}{...}
		tagRuleRoute(pathRoute, rule.CaddyID, fmt.Sprintf("path_%d", pathIndex))
```

`GetConfigByID(caddyID)` 只返回主路由对象，`caddyID_path_N` 的路由不出现在响应 `config.route` 中；对话框 `SyntaxHighlight` 只渲染该单对象（Rules.vue:906）。

**分类**：不合理逻辑（展示链不完整）。
**判定**：设计漂移（查看器建于路径路由特性之前，未随 v2 特性更新）。评估：纯展示缺口，不影响运行；但「真实渲染」核对场景（排障自定义路由）恰好是最需要完整 JSON 的场景。
**建议**：响应中并列返回 `caddyID_*` 前缀路由（已有 `routeIDBelongsToRule` 前缀工具，caddy.go:439-441）。
**是否待裁定**：否。

---

### LB-14【低】上游「最大请求数」tooltip 把 Caddy max_requests 描述为「累计处理」，实际是并发（simultaneous）

**位置**：`web/src/views/Rules.vue:488-493`

**代码证据**：

```html
'该上游累计处理的请求数达到上限后判定不可用并移出负载（Caddy max_requests 语义），0 为不限制——HTTP 反代无逐上游并发连接限制'
```

Caddy v2.11.4 源码（`modules/caddyhttp/reverseproxy/hosts.go:50-55`）：

```go
	// The maximum number of simultaneous requests to allow to
	// this upstream. If set, overrides the global passive health
	// check UnhealthyRequestCount value.
	MaxRequests int `json:"max_requests,omitempty"`
```

「判定不可用并移出负载（被动健康语义）」与「0 为不限制」两半正确，但「累计」应为「同时/在途」。TCP 侧 tooltip（l4 max_connections，同段 490 行）表述准确（l4 源码：「before being marked as unhealthy」）。

**分类**：不合理逻辑（UI 文案与上游语义不符）。
**判定**：设计漂移（文案笔误级）。影响：用户可能误以为计数器永不重置、设阈值时口径错误。
**建议**：「同时处理」替换「累计处理」。
**是否待裁定**：否。

---

### LB-15【低·待裁定】规则级 server_tokens_hidden（0/1/2 覆盖）后端全链路支持，UI 无编辑入口

**位置**：`internal/models/models.go:413`、`internal/handlers/rules.go:709-712`（校验）、`internal/services/caddy.go:2218-2223`（消费：1=隐藏、2=显示、0=随全局）；`web/src/views/Rules.vue` 全文无该字段控件（仅 1805/2213/2610 透传默认 0）；全局开关在 `web/src/views/settings/CaddyGlobalSettings.vue:58-61`。

**代码证据**：

```go
// caddy.go:2218-2223
	hideServer = rule.GlobalServerTokensHidden
	if rule.ServerTokensHidden == 1 {
		hideServer = true
	} else if rule.ServerTokensHidden == 2 {
		hideServer = false
	}
```

```go
// rules.go:709-712（校验完备）
	if req.ServerTokensHidden < 0 || req.ServerTokensHidden > 2 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
	}
```

**分类**：待裁定（按审计标准第 4 条列入）。
**判定**：待裁定 T-3。两种解读均成立：① 有意设计——为 API/MCP 预留的规则级覆盖，UI 刻意只暴露全局开关；② 设计漂移——字段随全局功能一起实现，UI 忘记跟进。
**影响**：UI 用户只能通过全局开关控制；API 设过的规则级覆盖在 UI 编辑保存时被透传保留（2610 `|| 0` 不会清值，因 `0` 仅在原值为 0 时发出……注：`wizardForm.server_tokens_hidden || 0` 原值 1/2 会原样回传），无破坏。
**建议**：裁定后二选一：UI 高级选项补开关，或文档声明 API-only。
**是否待裁定**：**是**。

---

### LB-16【低】GenerateSingleRuleCaddyConfig HTTP 分支的 redirect 子分支不可达（代码内已自注）

**位置**：`internal/services/caddy.go:2410-2461`（尤其 2414-2420 的可达性说明与 2422-2427 的 automatic_https 口径差异记录）

**代码证据**（节选）：

```go
		// 可达性说明（防止误用）：此单规则跳转形态当前并无调用方会触发——
		// handlers.go 的规则验证中 HTTP 协议走 GenerateRouteObject（合并进既有端口验证），
		// 仅 TCP 协议调用 GenerateSingleRuleCaddyConfig；rule_features.go 的
		// validateRuleConfigGeneration 也不填 EnableTLS/TLSHTTPRedirect 字段。
```

grep 核实调用方仅两处：`handlers.go:582`（TCP 分支）与 `rule_features.go:827`（不填 TLS 字段），与注释一致。

**分类**：已弃用代码（不可达分支）。
**判定**：有意保留（注释声明了保留原因与启用前置条件：须补齐 80/443 的 `disable_certificates` 例外）。评估：保留是合理的防御（防未来调用方踩坑），但按「已弃用代码」口径登记。
**影响**：无（不可达）。
**建议**：维持现状；若长期无启用计划可考虑删除并保留注释于 git 历史。
**是否待裁定**：否。

---

### LB-17【低】GetRuleCaddyConfig 每次查询 enabled 上游数仅用于 debug 日志

**位置**：`internal/handlers/rules.go:118-125`

**代码证据**：

```go
	var upstreamCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE rule_id = ? AND IIF(enabled IN ('1',1),1,0) = 1`, caddyID).Scan(&upstreamCount); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取上游服务器失败"})
		return
	}

	services.Logf("debug", "GetRuleCaddyConfig: caddyID=%s, port=%d, upstreams=%d, enabled=%v", ...)
```

`upstreamCount` 后续无业务消费（ responseData 组装不引用）。

**分类**：冗余代码。
**判定**：设计漂移（早期用于「无上游则 config_not_exists」判断，后该判断移除，查询遗留）。评估：每次打开配置对话框多一次 DB 查询；500 分支（查询失败会让整个查看失败）与用途（仅日志）不成比例。
**建议**：降级为 debug 级惰性查询或删除。
**是否待裁定**：否。

---

### LB-18【低】「超时必须小于间隔」校验：前端仅主动检查开启时校验，后端不分场景校验

**位置**：前端 `web/src/views/Rules.vue:2533-2536` vs 后端 `internal/handlers/rule_features.go:243-246`

**代码证据**：

```ts
// Rules.vue:2533-2536（门控在 enable_active_health_check 上）
  if (wizardForm.enable_active_health_check
      && wizardForm.health_check_interval > 0
      && wizardForm.health_check_timeout > 0
      && wizardForm.health_check_timeout >= wizardForm.health_check_interval) {
```

```go
// rule_features.go:243-246（不区分主动/被动）
	// Round 37 I-6: 健康检查超时必须小于检查间隔（两者都 > 0 时）。
	if input.HealthCheckInterval > 0 && input.HealthCheckTimeout > 0 && input.HealthCheckTimeout >= input.HealthCheckInterval {
		return fmt.Errorf("健康检查超时时间（%d 秒）必须小于检查间隔（%d 秒）", ...)
```

被动-only 规则（关闭主动检查）在 UI 将 interval 调小/timeout 调大（UI 允许 interval 5-300、timeout 1-30，可构成 timeout≥interval）可通过前端所有门，随后被后端 400 拒绝。

**分类**：逻辑 bug（前后端校验门控不一致，属轻微）。
**判定**：缺陷（轻微）。依据：同一约束两端口径不同且无注释说明差异；后端口径本身对被动-only 规则偏严（渲染侧被动检查并不消费 timeout，见 caddy.go:3073-3081 无 timeout 字段——该超时仅进入 active 块 3098-3104），严格说是后端过严+前端漏拦的组合。
**影响**：被动-only 规则保存时收到后端 400（文案清晰，可自行修正）；无运行面影响。
**建议**：前端去掉 active 门控对齐后端；或后端将该校验门控到 `EnableActiveHealthCheck`（与渲染消费对齐）。
**是否待裁定**：否。

---

### 3.18 专项核查结论（无发现，记录核查过程）

**A. 规则保存/重载失败回滚链（Create/Update/Enable/Disable/Delete）**：五端点均为「快照（validate 之前摄取，R69 C-N3-b）→ validateCaddyConfigBeforeSave（HTTP：合并候选进运行配置副本真载后 `DeleteRouteByID` 清理临时路由；TCP：`ValidateTCPServerMergedConfig` 同口径）→ 事务写库 → `ApplyConfigFromTx` → 失败即 `restoreImportRuntime` + 事务回滚/补偿」。与 `docs/caddy-config-rules.md` §错误处理表一致；validate 失败（4xx）时 Caddy 未加载配置、无副作用，成功时的真载副作用均被前置快照覆盖。HTTP 校验后临时路由清理失败仅告警不阻断（handlers.go:602-604），后续全量 apply 或恢复快照均会覆盖该残留——判定自洽。

**B. 权重/策略计算正确性**：HTTP `normalizeWeights`（caddy.go:3206-3230）为标准 GCD 约分，零权重条目不会出现于入参（上游权重先经 ≤0→1 强改）；Caddy `WeightedRoundRobinSelection.Weights` 与 upstreams 顺序一一对应（源码核实），`len(Weights)<2` 时直接取 pool[0]（与 caddy.go:3046-3053 注释对动态 DNS 场景的分析一致）。l4 侧 `weight<=0 视为 1`（l4 源码核实），生成端仅 >1 发射，等价。cookie 策略 `{"policy":"cookie","name":"lb_sticky"}` 字段合法（Caddy `CookieHashSelection.Name`）。

**C. 健康检查参数边界**：UI 边界（interval 5-300、timeout 1-30、阈值 1-10）严于后端（interval≥1、timeout≥1、timeout<interval）；渲染侧对 0/负值全部有兜底（10/5/3/2，caddy.go:3065-3103、3297-3319）；`unhealthy_status:[5]` 类码语义与 Caddy `StatusCodeMatches` 一致（<100 匹配整百段，代码注释含 2026-09 复审记录）。被动 `fail_duration=3×interval` 与 UI 文案一致。

**D. 路径规则链**：前端 `canonicalPathKey`（ruleValidation.ts:55-59）与后端 `pathMatcherSpecs`/查重归一（rule_features.go:323-350、caddy.go:2675-2684）同源（prefix 剥尾 `/*`、exact 剥尾 `/`、空回退 `/`）；空 upstreams 数组与 null 统一回退主上游（caddy.go:2642-2647）；DB 写入/读取（`replacePathRulesTx`/`decodePathUpstreams`）保序保形。排序按 sort_order 稳定排序（2636-2639），UI 以行序回写 sort_order（Rules.vue:2615-2621）。

**E. 规则冲突矩阵**：同端口 HTTP 域名冲突（保存+启用双检，规范化域名比较）、TCP 端口独占（enabled-only 口径）、80 端口跳转遮蔽（保存双向检查+渲染期复核+按域名粒度放行兄弟域名，caddy.go:1609-1655）、80 端口 TLS 自环拒绝——核查一致。通配符域名被 `isValidDomain`（helpers.go:1061-1087，标签仅字母数字连字符）排除，无通配符遮蔽类缺口。

**F. caddyDefaults.ts**：仅含访问日志格式模板，与本域规则默认值无交集（见 §1.4 表）；其「前端模板不对齐后端迁移行」的自注（R41 F1）属日志域，不在本域展开。

---

## 四、待裁定项汇总

| 编号 | 条目 | 问题 | 建议 |
|---|---|---|---|
| T-1 | LB-07 | `ValidateRouteMergedConfig` 目标 server 不存在时直接放行（候选路由未经 Caddy 校验），是否有意避免对空配置发请求？ | 裁定后补最小合并副本送验，或注释声明有意放行 |
| T-2 | （观察项，未单列编号）HTTP 规则重试窗口固定 `try_duration=5s/try_interval=250ms` 硬编码（caddy.go:3057-3061），UI「连接重试」仅 TCP 步骤暴露、文档未记载该 L7 固定值；L4 则完全可配。是否为有意的不对称？ | 裁定后补 UI 高级选项/文档说明，或开放规则级配置 |
| T-3 | LB-15 | 规则级 `server_tokens_hidden`（0/1/2）后端全链路支持（模型/校验/渲染）但 UI 无入口：API 预留还是 UI 缺失？ | 补 UI 或文档声明 API-only |
