# 安全模块（核心）审计报告（2026-09-05）

## 一、概览

### 1.1 范围文件清单

本域为「安全模块-核心」：安全事件、IP 封禁（IP ACL/黑名单/信任名单）、限流、登录保护联动、主从安全状态语义。本会话逐行读码核实的文件：

| 层 | 文件 | 说明 |
|---|---|---|
| 服务 | `internal/services/security.go`（1517 行） | 策略加载、coraza 指令发射（IP 控制/GeoIP/自定义规则/CRS）、IP 预检、CRS 排除、校验器 |
| 服务 | `internal/services/securityevents.go`（1038 行） | 审计日志 tailer（offset 消费链）、事务解析、多策略事件归因、畸形区恢复 |
| 服务 | `internal/services/securityevents_retention.go` | 事件保留清理（每日，分批） |
| 服务 | `internal/services/securityiplists.go` | 可复用 IP 列表：refs 解析、inline ∪ 引用合并集 |
| 服务 | `internal/services/auditlog_rotation.go` | copytruncate 轮转、.1 补采、delta-pending 标记 |
| 服务 | `internal/services/caddy.go`（相关段） | `buildRateLimitHandler`/`buildRateLimitErrorRoute`/`buildBlockPageErrorRoute`/`buildIPPrecheckDirectives` 调用点、X-LB-Rule-ID 注入/剥离 |
| 服务 | `internal/services/mfa.go`、`internal/handlers/mfa.go` | MFA 挑战/验证/锁定常量 |
| 处理器 | `internal/handlers/security.go`（2893 行） | 策略/自定义规则/拦截页 CRUD、绑定、事件查询、总览、CRS/IP 库端点 |
| 处理器 | `internal/handlers/security_overview.go` | `/security/rate-limit-blocks`（Caddy metrics 429 口径） |
| 处理器 | `internal/handlers/auth.go` | 登录、登录失败锁定、改密验当前密码 |
| 中间件 | `internal/middleware/middleware.go` | `loginRateLimit`（10 次/分/IP）、`jwtAuth`/`apiKeyAuth`、认证拒绝审计限流；对照 `security_contract_test.go`、`round24_setup_ratelimit_test.go` |
| 模型 | `internal/models/security.go` | SecurityPolicy/Event/Summary/CRS 排除条目/IP 列表 |
| 存储 | `internal/db/metrics.go:259-332`、`internal/db/db.go:504-534` | security_events 表（metrics 库）+ transaction_id 部分唯一索引；security_policies schema |
| 主从 | `internal/services/cluster_snapshot.go`、`cluster_apply.go`、`cluster_sections.go` | users/security 段同步列集与重放语义 |
| 前端 | `web/src/views/security/SecurityEvents.vue`、`SecurityOverview.vue`、`IPLocationAction.vue`、`SecurityPolicies.vue`（限流/ACL/状态码段）、`web/src/views/settings/BasicSettings.vue`（锁定开关文案）、`web/src/components/LogStorageBar.vue` + `internal/handlers/logstats.go`（保留期文案） | UI 语义对照 |
| 前端 | `web/src/views/Dashboard.vue` | **核实结论：当前 Dashboard 无任何安全区块**（仅系统概览/Caddy/资源/图表/规则表），审计任务所述「Dashboard 安全区块」在代码中不存在，安全统计入口为独立的「安全总览」页 |

### 1.2 方法

- 全程只读；逐条发现均在本次会话读码核实并摘录原文；未触碰 `data*`、`logs*`、`waf*`、`certs*` 运行数据。
- 运行了只读验证测试（均通过，见 §3.1 SC-1 的测试证据与 §1.4）。
- 按「UI 语义 → 存储 → 消费 → 真实渲染」三链对照四条主线：限流、IP 封禁、登录保护、安全事件。
- 对照 2026-09 已裁定认证基线逐条核对（见 §1.3）。

### 1.3 认证基线核对结论（基线本身不作为问题报告）

| 基线条目 | 证据 | 结论 |
|---|---|---|
| 登录阶段密码+MFA 验证码同计 5 次/10 分钟，受「登录失败锁定」开关控制 | `auth.go:58-89`（`loginLockMaxAttempts=5`/`loginLockCooldown=10min`/`recordLoginFailure`/`loginLockedNow`）；`mfa.go(handler):48-70`（验证码失败调 `recordLoginFailure`，锁定期间验证步 429 不耗挑战）；开关文案 `BasicSettings.vue:82-84`「密码或验证码失败 5 次锁 10 分钟（关闭则不锁定）」 | ✅ 一致 |
| 开关关闭只计数不锁定 | `auth.go:74-77`（关闭分支仅 `login_failed_attempts+1`） | ✅ 一致 |
| 登录后零密码输入，唯一例外=改密验当前密码（纯 bcrypt 不计数） | `auth.go:352-367`（改密需 `current_password`，失败仅 401 不调 `recordLoginFailure`）；`mfa.go(handler):186-216`（禁用 MFA 仅验码，失败只提示）、`:111-128`（重绑仅验码）、`:220-237`（恢复码会话即确认） | ✅ 一致 |
| MFA 验证失败（登录后）只提示不计数 | `MFADisable:200-208`、`MFAVerifyStep:252-259` 均无计数调用（另有挑战级 `MFARecordChallengeFailure` 10 次作废与 pending 5 次作废两道与开关无关的硬闸） | ✅ 一致 |
| API Key 无密码门、改密不吊销 Key | `middleware.go:654-755`：`apiKeyAuth` 不校验 `password_version`（对比 `jwtAuth:624-637` 有 `pwd_ver` 校验） | ✅ 一致 |
| 公开端点 IP 限流（10 次/分，登录/setup/ticket/MFA verify 共桶） | `middleware.go:113-142,233-237`；`round24_setup_ratelimit_test.go` 钉住 | ✅ 一致 |

主从维度偏差见 SC-4。

### 1.4 四条三链对照摘要

1. **限流**：向导「速率上限（次/秒，持续请求时的速率上限）/突发余量（次，短时允许超出速率上限的额外请求数）」（`SecurityPolicies.vue:484-491`）→ `security_policies.rate_limit_rps/burst` → `buildRateLimitHandler`（`caddy.go:2823-2858`：burst>0 时双区 AND——1s 区 `rps+burst`、60s 区 `rps*60`；burst=0 单 1s 区 `rps`；写入侧 `validateRateLimitShape` 拒绝 enabled+rps<1）→ caddy-ratelimit 429 → `buildRateLimitErrorRoute`（拦截页正文、恒 429）→ Caddy `/metrics` code=429 → `/security/rate-limit-blocks` → 安全总览「限流拦截」卡片（文案「按 429 响应计（含上游自返 429）」与 `overviewmetrics.go:14-16,63-87` 口径一致）。**语义与文案基本对齐；偏差见 SC-2（状态码文案）、SC-10（Retry-After）**。
2. **IP 封禁**：事件/总览页 IP 弹窗（`IPLocationAction.vue`）「加入黑名单/白名单/信任名单/移除」→ `PUT /security/policies/:id` 局部更新（`ip_acl_mode/ip_acl_list/ip_acl_enabled`）→ 发射为 coraza `id:2`（deny/allow ACL）、`id:4`（遗留黑名单）、多策略预检（`buildIPPrecheckDirectives`，deny 并集优先于全部 rate_limit/waf）→ 拒绝 403 进 audit.log → 摄取归因 → 事件表/UI。**链路闭环；偏差见 SC-6/SC-7/SC-8**。
3. **登录保护联动**：见 §1.3，全部符合基线；主从语义见 SC-4，残留见 SC-5。
4. **安全事件（含 `data/security_events.offset` 消费链）**：coraza `SecAuditEngine RelevantOnly` 写 `/app/waf/audit/audit.log`（JSON 逐事务）→ tailer 每 2s tick 从持久化 offset 续读（`securityEventsReadOffset/WriteOffset`，原子 tmp+rename）→ 解析（事务 ID 唯一索引去重、空 ID 跳过、异常分从 949/959 文本与自定义规则 setvar 提取）→ 归因（X-LB-Rule-ID 注入头优先，host 反查兜底；策略归属按 rule_triggered → 首匹配策略）→ 批量事务插入 metrics 库 `security_events`（500/批，批间推进 committedOffset）→ 轮转（copytruncate：先采集后轮转、活文件尾部补采、`.1` 归档补采、`delta-pending` 崩溃安全标记、truncate 后立即归零 offset）→ 保留清理（`audit_retention_months`×30 天 + 10 万条上限，UI 文案 `logstats.go:103-108` 一致）→ 查询端点（分页/筛选/时区边界）→ 前端渲染。**工程化程度高；缺陷见 SC-1（归因 off 门失效）、SC-3/SC-9/SC-11**。

### 1.5 结论摘要

共 11 条发现：高 0、中 3（SC-1 事件归因 off 门死代码；SC-2 限流状态码 UI 文案与实现矛盾；SC-4 主从登录锁定本地态语义未声明且重放清零）、低 8。认证基线全项核实无偏差；限流发射/校验/UI 三侧基本对齐（状态码文案与 Retry-After 除外）；事件摄入管线（offset/轮转/补采/去重）经多轮加固后未发现新缺陷。主要问题集中在：多策略归因的一处死代码、两处 UI 文案漂移、主从登录锁定语义未声明、M7 时代锁定残留。

## 二、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| SC-1 | internal/services/securityevents.go:358,449 | 逻辑 bug | 中 | 缺陷 |
| SC-2 | web/src/views/security/SecurityPolicies.vue:573 ↔ internal/services/caddy.go:2789-2808 | 不合理逻辑（UI 语义漂移） | 中 | 设计漂移 |
| SC-3 | internal/handlers/security.go:1743,1819-1822,2053-2058 ↔ web/src/views/security/SecurityEvents.vue:333-335 | 不合理逻辑（口径不一致） | 低 | 设计漂移 |
| SC-4 | internal/services/cluster_snapshot.go:758-762、cluster_apply.go:327-331,403-410 | 主从同步语义 | 中 | 设计漂移 |
| SC-5 | internal/services/mfa.go:24-25,296,350 | 已弃用代码（死常量+僵尸列） | 低 | 设计漂移（残留） |
| SC-6 | web/src/views/security/IPLocationAction.vue:50 ↔ SecurityPolicies.vue:2180 | 已弃用代码（指引不可达） | 低 | 设计漂移 |
| SC-7 | web/src/views/security/SecurityPolicies.vue:2179-2202 | 不合理逻辑（语义不对称未透出） | 低 | 有意设计（未透出） |
| SC-8 | web/src/views/security/IPLocationAction.vue:515、SecurityPolicies.vue:420 ↔ internal/services/security.go:727-728 | 不合理逻辑（多策略文案偏差） | 低 | 设计漂移 |
| SC-9 | internal/handlers/security.go:2141,2164,2195 ↔ SecurityOverview.vue:111,187 | 不合理逻辑（窗口未标注） | 低 | 设计漂移 |
| SC-10 | internal/services/caddy.go:2789-2808 | 不合理逻辑（Retry-After 恒 1s） | 低 | 有意设计（合理性存疑） |
| SC-11 | internal/handlers/security.go:2225-2231 | 逻辑 bug（自述标准偏离） | 低 | 缺陷 |

统计（按分类）：逻辑 bug 2（SC-1、SC-11）、不合理逻辑 6（SC-2、SC-3、SC-7、SC-8、SC-9、SC-10）、已弃用代码 2（SC-5、SC-6，冗余代码并入 SC-5）、主从同步语义 1（SC-4）。严重度：高 0 / 中 3（SC-1、SC-2、SC-4）/ 低 8。判定（三选一）：缺陷 2（SC-1、SC-11）/ 设计漂移 7（SC-2、SC-3、SC-4、SC-5、SC-6、SC-8、SC-9）/ 有意设计 2（SC-7、SC-10）。

> 注：SC-4 在「分类」维度单列（主从语义），严重度计为中；上表判定列仍为三选一。

## 三、逐条详述

### SC-1 安全事件多策略归因：`mode` 列未加载，A1-S6「off 策略不认领 CRS 事件」门为死代码

**位置**：`internal/services/securityevents.go:358`（加载查询）、`:367`（Scan）、`:449`（off 门）

**代码证据**：

加载查询（`:358`，不含 `mode` 列）：
```go
polRows, err := db.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(custom_rules,'[]'), COALESCE(crs_rule_groups,'[]'), COALESCE(ip_blacklist,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_list_refs,'[]'), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,''), COALESCE(waf_check_response,0) FROM security_policies WHERE enabled=1`)
```
Scan 目标（`:367`）12 个，无 `&p.Mode`：
```go
if err := polRows.Scan(&p.ID, &p.Name, &customJSON, &crsJSON, &blacklistJSON, &p.IPACLEnabled, &p.IPACLMode, &p.IPACLList, &p.IPACLListRefs, &geoipJSON, &p.GeoIPMode, &p.WAFCheckResponse); err != nil {
```
off 门（`:441-451`）：
```go
case n >= 900000 && n < 1000000:
	// …
	// A1-S6：mode=off 不发射任何 CRS（engine 分支不成立或零 Include），
	// 不得认领 CRS 事件（与 GeoIP 分支的 off 门同口径）。
	if policy.Mode == "off" {
		return false
	}
```

**分类**：逻辑 bug。**判定：缺陷**。依据：注释明确声明该门的意图（A1-S6，与 GeoIP 分支的 `geoip_mode` off 门同口径——后者因 `geoip_mode` 已加载而生效），但加载查询从未 SELECT `mode` 列，`p.Mode` 恒为零值 `""`，门条件 `policy.Mode == "off"` 永假。GeoIP 分支（`:413` `if policy.GeoIPMode == "off"`）能工作正说明这是遗漏而非有意。

**测试证据（本会话运行）**：`internal/services/securityevents_test.go:252` 插入策略仅 `(id,name)`（schema 默认 `mode='off'`，`db.go:508` `mode TEXT DEFAULT 'off'`），`:268-271` 期望 942100（CRS 事件）归因到该策略并通过：
```go
if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name) VALUES (7,'policy-seven')`); err != nil { … }
…
pid, pname := securityEventsAttributePolicy(rule.caddyID, "942100", policyByID, bindings)
if pid != 7 || pname != "policy-seven" {
```
`go test ./internal/services/ -run 'TestSecurityEventsMapHost_MatchesCanonicalAndReportsUnknown' -count=1` → ok（0.580s）。该测试反向钉死了缺陷行为：若 off 门生效此测试应失败。归因测试组（`:1717-1960`）无任何 mode=off 不认领 CRS 的用例。

**影响**：一规则绑定多策略且低 policy_id 策略为 mode=off（如仅开 IP 控制/GeoIP/自定义规则）时，其 `crs_rule_groups='[]'`（空=「包含全部 CRS」语义，`:471-473`）会抢先认领实际由高 policy_id 的 blocking/detection 策略发出的 CRS 事件：① 事件表 `policy_id/policy_name` 落错；② 事件页「归属策略」与 CRS 快捷排除弹框（`SecurityEvents.vue:523-572` 用 `ev.policy_id` 提交 `crs_excluded_rules`）会把排除写到从未发射 CRS 的 off 策略上——排除永久不生效且无告警。展示层+快捷操作双影响。

**建议**：加载查询补 `COALESCE(mode,'off')` 列与 Scan 目标；为 A1-S6 补一条「mode=off 策略不认领 CRS 事件」的归因测试，并修正现有测试的钉死行为。

**是否待裁定**：否（注释意图与实现明确矛盾，属可直判缺陷）。

### SC-2 限流状态码 UI 文案与实现矛盾：「WAF、IP ACL、限流拦截统一使用此状态码」实际限流恒 429

**位置**：`web/src/views/security/SecurityPolicies.vue:573` ↔ `internal/services/caddy.go:2789-2808`

**代码证据**：

UI（策略向导「返回状态码」步骤，`SecurityPolicies.vue:564-573`）：
```html
<el-form-item label="返回状态码">
  <el-select v-model="form.block_status_code" style="width: 200px">
    … <el-option :value="429" label="429 Too Many Requests" /> …
  </el-select>
  <span class="form-tip-inline">WAF、IP ACL、限流拦截统一使用此状态码</span>
</el-form-item>
```
实现（`caddy.go:2789-2808`）：
```go
// 限流拦截恒 429（不再取策略 BlockStatusCode）：429 Too Many Requests 是
// 限流的语义正确状态码，且使 caddy_http_requests_total{code="429"} 可单独
// 计量——Wave 6 状态统一后 403 与 WAF 拦截在指标中同形不可区分…
		"handler":     "static_response",
		"body":        content,
		"status_code": 429,
		"headers": map[string]interface{}{
			"Content-Type": []string{"text/html; charset=utf-8"},
			"Retry-After":  []string{"1"},
```
WAF/IP ACL/GeoIP 侧则确实按配置渲染（`buildBlockPageErrorRoute`，`caddy.go:2735-2755`：`statusCode := pagePolicy.BlockStatusCode; if statusCode == 0 { statusCode = 403 }`）。

**分类**：不合理逻辑（UI 语义→行为漂移）。**判定：设计漂移**。依据：行为侧是后期的明确设计决策（代码注释完整记载动机：429 可单独计量），但向导文案仍停留在旧契约（「三处统一」），二者未同步。三链对照：UI 文案宣称 → 存储 `block_status_code` → 消费仅 WAF/IP ACL/GeoIP 错误路由 → 限流渲染恒 429，链路在第 4 段断裂。

**影响**：管理员为限流场景配置 403/503 等状态码时被误导（例如为过载保护配 503 的常见诉求无法经此实现，且界面暗示可以）；监控口径与预期不符。

**建议**：文案改为「WAF、IP ACL 拦截使用此状态码；限流拦截恒为 429（用于指标单独计量）」。属文案修复，不改变行为契约。

**是否待裁定**：否（行为侧已有裁决性注释，文案滞后明确）。

### SC-3 触发规则 ID 的三处分类口径不一致（6 位 1xxxxx 段）

**位置**：`internal/handlers/security.go:1737-1744`（筛选 family 映射）、`:1819-1822`（glob5 补充）、`:2053-2058`（总览 categorizeAttack）↔ `web/src/views/security/SecurityEvents.vue:333-335`（列表 triggeredLabel）

**代码证据**：

事件筛选 family（`handlers/security.go:1743`）：
```go
"自定义规则":   {"10", "11", "12", "13", "14", "15", "16", "17", "18", "19"},
```
加 5 位数字 GLOB（`:1819-1822`）：
```go
// 自定义规则族补 5 位数字段（emit 20000-99999 不以 1 开头，前缀清单覆盖不到）。
if input == "自定义规则" {
	ors = append(ors, glob5)
}
```
总览分类（`:2053-2058`）：
```go
// 5 位数字 ID 仅自定义规则（emit=crID+10000，10000-99999）；首字符不再限定 1
case len(ruleTriggered) == 5 || (strings.HasPrefix(ruleTriggered, "1") && len(ruleTriggered) >= 7):
	return "自定义规则"
```
列表标签（`SecurityEvents.vue:333-335`）：
```ts
// 5 位数字 ID 仅自定义规则（emit=crID+10000）；与后端过滤器 GLOB/概览口径一致
if (/^\d{5}$/.test(t)) return '自定义规则'
```

**分类**：不合理逻辑。**判定：设计漂移**。依据：三处注释各自声明了口径，但互相不一致——筛选 family 的 `LIKE '1x%'` 会把 6 位 `100000-199999` 归入「自定义规则」，而 `categorizeAttack` 把 6 位 1xxxxx 判「其他」（`:2054-2055` 注释明言「6 位 1xxxxx 无归属源…保持『其他』」），列表标签则显示原始 ID。SecurityEvents.vue:333 的注释「与后端过滤器 GLOB/概览口径一致」在 6 位段不成立。

**影响**：极低。6 位 1xxxxx 仅在自定义规则表主键 ≥90000（emit id=DB id+10000 落入六位）时出现，常规规模不会产生；一旦出现，同一事件在筛选器算「自定义规则」、在总览算「其他」、在列表显示裸 ID。

**建议**：统一三处判定为一个共享谓词（或在两处注释中互相援引说明 6 位段的差异是有意的），并修正前端注释。可顺带在 SC-1 修复时同文件处理。

**是否待裁定**：否（低影响，口径统一方向明确；若坚持差异需在注释中显式声明差异理由）。

### SC-4 主从实例下登录锁定为节点本地态：计数不入快照，users 节重放将 login_* 清零

**位置**：`internal/services/cluster_snapshot.go:758-762`、`internal/services/cluster_apply.go:327-331,403-410`、`internal/services/cluster_sections.go:89-99`

**代码证据**：

快照 users 列集（`cluster_snapshot.go:759-762`，不含 `login_failed_attempts/login_locked_until`）：
```go
rows, err := store.QueryContext(ctx, `SELECT id, username, password_hash, role, COALESCE(display_name,''), COALESCE(is_enabled,1),
	COALESCE(password_version,0), strftime('%Y-%m-%dT%H:%M:%fZ', password_changed_at), created_at, last_login,
	COALESCE(mfa_enabled,0), COALESCE(mfa_secret,''), COALESCE(mfa_recovery_codes,'[]'),
	COALESCE(mfa_last_timestep,0), COALESCE(mfa_failed_attempts,0), COALESCE(mfa_locked_until,'') FROM users ORDER BY username`)
```
重放为全量替换（`cluster_apply.go:327-331`）：
```go
if !skip.skip("users") {
	if err := clearSyncTables(ctx, tx, "api_keys", "users"); err != nil {
		return err
	}
}
```
重插不含 login_*（`cluster_apply.go:405-407`）：
```go
if _, err := tx.ExecContext(ctx, `INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at,created_at,last_login,mfa_enabled,mfa_secret,mfa_recovery_codes,mfa_last_timestep,mfa_failed_attempts,mfa_locked_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, …
```
而本地记账声明只覆盖 mfa_*/last_login（`cluster_sections.go:90-99`，`sanitizeUsersForHash` 只清零 `LastLogin/MFALastTimestep/MFAFailedAttempts/MFALockedUntil`）：
```go
// last_login（登录时间）与 v2.1.8 的三个 MFA 记账字段
// （mfa_last_timestep——从节点本地登录推进；mfa_failed_attempts /
// mfa_locked_until——从节点本地失败计数与锁定）都是「从节点登录端点会写、
// 主节点值无权威意义」的本地态…
```

**分类**：主从同步语义。**判定：设计漂移**。依据：login_* 不入快照与「节点本地态」方向一致（快照本就不该回传主节点无权威意义的计数），但与 mfa_* 的处理相比缺了两件事：① `cluster_sections.go` 的本地态声明未覆盖 login_*（2026-09 基线把锁定统一到 login_* 后该注释未更新）；② mfa_* 虽为本地态仍随重放覆盖（注释承认「属低频、外观性损失」），login_* 则是**从节点上的失败计数与锁定被任何 users 节重放清零**——重放触发条件是主节点 users 表任何实质变更（改昵称/改密/建删用户/MFA 变更），与登录安全无关的变更即可解锁从节点上被锁定的账户。

**影响**：① 双实例部署下「5 次/10 分钟」按节点独立计数：攻击者对主、从各 5 次/10 分钟（合计翻倍），基线表述「全系统唯一锁定…5 次/10 分钟」在多节点形态下未成立；② 从节点锁定可在 10 分钟窗口内被主节点无关 users 变更意外解除（同步周期默认 60s，`cluster_snapshot.go:392 `COALESCE(sync_interval,60)``）。主节点不受影响（不应用快照）。

**建议**（只报告）：短期在 `cluster_sections.go` 注释补 login_* 本地态声明，并评估重放时保留从节点 login_*（INSERT 后 `UPDATE … SET login_failed_attempts/login_locked_until` 不可行——原行已被 DELETE；可改为重放前读出、重放后回写，或接受现状并记录）；长期若要求全系统统一计数需经集群通道同步锁定状态（实时性受 sync_interval 限制）。

**是否待裁定**：**是**。涉及「基线中『全系统唯一锁定』在主从部署下的预期语义」与「重放清零是否可接受」的行为契约，需用户裁定。

### SC-5 M7 时代 MFA 锁定残留：死常量与僵尸列

**位置**：`internal/services/mfa.go:24-25`（常量）、`:296`、`:350`（仅清零）；列 `users.mfa_failed_attempts/mfa_locked_until`

**代码证据**：

```go
// —— 常量（v2.1.8 MFA）——
const (
	mfaChallengeTTL      = 5 * time.Minute
	mfaRecoveryCodeCount = 10
	mfaLockoutThreshold  = 5
	mfaLockoutDuration   = 10 * time.Minute
	mfaStepUpWindow      = 10 * time.Minute
)
```
全仓生产代码对 `mfaLockoutThreshold/mfaLockoutDuration` 零引用（本会话 grep 核实，仅此声明处）；`mfa_failed_attempts/mfa_locked_until` 仅在启用/重置 MFA 时被清零（`mfa.go:296` `…, mfa_failed_attempts=0 WHERE id=?`、`:350` `…, mfa_failed_attempts=0, mfa_locked_until=NULL …`），从无递增/判定路径。现行锁定统一走 `users.login_failed_attempts/login_locked_until`（`auth.go:72-89`，见 §1.3）。

**分类**：已弃用代码（含冗余）。**判定：设计漂移（残留）**。依据：2026-09 基线把锁定统一到登录阶段后，M7 的 MFA 专属锁定（threshold/duration 常量 + 计数列）失去全部读写语义，仅作为兼容负载存续：仍随集群快照同步（`cluster_snapshot.go:762`）、参与 users 节哈希（经 sanitize 清零，`cluster_sections.go:109-110`）、进入配置备份（`config_backup.go:154`）。挑战级/pending 级计数已由 `mfa_challenges` 表与 `mfa_pending_fails` 列承担。

**影响**：无行为影响；认知负担与同步负载残留，且 SC-4 的注释更新时容易与这组僵尸字段混淆。

**建议**：择机清理常量；列清理需连同快照/备份/schema 迁移一并处理（涉及兼容契约，宜独立变更）。

**是否待裁定**：清理本身无需裁定；**列删除涉及集群兼容（旧从节点快照含该列）需在执行时评估**。

### SC-6 遗留 `ip_blacklist` 字段：UI 无任何编辑入口，弹窗指引「可在策略编辑中清理」不可达

**位置**：`web/src/views/security/IPLocationAction.vue:50` ↔ `web/src/views/security/SecurityPolicies.vue:2180`、`:860-861`

**代码证据**：

IP 弹窗对「IP 还在旧版黑名单字段」的提示（`IPLocationAction.vue:50`）：
```html
<div v-if="row.inLegacy" class="ipo-legacy">该 IP 还存在于旧版独立黑名单字段中，可在策略编辑中清理</div>
```
而策略向导从不下发该字段（`SecurityPolicies.vue:2179-2181`）：
```ts
// 名单保留语义（与 ip_acl_list 对齐）：关闭开关不清空已配置的名单，保存时
// 始终回传当前名单内容，避免"关掉开关再打开"丢数据；ip_blacklist 本页不下发，
// 后端指针语义自动保留原值。
```
及 `:860-861`：
```ts
// 本策略既有 ip_blacklist（仅用于跨策略冲突比较；本对话框不编辑该字段，
// 保存时由后端指针语义自动保留原值）
```
本会话核实：前端所有 `ip_blacklist` 引用均为只读（冲突比较/计数/`inLegacy` 判定），无任何写入路径；唯一写入口是 REST/MCP `PUT /security/policies/:id` 显式携带 `ip_blacklist`。

**分类**：已弃用代码（UI 指引失效）。**判定：设计漂移**。依据：字段本身保留是有意的（发射端 `id:4` 仍生效、事件归因仍认领、快照仍同步——`security.go:255-257`、`securityevents.go:421-426`、`cluster_snapshot.go:476`），但「向导不再编辑」的决定落地后，弹窗的清理指引没有同步更新，指向一个不存在的操作路径。

**影响**：存量含 `ip_blacklist` 条目的部署里，用户按指引打开策略编辑找不到任何清理入口，旧黑名单条目实际上只能经 API/MCP 清理——封禁解除链路对 UI 用户断开（该字段的条目仍真实拦截，`id:4` deny）。

**建议**：改指引文案为「可经 API 更新策略的 ip_blacklist 字段清理」或在向导加只读展示+一键迁移（并入 ip_acl_list deny）入口；后者更符合清退方向。

**是否待裁定**：**是**（是否提供迁移入口属产品决策；纯文案修复无需裁定）。

### SC-7 ACL 关闭时内联名单保留、refs 引用被静默清空：语义不对称且 UI 未透出

**位置**：`web/src/views/security/SecurityPolicies.vue:2179-2202`

**代码证据**：

```ts
// 名单保留语义（与 ip_acl_list 对齐）：关闭开关不清空已配置的名单，保存时
// 始终回传当前名单内容…
ip_acl_list: JSON.stringify(ipACLList.value),
…
// 开关关闭即解除引用（内联名单按三态语义保留，refs 指向共享列表——
// 消费方关闭时释放，IP 地址列表页的引用数反映真实占用，且不阻塞列表删除）
ip_acl_list_refs: form.value.ip_acl_enabled ? JSON.stringify(ipACLListRefs.value) : '[]',
ip_whitelist_refs: ipWhitelistEnabled.value ? JSON.stringify(ipWhitelistRefs.value) : '[]',
```

**分类**：不合理逻辑（语义不对称未透出）。**判定：有意设计**。依据：代码注释完整声明动机（共享列表的引用计数与删除不被阻塞），是明确取舍而非疏忽；但「与 ip_acl_list 对齐」的保留语义对 refs 并不成立——关闭再启用后内联条目还在、引用全部丢失且无提示，向导内亦无任何文案说明该差异（`aclRefHint`/`whitelistRefHint` 仅显示条数）。

**影响**：重度使用「引用地址列表」的用户在临时关闭再启用访问控制后，静默丢失全部引用配置，需逐个重选；与「关闭开关不清空已配置的名单」的用户预期相悖。

**建议**：在引用列表控件下补一句 tip（「关闭访问控制后保存将解除全部引用，内联名单保留」），或在重新启用时提示引用已清空。

**是否待裁定**：**是**（保留现状+补文案，还是改为 refs 也保留，属交互契约取舍）。

### SC-8 多策略绑定下信任名单文案偏差：「跳过 WAF 与访问控制检测」不限定本策略，且 deny 预检优先于信任

**位置**：`web/src/views/security/IPLocationAction.vue:515`、`SecurityPolicies.vue:420` ↔ `internal/services/security.go:727-728`、`caddy.go:2934-2941`

**代码证据**：

UI 承诺（IP 弹窗确认框 `IPLocationAction.vue:514-515`；向导 tip `SecurityPolicies.vue:420` 同文）：
```
将把 {ip} 加入策略「{name}」的信任名单，该 IP 将跳过 WAF 与访问控制检测（限流仍然生效）。是否继续？
```
多策略预检语义（`security.go:727-728`）：
```
// 信任名单/免检测不并入预检（deny 优先于信任，且信任仅豁免所属策略
// 的检查、限流仍生效的语义保持不变）。
```
预检置于链首先于一切（`caddy.go:2938-2941`）：一规则绑定 P1（信任该 IP）+ P2（deny 含该 IP）时，该 IP 被 P2 的预检直接拒绝，P1 的信任不提供豁免。

**分类**：不合理逻辑（多策略文案偏差）。**判定：设计漂移**。依据：单策略内语义实现与文案一致（信任=ctl:ruleEngine=Off+ctl:auditEngine=Off，限流独立 handler 不受影响）；多策略合并语义（deny 优先于信任、信任不跨策略）是 v2.2.0 的明确设计，但两处 UI 文案均未加「本策略」限定。缓解：向导在编辑期有跨策略「信任 IP × 他策略黑名单」冲突实时警告（`SecurityPolicies.vue:429-431`），覆盖了配置时的大多数场景；IP 弹窗（事件页快捷路径）无此警告。

**影响**：多策略绑定且存在跨策略 deny 的场景，用户经事件页把攻击 IP 加入信任名单（用于放行误杀）可能不生效（仍被预检拒绝），且确认框文案使其预期必然生效。

**建议**：IP 弹窗文案加「（限本策略；若其他绑定策略拒绝该 IP 则仍会被拦截）」，或在该弹窗检测到冲突时复用向导警告。

**是否待裁定**：**是**（是否在快捷路径补冲突检测属交互范围决策；纯文案限定可直做）。

### SC-9 安全总览「Top 10 源 IP / 攻击类型分布」为 7 天窗口，卡片无窗口标注

**位置**：`internal/handlers/security.go:2141`（TopIP 查询）、`:2164`（攻击族查询）、`:2195`（类型查询）↔ `web/src/views/security/SecurityOverview.vue:111`（「攻击类型分布」）、`:187`（「Top 10 源 IP」）

**代码证据**：

```go
ipRows, err := db.MetricsDB.Query(`SELECT client_ip, … FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY client_ip ORDER BY b + l DESC LIMIT 10`, todayStartUTC)
```
```go
typeRows, err := db.MetricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY rule_triggered, rule_msg`, todayStartUTC)
```
而同页趋势卡片标题为「7 天拦截趋势」（`SecurityOverview.vue:95`），Top IP/攻击类型卡片无任何时间窗口说明。

**分类**：不合理逻辑（UI 语义缺失）。**判定：设计漂移**。依据：查询口径本身合理（与趋势同窗口，`datetime(?, '-6 days')` + 今日 = 7 天），仅 UI 未标注，用户易把两卡片理解为「全部累计」或「今日」。

**影响**：数据解读偏差（低）。

**建议**：两卡片 header 加「近 7 天」标签，与趋势卡片一致。

**是否待裁定**：否。

### SC-10 限流拦截响应 `Retry-After: 1` 恒定，与 60s 分钟区窗口不符

**位置**：`internal/services/caddy.go:2794-2809`

**代码证据**：

```go
return map[string]interface{}{
	…
	"handle": []interface{}{
		map[string]interface{}{
			"handler":     "static_response",
			"body":        content,
			"status_code": 429,
			"headers": map[string]interface{}{
				"Content-Type": []string{"text/html; charset=utf-8"},
				"Retry-After":  []string{"1"},
			},
		},
	},
```
注释（`:2793`）：「Retry-After 按限流 1s 窗口给出重试契约」。但 burst>0 时限流是双区 AND（`caddy.go:2839-2851`：1s 区 `rps+burst`、60s 区 `rps*60`），持续超速的客户端真正受制于 60s 分钟区。

**分类**：不合理逻辑。**判定：有意设计（合理性存疑）**。依据：值是显式硬编码并附注释，非疏忽；但注释援引的「1s 窗口」只在 burst=0 形态下是真实约束，分钟区限流时该头系统性偏小，礼貌客户端会按 1s 重试并连续收 429。

**影响**：轻微——客户端重试风暴被 429 顶回，无正确性破坏；与 HTTP 语义的契合度欠佳。

**建议**：若保留硬编码，注释应说明「取最小窗口，分钟区限流时偏保守」；精确化需按触发 zone 动态给值（caddy 错误路由层拿不到触发 zone，成本较高，可不改）。

**是否待裁定**：**是**（契约细节：是否接受保守 Retry-After）。

### SC-11 `GetSecurityOverview` 的 CRS 版本查询静默吞错，违反本函数自述的「任一查询失败都必须显式报错」标准

**位置**：`internal/handlers/security.go:2225-2231`（对照 `:2094-2096` 自述标准、`:2103-2105` 已 trackErr 的兄弟查询）

**代码证据**：

函数自述标准（`:2094-2096`）：
```go
// 任一查询失败都必须在结束时显式报错：否则 metrics 库故障会静默返回
// 全零面板，与「无攻击」不可区分（R35 D2）。
```
CRS 版本查询（`:2225-2231`）：
```go
var crsVersion, crsUpdateStatus string
if err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,'idle') FROM security_crs_version WHERE id=1`).Scan(&crsVersion, &crsUpdateStatus); err == nil {
	if crsVersion != "" {
		overview.CRSVersion = crsVersion
	}
	overview.UpdateStatus = crsUpdateStatus
}
```
`err != nil` 时无 trackErr、无日志：面板回落到 `CRSBundledVersion` + `"idle"`。

**分类**：逻辑 bug（与函数自身确立的错误处理契约不一致）。**判定：缺陷**。依据：同函数内主库查询 `ActivePolicies`（`:2105`）已纳入 trackErr，此查询是唯一例外；错误态（显示内置版本+「已最新」）与真实态（用户已更新至更高版本）不可区分，正是该标准要防的形态。

**影响**：低——仅 CRS 版本/状态标签失真（例如手动更新到 v4.x 后主库瞬时故障时显示捆绑版本且标「已最新」），不涉及计数。

**建议**：将该查询纳入 trackErr（或至少 `log.Printf` 留痕），与兄弟查询同口径。

**是否待裁定**：否。

## 四、待裁定项汇总

| 编号 | 待裁定内容 | 关联发现 |
|---|---|---|
| P-1 | 「全系统唯一锁定=5 次/10 分钟」在主从双实例下的预期语义：按节点独立计数（现状，攻击容量 ×节点数）是否接受；users 节重放清零从节点 login_* 计数/锁定是否可接受（mfa_* 同型行为已有「低频、外观性损失，可接受」裁定，login_* 未被该裁定覆盖） | SC-4 |
| P-2 | 遗留 `ip_blacklist` 的清退路径：仅修正弹窗指引文案，还是提供向导内迁移/清理入口（现状 UI 用户无法清理仍生效的旧黑名单条目） | SC-6 |
| P-3 | ACL 关闭时 refs 解除引用 vs 内联保留的语义不对称：保留现状补 UI 提示，还是 refs 与内联同为三态保留（涉及 IP 列表引用计数/删除阻塞的设计动机） | SC-7 |
| P-4 | 事件页 IP 弹窗「加入信任名单」是否需要多策略冲突检测/文案限定（向导已有冲突警告，快捷路径没有） | SC-8 |
| P-5 | 限流 429 响应 `Retry-After: 1` 恒定值契约：接受保守值（分钟区限流时偏小）还是精确化 | SC-10 |
| P-6 | SC-5 僵尸列（`mfa_failed_attempts/mfa_locked_until`）的删除时机：需与集群快照兼容（旧节点快照仍含该列）协同评估 | SC-5 |

（SC-1/SC-2/SC-3/SC-9/SC-11 无行为契约争议，可直接按建议处置。）

## 附：本会话验证记录

- `go test ./internal/services/ -run 'TestSecurityEvents' -count=1` → ok（2.955s）：事件解析/摄取/轮转/归因测试组全绿（其中 `TestSecurityEventsMapHost_MatchesCanonicalAndReportsUnknown` 反向钉死 SC-1 行为，见该条目）。
- 未修改任何源码/配置/测试文件；未触碰运行数据目录。
