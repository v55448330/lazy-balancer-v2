# 系统模块审计报告（2026-09-05）

> 审计域：系统模块（认证与权限、用户/MFA/API Key、审计日志、系统设置、指标库、启动装配）。
> 本报告为全项目再审计的功能域拆分之一，只读审计、只报告不修复。
> 所有发现均在本会话中实际读码核实并给出 file:line 与代码原文摘录；运行数据与服务未触碰。

---

## 一、概览

### 1.1 范围文件清单（本会话实际读取）

后端：
- `internal/handlers/auth.go`（登录/登出/自助资料/初始化，498 行全文）
- `internal/handlers/mfa.go`（MFA 全部端点，345 行全文）
- `internal/handlers/users.go`（用户管理 CRUD，427 行全文）
- `internal/handlers/apikeys.go`（API Key 全部端点，370 行全文）
- `internal/handlers/auditlog.go`（审计查询/筛选项，236 行全文）
- `internal/handlers/audit.go`（recordAudit 辅助）
- `internal/handlers/config_changes.go`（配置变更计划/字段级审计映射，全文）
- `internal/handlers/caddy.go` 的 `GetConfig`/`UpdateConfig`/`ReloadCaddy`/`ValidateConfig`（147-627 行）
- `internal/handlers/cluster_ticket.go`（票据登录，全文）
- `internal/handlers/system.go`、`internal/handlers/logstats.go`、`internal/handlers/metrics.go`（系统信息/日志体量/指标查询）
- `internal/handlers/handlers.go`、`internal/handlers/db_errors.go`（辅助函数）
- `internal/services/mfa.go`（MFA 服务，390 行全文）
- `internal/services/auditpolicy.go`（审计路由策略/只读写路由清单，全文）
- `internal/services/auditlog.go`（审计写入/保留清理，全文）
- `internal/services/auditdetail.go`（审计详情格式化）
- `internal/services/auditlog_rotation.go`（Coraza 审计日志轮转，结构+关键注释）
- `internal/services/settings.go`、`internal/services/services.go`（MetricsService 清理路径）
- `internal/services/cluster_snapshot.go`/`cluster_apply.go`/`cluster_sections.go`（用户同步相关片段）
- `internal/middleware/middleware.go`（全文 897 行：路由表、jwtAuth/apiKeyAuth/apiKeyReadOnlyGuard/mfaStepUpGuard/auditMiddleware/loginRateLimit/adminOnly）
- `internal/middleware/readonly.go`（readOnlyGuard 白名单，全文）
- `internal/db/db.go`（Initialize、schema、迁移列映射、users 表重建，1-250 + 560-800 + 1675-1745 行）
- `internal/db/audit.go`（审计库初始化/词汇迁移/系统事件缓冲，全文）
- `internal/db/apikey_last_used.go`（last_used 脏集批刷 + revoked_jti 清理，全文）
- `internal/db/metrics.go`（指标库隔离自愈/保留清理，全文）
- `internal/db/sqlite_pragmas.go`（全文）
- `internal/config/config.go`（全文：装配、JWT secret 装载）
- `cmd/server/main.go`（全文：启动装配、优雅退出）

前端：
- `web/src/views/Login.vue`（登录/初始化/MFA 两步，全文）
- `web/src/views/Users.vue`（用户管理 + MFA 绑定向导，全文）
- `web/src/views/Keys.vue`（API Key 自助管理 + MCP 文档，全文）
- `web/src/views/AuditLog.vue`（操作日志页，全文）
- `web/src/views/Settings.vue`、`web/src/views/settings/BasicSettings.vue`（全文）
- `web/src/views/settings/CaddyGlobalSettings.vue`、`FreeCertificates.vue`（数值边界抽查）
- `web/src/stores/auth.ts`（会话语义，全文）
- `web/src/utils/api.ts`（401/428 全局拦截流，全文）
- `web/src/components/layout/AppLayout.vue`（菜单可见性抽查）
- `web/src/components/LogStorageBar.vue`（日志体量展示链）

契约参考（测试作为契约读）：`internal/handlers/mfa_verifystep_test.go`、`users_password_version_test.go`、`users_password_maxlen_test.go`、`internal/middleware/r72_mfa_guard_test.go`、`apikey_auth_test.go`、`audit_routes_test.go`、`internal/services/audit_action_mapping_test.go`。

### 1.2 方法

1. 逐文件读码 → 以「UI 文案 → 存储 key → 消费点 → 真实渲染」三链对照核对设置项；
2. 以路由注册表（middleware.go 209-455 行）为基准核对角色/守卫矩阵；
3. 逐条对照 2026-09 已裁定认证底线（见第二节）；
4. 辅以 git log 核对裁定落地提交（`66b35ce0`「按用户二次裁定收敛认证门禁」、`137fbb43`「登录阶段密码与 MFA 验证码统一计数」等）；
5. 定向单测验证（本会话实跑）：
   - `go test ./internal/handlers -run TestMFAVerifyStep_rejectsRecoveryCode -count=1` → ok
   - `go test ./internal/middleware -run 'TestAPIKeyAuth|TestMFAGuard|TestAuditRoutes' -count=1` → ok
   - `go test ./internal/services -run 'TestAuditPolicyListsEqual|TestAuditExplicitRoutesMappingEmpty' -count=1` → ok
   - 依赖行为实证：validator v10.30.3 `baked_in.go:2602`（字符串 max 按 rune 计）；`x/crypto v0.55.0 bcrypt.go:96-97`（>72 字节返回 `ErrPasswordTooLong`）。

### 1.3 结论摘要

- **认证底线五条整体落地质量高**：统一登录锁定（5 次/10 分钟、开关控制、密码+MFA 同计）、登录后零密码输入（MFA/Key 全链无密码门）、API Key 无密码门且改密不吊销、登录后 MFA 失败只提示不计数——均与裁定一致，未发现实质性偏离路径，除 **S-1**（管理员经 admin 端点改自己密码绕过当前密码确认门，属边界绕行，待裁定）。
- 审计链路（产生→存储→查询→保留→展示）完整、双清单有契约绊线；仅 recovery-codes/setup 两个高敏动作零留痕（S-8，待裁定）。
- 主要问题集中在**残留与漂移**：已移除的 M7/R74 `mfa_*` 锁定机制留下死列、过时注释（S-4/S-5）；两个死配置列（S-6）；一个无入口配置（S-7）；两处 UI↔后端数值边界不一致（S-3）；一个多字节密码边界 500（S-2）。
- 指标库自愈（损坏隔离+GC+分批清理）、审计库独立+系统事件缓冲、JWT secret 持久化装载、优雅退出顺序（worker 先停、DB 后关）均验证无问题。
- 无高严重度发现；中严重度 1 条（S-1），低严重度 10 条。

---

## 二、认证底线对照（2026-09 裁定，逐条）

### 底线 1：登录后零密码输入（唯一例外 = 改密验当前密码，纯 bcrypt 不计数）

**结论：基本一致；存在一条 admin 自助改密绕行路径（见 S-1，待裁定）。**

| 检查点 | 实现位置 | 一致性 |
|---|---|---|
| 自助改密需当前密码 | `internal/handlers/auth.go:352-368`：`if req.Password != "" { ... if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)) != nil { 401 } }`，失败仅 401，无计数无锁定 | ✅ |
| MFA 恢复码重生成无密码 | `internal/handlers/mfa.go:218-237`：纯 JWT 会话 + `MFAEnabled` 前置检查 | ✅ |
| MFA 解绑仅验有效验证码 | `internal/handlers/mfa.go:188-216`：`MFAVerifyTOTPCode` 通过后 `MFAResetForUser` | ✅ |
| MFA 重绑（已启用者）仅验码 | `internal/handlers/mfa.go:110-129` | ✅ |
| 特权 API Key 创建无密码 | `internal/handlers/apikeys.go:134-158`（M6 注释明确「创建不验密码」；可选防线为写守卫 428） | ✅ |
| admin 重置 MFA 前置验码 | `internal/handlers/mfa.go:307-322`（守卫开启时第一层豁免，机器身份不免） | ✅ |
| **admin 经 PUT /users/:id 或 POST /users/:id/reset-password 改自己密码** | `internal/handlers/users.go:405`（`UPDATE users SET password_hash = ...`，无任何当前密码校验）；前端 `web/src/views/Users.vue:298-310` 将 admin 编辑本人行走 admin 端点 | ⚠️ 偏离（S-1） |

### 底线 2：全系统唯一锁定 = 登录阶段密码 + MFA 验证码同计 5 次/10 分钟，受「登录失败锁定」开关控制

**结论：一致；未发现第二处账户级锁定。**

- 常量与开关：`internal/handlers/auth.go:58-67`
  ```go
  const (
      loginLockMaxAttempts = 5
      loginLockCooldown    = 10 * time.Minute
  )
  func loginLockoutEnabled() bool { return services.MFALockoutEnabled() }
  ```
  开关读 `global_config.mfa_lockout_enabled`（`internal/services/mfa.go:119-125`），与基础设置「登录失败锁定」开关同键。
- 密码失败计数：`auth.go:132-137` → `recordLoginFailure`（`auth.go:72-84`，单条条件 UPDATE 原子置锁、锁满清零不延长冷却；开关关闭仅累加不置锁）。
- MFA 验证码失败同计：`internal/handlers/mfa.go:58-70`——`recordLoginFailure(userID)` 与密码失败同一计数列（`users.login_failed_attempts`/`login_locked_until`）。
- MFA 验证步锁定检查：`mfa.go:51-56`（锁定期间 429，不消耗挑战次数）。
- 计数清零仅在完整登录成功：无 MFA 路径 `auth.go:166-169`；MFA 完整成功 `mfa.go:76-78`；密码步刻意不清零（`auth.go:138-140` 注释，堵「对密码+连错验证码+重登清零」绕过）。
- 全仓无其它账户锁定写入点（grep `login_locked_until`/`mfa_locked_until` 核实；`mfa_*` 旧列已无递增者，见 S-4）。
- 边界项（非偏离，记录在案）：登录阶段另有两条**与开关无关的硬闸**——单挑战 10 次失败作废（`internal/services/mfa.go:150-170`，R72 B-I-4）与 pending 绑定 5 次失败作废（`mfa.go:321-336`，R72 A-F-2）。二者分别作废的是挑战令牌/待激活密钥，不是账户锁定，与「唯一锁定在登录阶段」不冲突；pending 作废发生在登录后的绑定向导，属可立即重试的流程性失效。

### 底线 3：API Key 无密码门、改密不吊销 Key

**结论：一致。**

- 创建：`internal/handlers/apikeys.go:121-207`，无密码字段；非 admin 强制 `req.ReadOnly = true`（127-129）；特权 Key（非只读或 MCP）在写守卫开启时走 428 step-up（141-158，机器身份豁免）——与 M6 裁定逐字对应。
- 改密不吊销：`users.go:391` 注释「M6 吊销已按用户裁定移除」；`UpdateCurrentUser`/`UpdateUser`/`ResetUserPassword` 均无 `DELETE FROM api_keys`。全仓 `DELETE FROM api_keys` 仅出现在 `users.go:273`（删除用户级联，属预期）与密钥显式删除端点（`apikeys.go:61,354`）。
- Key 登出语义：`auth.go:252-260`——API Key 认证调用登出返回 404「API 密钥认证无会话令牌可吊销」（无会话令牌概念，幂等契约）。

### 底线 4：MFA 验证失败（登录后）只提示不计数

**结论：一致。**

四个登录后验码入口均无计数/锁定写入，仅 401 +（部分）审计：
- verify-step：`internal/handlers/mfa.go:252-260`（仅 `recordAudit("认证拒绝", ...)`）
- 禁用 MFA：`mfa.go:200-209`（审计留痕 B5 I-A）
- 重绑确认：`mfa.go:121-128`
- admin 重置前置验码：`mfa.go:311-321`
服务层 `MFAVerifyCode`/`MFAVerifyTOTPCode` 失败路径恒 `return false, nil`（`internal/services/mfa.go:221-224、259-262`，注释即裁定原文）。

### 底线 5（附带核对）：JWT secret 装载与会话语义

- 装载：`internal/config/config.go:94-135`——`JWT_SECRET` 环境变量优先；否则 `data/jwt_secret` 持久化随机 32 字节 hex（0600 权限，读取要求 ≥32 字节，写失败响亮告警「重启后令牌将失效」）。主从各实例独立 secret，跨节点登录走一次性票据（`cluster_ticket.go`），语义正确。
- 会话：`jwtAuth`（`internal/middleware/middleware.go:526-652`）逐请求校验签名+过期+`revoked_jti`+用户存在/启用+`username` 一致性+`pwd_ver` 版本——降权/禁用/改密即时生效；角色取 DB 值而非 claim（`middleware.go:641`）。登出写入 jti 哈希吊销（`auth.go:270-273`），过期行按 RFC3339 `strftime` 口径每小时清理（`internal/db/apikey_last_used.go:84-91`，R68 B-F4 修复格式错位）。
- 前端会话：`web/src/utils/api.ts:296-326`（401 会话失效单弹窗+止损拦截）、`327-365`（428 全局弹码→verify-step→重试一次），`stores/auth.ts:61-73`（fail-closed 只读呈现）。链路自洽。

---

## 三、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| S-1 | internal/handlers/users.go:271-427 + web/src/views/Users.vue:298-310,347 | 逻辑 bug（安全门禁绕行） | 中 | 缺陷（待裁定） |
| S-2 | internal/handlers/auth.go:316-321、users.go:95/374、models.go:370 + validator/bcrypt 依赖行为 | 逻辑 bug | 低 | 缺陷 |
| S-3 | web/src/views/settings/BasicSettings.vue:27、CaddyGlobalSettings.vue:34 ↔ internal/handlers/caddy.go:348-351,387-390 | 不合理逻辑 | 低 | 设计漂移 |
| S-4 | internal/db/db.go:694-695、internal/services/mfa.go:296,350、cluster_snapshot.go:761-762、cluster_sections.go:89-99 | 已弃用代码（含冗余写） | 低 | 设计漂移（残留） |
| S-5 | internal/handlers/mfa_verifystep_test.go:19-25、internal/services/mfa.go:186-188 | 已弃用代码（过时注释） | 低 | 设计漂移 |
| S-6 | internal/db/db.go:714-715、internal/handlers/config_backup.go:217 | 已弃用代码（死配置） | 低 | 设计漂移 |
| S-7 | internal/services/services.go:565-578、internal/models/models.go:487-524 | 不合理逻辑（无入口配置） | 低 | 设计漂移（待裁定） |
| S-8 | internal/services/auditpolicy.go:20,24、internal/handlers/mfa.go:100-150,218-237 | 不合理逻辑（审计盲区） | 低 | 待裁定 |
| S-9 | internal/middleware/middleware.go:359,451-452 + AppLayout.vue 菜单 | 权限模型确认 | 低 | 待裁定 |
| S-10 | internal/handlers/auth.go:182-190 | 不合理逻辑 | 低 | 待裁定（倾向有意保守） |
| S-11 | internal/handlers/auditlog.go:53-55,98-103 + internal/db/audit.go:49 | 冗余/性能观察 | 低 | 设计取舍 |

统计：逻辑 bug 2（中 1 / 低 1）；不合理逻辑 4（低 4）；已弃用代码 3（低 3）；冗余/性能 1（低 1）；另有 1 条权限模型确认项（低）。**高严重度 0 条。**

### 附表 A：系统设置项「UI 文案 → 存储 key → 消费点 → 真实渲染」三链对照（本会话逐项核实）

| UI 文案（BasicSettings 等） | 存储 key（global_config） | 消费点（已核实） | 渲染回路 | 结论 |
|---|---|---|---|---|
| 日志级别 | `log_level` | `services.ApplyLogLevel`、`shouldLogRequest`（middleware.go:462-471） | 保存后 `ApplyLogLevel` 即时生效 | ✅ |
| 任务日志大小 | `cert_job_log_size_mb` | certjob/CRS/IP2Region 更新日志轮转；`logstats.go:109-111` 标注同一键 | LogStorageBar 显示「满 N 轮转保留 5 份」 | ✅ |
| 审计日志大小 | `audit_log_size_mb` | **Coraza WAF 审计日志**轮转阈值（`auditlog_rotation.go` getAuditLogSizeBytes）；UI 提示已明确「WAF 审计日志」 | `logstats.go:115`（key=coraza_audit） | ✅ 语义链一致；但 UI max=1024 vs 后端 512 → S-3 |
| 运行日志大小 | `runtime_log_size_mb` | 运行日志轮转（main.go:78-80 启动） | `logstats.go:112` | ✅ |
| 日志保留 | `audit_retention_months` | 操作日志 `CleanupAuditLogs`（auditlog.go:132-148，每日）、安全事件保留（securityevents_retention.go:35-39）、运行日志轮转副本（logrotate.go:187-190） | `logstats.go:103` retentionNote | ✅（提示文案「操作/运行/安全事件」与三个消费点吻合） |
| 登录过期 | `jwt_expire_minutes` | `respondLoginWithMFA`（auth.go:198-202，1-1440 钳制） | 登录时读 | ✅（UI min=5 比后端 min=1 严，无害） |
| 时区 | `timezone` | main.go:87-97 TZ 装载、UpdateConfig 后 `ConfigureLocation`、GetAuditLogs 按配置时区解析 | 前端 formatDate + authStore.fetchConfig | ✅ |
| GitHub 加速 | `github_proxy_url` | CRS/IP2Region 下载；`ValidateGitHubProxyURL` 白名单（防 SSRF）；BasicSettings 自拉自填 | 固定三选项 | ✅ |
| 写操作验证 | `mfa_write_guard` | `mfaStepUpGuard`、`createAPIKeyForUser` 特权 Key 428、`MFAResetByAdmin` 第一层豁免、Users.vue resetMfa 对话框形态切换 | 428 全局弹码流 | ✅（「支持的操作」清单与守卫覆盖面一致） |
| 登录失败锁定 | `mfa_lockout_enabled` | `MFALockoutEnabled` → `recordLoginFailure`/`loginLockedNow` | — | ✅ 语义一致；键名残留 mfa_ 前缀（并入 S-4 语境，不单列） |
| 强制 HTTPS | `admin_tls_*`（独立 /admin-tls 端点） | `LoadAdminTLSConfig`（main.go:205-228） | 保存后重启提示 | ✅（不在 /config 载荷内，走独立端点+暂存交互，链路自洽） |
| —（无 UI） | `metrics_retention_days` | `cleanupHistory` 每日清理 | 无 | ⚠️ S-7 |
| —（无 UI） | `metrics_public`/`metrics_origins` | **无任何消费者** | 无 | ⚠️ S-6 |

---

## 四、逐条详述

### S-1 管理员可经 admin 端点修改自己的密码，绕过「改密验当前密码」确认门

- **位置**：
  - 后端：`internal/handlers/users.go:271-427`（`UpdateUser`）、`internal/handlers/users.go:366-427`（`ResetUserPassword`）
  - 前端：`web/src/views/Users.vue:298-310`（admin 编辑本人行提交 PUT）、`Users.vue:347`（`selfEdit.value = authStore.user?.role !== 'admin'`）
- **代码证据**：
  - `users.go:405`（ResetUserPassword，UpdateUser 同型见 165-169）：
    ```go
    result, err := tx.ExecContext(c.Request.Context(), "UPDATE users SET password_hash = ?, password_changed_at = datetime('now'), password_version = password_version + 1 WHERE id = ?", string(hash), id)
    ```
    全程无当前密码比对。两个端点均在 admin 路由组（`middleware.go:260-263`），对「目标=操作者本人」无任何特殊分支。
  - 对照自助端点的门（`internal/handlers/auth.go:364-367`）：
    ```go
    if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)) != nil {
        c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "当前密码错误"})
    ```
    其设计理由（auth.go:318-320）正是「劫持会话可直接置换密码把原主锁在门外」。
  - 前端把 admin 编辑本人行路由到 admin 表单：`Users.vue:337-349` 中 `selfEdit.value = authStore.user?.role !== 'admin'` → admin 恒 false；`Users.vue:298-304` 随即 `request.put('/users/:id', { ..., password })`，请求体无 `current_password`；模板 `Users.vue:46-48` 的「当前密码」输入框 `v-if="selfEdit"`，admin-self 不渲染。
  - 该行为被测试钉住为契约：`internal/handlers/users_password_version_test.go:27-29`（`administrator update` 用例仅带 `password` 即 200）。
- **分类**：逻辑 bug（安全门禁绕行）。
- **判定**：缺陷（依据：与已裁定底线「唯一例外=改密验当前密码」直接冲突；非 admin 用户同场景被强制走带确认门的 PATCH，唯独 admin 暴露无门路径，属实现缝隙而非可辩护的语义差异——admin 端点免门是为管理他人，UI 将本人行也送入该端点）。因后端语义被既有测试钉住、且改动涉及契约，列**待裁定**。
- **影响**：admin 会话被劫持（XSS/令牌泄露）后，攻击者可经用户管理页直接置换该 admin 密码（`password_version+1` 令原主全部会话失效），无需知道原密码；与 M5 门的威胁模型正面冲突。普通用户不受影响。
- **建议**：任选其一——① `UpdateUser`/`ResetUserPassword` 在 `id == 操作者 user_id` 且提交了密码时要求 `current_password`（与自助端点同门）；② 前端将 admin 编辑本人行也强制走 PATCH `/users/me`（改密时带当前密码字段）。相应调整 `users_password_version_test.go` 契约。
- **是否待裁定**：是。

### S-2 多字节密码（>72 字节但 ≤72 rune）通过绑定层后触发 bcrypt 报错，返回 500 而非承诺的 400

- **位置**：`internal/handlers/auth.go:314-321`（UpdateCurrentUserRequest）、`internal/handlers/users.go:95`（UpdateUser）、`users.go:374`（ResetUserPassword）、`internal/models/models.go:370`（CreateUserRequest）、`auth.go:463-466`（SetupAdmin）。
- **代码证据**：
  - 绑定注释与约束（auth.go:316-317）：
    ```go
    // bcrypt 只取前 72 字节（超出即静默截断），超长密码直接 400 而不是落库后被截断
    Password string `json:"password" binding:"omitempty,max=72"`
    ```
  - 本会话实证依赖行为：
    - validator v10.30.3 `baked_in.go:2602`：`return int64(utf8.RuneCountInString(field.String())) <= p` —— `max=72` 按 **rune** 计数；
    - 仓库所用 `x/crypto v0.55.0` `bcrypt/bcrypt.go:96-97`：
      ```go
      if len(password) > 72 {
          return nil, ErrPasswordTooLong
      }
      ```
      （新版本已不再静默截断，而是显式报错。）
  - 于是 25-72 个多字节字符（如 40 个中文 = 120 字节）的密码：binding 通过（40 rune ≤ 72）→ `bcrypt.GenerateFromPassword` 返回 `ErrPasswordTooLong` → 各端点落入 500 分支（如 `users.go:66-68`「密码加密失败」）。
  - 既有测试只覆盖 ASCII（`users_password_maxlen_test.go:17` `strings.Repeat("a", 73)`），未覆盖多字节。
- **分类**：逻辑 bug（边界输入的错误码/文案漂移；无安全后果——不存在静默截断落库）。
- **判定**：缺陷（依据：注释与测试明示意图为「400 拒绝」，实际得到 500「密码加密失败」，用户无从知道该输什么；三链对照中 UI maxlength=72 同样按字符计，用户在 UI 层完全合法）。
- **影响**：使用中文/全角长密码的用户在创建/改密时收到误导性 500；登录不受影响（该密码从未落库）。
- **建议**：校验改为按字节（`len([]byte(pwd)) > 72`）在 handler 层 400，或将 binding 换成自定义字节级校验；补一条多字节用例。
- **是否待裁定**：否。

### S-3 UI 数值上限与后端校验边界不一致（两处）

- **位置**：
  - `web/src/views/settings/BasicSettings.vue:27` ↔ `internal/handlers/caddy.go:387-390`
  - `web/src/views/settings/CaddyGlobalSettings.vue:34` ↔ `internal/handlers/caddy.go:348-351`
- **代码证据**：
  - 审计日志大小：UI `<el-input-number v-model="settings.audit_log_size_mb" :min="1" :max="1024" .../>`；后端：
    ```go
    if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB > 512 {
        c.JSON(http.StatusBadRequest, ... "审计日志轮转大小上限 512MB")
    ```
  - 请求体大小：UI `:max="86400"`；后端：
    ```go
    if req.RequestBodyMaxSizeMB != nil && (*req.RequestBodyMaxSizeMB < 0 || *req.RequestBodyMaxSizeMB > 4096) {
        ... "request_body_max_size_mb 必须在 0-4096 MB 之间"
    ```
- **分类**：不合理逻辑（UI↔后端契约漂移）。
- **判定**：设计漂移（依据：后端上限系 R57 C-7 / Round 33 N-5 后加的安全钳制，UI 输入框未同步收紧；513-1024 与 4097-86400 区间在 UI 合法、提交必 400）。
- **影响**：用户按 UI 允许的范围填写后被 400 拒绝，报错文案虽为中文可读，但与输入框上限矛盾，体验割裂；无数据风险（预览/保存均被拒）。
- **建议**：UI 上限对齐 512 / 4096（或在后端放宽，二选一，以产品意图为准）。
- **是否待裁定**：否（纯对齐修复）。

### S-4 `users.mfa_failed_attempts` / `users.mfa_locked_until` 已成死列，残留清零写与过时注释

- **位置**：`internal/db/db.go:694-695`（迁移加列）、`db.go:1728-1729`（users 表重建保留）、`internal/services/mfa.go:296`（MFAActivate 清零）、`mfa.go:350`（MFAResetForUser 清 NULL）、`internal/services/cluster_snapshot.go:761-762` + `cluster_apply.go:404-407`（跨节点同步）、`internal/services/cluster_sections.go:89-99`（过时注释）。
- **代码证据**：
  - 全仓 grep 核实：生产代码中**不存在任何**对 `mfa_failed_attempts`/`mfa_locked_until` 的递增写入（仅 `=0`/`=NULL` 重置、快照搬运、建表/迁移定义）。现行登录锁定使用的是 `login_failed_attempts`/`login_locked_until`（auth.go:75-84）。
  - git 佐证：`66b35ce0`「…移除 R74 端点硬门与 mfa_* 锁定机制，全系统唯一锁定=登录阶段…」。
  - 过时注释（cluster_sections.go:90-95）仍称：「mfa_failed_attempts / mfa_locked_until——从节点本地失败计数与锁定…」，描述的是已删除机制；且真实本地锁定列 `login_*` 并不进快照（`cluster_snapshot.go:759-762` 的列清单可证），注释与实现双重失真。
  - 残留清零写（mfa.go:350）：
    ```go
    "UPDATE users SET mfa_enabled=0, mfa_secret='', ..., mfa_failed_attempts=0, mfa_locked_until=NULL WHERE id=?"
    ```
    清的是死列，而 `login_locked_until` 不清（与「唯一锁定在登录阶段、10 分钟自愈」一致，故不清是对的——但正说明 mfa_* 两列的清理动作已无意义）。
- **分类**：已弃用代码（死列 + 冗余写 + 文档失真）。
- **判定**：设计漂移（残留。依据：裁定移除机制时未做 schema/快照/注释的净移除；行为无错但状态面与注释误导后续维护，且快照体积/哈希计算持续携带无用字段）。
- **影响**：无运行期错误；主要是认知负担与集群快照冗余。附注：users 节重放（主节点用户变更触发）会在从节点以 INSERT 默认值重置从节点本地 `login_*` 计数（cluster_apply.go:405 的 INSERT 不含 login_* 列）——影响为从节点进行中的 10 分钟锁定被低频用户变更提前抹除，属可接受的外观性损失，但与 cluster_sections.go 注释声称的「本地态保护」意图并不严格成立。
- **建议**：择机迁移删除两列并同步收缩快照结构体/注释（涉及快照 schema_version 评估）；短期至少修正 cluster_sections.go 注释与移除两处清零写。
- **是否待裁定**：否（定性明确）；迁移时机可议。

### S-5 描述已移除 R74 硬门的过时注释留存于测试与服务的文档注释

- **位置**：`internal/handlers/mfa_verifystep_test.go:19-25`、`internal/services/mfa.go:186-188`。
- **代码证据**：
  - mfa_verifystep_test.go:19-25（注释原文）：
    ```
    // R74（审计 B3 I-5）verify-step 端点级硬失败上限：mfa_lockout_enabled 关（默认）
    // 时 verify-step 无任何硬门——每次 401 仅自增 mfa_failed_attempts 而无效果，
    // ...
    // 硬门与登录 challenge 10 次（B-I-4）/激活 pending 5 次（A-F-2）同族：
    // 连续失败 ≥10 → 10 分钟冷却，一律 429「连续失败过多，请 10 分钟后重试」
    ```
    该硬门已在 `66b35ce0` 被用户二次裁定移除；文件内现存的唯一测试 `TestMFAVerifyStep_rejectsRecoveryCode` 与这段注释无关。注释描述的 `mfa_failed_attempts` 自增、429 文案在实现中均不存在。
  - services/mfa.go:186-188（MFAVerifyCode doc）：
    ```
    // 成功：清失败计数、推进 mfa_last_timestep（重放防护）；失败：按全局开关计数/锁定。
    ```
    实现中成功路径不清任何失败计数、失败路径不计数不锁定（裁定后语义，函数体内 221-224 行注释与之自相矛盾——同一函数两段注释说法相反）。
- **分类**：已弃用代码（过时文档/注释）。
- **判定**：设计漂移（依据：行为按新裁定收敛时注释未同步；测试文件头注释完整保留了旧机制的操作细节，极易诱导维护者「补回」已裁撤的功能或据其写错误契约测试）。
- **影响**：纯认知风险；无行为影响。
- **建议**：删除/改写两处注释为新裁定语义（本会话已实跑 `TestMFAVerifyStep_rejectsRecoveryCode` 确认现存契约仅恢复码拒绝一条）。
- **是否待裁定**：否。

### S-6 `global_config.metrics_public` / `metrics_origins` 死配置列

- **位置**：`internal/db/db.go:714-715`（迁移定义）、`internal/handlers/config_backup.go:217`（备份导出布尔键清单）。
- **代码证据**：全仓（Go/Vue/TS，排除测试与 dist）grep 仅命中上述两处定义/搬运，无任何读取消费点：
  ```go
  "global_config.metrics_public":                "BOOLEAN DEFAULT 0",
  "global_config.metrics_origins":               "VARCHAR(500)",
  ```
  （语义推断为早期「指标公开访问/CORS 白名单」设想的残留——推断，非实证。）
- **分类**：已弃用代码（死配置）。
- **判定**：设计漂移（依据：schema 定义 + 备份搬运 + 零消费，三链中「消费」一环缺失，属典型死配置）。
- **影响**：无；仅随备份导出空转，误导审计者以为存在指标公开开关。
- **建议**：迁移删除两列并从 `backupBooleanConfigKeys` 移除。
- **是否待裁定**：否。

### S-7 `metrics_retention_days` 有消费但无任何产品内写入口

- **位置**：消费 `internal/services/services.go:565-578`（`cleanupHistory` 启动+每 24h，读 `COALESCE(metrics_retention_days,7)`，<1 回退 7）；定义 `internal/db/db.go:379`（DEFAULT 7）；唯一写路径为备份导入钳制 `internal/handlers/config_backup.go:1683-1686`（1..3650）。
- **代码证据**：`internal/models/models.go:487-524`（`UpdateConfigRequest`）不含 `metrics_retention_days` 字段；`web/src/views/settings/*` 与 Settings.vue 的 SettingsConfig 均无该键——UI 三链中「UI 语义」一环缺失。
- **分类**：不合理逻辑（半死配置）。
- **判定**：设计漂移（待裁定。依据：与 `audit_retention_months`（有 UI 有消费）形成对照，此键有存储有消费却只能靠导入备份或直改 DB 调整；无法判断是「刻意不给用户调」还是「漏做 UI」）。
- **影响**：指标历史保留期对用户不可见不可调；导入备份可将其设为最长 3650 天（约 10 年）而无任何界面提示，指标库体积不受 UI 治理口径约束。
- **建议**：若产品确认需要，在基础设置补 UI（与「日志保留」同卡片）；若不需要可调，将导入钳制上限收紧并考虑从导出清单移除。
- **是否待裁定**：是。

### S-8 MFA 恢复码重生成与重绑定向导（setup）零审计留痕

- **位置**：`internal/services/auditpolicy.go:20,24`（两路由 `AuditPolicySkip`）、`internal/handlers/mfa.go:100-150`（MFASetup 无 recordAudit）、`mfa.go:218-237`（MFARecoveryCodes 无 recordAudit）。
- **代码证据**：
  - 策略注释（auditpolicy.go:14-18）将 setup/recovery-codes 归为「读或内部动作不产生审计」；
  - 对照同类高敏动作均有留痕：启用 `mfa.go:182`、禁用 `mfa.go:214`（且失败留痕 `mfa.go:202`）、admin 重置 `mfa.go:343`（失败留痕 `mfa.go:314`）；
  - `MFARecoveryCodes` 的响应语义（mfa.go:236）：`"恢复码已重新生成（旧码全部作废）"`——旧码全量作废 + 新码明文下发，安全敏感度不低于禁用 MFA。
- **分类**：不合理逻辑（审计覆盖缺口）。
- **判定**：待裁定（依据：策略表是有意收敛的结果且注释给出了理由，但「重生成恢复码」并非「读」，与同卡片其它动作的留痕密度不一致；在 2026-09 裁定「恢复码重生成=纯 JWT 会话门」后，该动作成为会话劫持者可静默完成且事后无痕的少数操作之一——劫持者轮换受害者恢复码不影响其登录（TOTP 仍在），但破坏受害者丢失验证器后的应急通道）。
- **影响**：事后取证时无法从操作日志判断恢复码是否被第三方重生成、pending secret 是否被反复签发。
- **建议**：为 `POST /auth/mfa/recovery-codes`（及已启用者的 setup）补 handler 显式审计（动作「生成」/对象「恢复码」），入 Explicit 清单；不改变现有密码/验码门。
- **是否待裁定**：是。

### S-9 操作日志/用户列表对非管理员（viewer 语义角色）全量开放

- **位置**：`internal/middleware/middleware.go:359`（`business.GET("/users", h.ListUsers)`）、`middleware.go:451-452`（`business.GET("/audit-logs", ...)` 与 options）；菜单 `web/src/components/layout/AppLayout.vue:84-92`（用户管理/操作日志对全体登录用户可见）；写侧封堵 `internal/middleware/readonly.go:48-57`。
- **代码证据**：`business` 组仅挂 `readOnlyGuard`（读方法直接放行）；`readOnlyGuard` 只拦写方法——非 admin 在主节点「只读」但可读全部数据。操作日志内容包含：全部用户的登录失败记录（含 IP、`用户 N` 归因）、账户锁定事件、重置密码/重置 MFA 明细（`auditlog.go` 查询无按用户过滤）。
- **分类**：权限模型确认项。
- **判定**：待裁定（依据：与「非管理员用户只读」的角色模型自洽——viewer 即全量只读观察者，前端也以只读形态呈现；但审计日志的安全信息密度（源 IP、失败归因）对最低权限角色通常不开放，是否收紧属产品裁量，非实现缺陷）。
- **影响**：低权限账号（或泄露的只读 API Key——`GET /audit-logs` 对只读 Key 同样放行）可枚举管理员用户名、登录失败 IP 分布等侦察信息。
- **建议**：如需收紧，将 `/audit-logs`、`/users` 移入 admin 组或做行级脱敏；维持现状则在文档明示 viewer 角色的可见范围。
- **是否待裁定**：是。

### S-10 认证全部通过后，`last_login` 更新失败将整个登录判为 500（不发令牌）

- **位置**：`internal/handlers/auth.go:182-190`。
- **代码证据**：
  ```go
  if isLogin {
      lastLogin := time.Now().UTC()
      if _, err := db.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", lastLogin, user.ID); err != nil {
          services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.AuditResultPart("internal_error"), c.ClientIP())
          c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新登录时间失败"})
          return
      }
  ```
  密码（与 MFA）均已验证成功，仅装饰性字段写失败即拒绝发 JWT。
- **分类**：不合理逻辑（成功路径被非关键写放大为失败）。
- **判定**：待裁定，倾向「有意保守」（依据：代码将 last_login 视为登录事实的一部分且失败留审计「登录失败/internal_error」，口径自洽；但该字段不参与任何安全判定（UI「最后登录」列展示），fail-open 降级为「登录成功但 last_login 陈旧 + 告警」不会引入风险。DB 瞬时抖动窗口内用户被拒登录并看到误导性文案）。
- **影响**：低频（主库写失败同时段其它写也会失败）；影响为可用性而非安全。
- **建议**：降级为告警 + 继续发令牌，或保持现状并在文案中提示重试。
- **是否待裁定**：是。

### S-11 审计查询的 LIKE 前导通配与 `datetime()` 包裹使索引失效（全表扫描）

- **位置**：`internal/handlers/auditlog.go:53-55`（`like` 构造 `"%" + value + "%"`）、`auditlog.go:98-103`（`datetime(created_at) >= datetime(?)`）；索引 `internal/db/audit.go:49`（`idx_audit_log_created ON audit_log(created_at)`）。
- **代码证据**：
  ```go
  func like(column, value string) (string, interface{}) {
      return " AND " + column + " LIKE ?", "%" + value + "%"
  }
  ...
  conds = append(conds, " AND datetime(created_at) >= datetime(?)")
  ```
  表达式包裹 + 前导 `%` 均无法使用 `idx_audit_log_created`；`GetAuditLogOptions`（auditlog.go:23-42）的 GROUP BY 全表聚合同源。
- **分类**：冗余/性能观察。
- **判定**：设计取舍（依据：审计库按 `audit_retention_months`（默认 3 个月，1-12）每日清理且写入速率有限，行数上界可控；分页 LIMIT/OFFSET 有 page≤100000、page_size≤100 钳制（auditlog.go:112-124），深翻页成本有界。以当前数据规模换取模糊筛选灵活性，可接受）。
- **影响**：大保留期（12 个月）+ 高写入量部署下筛选与下拉项聚合变慢；无正确性问题。
- **建议**：如需优化，时间过滤去 `datetime()` 包裹（两侧同为 `YYYY-MM-DD HH:MM:SS` 文本可直接比较）、选项聚合加 LIMIT 已有（100/50/100）。
- **是否待裁定**：否。

### 已核实无问题的要点（正面清单，供交叉审计引用）

1. **SetupAdmin 无 TOCTOU**：计数检查后用条件 INSERT `WHERE NOT EXISTS (SELECT 1 FROM users)`（auth.go:480-481），并发双请求仅一方成功，败者 403。
2. **登录防枚举等时**：不存在用户跑等时 bcrypt 占位（auth.go:46-53, 109-116）；锁定账户仍跑真实 bcrypt 再 429（auth.go:122-130），不泄露锁定账户密码正误。
3. **公开认证端点体量与频控**：64KB body 硬上限（auth.go:25-44）；login/ticket-login/mfa-verify/setup 均挂 `loginRateLimit`（10 次/分/IP，middleware.go:113-142，含清理协程）。
4. **MFA DB 错误 fail-closed**：Login 的 mfa_enabled 判定 DB 错误即 500（auth.go:151-156，R72 C-I-3）；mfaStepUpGuard 同口径（middleware.go:853-857）。
5. **挑战/恢复码并发安全**：挑战消费 CAS（mfa.go:172-182）；恢复码消费条件 UPDATE CAS + `mfaMu` 串行化（mfa.go:87-114、303-317）；TOTP 重放防护（step ≤ lastStep 拒绝）。
6. **API Key 认证**：前缀+全键哈希双匹配、账户禁用/过期联动（middleware.go:695-704）；`last_used` 脏集每分钟批刷、失败回灌（apikey_last_used.go:25-62）；IP 白名单 CIDR 解析失败 500 fail-closed；内部 MCP 密钥常量时间比较。
7. **只读 Key 与 step-up 同源判定**：`IsReadOnlyWriteRoute` 单一事实源服务三个守卫（auditpolicy.go:117-135）；`GET /config/export` 被两侧单独设卡（middleware.go:768-774、792-802）。
8. **审计双清单契约**：Explicit 清单 ↔ `HasExplicitAuditEvent` 集合相等有绊线测试（本会话实跑通过）；`auditMiddleware` 跳 4xx、≥500 标失败、API Key 归因追加（middleware.go:473-506）；认证拒绝类按 reason+path+IP 限流去刷屏（middleware.go:47-100）。
9. **审计库独立 + 启动缓冲**：审计事件先进内存缓冲（上限 10000、超限丢最旧并告警），审计库就绪后 flush（db/audit.go:148-220）；词汇迁移幂等。
10. **指标库自愈**：头部魔数 + Ping 损坏码双防线隔离重建（含 -wal/-shm 伴生与同秒序号防覆盖），隔离文件 GC 每基础名留 3 份（db/metrics.go:71-232）；保留清理 5000 行/批 + 10ms 让锁（metrics.go:334-364）。
11. **优雅退出顺序正确**：`main.go` 中 `defer db.Close()` 最先注册故最后执行；worker（事件摄入/metrics/CRS/IP2Region/看门狗/审计清理/时区/日志轮转/lifecycle）先停再关库（main.go:66-70, 173-191）；重启信号双通道（quit/restart）统一先 `signal.Stop` 再 ≤10s 优雅关停（main.go:253-279）。
12. **多实例装配**：端口经配置文件、1-65535 早校验（config.go:100-105）；TZ 按 `global_config.timezone` 装载（main.go:87-97）；`is_master` 读取失败回退主节点并告警（main.go:153-157）。

---

## 五、待裁定项汇总

| 编号 | 议题 | 需要裁定的点 | 倾向性建议 |
|---|---|---|---|
| S-1 | admin 经 PUT /users/:id（及 reset-password 端点）改自己密码无当前密码确认 | 是否将「改密验当前密码」例外扩展覆盖 admin 自助场景（后端加自身目标门，或前端改走 PATCH /users/me） | 建议补门：与 M5 威胁模型一致，改动面小 |
| S-7 | `metrics_retention_days` 无 UI/API 写入口 | 补 UI 还是收紧导入钳制/移除导出 | 若指标保留期需要治理，补基础设置卡片入口 |
| S-8 | 恢复码重生成与 MFA setup 零审计 | 是否为这两个高敏动作补显式审计（入 Explicit 清单） | 建议补：与同卡片 disable/activate/reset 留痕密度对齐 |
| S-9 | /audit-logs、/users 对非管理员与只读 API Key 全量开放 | viewer 角色是否应看到全量审计（含 IP/失败归因）与用户名单 | 产品裁量；收紧则移 admin 组或脱敏 |
| S-10 | last_login 写失败吞掉已完成的认证（500 不发令牌） | 维持保守 fail-closed 还是降级为告警+发令牌 | 倾向降级（该字段无安全语义） |

其余发现（S-2、S-3、S-4、S-5、S-6、S-11）定性明确，无需裁定，修复方向已在各条「建议」中给出。
