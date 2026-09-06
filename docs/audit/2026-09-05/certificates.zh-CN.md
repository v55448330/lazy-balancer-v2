# 证书模块审计报告（2026-09-05）

## 一、概览

### 1.1 审计范围与文件清单

后端（全部逐行通读）：

| 文件 | 行数 | 说明 |
|---|---|---|
| `internal/acme/client.go` / `client_test.go` | 433/460 | ACME 账户密钥管理、注册复用、账户清理、证书下载缓存 |
| `internal/acme/issuer.go` / `issuer_test.go` | 659/579 | DNS-01 签发编排：订单→TXT 写入→传播等待→验证→finalize→下载 |
| `internal/dnsprovider/dnsprovider.go` | 29 | Provider/ValueCleaner 接口 |
| `internal/dnsprovider/factory.go` | 96 | 凭证 JSON 解析（新/旧两种形态）与 provider 构造 |
| `internal/dnsprovider/dnspod/dnspod.go` | 315 | DNSPod China API（dnsapi.cn） |
| `internal/dnsprovider/tencent/tencent.go` | 230 | 腾讯云 DNSPod SDK |
| `internal/dnsprovider/ownership/store.go` | 204 | `data/acme_dns_ownership.json` 持久化所有权 |
| `internal/dnsprovider/internal/retry/retry.go` | 131 | 429/5xx 传输层重试 |
| `internal/services/certificates.go` | 1402 | 证书服务：续签巡检、启动恢复、孤儿清扫、快照补偿 |
| `internal/services/certissuer.go` | 811 | Issue 主流程 + 部署/回滚/退避 + 域名校验 |
| `internal/services/certstore.go` | 442 | certs/ 落盘（lb_*.crt/.key）、快照/恢复、DeployLock |
| `internal/services/certjoblog.go` | 151 | logs/certjob-*.log 写入与轮转 |
| `internal/services/certselector.go` | 93 | 候选证书择优 |
| `internal/services/certinfo.go` | 214 | 规则证书信息解析 |
| `internal/services/caqueue.go` | 1267 | 按 CA provider 的签发队列、并发/间隔闸门、取消/退役/僵尸保护 |
| `internal/services/caproviders.go` | 425 | CA provider 服务、ZeroSSL EAB 自动获取、CA 测试 |
| `internal/services/jobstate.go` | 154 | 状态机：26 状态枚举 + CAS transitionJob |
| `internal/services/dnsproviders/dnspod.go`、`registry.go` | 116/46 | DNS 提供商表单元数据 + 凭证构建/实弹测试 |
| `internal/services/cluster_snapshot.go`、`cluster_apply.go`（证书/DNS ownership 段） | — | 主从证书同步交接点 |
| `internal/handlers/certificates.go`、`certjobs.go`、`certinfo.go`、`caproviders.go` | 541/613/183/201 | REST 层 |
| `internal/handlers/rules.go`、`handlers.go`（证书任务相关段） | — | 规则启停/删除与任务联动 |
| `cmd/server/runtime_lifecycle.go`、`main.go`（启动接线段） | 74/— | StartACME/StopACME 主从生命周期 |
| `internal/middleware/middleware.go`（路由分组段） | — | 证书相关端点权限分组 |
| `internal/db/db.go`（cert_jobs/certificate_configs/ca_providers 建表段） | — | 存储契约 |

前端：

| 文件 | 说明 |
|---|---|
| `web/src/utils/certJobStatus.ts` | 26 个状态 → 中文标签 |
| `web/src/views/settings/CertJobs.vue` | 签发任务列表（5s 轮询）、重签、日志弹窗（3s 轮询） |
| `web/src/views/settings/FreeCertificates.vue` | ACME 全局设置、CA 提供商、DNS 提供商配置 |
| `web/src/views/Rules.vue`（证书相关段） | TLS 标签/tooltip、任务轮询、向导 TLS 步骤 |

### 1.2 方法

- 全量读码（上述清单），每条发现附 `file:line` 与代码原文摘录，本会话逐一核实。
- 以 `internal/acme/*_test.go`、`internal/services/cert*_test.go`、`internal/handlers/*cert*_test.go` 作为行为契约参考。
- 运行单包测试验证契约（全部通过，作为"无回归基线"证据）：
  - `go test ./internal/acme/... ./internal/dnsprovider/... -count=1` → 全 ok
  - `go test ./internal/services/ -run 'Cert|CAQueue|JobState|Deployment|Ownership' -count=1` → ok
  - `go test ./internal/handlers/ -run 'CertJob|Certificate|CAProvider' -count=1` → ok
- 落盘行为链只核对代码路径与命名约定（`certs/lb_*.crt|.key`、`certs-slave/`（compose 挂载 `/app/certs`）、`data/acme_dns_ownership.json`、`logs/certjob-*.log(.1-.5)`），未读取任何运行数据内容。

### 1.3 结论摘要

- **未发现高严重度逻辑缺陷。** 签发状态机（创建→验证→签发→落盘→加载）经多轮加固（R28–R72 注释可考），CAS 状态转换、双执行防护、部署回滚、补偿恢复均有测试契约支撑；本轮测试全绿。
- 发现 **2 项中严重度设计漂移**（CA EAB 凭证明文对全体登录用户可读，与 DNS 凭证掩码口径不一致；前端把 `waiting_ca` 限流冷却当作"申请中"禁用规则启停/删除，与后端守卫语义相悖）、**1 项中严重度遗留字段暴露面**（`global_config.dns_credentials` 明文返回且已无消费方）。
- 其余为低严重度的冗余/注释漂移/UI 语义缝隙，共 16 项，另有 4 项待裁定。
- 三链对照（UI 语义→存储→消费→渲染）总体一致性**良好**：重签冷却阈值前后端镜像、证书择优三处（UI cert-info / Caddy 渲染 / 集群快照）同源、状态枚举三处（DB CHECK / allJobStatuses / 前端 union）完全一致（均 26 个）。

## 二、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| C-01 | internal/services/caproviders.go:61,84-109 + internal/middleware/middleware.go:387-388 | 不合理逻辑（凭据暴露不一致） | 中 | 设计漂移 |
| C-02 | web/src/views/Rules.vue:1535-1537,214-215,245-246 vs internal/services/caqueue.go:519-524 | 不合理逻辑（UI 守卫过严+文案误导） | 中 | 设计漂移 |
| C-03 | internal/handlers/caddy.go:150 + internal/dnsprovider/factory.go:12 | 已弃用代码（遗留字段暴露） | 中 | 设计漂移（待裁定 C-03a） |
| C-04 | internal/handlers/certificates.go:235-252 | 不合理逻辑（删除无引用检查） | 中低 | 设计漂移 |
| C-05 | internal/handlers/certjobs.go:563-569 vs internal/services/certjoblog.go:18,141-148 | 不合理逻辑（轮转备份不可见） | 低 | 设计漂移 |
| C-06 | internal/services/certissuer.go:64-94 vs internal/dnsprovider/internal/retry/retry.go:27-45 | 冗余代码（重复实现+边界不一致） | 低 | 设计漂移 |
| C-07 | internal/services/certissuer.go:80-81 | 已弃用代码（失效注释） | 低 | 已弃用 |
| C-08 | internal/services/caproviders.go:359-370 | 已弃用代码（注释与实现不符） | 低 | 已弃用 |
| C-09 | internal/dnsprovider/dnspod/dnspod.go:109-117,231-267 | 不合理逻辑（无缓存全量扫描） | 低 | 有意设计（性能取舍） |
| C-10 | internal/dnsprovider/ownership/store.go:86-115 | 不合理逻辑（陈旧条目无全局 GC） | 低 | 有意设计 |
| C-11 | internal/services/certjoblog.go:82-96 | 逻辑 bug（轮转竞态+错误吞没，低危） | 低 | 缺陷 |
| C-12 | web/src/views/settings/CertJobs.vue:260-263 vs internal/handlers/certjobs.go:360-364 | 不合理逻辑（未知状态冷却默认值不一致） | 低 | 设计漂移 |
| C-13 | internal/handlers/apidocs.go:75,77 | 已弃用代码（文档与实现矛盾） | 低 | 已弃用 |
| C-14 | internal/services/dnsproviders/dnspod.go:57-63 | 冗余代码（凭证冗余拷贝） | 低 | 有意设计 |
| C-15 | internal/handlers/certjobs.go:107-110 | 不合理逻辑（配置读取失败放大为整页 500） | 低 | 设计漂移 |
| C-16 | internal/handlers/certificates.go:303,325,332,337,341 | 冗余代码（审计噪声"配置 0"） | 低 | 缺陷（低危） |
| C-17 | web/src/views/settings/CertJobs.vue:34,45,64 | 不合理逻辑（非 issued 任务隐藏证书时效信息） | 低 | 有意设计（观察项） |
| C-18 | internal/services/certificates.go:729-766 | 不合理逻辑（reconcile 只查存在不比对内容） | 低 | 已知局限（待裁定） |
| C-19 | internal/handlers/certificates.go:461-514 | 不合理逻辑（批量触发全量重签烧配额） | 低 | 待裁定（疑有意设计） |

统计（按总表分类列）：逻辑 bug 2（C-11、C-16，均低）；不合理逻辑 11（其中 C-09/C-10/C-17 判定为有意设计、C-18/C-19 待裁定）；冗余代码 2；已弃用代码 4。判定分布：设计漂移 8、缺陷 2、已弃用 3、有意设计 4、已知局限/待裁定 2。严重度：高 0、中 3、中低 1、低 15。

## 三、逐条详述

### C-01 CA 提供商 EAB 凭证明文返回给全体登录用户（与 DNS 凭证掩码口径不一致）

- **位置**：`internal/services/caproviders.go:61,84-109`；`internal/middleware/middleware.go:387-388`
- **代码证据**：

  `caproviders.go:55-67,84-109`：
  ```go
  // CAProviderListItem is a list view of a CA provider.
  type CAProviderListItem struct {
      ...
      Credentials   string    `json:"credentials"`
  ...
  func (s *CAProviderService) ListCAProviders() ([]CAProviderListItem, error) {
      ...
      p := CAProviderListItem{
          ID: provider.ID, Name: provider.Name, Provider: provider.Provider,
          DirectoryURL: provider.DirectoryURL, Credentials: provider.Credentials,
  ```
  `middleware.go:387-388`（business 组＝所有已登录用户，含非 admin 用户与普通角色）：
  ```go
  business.GET("/ca-providers", h.ListCAProviders)
  business.GET("/ca-providers/:id", h.GetCAProvider)
  ```
  对比 DNS 凭证的处理（`internal/handlers/certificates.go:91-94`，R72 二十六次 D4）：
  ```go
  // R72 二十六次 D4：凭证最小可见性——非 admin 只见掩码形态。
  if !isAdmin {
      cfg.DNSCredentials = maskDNSCredentialsJSON(cfg.DNSCredentials)
  }
  ```
- **分类**：不合理逻辑（安全一致性）。
- **判定及依据**：**设计漂移**。依据：同仓库在 R72 二十六次审计中已把 DNS 凭证收敛为"非 admin 掩码 + 掩码回传 sentinel"（`maskedDNSCredentialsSentinel`），而 ZeroSSL 的 `eab_kid/eab_hmac_key`（凭据价值等同：可替该邮箱注册/绑定 ZeroSSL ACME 账户、消耗其配额）仍原样返回且前端用其预填编辑框（`web/src/views/settings/FreeCertificates.vue:416-418` `parseCACredentials(... p.credentials ...)`）。写侧已收敛为 admin-only（`middleware.go:285-286`），读侧未对齐。
- **影响**：任意普通用户/只读角色登录会话可获取 ZeroSSL EAB HMAC 密钥；与 DNS 凭证最小可见性策略形成安全口径分叉。
- **建议**：对非 admin 响应掩码 `credentials`（复用 `maskDNSCredentialsJSON` 模式 + 更新路径 `credentialsMeaningfullyChanged` 已天然兼容全 `*` 形态，`internal/handlers/caproviders.go:47-53`）。
- **是否待裁定**：是（是否维持"内部工具全员可信"口径由用户裁定，见四-1）。

### C-02 前端把 `waiting_ca`（CA 限流冷却，可长达 1–3 小时）当作"证书申请中"，禁用规则启停/删除

- **位置**：`web/src/views/Rules.vue:1535-1537`（及 214-215、245-246 的消费点）；后端对照 `internal/services/caqueue.go:519-524`、`internal/handlers/rules.go:2618-2624`
- **代码证据**：

  `Rules.vue:1535-1537`：
  ```ts
  const isCertJobActive = (status?: CertJobStatus) => {
    if (!status) return false
    return !['issued', 'failed', 'disabled'].includes(status)
  }
  ```
  `Rules.vue:214-215`（启停开关）：
  ```html
  :disabled="isReadOnly || isCertJobActive(certJobMap[row.caddy_id]?.status) || ruleTogglePending[row.caddy_id]"
  ```
  后端明确相反的设计（`caqueue.go:519-524`）：
  ```go
  // HasRunningJobForRule 报告该规则当前是否有 worker 正在执行证书任务。
  // 只看 runningRules（执行中内存态）而非 DB 状态：queued 取消是瞬时的、
  // waiting_ca 冷却可长达 1-3 小时，均不应拦截删除/禁用；
  ```
  `DisableRule` 仅在真实执行中时 409（`rules.go:2621-2623`）。
- **分类**：不合理逻辑（UI 语义与后端守卫分叉）。
- **判定及依据**：**设计漂移（UI 侧）**。依据：后端 `HasRunningJobForRule` 的注释与实现是明确的用户裁定（waiting_ca 不拦截禁用/删除），且 DisableRule→EnableCertJobResume 的恢复链完备；前端 `isCertJobActive` 把 `waiting_ca`（以及 `downloaded` 部署退避窗，最长约 10 次×5min）一并视为活动态。注意：**编辑按钮**（`Rules.vue:225-229` → `canEditRule`）与后端一致——后端 `rules.go:1562` 的 SQL 守卫 `NOT EXISTS (... status NOT IN ('issued','failed','disabled'))` 同样阻塞 waiting_ca，故分叉仅存在于启停/删除两个按钮。
- **影响**：CA 限流冷却期（1–3 小时）内运维无法从前端禁用/删除规则；tooltip 文案"证书申请中，请等待完成或失败后再修改规则"在此场景为误导（并无签发在进行）。
- **建议**：`isCertJobActive` 收窄为后端 `HasRunningJobForRule` 同口径（排除 `waiting_ca`，`downloaded` 可按部署窗口保留），或至少为 `waiting_ca` 给出"CA 限流冷却中"文案。
- **是否待裁定**：否（后端注释即为裁定依据，属前端未对齐）。

### C-03 遗留字段 `global_config.dns_credentials`：明文返回给所有登录用户，且签发链已无消费方

- **位置**：`internal/handlers/caddy.go:150`；`internal/dnsprovider/factory.go:12`
- **代码证据**：

  `caddy.go:149-151`（GET /config，business 组）：
  ```go
  err := db.DB.QueryRow(`
      SELECT id, caddy_config, dns_provider, COALESCE(dns_credentials,'') as dns_credentials,
  ```
  签发链唯一的凭证来源（`internal/services/certissuer.go:417-425`）：
  ```go
  // Load DNS credentials from the rule's selected provider.
  var dnsCredentialsJSON string
  if acmeConfigID > 0 {
      err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=? AND enabled=1", acmeConfigID).Scan(&dnsCredentialsJSON)
  ```
  `factory.go:12` 的注释已与现实不符（真实存储在 `certificate_configs.dns_credentials`）：
  ```go
  // DNSCredentials is the unified credential envelope stored in global_config.dns_credentials.
  ```
- **分类**：已弃用代码（遗留暴露面）。
- **判定及依据**：**设计漂移**。依据：签发、UI（`web/src` 中无任何视图消费 `config.dns_credentials`，仅 `certificate-configs` 的 `dns_credentials`）、测试（`config_backup_test.go:635` 直改库种入）均不再消费该字段；它仅随 UpdateConfig 写入（`handlers/caddy.go:483`）并随集群快照同步（`cluster_snapshot.go:392`）。v1 迁移/历史部署可能在该字段留有真实 DNS token。
- **影响**：存量部署的遗留 DNS 凭证对所有登录用户明文可读；字段与注释持续制造"两处凭证"的误导。
- **建议**：从 GetConfig 响应剔除（或对非 admin 掩码），清理 factory.go 注释；若确认无迁移依赖可直接删列。
- **是否待裁定**：是（字段去留需确认 v1 导入路径是否依赖，见四-2）。

### C-04 DeleteCertificateConfig 无规则引用检查

- **位置**：`internal/handlers/certificates.go:235-252`
- **代码证据**：
  ```go
  func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {
      ...
      if _, err := db.DB.Exec("DELETE FROM certificate_configs WHERE id = ?", id); err != nil {
  ```
  消费侧对缺失配置的处理（`certissuer.go:426-429`）：
  ```go
  if dnsCredentialsJSON == "" {
      failJob(jobID, "未选择可用的 DNS 提供商，请先在规则中选择 DNS 凭证")
      return fmt.Errorf("no enabled DNS provider selected for rule")
  }
  ```
- **分类**：不合理逻辑。
- **判定及依据**：**设计漂移**。依据：创建/绑定侧有完整性校验（R53 系测试：规则绑定 `enabled=0` 的 DNS 配置会被 400 拒绝），删除侧却无 `lb_rules.acme_config_id` 引用检查，形成不对称；删除后规则仍在自动签发链中，下一次续签/首签必然失败且仅体现在任务 message。
- **影响**：误删被引用的 DNS 配置 → 关联规则后续签失败（证书到期前无自动恢复路径，需人工发现）。
- **建议**：删除前检查引用并 409（提示规则清单），或级联提示。
- **是否待裁定**：否。

### C-05 任务日志查看只拼接 `.1` 轮转备份，`.2`–`.5` 永不可见

- **位置**：`internal/handlers/certjobs.go:563-569`；`internal/services/certjoblog.go:18,141-148`
- **代码证据**：

  写侧保留 6 份（`certjoblog.go:18,88-96`）：
  ```go
  const maxRotatedFiles = 5
  ...
  os.Remove(fmt.Sprintf("%s.%d", path, maxRotatedFiles))
  for i := maxRotatedFiles - 1; i >= 1; i-- {
      ...os.Rename(oldPath, newPath)
  }
  os.Rename(path, path+".1")
  ```
  读侧只读两份（`certjobs.go:563-569`）：
  ```go
  logPath := services.CertJobLogPath(ruleID)
  logPathBackup := logPath + ".1"
  content := readCertJobLogFile(logPath)
  if oldData := readCertJobLogFile(logPathBackup); oldData != "" {
      content = oldData + content
  }
  ```
- **分类**：不合理逻辑（功能缝隙）。
- **判定及依据**：**设计漂移**。依据：写侧明确维护 6 份历史，读侧（也是 UI 日志弹窗的唯一数据源）只拼接 1 份备份；叠加 `readCertJobLogFile` 的 128KB/500 行截断，实际可回看窗口远小于磁盘保留量。
- **影响**：排查长周期失败（多次轮转后）时历史日志在 UI 不可达，只能登机看文件。
- **建议**：读侧按序拼接全部轮转文件（或至少提供下载原始日志入口）。
- **是否待裁定**：否。

### C-06 `parseRetryAfter` 与 `retry.After` 重复实现且边界语义不一致

- **位置**：`internal/services/certissuer.go:64-78`；`internal/dnsprovider/internal/retry/retry.go:27-45`
- **代码证据**：

  `certissuer.go:65-71`：
  ```go
  func parseRetryAfter(header string) time.Duration {
      if header == "" { return 0 }
      if seconds, err := strconv.Atoi(header); err == nil {
          return time.Duration(seconds) * time.Second   // 负数原样返回
      }
  ```
  `retry.go:33-38`：
  ```go
  if seconds, err := strconv.Atoi(header); err == nil {
      if seconds <= 0 {
          return 0                                      // 负数归零
      }
      return time.Duration(seconds) * time.Second
  }
  ```
- **分类**：冗余代码。
- **判定及依据**：**设计漂移**。依据：两处解析同一 HTTP 语义（Retry-After），防御口径却不同；`parseRetryAfter` 的负值结果被 `computeBackoff`（`if retryAfter > 0`）兜住，当前无实际危害，属重复实现漂移。
- **影响**：低；维护双份语义易在未来改动中分叉。
- **建议**：收敛为一份（dnsprovider/internal/retry 导出或提取公共包）。
- **是否待裁定**：否。

### C-07 `defaultRetryAfter` 失效注释

- **位置**：`internal/services/certissuer.go:80-81`
- **代码证据**：
  ```go
  // defaultRetryAfter returns the default cooling duration when a CA does not provide Retry-After.
  // computeBackoff returns the cooling duration based on attempt count and CA Retry-After.
  func computeBackoff(attempts int, retryAfter time.Duration) time.Duration {
  ```
- **分类**：已弃用代码（注释残留）。
- **判定及依据**：**已弃用**。依据：仓库内已无 `defaultRetryAfter` 函数（全仓 grep 仅此注释一处命中），默认冷却已内联进 `computeBackoff` 的 switch（1h/2h/3h）。
- **影响**：低（误导读者）。
- **建议**：删除首行注释。
- **是否待裁定**：否。

### C-08 `maskEmail` 注释与实现不符

- **位置**：`internal/services/caproviders.go:359-370`
- **代码证据**：
  ```go
  // maskEmail 脱敏邮箱地址：保留首字符与域名，中间用 *** 替代。
  // 例如：admin@example.com → a***@example.com
  func maskEmail(email string) string {
      at := strings.IndexByte(email, '@')
      ...
      return string(email[:2]) + "***" + email[at:]      // 实际保留前两个字符
  ```
- **分类**：已弃用代码（注释漂移）。
- **判定及依据**：**已弃用**。依据：实现保留 `email[:2]`（两个字符），注释与示例均称"首字符"；`at<=3` 分支还返回 `"***"+domain`（连首字符也不保留），三处口径互不一致。
- **影响**：低（仅日志脱敏展示；泄露 2 字符 vs 1 字符差异可忽略，但注释失真）。
- **建议**：修正注释或实现择一。
- **是否待裁定**：否。

### C-09 DNSPod `getDomainID` 无缓存全量扫描，且 cleanUp 空结果时也先扫描

- **位置**：`internal/dnsprovider/dnspod/dnspod.go:109-117,231-267`
- **代码证据**：

  `cleanUp` 无条件先解析 domainID（`dnspod.go:109-117`）：
  ```go
  func (p *Provider) cleanUp(ctx context.Context, zone, tokenFQDN string, value string, byValue bool) error {
      ...
      domainID, err := p.getDomainID(ctx, zone)   // 先于 ownership 查询
      if err != nil { return err }
  ```
  `getDomainID` 每次分页拉全量域名（`dnspod.go:231-267`，`domainListPageSize=3000`、最多 100 页）：
  ```go
  func (p *Provider) getDomainID(ctx context.Context, zone string) (string, error) {
      offset := 0
      for page := 0; page < domainListMaxPages; page++ {
          ...params.Set("length", strconv.Itoa(domainListPageSize))
          ...if err := p.apiCall(ctx, "Domain.List", params, &result); err != nil {
  ```
- **分类**：不合理逻辑（性能）。
- **判定及依据**：**有意设计（性能取舍）**。依据：签发器对每个挑战先 `CleanUpChallenge`（issuer.go:99）、再 `Present`（issuer.go:104）、结束后 `Cleanup`（defer），即每挑战≥3 次 `getDomainID` 全量扫描；域名量大的账号每次签发产生可观的 Domain.List 放大。未做缓存是简单性取舍，无正确性问题（分页推进与 total 判定已防御异常服务端）。
- **影响**：低（DNSPod API 压力与签发时延放大；无功能错误）。
- **建议**：在 Provider 生命周期内缓存 zone→domainID（签发为短生命周期对象，天然避免陈旧）。
- **是否待裁定**：否。

### C-10 DNS ownership 陈旧条目仅在同 (provider,zone,fqdn) 再次签发时清理，无全局 GC

- **位置**：`internal/dnsprovider/ownership/store.go:86-115`
- **代码证据**：
  ```go
  func (s *Store) MatchingValue(provider, zone, fqdn, value string) ([]Record, error) {
      ...
      for _, record := range current.Records {
          if record.Provider != provider || record.Zone != zone || record.FQDN != fqdn {
              continue
          }
          ...
          if record.Value == value || legacy || stale {
              matching = append(matching, record)
          }
      }
  ```
- **分类**：不合理逻辑（无界增长面）。
- **判定及依据**：**有意设计**。依据：`staleOwnershipAge=75min` 的清理只挂在按名匹配的查询上；换了域名/删除了规则后的陈旧条目永远留在 `acme_dns_ownership.json`，并随每次集群同步整体下发到从节点（`cluster_snapshot.go:640-644`）。条目体量小（每挑战一条），增长速率低。
- **影响**：低（文件缓慢膨胀；无功能影响）。
- **建议**：Add/同步物化时顺带全量剔除 `stale` 条目（单文件全量重写已是既有模式）。
- **是否待裁定**：否。

### C-11 证书任务日志轮转非跨实例互斥，且轮转错误被忽略

- **位置**：`internal/services/certjoblog.go:82-96`
- **代码证据**：
  ```go
  func (l *CertJobFileLogger) write(level, stage, message string) {
      l.mu.Lock()                       // 仅实例内互斥
      defer l.mu.Unlock()
      path := CertJobLogPath(l.ruleID)
      if info, err := os.Stat(path); err == nil && info.Size() >= getCertJobLogSizeBytes() {
          os.Remove(...)                 // 错误被丢弃
          for i := maxRotatedFiles - 1; i >= 1; i-- {
              ...os.Rename(oldPath, newPath)   // 错误被丢弃
          }
          os.Rename(path, path+".1")
      }
  ```
  每次写日志都新建实例（`certissuer.go:270` `NewCertJobFileLogger(ruleID)`、`certjoblog.go:122-129` `WriteCertJobLog`），实例间无共享锁。
- **分类**：逻辑 bug（低危竞态）。
- **判定及依据**：**缺陷**。依据：同 ruleID 的并发写者（在途 worker 的 jobLogger 与 DisableRule 的 `WriteCertJobLogByRule`、部署重试回调）各自持实例锁；check-then-rotate 窗口内两个实例同时轮转时，第二个 `os.Rename(path, path+".1")` 会覆盖第一个刚轮转出的 `.1`（丢失一整份历史），且所有轮转错误被吞，无法从日志察觉。触发需要"恰好同时越过大小阈值"，概率低。
- **影响**：低（极端并发下丢一段轮转日志；append 本身 O_APPEND 原子，主日志不撕裂）。
- **建议**：按 ruleID 维护包级互斥（或复用 `certWriteMu` 模式），轮转错误记 `log.Printf`。
- **是否待裁定**：否。

### C-12 前后端"未知状态"的重签冷却默认值不一致

- **位置**：`web/src/views/settings/CertJobs.vue:259-263`；`internal/handlers/certjobs.go:360-364`
- **代码证据**：

  后端（`certjobs.go:360-364`）：
  ```go
  guard := 2 * time.Minute
  if status == "queued" { guard = 15 * time.Minute }
  return now.Sub(updatedAt.Time) < guard, "任务正在执行中，请稍后重试"
  ```
  前端 default 分支（`CertJobs.vue:260-263`）：
  ```ts
  // Round 35 I-24: 同 statusType，避免运行时 throw。
  default:
    console.warn('Unknown cert job status:', status)
    return 0            // 立即可重签
  ```
- **分类**：不合理逻辑（防御分支分叉）。
- **判定及依据**：**设计漂移**。依据：对现有 26 个状态，前端 `retryCooldownMinutes` 与后端 `certJobRetryBlocked` 完全镜像（disabled=null、issued/waiting_ca=0、queued=15、failed=5、其余=2，逐项核对一致）；仅"未来新增未知状态"时前端放行（0）、后端拦截（2min），用户会看到按钮可点但收到 429。
- **影响**：低（当前不可触发；向前兼容缝隙）。
- **建议**：前端 default 返回 2 与后端兜底对齐。
- **是否待裁定**：否。

### C-13 API 文档仍宣称"凭证明文对所有登录用户可读"，与 R72 掩码行为矛盾

- **位置**：`internal/handlers/apidocs.go:75,77`
- **代码证据**：
  ```go
  {"GET", "/certificate-configs", "证书", "DNS 提供商配置列表", "", `[{...}]`, []string{"401 unauthenticated"}, "凭证明文对所有登录用户可读，仅管理员可修改。"},
  {"POST", "/certificate-configs", "证书", "创建 DNS 提供商配置", ..., "凭证保存后所有登录用户可读，仅管理员可修改。"},
  ```
  而实现（`certificates.go:91-94`）已对非 admin 掩码（见 C-01 引文）。
- **分类**：已弃用代码（文档漂移）。
- **判定及依据**：**已弃用**。依据：R72 D4 改变了可见性行为，apidocs 描述未同步；该描述同时是 API 使用者（MCP/AI）理解权限的依据。
- **影响**：低（文档误导；可能引导调用方假设明文可得）。
- **建议**：更新为"非 admin 仅见掩码，更新回传掩码按未改动处理"。
- **是否待裁定**：否。

### C-14 腾讯云凭证 envelope 冗余携带 `api_token = secret_id,secret_key`

- **位置**：`internal/services/dnsproviders/dnspod.go:57-63`
- **代码证据**：
  ```go
  case "tencent_cloud":
      ...
      data, _ := json.Marshal(map[string]string{
          "mode":       "tencent",
          "secret_id":  creds["secret_id"],
          "secret_key": creds["secret_key"],
          "api_token":  creds["secret_id"] + "," + creds["secret_key"],
      })
  ```
- **分类**：冗余代码。
- **判定及依据**：**有意设计**。依据：`api_token` 仅为兼容 factory 的"按字段形态推断"老数据路径（`factory.go:65-74` 有 token 无 secret 才推断 dnspod；mode 非空时根本不看 api_token），该拼接值只作为瞬时 envelope 存在（落库的是表单原始形态 `req.DNSCredentials`，`certificates.go:127`），但同一 secret 在内存/错误信息中出现两份。
- **影响**：低（无功能影响；错误串/调试输出中 secret 拷贝翻倍）。
- **建议**：envelope 中去掉 `api_token` 字段。
- **是否待裁定**：否。

### C-15 `cert_expiry_days` 读取失败使整个任务列表 500

- **位置**：`internal/handlers/certjobs.go:107-110`
- **代码证据**：
  ```go
  var expiryDays int
  if err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&expiryDays); err != nil {
      c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书过期提醒配置失败"})
      return
  }
  ```
- **分类**：不合理逻辑。
- **判定及依据**：**设计漂移**。依据：同仓库同类读取普遍采用"失败取默认 30 并告警"（`certificates.go:1202-1207` Round 35 I-20 明确该口径：避免查询失败时误报/整页失败）；此处将一个展示用阈值放大为列表端点整体失败。同请求内其他 DB 查询正常路径下该读取几乎不单独失败，故实际触发面窄。
- **影响**：低（global_config 读取抖动时"签发任务"页整页不可用，而非仅缺临期着色）。
- **建议**：失败降级为默认 30 + `log.Printf`。
- **是否待裁定**：否。

### C-16 无 id 的 DNS 凭证测试路径在审计详情中记录"配置 0"

- **位置**：`internal/handlers/certificates.go:303,325,332,337,341`
- **代码证据**：
  ```go
  idParam := c.Param("id")
  id, idErr := strconv.Atoi(idParam)
  ...
  if req.Domain == "" {
      recordAudit(c, "测试失败", "DNS配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, services.AuditResultPart("missing_domain")))
  ```
  前端保存流程先调无 id 的 `/certificate-configs/test`（`FreeCertificates.vue:544-547`），此时 `id=0` 且 `configName=""`。
- **分类**：冗余代码（审计噪声）/低危缺陷。
- **判定及依据**：**缺陷（低危）**。依据：每次保存前测试失败都会落一条"配置 0"审计，与既有审计明细规范（`AuditRulePart/AuditSourcePart` 等语义化部件）不符，稀释审计检索。
- **影响**：低。
- **建议**：无 id 路径改用 `AuditSourcePart("pre_save")` 之类的来源标注。
- **是否待裁定**：否。

### C-17 任务列表的过期时间/自动重签时间/剩余天数列仅在 `status==='issued'` 渲染

- **位置**：`web/src/views/settings/CertJobs.vue:34,45,64`；后端 `internal/handlers/certjobs.go:156-174` 对任意状态都计算
- **代码证据**：

  后端不区分状态计算（`certjobs.go:156-174`）：
  ```go
  j.CertificateStatus = "unknown"
  if j.ExpiresAt.Valid {
      remaining := j.ExpiresAt.Time.Sub(now)
      ...j.DaysRemaining = int(remaining.Hours() / 24)
  ```
  前端仅 issued 渲染（`CertJobs.vue:34`）：
  ```html
  <span v-if="row.status === 'issued' && row.expires_at" class="cell-text">{{ formatDate(row.expires_at) || '-' }}</span>
  ```
- **分类**：不合理逻辑（信息隐藏）。
- **判定及依据**：**有意设计（观察项）**。依据：`failed/disabled` 任务可持有仍有效的旧证书（续签失败场景），Rules.vue 的 tooltip 用"最近重签 失败：…"（`Rules.vue:152-155`）补充了该场景，但 CertJobs 页对该行完全隐藏证书时效，两处口径不一致；用户在任务页看不到"失败但证书仍剩 N 天"的关键缓冲信息。
- **影响**：低（信息呈现不全，需到规则页拼凑）。
- **建议**：failed 且 `expires_at` 有效时也渲染（弱化配色）。
- **是否待裁定**：否。

### C-18 `reconcileMissingCertFiles` 只查文件存在、不比对内容

- **位置**：`internal/services/certificates.go:729-766`
- **代码证据**：
  ```go
  certPath, keyPath := CertFilePaths(ruleID)
  ...
  if fileExists(certPath) && fileExists(keyPath) {
      continue            // 内容不比对
  }
  if err := materializeCertPair(ruleID, certPEM, keyPEM); err != nil {
  ```
- **分类**：不合理逻辑（已知局限）。
- **判定及依据**：**有意设计（自认局限）**。依据：`caddy.go:1220-1221` 注释明确"reconcile 只查存在不查内容"，并把"DB=新证、磁盘=旧证"的分叉防护交给了部署事务快照/终态 CAS（`certissuer.go:565-581` R56 N-1(b)）与强制重载（R72 W1-1）。若磁盘文件被外部改成"存在但错误"的内容，6 小时对账无法发现，需等下次续签或重启 `MaterializeAllCertsFromDB`（后者会比对内容，`certstore.go:434-440`）。
- **影响**：低（外部篡改/半写文件场景下分叉窗口最长 6 小时+）。
- **建议**：对账时复用 `materializeCertPair` 的内容比对（读两文件哈希对比，成本低）。
- **是否待裁定**：是（是否值得为低概率场景加 IO，见四-3）。

### C-19 `POST /certificates/issue` 批量模式将全部 issued 任务重置为 queued（全量重签）

- **位置**：`internal/handlers/certificates.go:461-514`；`internal/services/certificates.go:1036-1056`
- **代码证据**：

  handler 批量分支（`certificates.go:461-462`）：
  ```go
  rows, err := db.DB.Query("SELECT caddy_id, COALESCE(domain,'') FROM lb_rules WHERE enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND protocol='http' AND COALESCE(domain,'') != ''")
  ```
  UPSERT 的 WHERE 明确包含 issued（`certificates.go:1049`）：
  ```go
  WHERE cert_jobs.status IN ('waiting_ca','issued','failed','downloaded')
  ```
  前端无入口（`web/src` 无 `/certificates/issue` 调用），仅 API/MCP 暴露（`mcpserver/server.go:46`，apidocs.go:91 注明"请求体可省略以触发全部 ACME 规则"）。
- **分类**：不合理逻辑（危险默认）。
- **判定及依据**：**待裁定（疑有意设计）**。依据：文档与 MCP schema 均明示该语义，属对外契约；但一条无 body 的 POST 即触发**所有** ACME 规则整轮重签（含刚签发的），直接消耗 LE/ZeroSSL 配额并受 MinInterval 串行排队，风险与收益不对称。
- **影响**：中低（误触发成本高：全量配额+DNS 记录 churn；有 429 防护兜底）。
- **建议**：批量模式要求显式确认参数（如 `"all": true`），或仅对"无有效证书/临期"的规则入队。
- **是否待裁定**：是（见四-4）。

### 设计合理性正面评估（非发现，供裁定参考）

1. **状态机以日志 stage 直接落库为 status**（`certissuer.go:250-256` `jobLogger.Log` → `transitionJob(..., stage, ...)`）：`cleanup_dns/cleanup_warning` 身兼"签发中段"与"部署生命周期"（`jobstate.go:39-40`）双语义，成功路径末尾还会经历 `downloaded→cleanup_dns→downloaded→issued` 的往复（issuer.go:215 的 downloaded 日志先于 defer 的 cleanup_dns）。经核实这是刻意编排：`requeueNonTerminalCertJobs` 的 `materialFastPath`（`certificates.go:248-272`）正是利用该集合把带材料的中断任务转入快速重部署，且各转换 from-set 均覆盖（`certissuer.go:504,552`）。可读性差但有完整注释与测试契约，判为**有意设计**。
2. **三链对照一致性**（UI→存储→消费→渲染）抽查全部吻合：
   - 重签冷却：前端 `retryCooldownMinutes`（5/15/2/0/null）≡ 后端 `certJobRetryBlocked`（certjobs.go:347-365）≡ 存储 `updated_at`（transitionJob 每次刷新）。
   - 冷却时间列：`markJobWaitingCA` 写 UTC 规范串（caqueue.go:1196-1201）→ `JSONNullTime` RFC3339（models.go:315-320）→ 前端 `new Date` 解析无时区漂移。
   - 自动重签时间列：`expires_at - cert_renewal_days`（CertJobs.vue:285-291）≡ `CheckExpiration` 的 `datetime('now','+'||days||' days')` ≡ `ShouldRenewIssuedCert` 的 `AddDate(0,0,-renewalDays)`（handlers.go:81-84）。
   - 证书择优三处同源：UI `/rules/cert-info`（certinfo.go:17-23）、Caddy 渲染候选（caddy.go:981-990）、集群快照（cluster_snapshot.go:884-921）均收敛到 `SelectCertificate`，候选过滤口径（status!='disabled'、有材料、规则启用+acme_dns）一致。
   - 状态枚举三处一致：DB CHECK（db.go:329）、`allJobStatuses`（jobstate.go:24-28）、前端 union（certJobStatus.ts:1-27）均为 26 个且集合相等。
3. **DNS 凭证安全链**：存储明文（certificate_configs）→ 传输 TLS → 非 admin 掩码 + sentinel 回传闭环（`isMaskedDNSCredentials`，certificates.go:52-70）→ 签发时按规则 `acme_config_id` 取 `enabled=1` 配置。测试按钮的实弹验证（Present+CleanUp `_acme-challenge.lb-test.`，dnspod.go:89-116）写入后即清理。
4. **并发与故障防护**：同 jobID 双执行防护（IsJobActive/retiredQueues/zombieJobs）、同规则部署串行（DeployLock）、`ValueCleaner` 值级清理隔离并发签发（issuer.go:250-258 注释与测试 `TestIssuer_preCleanup_spares_concurrent_challenge_values`）、账户密钥 fail-closed（client.go:156-166）与 EAB 轮换清理（R71 F-A2）——均有对应测试。
5. **主从交接点**：从节点不签发（StartACME 仅主节点生命周期）、cert_jobs 全量替换与 rules 开关联动（cluster_apply.go:313-326 R64 A-N5）、DNS ownership 整文件同步（含回滚路径 `restoreSnapshotArtifacts`）、快照坏候选 fail-open 限频告警——链路完整。

## 四、待裁定项汇总

| 编号 | 事项 | 涉及发现 | 需要的裁定 |
|---|---|---|---|
| 四-1 | ZeroSSL EAB 凭证对全体登录用户明文可读 | C-01 | 是否与 DNS 凭证（R72 D4）对齐为"非 admin 掩码"；若维持全员可读则应同步修订掩码策略文档 |
| 四-2 | `global_config.dns_credentials` 遗留字段 | C-03 | 是否存在 v1 导入/外部消费依赖；无则建议从 GET /config 剔除并择机删列 |
| 四-3 | reconcile 是否比对磁盘证书内容 | C-18 | 6 小时对账加内容比对（每证书 2 次文件读+哈希）是否值得 |
| 四-4 | `POST /certificates/issue` 无 body 触发全量重签 | C-19 | 保留现契约（文档已明示）还是增加显式确认参数/按需筛选 |

（附：C-09/C-10/C-14/C-17 已按代码注释与测试证据判为有意设计，不计入待裁定。）
