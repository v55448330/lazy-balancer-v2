# 集群管理模块审计报告（2026-09-05）

## 一、概览

### 1.1 范围文件清单（本会话逐行读码核实）

| 文件 | 行数 | 说明 |
|---|---|---|
| internal/services/cluster_sync.go | 1547 | 从节点同步主循环：Pull/Report/注册轮询/TOFU pin/错误落库 |
| internal/services/cluster_snapshot.go | 975 | 主节点快照构建、缓存、节哈希、证书/ACME/安全表 dump |
| internal/handlers/cluster_sync.go | 123 | 快照下发/手动同步/forget-pins/WAF 文件包端点 |
| internal/middleware/cluster_version.go | 156 | 版本触发器安装 + 同步写识别 |
| internal/middleware/readonly.go | 78 | 从节点/非管理员写闸 |
| internal/models/cluster.go | 406 | 集群数据模型与 wire 契约 |
| docs/cluster-sync-assessment.zh-CN.md | 107 | 2026-08-11 历史评估（复核对象） |
| docker-compose.yml | 51 | 主从测试编排 |
| web/src/views/settings/ClusterSettings.vue（699）及 settings/cluster/ 下 5 个组件 | 1445 | 前端集群 UI |

交叉核实（超出清单但为验证链路所必读）：cluster_apply.go（applySnapshot/安全表回放）、cluster_sections.go（节哈希/开关/跳过）、cluster_report.go（Report）、cluster_status.go（Status/Nodes/ReportNode/BecomeSlave/UpdateSettings）、cluster.go（注册/审批/Promote/脱离通知）、cluster_control.go（服务控制票据）、waffiles_sync.go（WAF 文件引用/包/校验落盘）、cluster_auth.go、middleware.go 路由树、main.go 生命周期接线、db.go is_master 回填、auditpolicy.go 只读豁免表；行为契约参考 cluster_routes_test.go / slave_readonly_test.go / cluster_version_test.go。

### 1.2 方法

- 逐行读码 + 跨文件链路追踪（快照产生→版本号→推送→从端应用→状态上报→UI 渲染）。
- 逐路由核对从节点写边界（见 1.4）。
- 运行单包测试验证行为契约：`go test ./internal/middleware -run 'ReadOnlyGuard|ClusterVersionTriggers|IsSynchronizedWrite' -count=1` → ok；`go test ./internal/services -run 'TestSyncService|TestPull|TestWaf|TestSnapshot' -count=1` → ok。
- 前端以组件源码核对 UI 语义（grep web/src 全量确认 forget-pins 无调用方）。

### 1.3 结论摘要

**主链路（快照→版本→推送→应用）一致性保证完备且设计成熟**：schema v3 canonical 载荷 + 指纹（sha256）+ 每节点 HMAC 签名三重校验；304 增量由「版本 + 指纹」双门控制；应用侧逐节哈希跳过 + 漂移守卫（本地重建哈希 vs 已应用记录）+ 三通道自愈补偿（重载失败标记 / 三节漂移 / WAF 文件态）；主节点版本回退（备份恢复）采取跟随策略并告警。凭据（注册令牌/集群令牌/票据）生命周期管理严谨（一次性、限时报文、哈希落库）。

**从节点只读边界逐路由核对无漏保护**（矩阵见 1.4）：机器接口在认证中间件之前注册但各有凭证防线；admin 组主节点专属操作全部有 `requireMaster` 二道门；`/api/v1/cluster/*` 白名单较宽但无提权路径。

**未发现高严重度问题**。发现 12 项（中 2 / 低 10），集中在：①补偿重拉窗口内 apply 失败会永久丢失重载失败标记（C-1，中）；②PinMismatch 补救端点无 UI 入口且「重新注册」无法自救（C-2，中）；其余为 UI 语义/冗余/文案一致性/环境语义问题。

### 1.4 从节点只读边界核对矩阵（逐路由）

机器接口（`v1` 组，注册于 `apiKeyAuth` 之前，middleware.go:239-247）：

| 路由 | 从节点行为 | 证据 |
|---|---|---|
| POST /cluster/register | requireMaster → 403 | cluster_registration.go:55-57 |
| GET /cluster/register/:id/status | GET 放行；registrationAuth 验证注册密钥 | cluster_auth.go:32-50 |
| GET /cluster/sync/snapshot、/sync/waf-files | clusterTokenAuth 查本地 nodes 表（从节点为空）→ 401 | cluster_auth.go:15-30 |
| POST /cluster/registration/confirm | requireMaster → 403 | cluster_registration.go:95-97 |
| POST /cluster/nodes/report | clusterTokenAuth → 401（本地无节点行） | 同上 |
| POST /cluster/service-control | 票据 HMAC 验签 + `is_master` 拒绝主节点调用 + 节点/动作绑定 + 一次性消费 | cluster_control.go:108-157 |

admin 组（`adminOnly() + readOnlyGuard`，middleware.go:257-301）：register-tokens / approve / reject / login-ticket / access-url / service / delete 均经 `requireMaster`（cluster_registration.go:129、cluster_service.go:49、cluster_ticket.go:17、cluster_status.go:28）；mode / promote / sync/pull / forget-pins 为从节点合法操作（forget-pins 在 handler 内拒绝主节点调用，cluster_sync.go:91-97）；PUT /cluster/settings 的每条 UPDATE 带 `WHERE is_master=1`，从节点 0 行命中 → 403「从节点不能修改同步开关」（cluster_status.go:94-104）。

business 组：PATCH /users/me、MFA 自助、自助 API 密钥在从节点 403（不在 `isReadOnlyGuardWhitelisted` 白名单，readonly.go:62-67；契约测试 TestReadOnlyGuard_blocks_slave_profile_update）；`readOnlyWriteRoutes` 豁免的 POST（test/parse/preview/jobs/current/cert-info/import validate）抽查均无持久化写（PreviewConfigUpdate 为纯读计划，caddy.go:220-233）。非管理员由 adminOnly/自助白名单拦截（契约测试 TestReadOnlyGuard_blocks_non_admin_*）。

**结论：无漏保护路由。**

### 1.5 同步失败恢复通道盘点（正面核实）

| 故障 | 检测 | 恢复 | 证据 |
|---|---|---|---|
| 传输故障/主节点宕机 | Pull err → degraded + 指数退避 1s→30s | 周期重试；last_sync_error 组合保留标记 | cluster_sync.go:1275-1290、1348-1359 |
| 应用成功但 Caddy 重载失败 | apply_ok_reload_failed 标记 | 下周期 304 识别 → since_version=0 全量重拉强制重载；5 轮后降频每 10 轮 | cluster_apply.go:181-195、cluster_sync.go:653-677 |
| 本地三节数据漂移 | driftedSections 本地重建哈希 vs 记录 | 全量重拉强制重放该节 | cluster_sync.go:678-684、787-811 |
| WAF 文件未收敛 | wafFilesDrifted（含空引用基准跳过） | 全量重拉 → fetchWafFiles + 哈希核验落盘；5 轮降频 | cluster_sync.go:691-706、895-917 |
| 令牌撤销（401/403） | errSyncTokenRevoked | 终止（Halted），人工重新注册/提升 | cluster_sync.go:722-726、1308-1315 |
| schema 过新 | SnapshotSchemaTooNewError | 终止等升级；过旧/旧签名形态为非终止降级重试 | cluster_sync.go:1128-1183、1301-1306 |
| 主节点版本回退 | appliedVersion > snapshot.Version | 跟随 + 告警日志 | cluster_sync.go:1187-1189 |
| 重复应用 | pullMu 单飞；cert_jobs 唯一索引全量回放语义 | 幂等 | cluster_sync.go:593-594、cluster_apply.go:313-326 |

---

## 二、旧评估复核（docs/cluster-sync-assessment.zh-CN.md，2026-08-11）

文档头部已声明「历史评估稿，结论不适用于当前版本」。逐条核对现状：

| # | 旧评估条目 | 当时结论 | 现状 | 证据（当前代码） |
|---|---|---|---|---|
| 1 | §1.1 security_policies 快照缺 ip_acl_mode/ip_acl_list/ip_acl_enabled/crs_excluded_rules/block_page_id 五列 | 部分同步、列不全 | **已修复**：快照 SQL 含全部列，另含 geoip/waf_check_response/log_request_body/ip_*_refs；从节点 INSERT 29 列对齐 | cluster_snapshot.go:476（dump SQL）；cluster_apply.go:477-486 |
| 2 | §1.1 security_custom_rules / block_pages / crs_version 完全不同步 | 不同步 | **已修复**：三表 + ip2region_version + ip_lists 均入快照并全量回放 | cluster_snapshot.go:490-560；cluster_apply.go:439-513 |
| 3 | §1.2 版本触发器缺安全五表、isSynchronizedWrite 无 /security 前缀 | 安全改动从不传播 | **已修复**：七张安全表全在触发器清单；/api/v1/security 前缀已捕获 | cluster_version.go:49-55、150-154 |
| 4 | §1.3 applySecurityTables 空载荷早退，主节点清空不传播 | 删除缺口 | **已修复**：无条件 DELETE 全部七表后回放，注释明确「空载荷意味着主节点已清空」 | cluster_apply.go:439-455 |
| 5 | §1.4 事务内 generateCaddyConfigFromStore(tx) 读不到未提交数据 | 时序缺陷 | **已修复**：重载移到事务提交后（`s.caddy.ApplyConfigForce(GenerateCaddyConfig())`），且 R72 二十六次 W1-1 改为强制重载 | cluster_apply.go:174-181 |
| 6 | §1.5 coraza 仅校验路径、主从均未生效 | 执行面缺失 | 已接入生产链路（buildWafHandler 读 db.DB，重载在提交后执行）；文档建议的「生效验证（coraza 计数回读）」**未实施**（当时即为可选项） | cluster_apply.go:174-181 |
| 7 | §1.6 CRS 无分发、各节点独立下载漂移 | 各自为政 | **已修复（方案 A 变体）**：快照携带 WafFilesRef 哈希引用（不搭车内容），从节点按需拉 /cluster/sync/waf-files，哈希核验+原子解包落盘；CRS/IP2Region 调度器按角色门禁（启动时按 is_master、BecomeSlave/Promote 时 SetMasterRole 切换） | cluster_snapshot.go:165；waffiles_sync.go:35-60、444-492；main.go:152-172；cluster_status.go:32-41 |
| 8 | §1.7 从节点只读性正确 | 正确约束 | **仍成立**（本次逐路由复核无漏保护，见 1.4） | readonly.go:14-67 |
| 9 | §2.3 security_events 本地产生、汇聚展示 | 建议方案 | **未实施**：事件仍本地（事件摄入/保留清理与角色无关，main.go:162-163 注释明确） | main.go:162-163 |
| 10 | §3 风险点（快照载荷增大、CRS 独立通道） | 建议 | 已按建议实现：CRS 走独立按需端点（64MB 上限、2000 文件/256MB 解包上限、gzip 炸弹拦截） | waffiles_sync.go:283-288、497 |
| 11 | 文档头部注记「cluster_version.go:41-46 安全表已入同步范围」 | — | **成立**（行号漂移至 49-55，内容属实） | cluster_version.go:49-55 |

结论：旧评估的 P0/P1 全部落地且有多轮加固；P2 中 CRS 分发已落地（形态为引用+按需拉取），事件汇聚未做（当时即标注为后续迭代）。

---

## 三、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| C-1 | internal/services/cluster_sync.go:1084-1094（联动 :765-769、:1042-1058、:1066-1082） | 逻辑 bug | 中 | 缺陷 |
| C-2 | internal/handlers/cluster_sync.go:79-109（前端无调用方） | 不合理逻辑 | 中 | 设计漂移 |
| C-3 | internal/services/cluster_control.go:160-170 + handlers/cluster_sync.go:91-97 | 不合理逻辑 | 低 | 设计漂移 |
| C-4 | internal/services/cluster_apply.go:187 + cluster_sync.go:1099-1108 + web/.../ClusterStatusCard.vue:38-40、ClusterSlavePanel.vue:21-29 | UI 语义 | 低 | 缺陷 |
| C-5 | internal/services/cluster_sync.go:1510-1542 + web/.../ClusterSlavePanel.vue:12-20 | UI 语义 | 低 | 缺陷 |
| C-6 | internal/models/cluster.go:149/144 + cluster_report.go:50-73 + cluster_status.go:281-299 | 冗余代码 | 低 | 有意设计（遗留契约） |
| C-7 | internal/services/cluster_status.go:14-19（对照 readonly.go:31-37） | 不合理逻辑 | 低 | 设计漂移 |
| C-8 | cluster_sections.go:24-30 vs ClusterMasterPanel.vue:155-161 vs cluster_mode.go:140-143 | UI 语义 | 低 | 设计漂移 |
| C-9 | internal/handlers/cluster_sync.go:32-38 + cluster_sections.go:340-346 | 冗余代码 | 低 | 有意设计 |
| C-10 | internal/services/cluster_sync.go:196-198、:557 + waffiles_sync.go:497 | 不合理逻辑 | 低 | 有意设计 |
| C-11 | docker-compose.yml:29-46 | 不合理逻辑 | 低 | 有意设计（测试编排） |
| C-12 | internal/services/cluster_status.go:123-125 + cluster_sync.go:1308-1315 | UI 语义 | 低 | 有意设计 |

统计：逻辑 bug 1、不合理逻辑 4、冗余代码 2、UI 语义 4、已弃用代码 0（未发现标记弃用但仍存活的代码路径；C-6 为「wire 契约字段无消费方」，归冗余）。严重度：高 0、中 2、低 10。

---

## 四、逐条详述

### C-1 补偿重拉窗口内的「应用失败」会覆盖并永久丢失 apply_ok_reload_failed 标记

- **位置**：internal/services/cluster_sync.go:1084-1094（判定函数）、:1066-1082（覆盖写）、:765-769（ApplyFailed 分类）、:1042-1055（成功清空）、:653-677（标记触发的补偿重拉）。
- **代码证据**：
  ```go
  // cluster_sync.go:1091-1094
  func syncErrorPreservesReloadMarker(code models.SyncErrorCode) bool {
      return code == models.SyncErrorCodeTransportError || code == models.SyncErrorCodePinMismatch ||
          code == models.SyncErrorCodeSchemaTooOld || code == models.SyncErrorCodeSignatureInvalid
  }
  ```
  ```go
  // cluster_sync.go:765-769 —— applySnapshot 失败以 ApplyFailed 上抛
  if err := s.applySnapshot(ctx, snapshot); err != nil {
      s.pullApplyMu.Unlock()
      RecordAuditLog("system", "同步失败", "集群同步", ...)
      return SyncResult{}, newSyncFailure(models.SyncErrorCodeApplyFailed, err)
  }
  ```
  ```go
  // cluster_sync.go:1070-1081 —— 非自愈类直接覆盖 last_sync_error
  if syncErrorPreservesReloadMarker(code) {
      ...仅自愈类与标记组合...
  }
  s.persistSyncError(ctx, message, code)
  ```
- **失败链**：① 周期 N：applySnapshot 提交版本 V（`:128` 已置 `last_sync_error=''`、applied_version=V、指纹=V 的指纹），随后 `ApplyConfigForce` 失败 → 标记落库（cluster_apply.go:187-195）。② 周期 N+1：304 → 标记识别 → since_version=0 补偿重拉（cluster_sync.go:658-674）→ 若本次 `applySnapshot` 因瞬时故障失败（SQLITE_BUSY、磁盘写失败、约束冲突等任何回滚路径）→ Pull 返回 ApplyFailed → defer 走 `recordSyncError` → `syncErrorPreservesReloadMarker(ApplyFailed)=false` → **无条件覆盖标记**。③ 周期 N+2：主节点仍在版本 V → 304 且标记已不存在、三节无漂移、WAF 已收敛 → 返回 no-change 且 err=nil → defer `recordSyncError(nil,nil)` → `persistSyncError("","")` **连上一周期的 apply 错误也清空**。此后 DB=版本 V、Caddy=旧配置，静默分叉直到下次真实版本变更或人工重启。
- **分类**：逻辑 bug（状态机边界）。
- **判定**：缺陷。注释（:1087「校验/应用失败）允许覆盖」）声明的意图针对的是普通应用失败（此时 applied_version 未推进、主节点重发快照可自愈）；但补偿重拉场景下 applied_version 已是 V 且指纹已对齐，标记是**唯一**的残留触发器，被覆盖即通道永久丢失——意图与该场景的语义冲突，属未考虑到的边界。
- **影响**：中。触发需要「重载失败后紧接一次补偿重拉的应用瞬时失败」，概率低；且 `StartConfigWatchdog`（main.go:136-138）会三通道告知 DB/运行配置不一致，但该通道不自动恢复。
- **建议**：`syncErrorPreservesReloadMarker` 增加 `SyncErrorCodeApplyFailed`（或仅在 Pull 检测到「本轮请求源自标记补偿」时保留标记），使补偿窗口内的应用失败与传输失败同语义。
- **是否待裁定**：否。

### C-2 PinMismatch 补救端点 /cluster/forget-pins 无任何前端入口，且「重新注册」无法自救

- **位置**：internal/handlers/cluster_sync.go:79-109（端点）；web/src 全量 grep `forget-pins` 无匹配；cluster_sync.go:142-165（do() 预检）、:321-343（verifyOrStoreClusterPin 拒绝不匹配）。
- **代码证据**：
  ```go
  // handlers/cluster_sync.go:79-82
  // ForgetClusterPins 是从节点管理员的 PinMismatch 补救端点（M13②）：主节点更换
  // 管理面板证书后从节点同步持续指纹不匹配，运维确认新证书合法后清空全部 TOFU
  // 指纹钉（内存缓存+磁盘 pin 文件），下一同步 tick 按新证书重新钉扎。仅 admin
  // 路由组可达（readOnlyGuard 的 /cluster/* 白名单保证从节点可用），操作留审计。
  ```
  ```go
  // cluster_sync.go:337-341 —— pin 文件存在且不匹配即拒绝，TOFU 不覆盖
  stored, err := os.ReadFile(path)
  if err == nil {
      if strings.TrimSpace(string(stored)) != fingerprint {
          return errClusterPinMismatch
      }
  ```
- **链路分析**：主节点更换面板证书后，从节点 `Pull` 持续 `pin_mismatch`；`RegisterWithMaster` 复用同一 `s.do()`/TOFU transport，`verifyOrStoreClusterPin` 对既有 pin 文件不匹配即拒绝 → **「重新注册」同样失败**。从节点面板（ClusterSlavePanel）只提供 立即同步/重新注册/提升为主节点 三个动作，`ClusterStatusCard` 仅展示错误文案；实际唯一救援是直接调 API `POST /cluster/forget-pins`（或手工删 `<data>/cluster_ca_pins/`）——该端点已在 apidocs.go:112 对外文档化，但 UI 零入口。
- **分类**：不合理逻辑（可恢复状态缺少可达的恢复路径）。
- **判定**：设计漂移。后端能力（M13②）先行落地，前端未跟进；非原始意图（注释明确设想了「运维确认新证书合法后调用」，预设了操作入口）。
- **影响**：中。pin_mismatch 属非终止可重试错误，但永不自愈；对不熟悉 API 的管理员，从节点看似只能「提升为主节点」（破坏性）。
- **建议**：从节点面板在 `sync_error_code === 'pin_mismatch'` 时渲染「清除证书指纹并重新钉扎」按钮（带确认框），调用既有端点。
- **是否待裁定**：否。

### C-3 主节点侧「从节点 pin」无任何补救通道（服务控制链路）

- **位置**：internal/services/cluster_control.go:160-170；internal/handlers/cluster_sync.go:91-97。
- **代码证据**：
  ```go
  // cluster_control.go:163-167 —— 主→从服务控制复用 TOFU transport（钉从节点证书）
  func NewClusterControlHTTPClient(dataDir string, database *sql.DB) *http.Client {
      client := &http.Client{
          Timeout:   60 * time.Second,
          Transport: newClusterTOFUTransport(dataDir, database, nil),
      }
  ```
  ```go
  // handlers/cluster_sync.go:92-96 —— forget-pins 在主节点被显式拒绝
  if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err == nil && isMaster {
      ...
      c.JSON(http.StatusBadRequest, ..., "主节点无需清除指纹（本端点仅从节点使用）")
  ```
- **分析**：从节点重建/更换管理面板证书后，主节点对其服务控制将永久 PinMismatch；forget-pins 端点按「复审裁定 4」在主节点拒绝（避免误清全部从节点钉），结果是主节点侧单节点粒度的重钉只能手工删 pin 文件（`cluster_ca_pins/` 以 host:port 哈希命名，可精确定位）。设计上「整体重置」确实不该开，但「单节点重钉」无任何产品化通道。另注意 `:92` 的拒绝依赖 IsMaster 读成功，DB 读失败时 fail-open 放行（罕见、后果仅为误清可重钉的从节点钉，可接受）。
- **分类**：不合理逻辑。**判定**：设计漂移（只堵未疏）。**影响**：低。**建议**：服务控制失败返回 PinMismatch 时，主节点 UI 提示按节点清除对应 pin（新端点按 nodeID 定位 pin 路径）。**是否待裁定**：是（是否值得为低频场景加端点）。

### C-4 apply_ok_reload_failed 内部标记原文直接渲染给用户

- **位置**：internal/services/cluster_apply.go:187、cluster_sync.go:1099-1108（消息构造）；web/src/views/settings/cluster/ClusterStatusCard.vue:38-40、ClusterSlavePanel.vue:21-29（原样渲染 `status.last_sync_error`）。
- **代码证据**：
  ```go
  // cluster_sync.go:1107
  return syncReloadFailureMarkerPrefix + ": " + reason + " | " + syncFailureCountPrefix + strconv.Itoa(count) + syncFailureCountSuffix + ": " + newMsg
  // 产出形如：apply_ok_reload_failed: load config failed | 同步失败（已连续 3 次）: 同步拉取失败: ...
  ```
  ```html
  <!-- ClusterSlavePanel.vue:21-24 -->
  <el-alert v-else-if="status.last_sync_error" title="最近同步失败" :description="status.last_sync_error" ... />
  ```
- **分析**：标记前缀（`apply_ok_reload_failed`）、` | ` 分段符与计数段是机内协议串，与中文文案拼在一起直接呈现；语义上「配置已入库但运行配置未生效，将自动重试」这一关键信息用户需要反推。信息可达但表达为内部格式。
- **分类**：UI 语义（存储→渲染链）。**判定**：缺陷（有界消息设计优先解决了存储膨胀，未做展示层翻译；`sync_error_code=apply_failed` 已随状态下发但未被用于渲染分支）。**影响**：低。**建议**：前端按 `sync_error_code==='apply_failed'` 且消息含标记前缀时翻译为「配置已同步但 Caddy 重载失败，系统将自动重试（第 N 次）」。**是否待裁定**：否。

### C-5 注册终止（confirm 5 连败/轮询被拒）后从节点面板仍显示「等待主节点审批」

- **位置**：internal/services/cluster_sync.go:1510-1542（终止清理）；web/src/views/settings/cluster/ClusterSlavePanel.vue:12-20。
- **代码证据**：
  ```go
  // cluster_sync.go:1525-1538 —— 达到上限后清注册态（含 cluster_token），退出注册循环
  if failures >= registrationConfirmMaxFailures {
      message := fmt.Sprintf("集群注册确认连续失败 %d 次（最后一次：%s）。已停止自动重试，请在“集群管理”页面重新注册，或使用“提升为主节点”脱离集群", failures, reason)
      ...
      if _, derr := s.db.ExecContext(ctx, "UPDATE global_config SET registration_secret='', registration_id=NULL, registration_confirm_failures=0 WHERE id=1"); ...
      if clusterToken != "" {
          _, _ = s.db.ExecContext(ctx, "UPDATE global_config SET cluster_token='' WHERE id=1")
      }
  ```
  ```html
  <!-- ClusterSlavePanel.vue:12-15 —— cluster_active=false 优先分支 -->
  <el-alert v-if="!status.cluster_active" title="等待主节点审批"
      description="主节点确认后将自动激活同步。您也可以重新注册或提升为主节点。" ... />
  <el-alert v-else-if="status.last_sync_error" title="最近同步失败" ... />
  ```
- **分析**：终止路径清空 cluster_token → `cluster_active=false` → 面板命中第一分支显示「等待主节点审批」；而 `registration_id` 已清 NULL，`pollRegistration`（:1373-1375）空转，「自动激活」永不发生。终止文案仅经由 ClusterStatusCard 的「同步错误」字段可见（该卡确实展示，信息部分可达）。R64 A-N6 注释设想了「last_sync_error 持续显示可行动文案」，但面板的 v-if 优先级使其被等待文案遮蔽。
- **分类**：UI 语义。**判定**：缺陷（面板分支条件未考虑「注册已终止」状态）。**影响**：低（有状态卡兜底 + 「重新注册」按钮仍正确）。**建议**：面板在 `!cluster_active && status.last_sync_error` 时优先渲染错误文案/终止态。**是否待裁定**：否。

### C-6 ClusterReport.ServiceStatus / ClusterHealth.UptimeSec 上报后无任何消费方

- **位置**：internal/models/cluster.go:149、:144；internal/services/cluster_report.go:50-73（计算并上报）；internal/services/cluster_status.go:281-299（ReportNode 忽略）。
- **代码证据**：
  ```go
  // models/cluster.go:148-149
  type ClusterReport struct {
      AppliedVersion int           `json:"applied_version" binding:"min=0"`
      ServiceStatus  string        `json:"service_status" binding:"required,oneof=ok degraded"`
  ```
  ```go
  // cluster_report.go:51-54 —— 每周期计算 degraded（含 lastSyncError!=""）
  serviceStatus := "ok"
  if caddyErr != nil || lastSyncError != "" {
      serviceStatus = "degraded"
  }
  ```
  ```go
  // cluster_status.go:282-290 —— ReportNode 只消费 Health/AppliedVersion/时间戳，ServiceStatus 丢弃
  health := report.Health
  ...
  s.db.ExecContext(ctx, `UPDATE nodes SET status='online',last_seen=?,reported_version=?,health_json=?,last_sync_at=?,last_sync_error=? ...`)
  ```
- **分析**：`service_status` 由从节点计算、经 binding 强校验、写入 apidocs 示例（apidocs.go:113），但主节点侧（ReportNode/Nodes/前端 ClusterHealth 类型）零消费；前端 `uptime_sec` 仅在 types/index.ts:169 声明，无渲染点。属「活着的死字段」：删除需动 wire 契约（旧主节点兼容），保留则有每周期无意义计算与误导性文档。
- **分类**：冗余代码。**判定**：有意设计（历史 wire 契约，binding 强校验说明曾打算消费），当前呈漂移态。**影响**：低。**建议**：保留字段（兼容）但补一行注释声明「主节点未消费」，或让节点列表 tooltip 使用它替代 caddy_ok 单一口径。**是否待裁定**：是。

### C-7 IsMaster 未做 is_master NULL 兜底，与写闸/触发器口径不一致

- **位置**：internal/services/cluster_status.go:14-19；对照 internal/middleware/readonly.go:31-37、cluster_version.go:66-69/100-103、internal/db/db.go:1151-1164。
- **代码证据**：
  ```go
  // cluster_status.go:16 —— 裸 SELECT，NULL 时 Scan 失败
  if err := s.db.QueryRowContext(ctx, "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
      return false, fmt.Errorf("读取节点模式: %w", err)
  }
  ```
  ```go
  // readonly.go:32-34 —— COALESCE 兜底「历史库 is_master 若为 NULL…」
  // COALESCE 兜底 schema 默认 TRUE：历史库 is_master 若为 NULL，裸 SELECT 会
  // Scan 失败导致每个写请求 500（登录路径 auth.go 已同法处理）。
  if err := database.QueryRowContext(..., "SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); ...
  ```
- **分析**：A5-N2 已在启动迁移回填 NULL（db.go:1161），稳态无 NULL；但 `requireMaster`/`Promote`/`UpdateSettings` 走 IsMaster 时 NULL → 500/报错（fail-closed），而 readOnlyGuard 对 NULL 判为主节点（fail-open）——同一脏数据在两处语义相反。Pull 首查（cluster_sync.go:625）同样裸 SELECT。纵深防御层面口径应统一。
- **分类**：不合理逻辑（一致性）。**判定**：设计漂移（回填修复后未收敛读取点口径）。**影响**：低（仅直改库可触发）。**建议**：IsMaster/Pull 首查补 COALESCE(is_master,1)。**是否待裁定**：否。

### C-8 同一同步开关/分区在三处文案不一致

- **位置**：internal/services/cluster_sections.go:24-30（节定义）；web/src/views/settings/cluster/ClusterMasterPanel.vue:155-161（开关标签）；internal/handlers/cluster_mode.go:140-143（审计文案）。
- **代码证据**：
  ```go
  // cluster_sections.go:28
  {Key: "waf_files", NewLabel: "CRS/IP2Region数据库"},
  ```
  ```ts
  // ClusterMasterPanel.vue:159
  { key: 'sync_waf_files', label: '规则库数据库', tip: 'CRS 规则文件与 IP2Region GeoIP 数据库（哈希一致时跳过传输）' },
  ```
  ```go
  // cluster_mode.go:142
  "sync_waf_files": "规则库数据库",
  ```
- **分析**：主节点设置卡/审计用「规则库数据库」，节点列表「分区同步状态」弹层（消费 `section.label`）用「CRS/IP2Region数据库」。同一开关在两处 UI 以两个名字出现，用户需自行等同。三链（UI→存储→消费→渲染）其余节均对齐（全局配置/系统数据/负载均衡(规则)/安全策略(及自定义规则) 措辞差异属可读性范围）。
- **分类**：UI 语义。**判定**：设计漂移（分区标签与开关标签各自演化）。**影响**：低（仅文案）。**建议**：统一以 syncSections.NewLabel 为单一事实源导出前端标签。**是否待裁定**：否。

### C-9 集群链路中绕过依赖注入直连 db.DB 全局

- **位置**：internal/handlers/cluster_sync.go:32-38；internal/services/cluster_sections.go:340-346。
- **代码证据**：
  ```go
  // handlers/cluster_sync.go:35 —— 审计查节点名直连全局 db.DB（同文件其余经 service）
  _ = db.DB.QueryRow("SELECT COALESCE(name,'') FROM nodes WHERE id=?", nodeID).Scan(&nodeName)
  ```
  ```go
  // cluster_sections.go:340-345 —— logSyncSwitchGuards 在 SyncService（持有 s.db）内用全局 db.DB
  var lastWarnVersion int
  if db.DB != nil {
      if err := db.DB.QueryRow("SELECT applied_version FROM cluster_applied_sections WHERE section='waf_files'").Scan(&lastWarnVersion); err != nil ...
  ```
- **分析**：功能等价（生产单库），但破坏可测性与口径一致性：handlers 侧其余操作经 `h.clusterService`，services 侧 `SyncService` 自带 `s.db`。`logSyncSwitchGuards` 在测试环境（db.DB 未设）静默跳过去重，可能重复审计。
- **分类**：冗余代码（重复数据源）。**判定**：有意设计（历史路径，快照下发审计属 handler 便利写法）。**影响**：低。**建议**：改经注入句柄。**是否待裁定**：否。

### C-10 集群 HTTP 客户端 30s 超时与 256MB/64MB 大包上限不匹配

- **位置**：internal/services/cluster_sync.go:196-198（Timeout 30s）、:557（maxSnapshotResponseBytes 256MB）；internal/services/waffiles_sync.go:497（64MB）。
- **代码证据**：
  ```go
  // cluster_sync.go:197
  s.client = &http.Client{Timeout: 30 * time.Second}
  ```
- **分析**：`http.Client.Timeout` 覆盖至响应体读完；256MB 快照需 ≈68Mbps、64MB WAF 包需 ≈17Mbps 才能在 30s 内完成。LAN 稳态远低于上限（快照 MB 级），但跨 WAN 主从 + 大证书库时会把「大包」误诊为 transport_error 进入退避循环。上限本意是防御异常膨胀主节点，与传输时限无耦合。
- **分类**：不合理逻辑（参数耦合）。**判定**：有意设计（30s 面向常规小包；上限防滥用），未考虑两者交集场景。**影响**：低。**建议**：对 snapshot/waf-files 两条链路放宽超时（如 120s）或按 Content-Length 自适应。**是否待裁定**：是（取决于是否支持 WAN 部署）。

### C-11 docker-compose 从节点 bridge 网络注册地址的环境依赖语义

- **位置**：docker-compose.yml:29-46。
- **代码证据**：
  ```yaml
  lazy-balancer-slave:
    ports:
      - "8001:8000"
    volumes:
      - ./data-slave:/app/data
      ...
    # 独立 WAF 目录：两节点的 CRS/IP2Region 每日更新会并发写共享目录，存在竞争
      - ./waf-slave:/app/waf
  ```
- **分析**：从节点注册时上报 `localOutboundIP()`+`cfg.Port`（cluster_mode.go:50）＝ bridge 内网 IP:8000。Linux host-network 主节点可直接路由 bridge IP（服务控制/票据登录可用）；macOS Docker Desktop 下 host 无法路由 172.x，主节点→从节点的服务控制与「登录从节点」跳转不可达（浏览器需用 8001 映射口）。文件自述「从节点测试实例」，独立 waf 目录防并发写的设计正确。这是环境语义依赖而非代码缺陷，但编排文件未提示该差异，也未演示 access_url 修正用法（PUT /cluster/nodes/:id/access-url 正是为此设计）。
- **分类**：不合理逻辑（文档/编排完备性）。**判定**：有意设计（测试编排）。**影响**：低。**建议**：compose 注释补充 macOS 下需为从节点设置 access_url=http://127.0.0.1:8001。**是否待裁定**：是。

### C-12 令牌撤销停摆（Halted）后 cluster_active 仍显示「已激活」

- **位置**：internal/services/cluster_status.go:123-125；cluster_sync.go:1308-1315。
- **代码证据**：
  ```go
  // cluster_status.go:124-125 —— 从节点激活判定只看 token 非空
  status.NodeMode = "slave"
  status.ClusterActive = clusterToken != ""
  ```
  ```go
  // cluster_sync.go:1308-1315 —— 令牌撤销置 Halted 并退出循环，token 未清
  terminal := errors.As(pullErr, &schemaTooNew)
  if terminal || errors.Is(pullErr, errSyncTokenRevoked) {
      s.state.Store(uint32(syncStateHalted))
  }
  if errors.Is(pullErr, errSyncTokenRevoked) { ... return }
  ```
- **分析**：撤销停摆后 token 仍在库 → 状态卡「集群状态：已激活」，与「同步已终止待人工介入」实情不符；错误文案（last_sync_error）正确可达。schema_too_new 停摆同理。`syncStateHalted` 未投射到任何对外状态字段。
- **分类**：UI 语义（存储→渲染）。**判定**：有意设计（cluster_active 语义=「已获令牌」而非「同步在运行」），呈漂移态：用户视角的「激活」隐含正在同步。**影响**：低。**建议**：Status 增加 `sync_state`（running/degraded/halted）或 UI 以「已停止」标签呈现 halted。**是否待裁定**：是（语义口径由维护者裁定）。

---

## 五、待裁定项汇总

| 编号 | 事项 | 需要裁定的问题 |
|---|---|---|
| C-3 | 主节点侧从节点 pin 无补救通道 | 是否为低频场景增加按节点的 pin 重置端点（或仅在 UI 提示手工路径） |
| C-6 | service_status/uptime_sec 无消费方 | 保留兼容并注释，还是让节点列表真正消费（替代/补充 caddy_ok 口径） |
| C-10 | 30s 客户端超时 vs 256MB/64MB 包上限 | 是否官方支持 WAN 主从部署；如是则放宽大包链路超时 |
| C-11 | compose bridge 从节点地址语义 | 是否在编排/文档中明确 macOS 差异与 access_url 修正示例 |
| C-12 | cluster_active 不反映 Halted | 「已激活」语义是否需要区分「同步运行中/已停摆」 |

另记录两处**核实为非问题**的怀疑点（供后续审计参考，不占用发现编号）：
1. `wafRepollDue`/`reloadRepull` 节流与标记保留语义经逐分支推演自洽（含降频期 304 返回、重拉轮 defer 重新上表面）；
2. 从节点 `/api/v1/cluster/*` 白名单宽度经逐路由核对无提权路径（所有主节点专属操作均有 requireMaster 或 `WHERE is_master=1` 二道门）。
