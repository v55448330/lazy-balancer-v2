# 安全防护子系统集群同步评估与方案

**日期：** 2026-08-11
**范围：** 安全防护（策略 / 自定义规则 / 拦截页面 / CRS 规则库 / 安全事件）在主从集群中的同步现状评估与解决方案建议
**结论先行：** 安全防护当前**不具备可靠的集群同步能力**——策略与绑定仅部分同步且列不完整，自定义规则 / 拦截页面 / CRS 版本完全不同步，安全表改动**从不触发**同步流程，从节点的 CRS 各自为政。本文给出分阶段修复方案。

---

## 一、现状评估（全部经代码与实例验证）

### 1.1 快照覆盖矩阵

| 表 | 快照载荷 | 从节点应用 | 问题 |
|---|---|---|---|
| `security_policies` | 部分 | 部分 | 快照 SQL 仅含 `id,name,description,mode,anomaly_threshold,ip_whitelist,ip_blacklist,rate_limit_*,crs_rule_groups,custom_rules,enabled,created_at,updated_at`（cluster_snapshot.go:240-242），**缺失** `ip_acl_mode`/`ip_acl_list`/`ip_acl_enabled`/`crs_excluded_rules`/`block_page_id`（schema 存在且 handler 使用，handlers/security.go:197-198,232-236）。从节点拿到的策略丢失了**策略级 IP 访问控制、CRS 排除规则、拦截页面绑定** |
| `security_policy_bindings` | 是 | 是 | 仅两列，完整同步（cluster_apply.go:266-274） |
| `security_custom_rules` | 否 | 否 | 独立 CRUD 表，从未离开主节点（注意与策略内 `custom_rules` JSON 列是两个概念，后者随策略同步） |
| `security_block_pages` | 否 | 否 | 即使同步了 `block_page_id`，从节点也找不到对应页面（且该列本身也未同步） |
| `security_crs_version` | 否 | 否 | CRS 版本/自动更新开关为各节点本地状态 |
| `security_events` | 否 | 否 | 运行时数据，本地产生，本不应同步（见 §3.4 可见性讨论） |

### 1.2 版本触发器缺失（主节点侧，最严重）

`cluster_version` 触发器仅安装在 `lb_rules, upstreams, path_rules, users, api_keys, ca_providers, certificate_configs, cert_jobs, global_config`（middleware/cluster_version.go:29-41, 82-89）；`isSynchronizedWrite` 前缀（:121）不含 `/api/v1/security/*`。

**后果：** 任何安全防护改动（建/改/删策略、自定义规则、拦截页面）都**不会**增加 cluster_version，从节点的轮询永远看不到新版本——安全改动**从不传播**，而非延迟传播。

### 1.3 删除缺口（从节点侧）

`applySecurityTables` 在载荷为空时提前返回（cluster_apply.go:241-243）：主节点**删光**全部策略后，从节点的策略与绑定**永不清除**，陈旧策略长期残留。

### 1.4 应用时序问题（从节点侧）

从节点在事务内调用 `generateCaddyConfigFromStore(tx)` 生成本地 Caddy 配置（cluster_apply.go:74），但安全策略查询（`GetSecurityPolicyForRule`）与拦截页面查询（`BuildCorazaDirectives` 内）走的是全局 `db.DB` 句柄（services/security.go:13-32, 49）——SQLite WAL 下另一连接**看不到未提交事务**，即配置按**同步前**的安全状态生成，提交后也不再重新应用（成功路径无二次 apply）。

### 1.5 WAF 执行面（本轮已修复，但集群侧有窗口期）

本轮之前 coraza 处理器仅存在于校验路径，生产配置链路完全没有——WAF 在主从节点上均未生效（已在运行实例验证 config 中 coraza 计数为 0）。本轮 I1 将其接入生产链路后：主节点下次配置应用即生效；**从节点需升级到新二进制**才能生成本地 WAF 配置——集群混版期间存在执行面不一致窗口。

### 1.6 CRS 规则库分发

无分发机制。`/app/waf/crs` 原本镜像烘焙，本轮起改为 bind mount 持久化。CRS 更新调度器在**所有节点**运行（main.go:132-133 未按 is_master 门禁），`auto_update` 默认开启——**各从节点独立从上游下载 CRS**，节点间版本必然漂移；且从节点出网下载在很多部署中并不期望。

### 1.7 从节点只读性

安全写端点位于 admin 组，从节点被 readOnlyGuard 拦截（403），无法在从节点本地创建策略——这与"主节点为唯一配置源"一致，是正确约束。

---

## 二、方案总览

按依赖与风险分三个阶段。P0 是"让安全改动能到达从节点"，P1 是"到达的内容完整且正确生效"，P2 是"CRS 与事件的集群一致性"。

### 2.1 P0 — 打通同步管道

| 项 | 改动 | 位置 |
|---|---|---|
| 版本触发器 | 安全五表（`security_policies`, `security_policy_bindings`, `security_custom_rules`, `security_block_pages`, `security_crs_version`）加入触发器安装清单 | middleware/cluster_version.go:29-41 |
| 同步写识别 | `isSynchronizedWrite` 前缀加入 `/api/v1/security` | middleware/cluster_version.go:121 |
| 快照表扩展 | 新增 `security_custom_rules`、`security_block_pages`、`security_crs_version` 三个快照/应用函数；`security_policies` 快照 SQL 补齐缺失五列 | cluster_snapshot.go, cluster_apply.go, models/cluster.go |
| 删除语义 | `applySecurityTables` 移除空载荷早退，空数组同样执行整表替换 | cluster_apply.go:241-243 |

### 2.2 P1 — 生效正确性

| 项 | 改动 | 说明 |
|---|---|---|
| 应用时序 | 快照事务**提交后**再生成并应用 Caddy 配置（`generateCaddyConfigFromStore` 移到 commit 之后，安全查询自然读到新数据）；或将安全查询参数化传入 store/tx | 推荐前者，改动小、语义清晰 |
| 生效验证 | 从节点 apply 完成后回读自身 Caddy 配置校验 coraza 计数（策略存在时应 >0），失败记日志并告警 | 可选但建议 |
| 混版窗口 | 发布说明中注明：集群需滚动升级到含 I1 的版本，否则从节点无 WAF 执行面 | 运维事项 |

### 2.3 P2 — CRS 与事件一致性

**CRS 分发（推荐方案 A）：主节点统一下载，分发到从节点。**

- 从节点 CRS 调度器按 `is_master` 门禁关闭（crsscheduler.go tick 中已有 master 检查，将 `StartScheduler` 的启动也按角色门禁，角色切换时启停）
- 分发通道复用现有快照机制：主节点更新成功后，将 `/app/waf/crs`（rules + crs-setup.conf + VERSION）打包（tar.gz，复用下载解包代码）纳入集群快照或专用端点；从节点应用后本地重载
- 备选方案 B（更轻）：从节点调度器保留但改为"跟随主节点版本"——快照携带主节点 `security_crs_version.version`，从节点发现落后时自行从上游下载对应版本。**不推荐**：仍要求从节点出网，且受 GitHub 可用性影响
- `security_crs_version` 表随 P0 同步后，主节点版本号/更新状态在从节点可见，卡片显示与主节点一致

**安全事件可见性（推荐方案）：事件本地产生、主节点按需汇聚。**

- `security_events` 保持本地写入（运行时数据，同步成本高且意义小）
- 事件日志页增加节点筛选：主节点通过已有的集群状态通道从各节点拉取分页事件合并展示；或各从节点定期（分钟级）批量上报到主节点事件表（带来源节点列）
- 轻量起步：先支持主节点本地事件 + 从节点数量汇总，明细拉取作为后续迭代

### 2.4 不在本方案范围

- `security_events` 摄入（/app/waf/audit/audit.log → security_events）——主从都缺摄入服务，属独立功能项，建议单独立项
- 审计库（audit_log）的集群同步——当前各节点独立审计，与安全策略同步无耦合

---

## 三、实施清单（供后续排期）

| 阶段 | 内容 | 预估改动面 |
|---|---|---|
| P0 | 触发器 + 同步写前缀 + 三张表快照/应用 + 策略列补齐 + 删除语义 | middleware/cluster_version.go, cluster_snapshot.go, cluster_apply.go, models/cluster.go + 测试 |
| P1 | apply 提交后生成配置 + 从节点生效校验 + 发布说明 | cluster_apply.go (+services/caddy.go 可选参数化) |
| P2 | CRS 调度器角色门禁 + 快照打包分发 + 事件汇聚查询 | crsscheduler.go, main.go, cluster_snapshot/apply (+新端点), SecurityEvents.vue |

**风险与注意：**
1. 快照载荷增大（CRS 打包约 3MB）——建议 CRS 分发独立于高频快照，走"版本变化才传输"的增量通道
2. 从节点应用 CRS 后必须本地重载（与主节点同一 reloader 路径）
3. 策略列补齐涉及已同步集群的兼容：老从节点收到新列应忽略（JSON 宽容反序列化天然满足）
4. 删除语义变更（空载荷也替换）需同步调整既有测试
