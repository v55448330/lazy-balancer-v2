# 任务引擎标准 v2.0（四类型）

> 2026-10-01 用户裁定重构。任务类型决定一切——调度方式、记录策略、日志行为、控制面。
> 零 flag、零补丁、零特判；任务体只写业务逻辑，引擎处理全部基础设施。

## 1. 四类型定义

| 维度 | 定时 Scheduled | 常驻 Daemon | 循环 Periodic | 触发 Oneshot |
|---|---|---|---|---|
| **调度方式** | `NextSlotFn() → time.Time` 引擎每 tick 重读，槽到点执行 | `Run(ctx)` 引擎启动时调用一次，阻塞直到 ctx 取消 | `IntervalFn() → Duration` 每间隔执行一次 | 仅 `Trigger()`（手动/代码） |
| **中间空窗** | **零活动**（零执行/零 task_runs/零日志） | Run 持续运行，引擎不干预 | 间隔等待 | 空闲 |
| **task_runs** | 每次排程执行 1 行 | 每生命周期 1 行（boot 落行即记 success——启动是既成事实，2026-10-01 用户裁定；异常退出补记 failed） | 每轮 1 行 | 每次触发 1 行 |
| **日志（tasks/{id}.log）** | [done]+业务行 | [start]+[done]+失败行+业务行 | 每轮 [done]+业务行 | [start]/[done]+业务行 |
| **调度开关** | ✅ 停止/恢复调度 | ✅ 启停自管理循环 | ✅ 停止/恢复调度 | ❌ 显示禁用开关（页面一致性） |
| **手动触发** | ✅ | ❌（启停即可） | ✅ | ✅（唯一执行方式） |
| **取消** | ✅ 执行中可取消 | 用停止代替 | 每轮自动完成 | 每次自动完成 |

### 1.1 引擎调度循环（每 1s tick）

```
Scheduled: loopEnabled && !running && EnabledFn()≠false && NextSlotFn() ≤ now → Run
           （每 tick 重读槽——µs 级 SELECT；EnabledFn=false 整分支跳过：零评估零落行）
Periodic : loopEnabled && !running && now-lastCheck ≥ IntervalFn() → Run
           （EnabledFn=false 同跳过且不推进节拍——恢复后下一 tick 到期即跑，F73-E 第 73 轮）
Daemon   : 不进 tick——StartLoop 启动 Run 一次（阻塞）；StopLoop 取消 ctx；
           EnabledFn 不可用（Daemon 调度面永不消费——Register 期响亮拒绝，
           常驻业务门归 Run 体首行）
Oneshot  : 不进 tick——仅 Trigger
```

单飞：引擎 CAS 强制（in-flight 拒绝重入，全部 Kind 统一）。

### 1.2 Descriptor 接口

```go
type Descriptor struct {
    ID, Family, Name, Description, Category string
    Kind Kind // Scheduled | Daemon | Periodic | Oneshot
    NextSlotFn func() time.Time      // Scheduled：返回下次执行时间（zero=无配置）
    IntervalFn func() time.Duration  // Periodic：固定间隔
    Run        func(RunContext) error // Daemon: 阻塞直到 ctx.Done()
    CancelHook func() bool; EnabledFn func() bool
    StatusFn func() string
    Cancelable bool
    RunsOn Role // 角色门唯一事实源（MasterOnly bool 双机制第 72 轮收敛删除——调度/手动触发守卫统一 roleAllows）
    RestartOnRoleFlip bool // Run 体按角色分流时置位（2026-10-03 裁定，cluster-sync 引入）
}
```

已删除：`SilentProbes`/`RecordFailuresOnly`/`SignalledWork`/`AsKind`/`Cadence`/`Singleton`——Kind 单独决定全部行为；`ToggleFn`/`ToggleName`（LNK71-3，2026-10-11）——v2.0 调度开关统一（StartLoop/StopLoop）后声明族零消费退役，TaskMeta/TaskInfo 的 `toggleable`/`toggle_name` 序列化字段一并删除；`ManualRun`（第 76 轮勘误）——手动触发能力由 Kind 派生（DescribeAll `CanTrigger`），声明字段无消费。

## 2. 任务清单（18 注册任务）

### 定时（5）——排程槽驱动，Run 纯业务

| 任务 | NextSlotFn 数据源 | Run 体 |
|---|---|---|
| threat | `security_threat_sources.next_update` 最早值（UTC） | `m.RunUpdate(trigger)` 直达 |
| crs | `security_crs_version.next_update` | `StartUpdate`+wait |
| ip2region | `security_ip2region_version.next_update` | `StartUpdate`+wait |
| crawlerbot-update | `security_crawler_sources.next_update` 最早值（UTC） | `RunCrawlerBotUpdate` 直达 |
| auto-backup | `nextAutoBackupSlot()`（last_run 感知——漏跑追补/已跑步进） | `runAutoBackupScheduled` |

到期检查全部移出 Run 体——引擎保证在排程槽调用，Run 只执行业务。

### 常驻（3）——Run 阻塞自管理循环

| 任务 | Run 体 | 实际工作 |
|---|---|---|
| security-events-ingestion | `runIngestionLoop(ctx)`（内部 2s ticker） | 尾读 coraza 审计日志 |
| cert-issuance | daemonLifecycleRun（真实 StartACME/StopACME 挂钩——B 完全标准化） | CAQueueManager+证书 worker（引擎 daemon 即生命周期所有者）——**RunsOn=MasterOnly** |
| cluster-sync | Run 体按角色分流：从节点=daemonLifecycleRun（真实 SyncService.Start/Stop 挂钩，Halted/Resume 内部状态机保留）；主节点=masterSyncServingLifecycleRun（服务面巡检：节点在线/版本滞后） | **RunsOn=RoleAny + RestartOnRoleFlip**（2026-10-03 裁定：两角色同启停语义，角色翻转换代重启使 Run 分支与角色同步切换；原「RunsOn=SlaveOnly」口径已随主节点巡检引入过期） |

系统启动即运行（默认 StartLoop）；关闭调度=启动也不运行；允许手动停止和启用。

**Daemon 角色门（2026-10-01 追加）**：StartLoop 仅在 roleAllows 时启动 Run；
SetRole（promote/demote）自动拉起/停止角色不符的 daemon（loopEnabled 保留——
再 promote 自动恢复）。显示用实际运行态（TaskMeta.Running）：Run 存活=运行中；
调度开但角色不符=空闲；调度关=空闲（方案 A，2026-10-12：状态列只承载执行语义，调度语义归开关列）。

**Daemon 启动计数（2026-10-01 用户裁定）**：启动即记 success 1 行（启动是既成
事实——成功列体现启动计数）；异常退出（Run 返回错误且非 ctx 取消）补记
failed 行（真实时长与错误）；取消/正常停止不增行。

### 循环（9）——固定间隔，每轮独立执行+记录

| 任务 | 间隔 |
|---|---|
| config-watchdog | 60s |
| cert-renewal-scan | 6h（入队时唤醒 cert-waiting-ca） |
| cert-reconcile | 6h |
| cert-manual-poll | 10min |
| cert-waiting-ca | 30s（**默认调度关闭**——见 §3） |
| log-cleanup | 24h |
| audit-retention | 24h |
| security-events-retention | 24h |
| autoban | 60s（调度唯一前提=业务启用：PUT 保存联动启停+启动按库实态对齐，Descriptor 无 EnabledFn；观察模式默认开） |


另：cert-job 动态行（`cert_jobs` 表逐单镜像）为签发工作项视图，不入引擎注册表。
**行存在即显示**（2026-10-01 用户裁定——无状态/时间过滤，曾按「issued 超 1 天
隐藏」过滤致主节点签发行消失；24h 计数仍按窗口）；仅排除从节点材料物化行
（message=「从主节点同步…」——非签发任务，从节点禁签发）。

### 触发（1）

| 任务 | 说明 |
|---|---|
| startup:config-load | 启动单次（main 记录）+手动重载 |

另：cert-job 动态行（`cert_jobs` 表逐单镜像）为签发工作项视图，不入引擎注册表。

## 3. cert-waiting-ca 特例（默认关闭 + 唤醒/自停）

```
默认：调度关闭（不在默认 StartLoop 清单）——引擎不 tick，页面状态列「空闲」+开关列「已停止」（方案 A，2026-10-12）
唤醒（U1-66-05 勘误：非单点——四处入队成功路径各自唤醒）：
      cert-renewal-scan Run 体入队后 certJobsActive → StartLoop
      CreateOrRequeueCertJobWithChange 成功路径（规则写路径 Create/Retry/Renew 收敛点）
      RetryCertJob 成功路径（handlers/certjobs.go）
      DeleteCertJob 删除失败恢复重入队成功路径（handlers/certjobs.go）
自停：Run 体发现 certJobsActive()==false → StopLoop（回到默认关闭态）
```

30s 循环为循环任务正常定义；调度关闭期间零执行零记录。

## 4. 控制面（API + 页面）

| 操作 | 端点 | 语义 |
|---|---|---|
| 手动触发 | `POST /system/tasks/{id}/trigger` | 定时/循环/触发类；单飞由引擎 CAS |
| 调度开关 | `POST /system/tasks/{id}/toggle` `{enabled}` | 统一路由 StartLoop/StopLoop（按 Kind 分语义）；触发类 400 |
| 重启 | `POST /system/tasks/{id}/control` `{action:"restart"}` | 仅常驻族 |
| 取消 | `POST /system/tasks/{id}/cancel` | 仅 Cancelable 声明族 |

页面（任务监控）：
- 类型标签四色：定时(蓝)/常驻(绿)/循环(青)/触发(橙)
- 筛选：全部/定时/常驻/循环/触发
- 调度列：非触发类=开关（绑定 loop_on）；触发类=禁用开关（一致性）；cert-job 动态行=「—」
- 常驻族停止需确认弹框；操作列常驻族有「重启」

### 4.1 业务开关与调度开关同源（2026-10-17 用户裁定）

四个规则库任务（threat/CRS/IP2Region/crawlerbot-update）的业务自动更新**就是调度任务本身**，因此业务开关与引擎调度开关必须双向同源：

- 业务页开启自动更新 → 写业务字段后立即 `StartLoop`；关闭 → 立即 `StopLoop`。
- 任务监控的业务驱动任务调度开关**只读**：只允许查看 `loop_on`，不得从引擎或任务监控反写业务配置；非业务驱动任务仍可由任务监控启停。
- 启动装配按业务实态对齐 `loop_on`；首槽武装必须覆盖全部四个源表，缺槽时开启业务即补槽。
- `EnabledFn` 仅作执行面纵深校验，不向任务视图暴露额外「业务开关」字段；任务监控与详情只展示 `loop_on` 调度开关。

## 5. 记录与日志口径

| 场景 | task_runs | 日志 |
|---|---|---|
| 定时槽间隙 | 0 行 | 0 行 |
| 定时执行 | 1 行（引擎预插 running→终态） | [done]+业务 |
| 常驻生命周期 | 启动即记 success；异常退出补 failed 行 | [start]；停止 [done stopped]；失败 [done failed] |
| 循环每轮 | 1 行 | [done]+业务 |
| 触发执行 | 1 行 | [start]/[done]+业务 |
| 手动触发 | 1 行（trigger=manual） | 同上 |
| 崩溃恢复 | 残留 running → interrupted | — |

task_runs 保留 90 天（audit-retention 每日清理）。

## 6. 业务侧 helper

- `TaskLogf(taskID, stage, format, ...)` — 业务摘要行（tee 到任务日志）
- `taskengine.TeeTaskLog` — 分阶段流水
- `RecordRunStart/RecordRunFinish` — legacy 直调路径（引擎外执行）

### 6.1 统一日志滚动与统计（2026-10-17 用户裁定）

所有任务日志只使用一种滚动标准：**写入前按真实文件大小滚动**。

- 统一入口为 `taskengine.RotateTaskLogBeforeWrite`：`size(path)+len(待写入行) > task_log_size_mb` 时先 `RotateTaskLogFile` 再追加。`taskLogAppend`、`TeeTaskLog` 与证书任务日志全部经过该入口，禁止另设每日巡检滚动或第二套滚动实现。
- 主流水 `tasks/{id}.log` 保 1 份，证书任务 `tasks/certjobs/*.log` 保 5 份；归档份数是保留策略差异，不是第二种滚动机制。
- `log-cleanup` 只负责保留期清理，不再负责尺寸滚动。
- 日志统计与弹框使用 `task:<id>`：每个任务对应自己的真实文件、活动大小、轮转副本和阈值；禁止用 `tasks/*.log` 目录聚合值代替当前任务。

### 6.2 新增任务注册门禁

新增/修改任务必须同时满足，缺一即视为未完成：

1. Descriptor 的 ID/Name/Kind/Run/角色门/调度函数齐全，禁止复用其他任务 ID、状态表、日志或生命周期。
2. 非 oneshot 任务进入默认 `StartLoop`（或写入带理由的显式豁免清单）；首槽/首间隔有真实可执行值。
3. 业务自动更新开关与调度开关双向同源（若任务有业务开关）。
4. 业务日志走 `TaskLogf`/`TeeTaskLog`，状态与 `task_runs` 时间同源；写入前滚动自然覆盖，禁止自行实现第二种滚动。
5. `/logs/stats` 返回 `task:<id>` 真实文件统计，任务监控弹框不得使用目录聚合值。
6. 注册级测试必须覆盖：默认调度、首槽/首间隔、业务/调度双向同源、日志与状态时间、逐任务真实文件统计。

## 7. 修订记录

- v2.0.3（2026-10-14，用户裁定「启用后按配置调度」）：autoban 调度模型收编——Descriptor 去除 EnabledFn（任务监控 enabled 列恒开，启停语义全在调度开关+事件页业务开关）；PUT /security/autoban 保存联动启停（enabled=true→StartLoop、false→StopLoop；第 74 轮补：禁用保存先收敛已到期条目与暂存重载再停调度——禁用后无循环 flush/到期清理点）；启动按库内业务开关实态对齐调度；手动开调度/手动触发但未启用由 Run 体首行业务门拦停（TaskLogf「手动调度，执行失败：未启用」+task_runs failed 行+StopLoop 重禁调度）；POST /security/autoban/run「立即执行」端点与前端按钮删除。

- v2.0.2（2026-10-14，F73-A）：新增 autoban 循环任务（60s/主节点/EnabledFn=autoban_enabled 业务开关联动）——WAF 事件固定窗口计数（摄取提交点喂入）→ 阈值判定 →「自动封禁名单」merge（清到期/保留手动/已在名单过滤/超限挤最早到期）→ 重载 60s 节流暂存合并；观察模式（dry_run 默认开）仅记建议；每轮 TaskLogf 摘要行入 tasks/autoban.log。

- v2.0.1（2026-10-14，F73-E）：EnabledFn 调度门补全——tick 的 Scheduled/Periodic 分支业务关即整支跳过（不落行不推进节拍，恢复后下一 tick 到期即跑；手动触发不受门拦）；术语统一「已暂停」→「已停止」（任务监控开关列/详情/tooltip、API 消息与本文档）。
- v2.0（2026-10-01）：四类型标准重构。Kind 枚举 4 值替代 Continuous/Queue/Info；删除 SilentProbes/RecordFailuresOnly/SignalledWork/Singleton/AsKind/Cadence；NextSlotFn 返回 time.Time；Daemon 生命周期（StartLoop 调 Run 一次+阻塞）；cert-waiting-ca 默认调度关闭+唤醒/自停；自动备份遗留 1min 调度器删除（追补语义移入 nextAutoBackupSlot 的 last_run 感知）；ingestion 改自管理循环。
