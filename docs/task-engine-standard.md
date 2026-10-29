# 任务引擎标准 v2.0（四类型）

> 2026-10-01 用户裁定重构。任务类型决定一切——调度方式、记录策略、日志行为、控制面。
> 零 flag、零补丁、零特判；任务体只写业务逻辑，引擎处理全部基础设施。
>
> 口径说明：本文是工程标准文档（不在 README 用户文档索引内），用于工程实现与裁定溯源；面向用户/官网的文案不得引用内部流程口径。

## 0. 职责与边界（v2.1，用户裁定 2026-10-30）

**原则**：统一任务引擎提供通用全生命周期能力（调度、单飞、角色、启停、取消、运行历史、日志滚动、状态镜像、导入屏障）；任务与业务逻辑解耦；**禁止引擎外的调度与生命周期入口**。

### 0.1 归口矩阵

| 关注点 | 引擎 | 任务体（业务） |
|---|---|---|
| 何时执行（节拍/槽/间隔） | ✅ `RunTicker` / `IntervalFn` / `NextSlotFn` | ❌ 不得自建 ticker |
| 启停/取消/角色翻转/导入屏障/单飞 | ✅ StartLoop/StopLoop/Cancel/SetRole | ❌ 不得自起常驻 goroutine |
| 运行历史、日志滚动、`[start]/[done]` | ✅ | 只经 `TaskLogf`/`TeeTaskLog` 写业务行 |
| 状态镜像（running/pending/next） | ✅ `StatusFn` | 提供纯只读投影 |
| 业务判定、准入闸门、外部 API、业务写入 | ❌ | ✅ |

### 0.2 唯一许可的四种执行形态

| 形态 | 适用 | 禁止 |
|---|---|---|
| `Daemon` + **`taskengine.RunTicker(ctx, interval, wake, fn)`** | 高频/事件驱动常驻（<1min 节拍） | 业务体内手写 `for/select/ticker` |
| `Daemon` + 自管理阻塞循环（仅当循环含协议状态机，如从节点拉取） | 长生命周期连接/同步 | 为绕开 `RunTicker` 而自建 |
| `Periodic`（`IntervalFn`） | 节拍 ≥10s 的轮询 | 用高频 Periodic 制造 task_runs 噪音 |
| `Scheduled` / `Oneshot` | 排程/手动 | 借 BootSync 绕过调度 |

**第五种形态不存在**：任何"引擎外常驻循环/子资源自建 goroutine/独立 ticker 泵"均违规（含按业务实体拆分出的 per-provider、per-tenant、per-rule 循环）。

### 0.3 唤醒协议

- 业务事件只能表达三种意图：**唤醒**（`WakeTask(id)`，等价 `RearmLoop(id, hasWork)`）、**停止**（`StopLoop(id)`）、**复位节拍**（`RearmLoop(id,false)`）。
- 业务**不得**在事件里直接执行任务体，也不得用 `StartLoop` 越过用户停止态。
- 唤醒信号是"提示"：错过唤醒只会延迟下一次节拍，不得导致漏执行（引擎按库内时间/到期判定兜底）。

### 0.4 子资源（队列/租户/提供商/规则）归属

- 子资源只允许**状态与准入策略**（pending/在途/并发上限/最小间隔）留在业务域。
- 子资源的**泵**必须由宿主 daemon 的 `RunTicker` 的 `fn` 遍历驱动（如 `Manager.DispatchOnce`），不得 `go queue.loop()`。

### 0.5 违规反例（禁止复现，已在本仓发生过）

| 反例 | 位置 | 违规点 |
|---|---|---|
| 每个 CA 提供商一个 `go q.loop()` | `internal/services/caqueue.go:1163-1166` | 子资源自建 goroutine；不在引擎注册表；不可枚举/停止/观测 |
| manager 内自建 goroutine 由 Run 体等待 | `crsupdate.go:348-361`、`ip2regionupdate.go:173-176` | 擦边：执行实现外溢；须登记豁免理由（见 §6.4） |
| legacy `RecordRunStart/Finish` 直写 `task_runs` | `handlers/autobackup.go:354-366` | 第二写点；仅允许装配/测试兜底，生产必须走引擎 RunID |

### 0.6 机器守卫（缺一即视为未完成）

1. 注册表断言：每个 `Daemon` 的 `Run` 必须调用 `RunTicker` 或命中 §6.4 豁免登记（否则单测失败）。
2. 静态扫描：`internal/services`、`internal/handlers`、`caddygeoip` 等业务目录禁止新增 `go func()` 常驻循环与 `time.NewTicker`（一次性/有界工具需 `//loop-exempt: <理由>` 且入 §6.4）。
3. 子资源循环守卫：禁止 `go <queue|worker>.loop()` 形态。
4. 唤醒守卫：业务侧只允许 `WakeTask/RearmLoop/StopLoop`；`StartLoop` 仅限控制面与 §5 裁定的角色路径。

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
Scheduled: loopEnabled && !running && EnabledFn()≠false && 槽已到期 && 槽未消费 → Run
           （槽缓存 + 降频求值；EnabledFn=false 整分支跳过：零评估零落行）
Periodic : loopEnabled && !running && now-lastCheck ≥ IntervalFn() → Run
           （EnabledFn=false 同跳过且不推进节拍——恢复后下一 tick 到期即跑）
Daemon   : 不进 tick——StartLoop 启动 Run 一次（阻塞）；StopLoop 取消 ctx；
           EnabledFn 不可用（Daemon 调度面永不消费——Register 期响亮拒绝，
           常驻业务门归 Run 体首行）
Oneshot  : 不进 tick——仅 Trigger
```

Scheduled 槽语义（槽缓存 + 同一槽只执行一次）：

- **降频求值**：槽由 `NextSlotFn` 求值后缓存；仅「到期前导窗内（`schedSlotEvalLead`=30s）」
  与「重评地板到点（`schedSlotEvalFloor`=1min）」重读，其余 tick 零闭包求值零 DB 读。
  槽为零（未武装，或全局开关开但所有单源关）同样受地板约束——首槽武装的发现延迟
  上界=地板周期。
- **同一槽只执行一次**：成功落定后重读槽仍未到期推进（仍过期/未变）即写入
  `schedDoneSlot` 消费本槽，tick 要求 `slot > schedDoneSlot`；业务推进/重排为新槽后
  自然恢复。失败轮不消费（走 1s→5s→30s 退避重投，仅「已到期槽未推进+failed」形态）。
- **用户取消**：仅**自动轮**的**已到期**槽被消费（取消=显式放弃本槽）。手动触发轮不改
  预约（未来槽是下一次预约，与手动轮无归属关系），取消手动轮也不得消费槽——否则未来
  槽被水位永久压住，自动更新静默停摆。`CancelHook` 返回 false（取消未生效）不消费；调用前复核运行代际，执行期间拒绝新代占位，返回后再次复核，旧取消请求不得作用于新一轮。
- **成功轮的槽推进**（业务写侧门，`slotSuccessGateSQL` 单源）：`auto` 轮推进
  **空槽或过期槽**，`manual` 轮**只推进已过期槽**。引擎成功轮（含手动轮）会消费过期槽，
  业务侧不推进则水位与业务槽单边分叉（tick 的「槽 > 已消费水位」门永不成立 → 该族自动
  更新永久静默停摆，人工反复「立即更新」只会反复加固）。空槽不在 manual 范围：零值槽
  不会进入引擎消费分支（无停摆面），且预约只由排程保存/启用/启动武装路径建立。失败轮与
  取消轮仍只走 auto 门（手动轮失败时引擎按退避重投同一槽，业务抢先推进会把该自动槽吃掉）。
- **槽域 = 运行域**：`NextSlotFn` 取「启用源最早槽」时，源集合必须与运行体的处理集合
  一致（威胁族=内置注册表源名，爬虫族=全部启用行）。槽域宽于运行域时，运行域外的启用行
  槽没有任何推进写点，一旦过期「最早槽」恒钉过去 → 该族自动更新永久停摆。
- **显式复位**：`StartLoop` 关→开与业务侧重排槽（`RearmSecurityLibrarySlots`）经
  `ResetScheduleProgress` 清空槽缓存/水位/退避——否则旧水位会压住新预约。
- **导入排空**（`CancelInFlightRuns`）与 demote 取消不消费槽：恢复后到期轮补跑。

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
    BootSync bool // Oneshot：引擎初始化尾部同步执行一次（trigger=startup）
    StatusFn func() string
    Cancelable bool
    RunsOn Role // 角色门唯一事实源（MasterOnly bool 双机制历史收敛删除——调度/手动触发守卫统一 roleAllows）
    RestartOnRoleFlip bool // Run 体按角色分流时置位（2026-10-03 裁定，cluster-sync 引入）
}
```

`BootSync` 两条注册约束（注册期强制，违反即注册失败）：

1. 仅 `Kind=Oneshot` 允许置位——定时/循环/常驻的启动行为由调度语义承担，
   不得借 BootSync 绕过。
2. 必须显式声明 `RunsOn=RoleAny`（含空值拒绝）——启动执行面无角色语义，
   漏声明不得回落到旧任务兼容默认值。

`Daemon` 不得声明 `Cancelable`（注册期拒绝）：`Cancel` 只按 `Cancelable` 路由，被取消的
常驻任务走「非异常退出」分支——`loop_on` 保持 true 而 `running=false`，监控判 idle，常驻
采集/签发/同步永久停摆且无任何异常信号。常驻族启停一律 `StartLoop`/`StopLoop`。同理
`EnabledFn` 仅 Scheduled/Periodic、`RestartOnRoleFlip` 仅 Daemon 可声明（越界即注册失败）。

已删除：`SilentProbes`/`RecordFailuresOnly`/`SignalledWork`/`AsKind`/`Cadence`/`Singleton`——Kind 单独决定全部行为；`ToggleFn`/`ToggleName`（2026-10-11）——v2.0 调度开关统一（StartLoop/StopLoop）后声明族零消费退役，TaskMeta/TaskInfo 的 `toggleable`/`toggle_name` 序列化字段一并删除；`ManualRun`（勘误）——手动触发能力由 Kind 派生（DescribeAll `CanTrigger`），声明字段无消费；`TaskMeta.Enabled`（任务监控只认 `loop_on`，`Lookup/DescribeAll` 不再求值 `EnabledFn`）——`Descriptor.EnabledFn` 仍保留为 Scheduled/Periodic 调度门。

## 2. 任务清单（19 注册任务；实时全集以 `DescribeAll` 为准）

### 定时（5）——排程槽驱动，Run 纯业务

| 任务 | NextSlotFn 数据源 | Run 体 |
|---|---|---|
| threat | `security_threat_sources.next_update` 最早值（UTC） | `m.RunUpdate(trigger)` 直达 |
| crs | `security_crs_version.next_update` | `StartUpdate`+wait |
| ip2region | `security_ip2region_version.next_update` | `StartUpdate`+wait |
| crawlerbot-update | `security_crawler_sources.next_update` 最早值（UTC） | `CrawlerUpdateManager.RunUpdate` 直达 |
| auto-backup | `nextAutoBackupSlot()`（last_run 感知——漏跑追补/已跑步进） | `runAutoBackupScheduled` |

到期检查全部移出 Run 体——引擎保证在排程槽调用，Run 只执行业务。

**固有边界（裁定：文档化，不修）**：定时族 DB 全不可读时，NextSlotFn
fail-closed 返回零值槽 → 永不到期 → 零执行、零落行——任务历史不会出现
failed 行（没有执行就没有 task_runs 记录）。该形态的可观测性由应用日志
承担（排程读取失败按状态翻转留 WARN，恢复留 INFO），任务监控的「下次
执行」列显示「—」。引擎层对「槽未推进+本轮 failed」另有退避兜底
（1s→5s→30s 封顶，连续失败节流 WARN）——但那要求 Run 至少执行过一次；
纯排程读取失败（连首轮都无法投递）不在退避覆盖面内。

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

**Daemon 异常退出自愈（2026-10-18）**：异常退出且调度仍开
（`loopEnabled && 角色允许 && 引擎未停止`）时按有界退避自动重拉——默认
1s/5s/30s 三次（`taskengine.Options.DaemonRestartDelays` 可覆盖），每次重拉在
`tasks/{id}.log` 留 `[restart]` 行；次数用尽后置 `loop_on=false` 并留 `[done] … 已用尽`
行；可直接 `StartLoop` 恢复调度并重置预算，无需重启进程。Run 存活 ≥1 分钟后再崩视为新故障（预算归零）；用户显式
关→开（StartLoop/control restart）同样重置预算。退避窗口内 `TaskMeta.Running=false`
且状态列呈现 `failed`（修复前恒 `idle`「空闲」，采集/签发静默停摆无信号）；
显式停止调度后回 `idle`。

### 循环（10）——固定间隔，每轮独立执行+记录

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
| metrics-orphan-cleanup | 24h（已删除规则的残留历史指标收敛清理，单轮限量分批） |
| autoban | 60s（调度唯一前提=业务启用：PUT 保存联动启停+启动按库实态对齐，Descriptor 无 EnabledFn；观察模式默认开） |


另：cert-job 动态行（`cert_jobs` 表逐单镜像）为签发工作项视图，不入引擎注册表。
**行存在即显示**（2026-10-01 用户裁定——无状态/时间过滤，曾按「issued 超 1 天
隐藏」过滤致主节点签发行消失；24h 计数仍按窗口）；仅排除从节点材料物化行
（message=「从主节点同步…」——非签发任务，从节点禁签发）。

**任务监控=通用任务视图（2026-10-22 用户裁定）**：任务列表只呈现通用字段
（名称/分类/类型/状态/调度/执行时间/计数/操作），状态列词表=引擎执行语义
三态——空闲 / 运行中 / 失败。cert-job 动态行映射：终态成功
（issued/downloaded）与退役行（disabled）=空闲；失败=失败；其余（含
queued/pending/waiting_ca 限流停车）=运行中。业务生命周期态
（`cert_jobs.status` 等，如已签发/限流中/已禁用）**不属于任务面**——由
免费证书页与规则 TLS 列维护；任务列表的任何列（名称列、状态列、状态词表、
兜底）均不得引入业务词表。`TaskStatus` 枚举与前端状态列模板由钉测固化。

**状态归属本进程生命周期**：状态列的「运行中」只由本进程真实在途执行支撑。
crs/ip2region 状态镜像仅在对应 manager 本进程在途时采纳——持久化活动态可能是
上次进程崩溃残留或集群快照回放，采纳即伪造「运行中」死态；启动装配把残留
活动态归一为 failed（message「进程重启回收」）。`task_runs` 终态更新失败按
有界退避重试，仍有残留 running 行时视图按中断呈现，且进程内无在途执行时不再
显示运行中（「运行」按钮可用）。从节点上的 master-only 族状态镜像不采纳。

### 触发（1）

| 任务 | 说明 |
|---|---|
| startup:config-load | 引擎 BootSync 启动单次 + 手动重载 + `caddy-restart` 自愈触发 |

## 3. cert-waiting-ca 特例（默认关闭 + 唤醒/自停）

```
默认：调度关闭（不在默认 StartLoop 清单）——引擎不 tick，页面状态列「空闲」+开关列「已停止」（方案 A，2026-10-12）
唤醒（勘误：非单点——四处入队成功路径各自唤醒）：
      cert-renewal-scan Run 体入队后 → `RearmLoop("cert-waiting-ca", certJobsActive())`
      CreateOrRequeueCertJobWithChange 成功路径（规则写路径 Create/Retry/Renew 收敛点）
      RetryCertJob 成功路径（handlers/certjobs.go）
      DeleteCertJob 删除失败恢复重入队成功路径（handlers/certjobs.go）
      后三处入队成功入口=`services.WakeCertWaitingCAForEnqueuedJob()`
      （RearmLoop(..., true)，以入队成功为工作事实，不重查 certJobsActive）
自停：Run 体发现 certJobsActive()==false → StopLoop（回到默认关闭态）
```

唤醒语义：`RearmLoop(..., true)` 越过「已停止」态恢复调度并立即补跑，
`false` 零动作；唤醒不改写 `task_loop_prefs` 用户偏好。续期扫描以
`certJobsActive()` 作为 hasWork，无活零动作；已确认入队成功的路径经
`WakeCertWaitingCAForEnqueuedJob()` 直接传 `true`，避免任务快速转为 failed 后
重查活跃态造成漏唤醒。禁止唤醒路径直调 `StartLoop`——那会把用户手动停止的
调度隐式打开，且停止只在重启前有效。服务就绪补跑形态（无 hasWork 实参）仍只在
调度已开启时重置节拍。

30s 循环为循环任务正常定义；调度关闭期间零执行零记录。`NextRunAt` 仅由视图层查询 `cert_jobs.ca_available_after` 作为「下次 CA 可用时间」展示；Periodic 描述符不携带 Scheduled 专用 `NextSlotFn`。

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
- 调度列：非触发类=开关（绑定 loop_on）；触发类=禁用开关（一致性）；cert-job 动态行=「—」；
  `role_applicable=false`（从节点上的 master-only 族，服务端按 `RunsOn` 派生）的行改显
  「仅主节点」标签并解释从节点不调度，对应「下次执行」列显示「—」——避免把主节点语义的
  预约时刻误读为即将运行；`/system/tasks` 的 `next_run_at` 同口径置空（门覆盖全部来源：
  定时族 `NextSlotFn`、周期族「最近运行 + 间隔」兜底与 cert 等待时刻），直接消费该字段的
  脚本不得对角色不适用任务排程；详情弹框同步展示「角色适用性」
- 常驻族停止需确认弹框；操作列常驻族有「重启」

### 4.1 逐任务启停持久化（2026-10-18 用户裁定）

用户经任务监控显式停止/恢复的调度写入节点本地表 `task_loop_prefs`
（`task_id` / `enabled` / `updated_at`）。`InitTaskEngine` 先按 §2 默认清单
启动，再套用偏好覆盖：

- `enabled=0`：即使属于默认启动清单，进程重启/角色翻转后保持停止；
- `enabled=1`：恢复默认关闭任务的调度（如用户主动开启 `cert-waiting-ca`）；
- 无记录：保持 §2 默认启动清单（现行默认）。

边界：

- 六个业务驱动任务（threat/CRS/IP2Region/crawlerbot-update/auto-backup/
  autoban）不写偏好、套用时跳过——业务开关是唯一事实源，任务监控开关只读；
- 触发类（Oneshot）不可调度，不写偏好；
- 内部自动唤醒（证书入队 `WakeCertWaitingCAForEnqueuedJob` 等）只恢复运行态，
  不改写偏好；只有用户显式 Toggle/Control 才写入（Control restart 终态为运行）；
- `task_loop_prefs` 为节点本地表，不进入集群快照与配置备份/导入。

### 4.2 业务开关与调度开关同源（2026-10-17 用户裁定）

六个业务驱动任务（threat/CRS/IP2Region/crawlerbot-update/auto-backup/autoban）的业务启用状态**就是调度任务本身**，因此业务开关与引擎调度开关必须双向同源：

- 业务页开启 → 写业务字段后立即 `StartLoop`；关闭 → 立即 `StopLoop`。
- 任务监控的六个业务驱动任务调度开关**只读**：只允许查看 `loop_on`，不得从引擎或任务监控反写业务配置；非业务驱动任务仍可由任务监控启停。任务清单唯一事实源=`businessTaskDrivers`。
- 启动装配按业务实态对齐 `loop_on`；首槽武装必须覆盖全部四个规则库源表，缺槽时开启业务即补槽。
- `EnabledFn` 仅作执行面纵深校验，不向任务视图暴露额外「业务开关」字段；`TaskMeta.Enabled` 已删除，任务监控与详情只展示 `loop_on` 调度开关（`Lookup/DescribeAll` 不求值 `EnabledFn`），另以只读 `business_driven` 标记驱动 toggle 禁用（不是第二个开关）。
- 对齐时的读取分三态（`known`）：库瞬断/未初始化（`known=false`）**不得**落 `StopLoop`——保留上一次生效的调度态并登记待重试，由 60s 角色对账周期重对齐，读恢复即收敛到业务实态；tick 侧 `EnabledFn` 仍按二态 fail-closed（读错本轮不跑、下轮重新求值），两者不得混用同一口径。

### 4.3 API 写门与执行角色分层

- `Trigger/Toggle/Cancel/Control` 四个任务写端点统一 `requireMasterNode`，与路由组 `readOnlyGuard` 共同保证从节点只读和同步 403。角色查询失败（DB 故障/迁移窗口）返回 `500`「节点角色查询失败」，不得报 403（403 会把排障方向误导为集群角色问题）。
- `Descriptor.RunsOn` 是**执行调度**唯一角色事实源（引擎 tick/Trigger/RunSync/BootSync）；它不承担面板 API 权限语义，不与集群只读写门混用。
- 写端点状态码统一：引擎未初始化 `503`、任务不存在 `404`、语义拒绝（常驻族触发、触发类 toggle、业务驱动族 toggle 等）`400`。
- 引擎角色种子（启动装配读 `global_config.is_master`）读失败时 warn + 重试一次，仍失败按**从节点 fail-closed** 启动（不得沿用引擎默认主节点——否则会拉起 master-only daemon 并放开写面）；后续并发角色翻转由 `SetRole` 正常收敛。

## 5. 记录与日志口径

| 场景 | task_runs | 日志 |
|---|---|---|
| 定时槽间隙 | 0 行 | 0 行 |
| 定时执行 | 1 行（引擎预插 running→终态） | [done]+业务 |
| 常驻生命周期 | 启动即记 success；异常退出补 failed 行（真实时长与错误 message） | [start]；停止 [done stopped]；失败 [done failed]；异常退出重拉 [restart]（有界 1s/5s/30s，用尽后 [done] 已用尽） |
| 循环每轮 | 1 行 | [done]+业务 |
| 触发执行 | 1 行 | [start]/[done]+业务 |
| 手动触发 | 1 行（trigger=manual） | 同上 |
| 崩溃恢复 | 残留 running → interrupted | — |
| 用户取消自动轮 | 本轮 1 行（终态 cancelled） | [done] cancelled |
| 零到期源的成功轮 | 1 行（success） | 一行「本轮无更新」业务摘要；审计动作「更新」+ detail「无到期源」 |

用户取消（`Cancel`）只消费「自动轮所属的已到期槽」：本轮 `task_runs` 落 cancelled，
本槽不再投递；业务推进/重排新槽后恢复。手动触发轮被取消不改预约（不消费槽），
`CancelHook` 返回 false（取消未生效）同样不消费。

task_runs 保留 90 天（audit-retention 每日清理）。`Engine.Stop` 先取消全部运行，再等待 Scheduled/Periodic/Oneshot 在途 Run 与全部 daemon 落定终态；停止后新的 Trigger/RunSync 返回 `ErrEngineStopped`。

**配置导入暂停/排空**：`PauseScheduling` 与 `ResumeScheduling` 成对使用，均在 `e.mu` 内提交暂停状态，与 `runNow` 的 `inFlight` 登记严格定序。暂停后 tick 不再派发，`Trigger`、`RunSync` 及已越过入口检查的迟到 `runNow` 均返回 `ErrSchedulingPaused`；仅装配期 BootSync（`trigger=startup`）豁免。因此除该启动路径外，暂停返回后 `inFlight` 只减不增，导入可安全排空在途执行；恢复同样在 `e.mu` 内提交，暂停/恢复边界不留下登记窗口。

**装配期启动屏障**：`Options.StartPaused` 只覆盖 tick 投递与 `Trigger`/`RunSync`/`runNow` 登记，**不覆盖常驻族启停**——默认清单里 `security-events-ingestion`/`cert-issuance`/`cluster-sync` 先于 `startup:config-load` 被 `StartLoop` 拉起，其 Run 体起步即真实接管服务（证书签发 → `StartACME` → CA 队列 / 证书部署重试 → Caddy `/load`）。其中只有 `cert-issuance` 写部署面。因此装配方在启动默认清单**之前**进入配置屏障（`BeginConfigImportHold`），BootSync（规则库载入 → 证书物化 → Caddy 渲染/应用）完成后 `EndConfigImportHold` 兑现被延迟的队列与生命周期启动：配置载入前面板不得已有证书部署写入运行配置。**屏障的实际覆盖范围只有部署面**（`startCertIssuanceLifecycle` 与 `caqueue` 的 `configImportHoldActive` 门）：`security-events-ingestion`（只读尾读）与 `cluster-sync` 照常先启动，行为与引入屏障前一致（从节点快照应用由快照应用自身收敛），不得据此宣称「全部常驻族被挡在配置载入之后」。不得把常驻启停并入 `schedPaused`（会与 `loopEnabled`/`pendingRestart` 语义纠缠）。

**调度自动停摆的留痕口径**：两类「引擎自行停止调度」都必须与用户主动停止可区分——① `IntervalFn` 返回非正周期：立即停调并落一条 `failed` 运行行（状态列呈现 failed，含原因）+ `[error]` 日志；② 定时槽连续 `scheduledFailStreakStopLimit`（4）轮**自动轮**未推进且本轮失败/跳过：停调 + `[error]` 日志（失败轮本身已有 failed 行），并在任务元数据透出 `schedule_stopped_reason=fail-streak`（视图据此把「引擎停调」与「用户停止」分开呈现，业务驱动任务提示到业务页重新保存自动更新）。手动轮失败只走退避节流，不消耗停调预算。恢复入口：`StartLoop` 关→开（业务驱动任务=对应业务页重新保存开关）、`ResetScheduleProgress` 或重启进程，均清空停调来源与退避/槽水位。

## 6. 业务侧 helper

- `TaskLogf(taskID, stage, format, ...)` — 业务摘要行（tee 到任务日志）
- `taskengine.TeeTaskLog` — 分阶段流水
- `taskRunStartedAt(rc)` — 业务状态表开始/检查时刻唯一时间源：回读 `task_runs.started_at` 并归一 UTC；threat/CRS/IP2Region/crawler 共用
- `RecordRunStart/RecordRunFinish` — legacy 直调路径（引擎外执行）

### 6.1 统一日志滚动与统计（2026-10-17 用户裁定）

所有任务日志只使用一种滚动标准：**写入前按真实文件大小滚动**。

- 统一入口为 `taskengine.RotateTaskLogBeforeWrite`：`size(path)+len(待写入行) > task_log_size_mb` 时先 `RotateTaskLogFile` 再追加。`taskLogAppend`、`TeeTaskLog` 与证书任务日志全部经过该入口，禁止另设每日巡检滚动或第二套滚动实现。
- 普通任务与证书任务日志共用 `taskengine.TruncateTaskLogLine`：滚动判定前将单行按 UTF-8 安全截到 4096 字节并保留显式截断标记，避免巨型错误行突破活动文件尺寸治理。
- 主流水 `tasks/{id}.log` 保 1 份，证书任务 `tasks/certjobs/*.log` 保 5 份；归档份数是保留策略差异，不是第二种滚动机制。
- `log-cleanup` 只负责保留期清理，不再负责尺寸滚动。`tasks/` 根日志删除统一经 `taskengine.RemoveTaskLogIfModifiedBefore`，在路径写锁内重新 stat 后删除（避免锁外旧 FileInfo 与 `rotate→rename→append` 交错误删新一代）；`tasks/certjobs/` 子目录仍由 ruleID 写锁同源复核。
- 每个 `tasks/{id}.log` 只能由该任务执行链写入：cluster-sync/普通配置导入不得写三库日志；`SecurityEventsPollOnce` 只返回条数，ingestion 自行记录；autoban 仅 Run/候选修剪同链写日志，摄取热路径不直接写。
- 普通任务路径=`TaskLogPath`；`cert-job:<job_id>` 先解析 `rule_id` 再进 `tasks/certjobs/certjob-<rule>.log`，API/MCP/`/logs/stats` 共用 `systemTaskLogPath`。
- 日志统计与弹框使用 `task:<id>`：每个任务对应自己的真实文件、活动大小、轮转副本和阈值；禁止用 `tasks/*.log` 目录聚合值代替当前任务。

### 6.2 新增任务注册门禁

新增/修改任务必须同时满足，缺一即视为未完成：

1. Descriptor 的 ID/Name/Kind/Run/角色门/调度函数齐全；重复 ID、空 Name、nil Run、非法 Kind/RunsOn 均注册失败，禁止复用其他任务 ID、状态表、日志或生命周期。wire 必须经 `mustRegisterTask`，注册错误启动即失败。
2. 非 oneshot 任务进入默认 `StartLoop`（或写入带理由的显式豁免清单）；首槽/首间隔有真实可执行值。动态 `IntervalFn` 仅在 tick 锁外求值，非正周期立即停止该任务调度且不执行 Run，禁止注册期调用函数。
3. 业务自动更新开关与调度开关双向同源（若任务有业务开关）。
4. 业务日志走 `TaskLogf`/`TeeTaskLog`，状态与 `task_runs` 时间同源；写入前滚动自然覆盖，禁止自行实现第二种滚动。
5. `/logs/stats` 返回 `task:<id>` 真实文件统计，任务监控弹框不得使用目录聚合值。
6. 注册级测试必须覆盖：默认调度、精确槽值/间隔与 **`DescribeAll` 注册全集**（不写死条数——全集以注册表/`DescribeAll` 输出为准，本文 §2 的「当前 N 个」仅作对照；曾写死 18 与实际的 19 分叉）、全部业务开关双向同源、日志与状态时间、逐任务真实文件统计、停止/取消/角色翻转/崩溃恢复、旧调度器零旁路。

### 6.3 仅测试消费的 API 面（勿新增生产消费方）

以下导出符号**没有生产调用方**，保留供测试装配与排障断言；生产线走注明的替代入口。登记目的是避免后续轮次重复判定为死代码：

| 符号 | 替代/说明 |
|---|---|
| `Engine.RunAsync` | 生产手动触发唯一入口=`services.TriggerTaskAsync`→`Engine.RunAsyncResult`（需 onDone 补记补偿审计） |
| `Engine.Stats24h` | 任务视图走 `Engine.RunOverview` 批量聚合（同 SQL 单源） |
| `Engine.Trigger` | 同步驱动测试；生产走异步入口 |
| `Engine.IsRunning` | 诊断投影（`Run 存活 或 loopEnabled∧roleAllows`），**不得**用作「是否正在执行」判据——该语义用 `IsTaskInFlight` |
| `RoleSlaveOnly` | 仅测试注册使用（生产 19 任务全集只有 RoleAny/RoleMasterOnly） |

### 6.4 循环豁免登记（缺理由即违规）

| 位置 | 形态 | 豁免理由 | 停止路径 |
|---|---|---|---|
| `db/apikey_last_used.go:76-125` | 1min flush + 1h 清理 | db 层写合并缓冲；引擎依赖 db，反向注册成环 | `db.Close`→stopAPIKeyLastUsedFlusher |
| `services/logrotate.go:41-92` | 30s | 为引擎写日志提供阈值，装配序在引擎前 | `StopLogRotateWithin` |
| `services/tz.go:48-92` | 30s | 引擎 `SetLocation` 依赖它 | `StopTimezoneRefreshWithin` |
| `middleware/middleware.go:703-708` | 1min | 请求路径内存清扫，无落盘无记录语义 | 随进程消亡 |
| `handlers/handlers.go:1175-1203` | 2s | Caddy 崩溃自愈的**触发源监听**；工作体已走 Oneshot `caddy-restart` | `StopCaddyRestartWatcher` |
| `taskengine_wire.go:1046-1068` | 60s | 角色对账，设计目标即"不受用户可停止的看门狗影响" | `te.Done()`/`StopTaskEngine` 有界等待 |
| `acme/issuer.go:461/615/852` | 3–5s | 单次签发内的有界轮询（纯等待工具） | 随签发 ctx |

### 6.5 待归口清单（已知缺口，逐项完成后从本表删除）

| 位置 | 现状 | 目标 |
|---|---|---|
| `services/caqueue.go:1163-1166` per-provider `go q.loop()` | 子资源自建泵 | 归 `cert-issuance` daemon 的 `RunTicker`（`Manager.DispatchOnce`） |
| `services/services.go:79-114` `MetricsService.Start` | main.go 手工 goroutine | 新 daemon `metrics-collector`（RunsOn=RoleAny） |
| `handlers/security_threat_screen.go:1085-1124` rollup warmer | main.go 手工 goroutine | 并入 `security-events-ingestion` daemon |

## 7. 修订记录

- **v2.1（2026-10-30，用户裁定）**：新增 §0「职责与边界」——归口矩阵、唯一许可的四种执行形态（`RunTicker`）、唤醒协议、子资源归属、违规反例、机器守卫；新增 §6.4 循环豁免登记与 §6.5 待归口清单（per-provider 队列泵 / metrics 采集 / rollup warmer）。起因：`caqueue.go:1163` 每提供商自建 goroutine 绕开引擎，导致不可枚举/不可停止/不可观测，并让证书签发派发节拍长期游离于引擎之外。

- v2.0.9（2026-10-24）：联动契约收敛——① 「活动态只属执行进程」补上导入通道：配置导入把四表 `update_status` 的活动态（版本表四活动词 + 源表 `running`）按类判据 `services.IsActiveUpdateStatus` 归一为 failed + 归属文案，`running` 补入共享词表（不再被误判为词表外值归 idle）；② 「槽域=运行域」落到写侧：威胁族首槽武装、时区重排与排程保存统一按注册表源名过滤，注册表外启用行的槽不再被清理后的武装反向补回；③ 角色不适用任务的 `next_run_at` 全部来源置空（定时族 `NextSlotFn`/cert 等待时刻同门），与 `role_applicable=false` 不再自相矛盾；④ 规则库读面（`/security/crs`、`/security/ip2region`、`/security/overview`）接入角色投影，从节点残留活动态与状态端点同结论。
- v2.0.8（2026-10-24）：停调语义与恢复入口口径收敛——① 只有自动轮消耗停调预算：手动轮失败/跳过只走退避节流、不推进 `schedFailStreak`（不再让几次手动重试提前用尽自动停调预算）；② 引擎停调来源机器可读（`schedule_stopped_reason=fail-streak`），任务视图把「引擎停调」与「用户停止」分开呈现，业务驱动任务给出「到业务页重新保存自动更新 / 重启进程」的可执行恢复入口；`[error]` 日志文案同步改为可执行指引；③ `RearmLoop(hasWork=true)` 只在「已停止→开启」过渡复位 Scheduled 槽水位/退避（已开启任务的普通唤醒不再把已消费的过期槽重新投递，与 `StartLoop` 同口径）；④ 源表族启动归一的告警写入注册任务 ID `threat`（此前写入不存在的 `threat-update`，产生游离日志文件且任务日志弹框不可见）；⑤ 任务/审计日志尺寸的兜底值单源 `db.DefaultTaskLogSizeMB`/`db.DefaultAuditLogSizeMB`（删除各自字面量）；⑥ 已停引擎的 `Cancel` 与 toggle/control 同口径回 503，`Register` 的停止门移到描述符校验之后（先报真正缺失的字段）；⑦ §5 装配期屏障口径收窄为「只覆盖部署面」。
- v2.0.7（2026-10-24）：调度自动停摆与观测口径收敛——① Periodic 的 `IntervalFn`
  返回非正周期时停调并落 failed 运行行 + `[error]` 日志（此前只有日志行，与用户
  主动停止同形；失败行让状态列与「近 24 小时」失败计数可见）；② 定时槽连续
  `scheduledFailStreakStopLimit`（4）轮未推进且本轮失败/跳过 → 停调（只对自动轮，
  手动轮有界不触发），退避兜底不再是无限重投；③ `RearmLoop(hasWork=true)` 越过
  停止态时复位 Scheduled 槽水位/退避（否则旧水位永久压住当前槽）；④ 装配期服务
  屏障：常驻族先于 `startup:config-load` 启动，配置载入完成前用
  `BeginConfigImportHold`/`EndConfigImportHold` 挡住部署面启动；⑤ 调度闭包 panic
  告警按任务分桶（跨任务不再互相遮蔽，被抑制次数随下次放行披露）；⑥ 运行历史与
  列表共用残留 `running` 行判定（归一 `interrupted` + 同源文案）；⑦ 从节点上
  角色不适用任务不再推算「下次执行」；⑧ 引擎已停止时调度写端点回 503 且
  `Register` 返回 `ErrEngineStopped`（不再回 200 假成功）；⑨ §6.3 登记仅测试
  消费的 API 面。
- v2.0.6（2026-10-24）：补充 §1.1「成功轮的槽推进」（auto=空/过期、manual=仅过期，
  `slotSuccessGateSQL` 单源）与「槽域=运行域」（威胁族槽按内置注册表源名收窄，注册表外
  启用行的槽在启动期清空）；§1.2 登记 `Daemon ∧ Cancelable` 注册期拒绝（及
  `EnabledFn`/`RestartOnRoleFlip` 的 Kind 约束）。§5 记录口径补：零到期源的成功轮在两族
  审计同记动作「更新」、detail 声明「无到期源，本轮无更新」，「跳过」专留降级中止。
- v2.0.5（2026-10-24）：任务状态归属本进程生命周期——状态镜像只在 manager 本进程在途时采纳、启动装配归一残留活动态（failed「进程重启回收」）、`task_runs` 终态写有界重试且残留 running 行按中断呈现；任务视图新增 `role_applicable`（从节点上 master-only 族标注「仅主节点」并解释调度开关不可用、下次执行显示「—」）；业务驱动调度对齐读失败保持上一次生效态并由 60s 角色对账重试（tick 侧 `EnabledFn` 仍二态 fail-closed）。
- v2.0.4（2026-10-23）：补充 §1.1 Scheduled 槽语义——槽缓存降频求值（前导窗 30s/地板 1min）、同一槽只执行一次（成功/自动轮到期的用户取消消费；失败退避不消费）、取消只消费「自动轮已到期槽」、`ResetScheduleProgress` 显式复位、导入排空/demote 不消费。同步 §5 记录口径（用户取消自动轮=放弃本槽）。
- v2.0.3（2026-10-14，用户裁定「启用后按配置调度」）：autoban 调度模型收编——Descriptor 去除 EnabledFn（任务监控只认 `loop_on`，启停语义全在调度开关+事件页业务开关）；PUT /security/autoban 保存联动启停（enabled=true→StartLoop、false→StopLoop；历史补：禁用保存先收敛已到期条目与暂存重载再停调度——禁用后无循环 flush/到期清理点）；启动按库内业务开关实态对齐调度；手动开调度/手动触发但未启用由 Run 体首行业务门拦停（TaskLogf「手动调度，执行失败：未启用」+task_runs failed 行+StopLoop 重禁调度）；POST /security/autoban/run「立即执行」端点与前端按钮删除。

- v2.0.2（2026-10-14，用户裁定）：新增 autoban 循环任务（60s/主节点/EnabledFn=autoban_enabled 业务开关联动）——WAF 事件固定窗口计数（摄取提交点喂入）→ 阈值判定 →「自动封禁名单」merge（清到期/保留手动/已在名单过滤/超限挤最早到期）→ 重载 60s 节流暂存合并；观察模式（dry_run 默认开）仅记建议；每轮 TaskLogf 摘要行入 tasks/autoban.log。

- v2.0.1（2026-10-14，用户裁定）：EnabledFn 调度门补全——tick 的 Scheduled/Periodic 分支业务关即整支跳过（不落行不推进节拍，恢复后下一 tick 到期即跑；手动触发不受门拦）；术语统一「已暂停」→「已停止」（任务监控开关列/详情/tooltip、API 消息与本文档）。
- v2.0（2026-10-01）：四类型标准重构。Kind 枚举 4 值替代 Continuous/Queue/Info；删除 SilentProbes/RecordFailuresOnly/SignalledWork/Singleton/AsKind/Cadence；NextSlotFn 返回 time.Time；Daemon 生命周期（StartLoop 调 Run 一次+阻塞）；cert-waiting-ca 默认调度关闭+唤醒/自停；自动备份遗留 1min 调度器删除（追补语义移入 nextAutoBackupSlot 的 last_run 感知）；ingestion 改自管理循环。
