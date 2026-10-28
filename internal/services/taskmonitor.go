package services

// 任务监控聚合服务（v2.3.4）：统一枚举系统全部定时/后台任务族，聚合各族
// 状态面（DB 行 + manager 内存态）为单一 DTO，供「系统设置 → 任务监控」
// 页面与 /system/tasks 端点消费。纯读聚合——零新表零迁移；操作面（触发/
// 暂停/取消）复用各任务族既有入口（handlers 映射层）。

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TaskStatus 任务当前状态。
type TaskStatus string

const (
	TaskStatusRunning TaskStatus = "running"
	TaskStatusIdle    TaskStatus = "idle"
	TaskStatusFailed  TaskStatus = "failed"
	// 状态列词表=引擎执行语义三态（2026-10-22 用户裁定，取代旧 stopped/
	// disabled/queued 扩展值）：调度语义归开关列 loop_on；业务生命周期态
	// （cert_jobs.status 等）只能进业务文本位，禁止进入任务状态列。
	// cancelled 常量删除——零产出零消费（取消只存在于
	// task_runs.result 字段，非 TaskStatus 状态产出）。
)

// TaskInfo 是单任务族的聚合视图。
type TaskInfo struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"` // 任务作用说明（任务名 hover 提示）
	Cadence        string          `json:"cadence,omitempty"`     // 运行节奏（如「每 6 小时」；非下次时间）
	Category       string          `json:"category"`              // 安全防护/证书/备份/集群/系统
	Kind           taskengine.Kind `json:"kind"`
	Status         TaskStatus      `json:"status"`
	Cancellable    bool            `json:"cancellable"`          // 运行中可手动取消（仅下载类）
	Controllable   bool            `json:"controllable"`         // 常驻循环可启停（start/stop/restart）
	Triggerable    bool            `json:"triggerable"`          // 支持手动触发（ManualRun 语义族）
	StartedAt      string          `json:"started_at,omitempty"` // 常驻族启动时刻；其他类型空
	LoopOn         bool            `json:"loop_on"`              // 调度开关当前态（定时/循环/常驻调度列绑定值；用户显式启停持久化于 task_loop_prefs，无记录走默认启动清单）
	BusinessDriven bool            `json:"business_driven"`      // 仅由业务页驱动调度（任务监控 toggle 只读）
	// RoleApplicable 本节点角色是否允许该任务运行（服务端派生，不暴露原始
	// 角色值）。从节点上 master-only 族的 LoopOn/NextRunAt 仍是主节点语义的
	// 值——视图据此标注「仅主节点运行」并解释调度开关不可用。
	RoleApplicable bool `json:"role_applicable"`
	// ScheduleStoppedReason 引擎自行停止调度的来源标记（taskengine.
	// ScheduleStopReason*），空=非引擎停调。业务驱动任务的调度开关在本页只读，
	// 视图据此把「引擎停调」与「用户关闭业务开关」分开呈现并指向业务页恢复入口。
	ScheduleStoppedReason string       `json:"schedule_stopped_reason,omitempty"`
	LastRun               *TaskRunInfo `json:"last_run,omitempty"`
	NextRunAt             string       `json:"next_run_at,omitempty"`
	// RetryCooldownSeconds 「运行/重试」按钮的剩余冷却秒数（无 omitempty：
	// 0 是「现在即可重试」的语义，前端以本字段为唯一判据；null=该状态永久不可
	// 重试，前端按 triggerable 呈现禁用态）。口径与证书任务列表
	// （/certificates/jobs 的 retry_cooldown_seconds）同源：
	// services.CertJobRetryRemainingSeconds——证书行下发「此刻剩余秒」（通用退避
	// 按 updated_at 起算扣减，waiting_ca 取 CA 退避到期时刻），非证书行恒 0
	// （引擎族无证书重试冷却概念）。
	RetryCooldownSeconds *int64 `json:"retry_cooldown_seconds"`
	Runs24h              int    `json:"runs_24h"`
	Success24h           int    `json:"success_24h"`
	Fail24h              int    `json:"fail_24h"`
}

// zeroRetryCooldown 是非证书任务行的统一下发值：引擎族没有证书重试冷却，
// 0 = 「现在即可运行」。包级只读指针避免逐行分配。
var zeroRetryCooldown = func() *int64 { seconds := int64(0); return &seconds }()

// TaskRunInfo 最近一次运行。
type TaskRunInfo struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	Trigger    string `json:"trigger"`            // manual/auto/startup/caddy-restart/schedule（queue=cert-job 动态行合成值；slave-sync 为历史版本遗留取值，零产出已退役，展示层不再保留映射——遗留行原样回显 token）
	Operator   string `json:"operator,omitempty"` // 手动触发操作者（manual 触发归人；auto/startup=空）
	Result     string `json:"result"`             // success/failed/cancelled/skipped/…
	Message    string `json:"message,omitempty"`
}

// collectSystemTasksCalls 任务族聚合调用计数（测试观测单行轮询是否短路任务枚举）。
var collectSystemTasksCalls atomic.Int64

// ResetCollectSystemTasksCallsForTest 测试缝：复位任务枚举计数。
func ResetCollectSystemTasksCallsForTest() { collectSystemTasksCalls.Store(0) }

// CollectSystemTasksCallsForTest 返回任务枚举累计调用次数。
func CollectSystemTasksCallsForTest() int64 { return collectSystemTasksCalls.Load() }

// CollectSystemTasks 聚合全部任务族（终态：引擎唯一事实源——全部任务族
// 注册于任务引擎，视图=DescribeAll 元数据+task_runs 真实运行/统计；
// 零收集器零特化）。certJobsTruncated=true 表示 cert-job 动态行触达
// 100 行上限（审计项：此前静默截断，消费方无法区分「只有 100 条」与
// 「被截到 100 条」）。
func CollectSystemTasks() (tasks []TaskInfo, certJobsTruncated bool) {
	collectSystemTasksCalls.Add(1)
	te := TaskEngine()
	if te == nil {
		return []TaskInfo{}, false
	}
	tasks = collectEngineFamilies(te)
	// 证书签发任务动态行（实时非终态 + 24h 内终态——执行状态进任务列表，
	// 队列卡只展示实时队列内容）
	certRows, truncated := collectCertJobRows()
	return append(tasks, certRows...), truncated
}

// collectCertJobRows 逐签发任务行：非终态（实时队列内容）+ 24h 内终态
// （结果可见）；id=cert-job:{jobID}，日志走 /certificates/jobs/{id}/logs。
func collectCertJobRows() ([]TaskInfo, bool) {
	// db.DB nil 防护——与引擎侧导出 DB 函数同形
	// （装配顺序变化即 nil panic，曾裸用）。
	if db.DB == nil {
		return nil, false
	}
	// 2026-10-01 用户裁定：行存在即显示（无状态/时间过滤——曾按
	// 「issued 超 1 天隐藏」窗口过滤致主节点签发行消失）；仅排除从节点
	// 材料物化行（非签发任务，从节点禁签发）。LIMIT 100（裁定后
	// 收敛：20 截断「存在即显示」——100 贴近裁定原文且长周期主节点不触顶）。
	// 审计项：多取 1 行作截断探针（LIMIT 101），触达上限时回传 truncated
	// 标记——此前 100 行静默截断，消费方无法区分「恰好 100 条」与「被截」。
	//
	// 镜像行过滤条件绑定「本节点当前为从节点」——曾无条件按 message
	// 前缀过滤，promote 后保留下来的同主节点同步行永久不可见（它们已经是本
	// 节点自己的签发工作项）。读角色失败按主节点处理（行可见：多展示无害，
	// 静默丢行不可恢复）。
	isMaster := 1
	if role, err := RoleOf(context.Background(), db.DB); err == nil && !role {
		isMaster = 0
	}
	readFailed := false
	// 查询单源（db.CertJobsMonitorRowsQuery）：排序键 COALESCE(updated_at,
	// created_at) DESC 由表达式索引 idx_cert_jobs_updated_fallback 承载，计划
	// 钉测在 db 包内看守两者一致。
	rows, err := db.DB.Query(db.CertJobsMonitorRowsQuery, isMaster, certJobRowsLimit+1)
	if err != nil {
		// 任务行读失败留痕：查询失败不再静默空列表（对照下方 rows.Err 留痕形态）。
		// 5s 轮询下按失败态转换留痕（首报一条，故障持续期静默，恢复补一条）。
		if lvl := logStateTransition(taskMonitorCertJobsLogKey, true); lvl != "" {
			Logf(lvl, "cert 任务行查询失败: %v", err)
		}
		return nil, false
	}
	defer rows.Close()
	var out []TaskInfo
	for rows.Next() {
		var id int
		var ruleID, domain, status, message, createdAt, updatedAt, caAvailableAfter string
		if err := rows.Scan(&id, &ruleID, &domain, &status, &message, &createdAt, &updatedAt, &caAvailableAfter); err != nil {
			// 任务行读失败留痕：单行扫描失败留痕后跳过该行（此前静默 continue）。
			readFailed = true
			if lvl := logStateTransition(taskMonitorCertJobsLogKey, true); lvl != "" {
				Logf(lvl, "cert 任务行扫描失败: %v", err)
			}
			continue
		}
		// 终态计数（24h 窗口内 issued=成功 1、failed=失败 1；超窗行显示
		// 但不计数——Runs24h 语义为近 24 小时）。
		success, fail := 0, 0
		// 统一双布局解析（RFC3339/平面 UTC），避免导入/历史形态静默归零。
		if t := parseUTCSlot(updatedAt); !t.IsZero() && time.Since(t) < 24*time.Hour {
			switch status {
			case "issued":
				success = 1
			case "failed":
				fail = 1
			}
		}
		runs24h := success + fail
		// 执行时间口径与历史端点同源（started=created_at/finished=updated_at/
		// duration=差），不得各自映射。
		startedAt, finishedAt, durationMs := CertJobRunTimes(createdAt, updatedAt)
		ti := TaskInfo{
			ID:       fmt.Sprintf("cert-job:%d", id),
			Name:     "ACME 签发 · " + domain,
			Category: "证书",
			Kind:     taskengine.KindOneshot, // 动态签发行=按需触发的工作项
			// 触发语义（2026-10-11 用户裁定）：cert-job 行视为触发任务——可自动
			// 调度（签发守护消费）即可手动调度（证书可重签发）；重试门（在途 409/
			// 退役 429/冷却 429）由 TriggerSystemTask 的 cert-job 分支复用承担。
			// disabled 为恒终态退役行——重试门对其恒 429，
			// Triggerable=false 让按钮呈现禁用态（点击必 429 是交互噪音）。
			Triggerable: status != "disabled",
			// 证书签发工作项只由主节点消费（从节点禁签发）——角色读取失败
			// 时按主节点处理（与上方行可见性判据同向）。
			RoleApplicable: isMaster == 1,
			LastRun: &TaskRunInfo{StartedAt: startedAt, FinishedAt: finishedAt, DurationMs: durationMs,
				Trigger: "queue", Result: status, Message: message},
		}
		ti.Runs24h, ti.Success24h, ti.Fail24h = runs24h, success, fail
		// 「运行/重试」按钮的冷却：与证书任务列表同口径同源——下发「此刻剩余
		// 秒」（0=现在可重试；null=永久不可重试）。通用窗口按 updated_at 扣减
		// （查询已 COALESCE 到 created_at），waiting_ca 取 CA 退避到期时刻。
		// 双布局解析与槽解析单源。
		var caWindow, updatedSlot, createdSlot sql.NullTime
		if t := parseUTCSlot(caAvailableAfter); !t.IsZero() {
			caWindow = sql.NullTime{Time: t, Valid: true}
		}
		if t := parseUTCSlot(updatedAt); !t.IsZero() {
			updatedSlot = sql.NullTime{Time: t, Valid: true}
		}
		if t := parseUTCSlot(createdAt); !t.IsZero() {
			createdSlot = sql.NullTime{Time: t, Valid: true}
		}
		if seconds, retryable := CertJobRetryRemainingSeconds(status, updatedSlot, createdSlot, caWindow, time.Now()); retryable {
			ti.RetryCooldownSeconds = &seconds
		}
		ti.Status = TaskStatusIdle
		switch status {
		case "failed":
			ti.Status = TaskStatusFailed
		case "issued", "downloaded", "disabled":
			// 状态列词表三态（2026-10-22 用户裁定）：终态成功与退役行均为空闲；
			// 「已签发/已禁用」等证书业务态由业务文本承载，不进状态列。
			ti.Status = TaskStatusIdle
		default:
			// 其余一律运行中：含 queued/pending/waiting_ca（限流停车仍是未完成
			// 工作项——停车与处理中的区分归业务文本，状态列不引入第四态）。
			ti.Status = TaskStatusRunning
		}
		out = append(out, ti)
	}
	if err := rows.Err(); err != nil {
		// 迭代失败不再静默部分列表（曾 rows.Err 未查）
		readFailed = true
		if lvl := logStateTransition(taskMonitorCertJobsLogKey, true); lvl != "" {
			Logf(lvl, "cert 任务行迭代失败: %v", err)
		}
	}
	if !readFailed {
		if lvl := logStateTransition(taskMonitorCertJobsLogKey, false); lvl != "" {
			Logf(lvl, "cert 任务行读取恢复")
		}
	}
	truncated := len(out) > certJobRowsLimit
	if truncated {
		out = out[:certJobRowsLimit]
	}
	return out, truncated
}

// certJobRowsLimit 任务监控视图内 cert-job 动态行上限（探针行 +1 由查询侧承担）。
const certJobRowsLimit = 100

// taskMonitorCertJobsLogKey cert-job 任务行读取失败态转换键（首报/恢复各一条，
// 避免 5s 轮询在库故障期间刷 WARNING 洪峰）。
const taskMonitorCertJobsLogKey = "task-monitor-cert-jobs"

// taskMonitorWaitingCALogKey cert-waiting-ca 下次可用时间查询失败态转换键
// （同族节流口径：首报警告、恢复补一条）。
const taskMonitorWaitingCALogKey = "task-monitor-waiting-ca"

// taskIP2RegionStatusLogKey ip2region 任务 StatusFn 状态列读取失败态转换键：
// 读失败会让状态列回落「执行实态」，与「确实空闲」不可区分，必须留痕
// （同族首报/恢复节流口径）。
const taskIP2RegionStatusLogKey = "task-ip2region-status"

// collectEngineFamilies 引擎注册族统一视图（终态：零特化零收集器——
// 元数据/开关/下一槽/状态镜像全来自 DescribeAll，最近运行与 24h 统计
// 来自 task_runs，下次时间兜底 last+interval）。
func collectEngineFamilies(te *taskengine.Engine) []TaskInfo {
	var out []TaskInfo
	// 最近运行与 24h 统计一次批量取（修复前逐任务 LatestRun+Stats24h
	// = 2N 条 SQL，前端 5s 轮询下为稳定常驻负载）。
	latestRuns, runStats := te.RunOverview()
	for _, m := range te.DescribeAll() {
		ti := TaskInfo{
			ID: m.ID, Name: m.Name, Description: m.Description,
			Category: m.Category, Kind: m.Kind,
			Controllable: m.Controllable, Cancellable: m.Cancelable, Triggerable: m.CanTrigger,
			LoopOn: m.LoopOn, BusinessDriven: IsBusinessDrivenTask(m.ID),
			RoleApplicable:        m.RoleApplicable,
			ScheduleStoppedReason: m.ScheduleStoppedReason,
			// 引擎族没有证书重试冷却概念：恒 0（现在即可运行），不得留 null。
			RetryCooldownSeconds: zeroRetryCooldown,
		}
		// 节奏：循环=间隔，定时=排程槽，常驻=自管理，触发=手动
		switch m.Kind {
		case taskengine.KindPeriodic:
			if m.IntervalSec > 0 {
				ti.Cadence = "每 " + humanInterval(m.IntervalSec)
			}
		case taskengine.KindScheduled:
			// Scheduled 族节奏补显——原缺分支恒空，前端显示「—」；
			// 槽位由 NextSlotFn 按用户配置派生（每日时刻等），具体时间归「下次执行」列。
			ti.Cadence = "定时排程"
		case taskengine.KindDaemon:
			ti.Cadence = "常驻自管理"
		case taskengine.KindOneshot:
			ti.Cadence = "手动触发"
		}
		// 最近运行与 24h 统计：单次批量取（曾每任务两查）——nil 库守卫在
		// RunOverview/Lookup 内部，本层不裸用 db.DB（下方 cert-waiting-ca
		// 分支是唯一显式守卫点）。
		latestRun := latestRuns[m.ID]
		// staleRunning 标记「task_runs 仍是 running 但进程内已无在途执行」的
		// 残留行（终态 UPDATE 失败）——最近运行结果按中断呈现。
		staleRunning := false
		// 状态分流（方案 A，2026-10-12 用户裁定）：状态列只承载执行语义
		// （运行中/空闲/失败；cert-job 退役行「已禁用」走 cert-job 行集）。
		// 调度语义全部归开关列——调度语义只由 loop_on 表达；business_driven
		// 为只读态（由对应业务页开关驱动调度）。stopped/disabled 不再作为
		// 状态列产出（原「stopped 仅常驻」模型与 disabled 三源混用同轮废除）。
		// StatusMirror 词表归一：产出侧（StatusFn）与消费侧（前端色表/标签）
		// 同守三态词表——非词表值（业务态混入/未来新增态未同步）不得直通
		// 状态列，按空镜像回落执行实态推导；状态翻转留痕（持续词表外不刷屏）。
		mirror := m.StatusMirror
		switch mirror {
		case "", string(TaskStatusIdle), string(TaskStatusRunning), string(TaskStatusFailed):
			logStateTransition("status-mirror-"+m.ID, false)
		default:
			if lvl := logStateTransition("status-mirror-"+m.ID, true); lvl != "" {
				Logf(lvl, "任务 %s 状态镜像 %q 不在执行态词表（idle/running/failed），按空镜像回落执行实态", m.ID, mirror)
			}
			mirror = ""
		}
		if mirror != "" {
			ti.Status = TaskStatus(mirror)
		} else if m.Kind == taskengine.KindDaemon {
			if m.Running {
				ti.Status = TaskStatusRunning
			} else if (m.LoopOn || m.RestartExhausted) && latestRun != nil && latestRun.Status == "failed" {
				// +：Run 已死（有界重拉窗口）或自愈预算
				// 用尽（此时 LoopOn=false，与用户主动停止同形）——必须呈现
				// failed。修复前恒 idle「空闲」，采集/签发永久停摆无信号。
				ti.Status = TaskStatusFailed
			} else {
				ti.Status = TaskStatusIdle // 未跑=空闲（调度关由开关列表达）
			}
		} else {
			ti.Status = TaskStatusIdle
			if m.Running {
				// 本进程确有在途执行但 task_runs 无 running 行（行插入失败仅
				// WARN、或 RunSyncQuiet 显式静默轮）：状态列必须反映真实在途，
				// 否则显示 idle 而「运行」被 IsTaskInFlight 拒为 409，视图与
				// 真实执行自相矛盾。staleRunning 的前提是 !m.Running，不受影响。
				ti.Status = TaskStatusRunning
			} else if latestRun != nil {
				switch latestRun.Status {
				case "failed":
					ti.Status = TaskStatusFailed
				case "running":
					// running 只在引擎确有在途执行时成立：终态 UPDATE 失败会
					// 把行永久留在 running，此时进程内已无该任务的执行——
					// 直通会让状态列恒显「运行中」并禁用「运行」按钮。
					// 但行快照（RunOverview）与内存快照（DescribeAll）是两次
					// 独立取数：两次快照之间刚完成的轮次会呈现「行 running、
					// 内存已空闲」的瞬态，立即判 failed 会误报一次失败/中断。
					// 年龄门只覆盖「刚写入」的行，终态写失败的行一定会变老。
					// （本分支的入口已保证 !m.Running，内存态无需二次判定。）
					if !taskengine.StaleRunningResidual(latestRun.StartedAt) {
						ti.Status = TaskStatusRunning
					} else {
						ti.Status = TaskStatusFailed
						staleRunning = true
					}
				}
			}
		}
		// 下一槽：定时=NextSlotFn（声明式）；循环=last+interval 兜底。
		// 角色门覆盖**全部**来源（不只下方周期族的兜底推算）：NextSlotFn 纯读
		// 本地库，从节点的槽值来自主端快照，不门控就恒有值——同一响应里
		// role_applicable=false 与具体执行时刻并存，直接消费 /system/tasks 的
		// 脚本会据此排程而实际永不投递。UI 另行遮蔽不构成 API 契约。
		if m.RoleApplicable {
			ti.NextRunAt = m.NextSlot
		}
		if m.ID == "cert-waiting-ca" && m.RoleApplicable && db.DB != nil {
			// 仅展示「下次 CA 可用时间」，不参与 Periodic 调度；Descriptor 不再携带
			// Scheduled 专用 NextSlotFn。
			var at string
			if err := db.DB.QueryRow(`SELECT COALESCE(MIN(NULLIF(ca_available_after,'')),'') FROM cert_jobs WHERE status='waiting_ca'`).Scan(&at); err != nil {
				// 查询失败不得静默丢弃（否则页面「—」与「无 waiting_ca 任务」
				// 不可区分）：按失败态转换留痕（首报 WARNING，恢复补 INFO）。
				if lvl := logStateTransition(taskMonitorWaitingCALogKey, true); lvl != "" {
					Logf(lvl, "cert 等待 CA 下次可用时间查询失败: %v", err)
				}
			} else {
				if lvl := logStateTransition(taskMonitorWaitingCALogKey, false); lvl != "" {
					Logf(lvl, "cert 等待 CA 下次可用时间查询恢复")
				}
				if slot := parseUTCSlot(at); !slot.IsZero() {
					ti.NextRunAt = slot.In(CurrentLocation()).Format("2006-01-02 15:04:05")
				}
			}
		}
		if latestRun != nil {
			ti.LastRun = &TaskRunInfo{StartedAt: latestRun.StartedAt, FinishedAt: latestRun.FinishedAt,
				DurationMs: latestRun.DurationMs, Trigger: latestRun.Trigger, Operator: latestRun.Operator,
				Result: latestRun.Status, Message: latestRun.Message}
			if staleRunning {
				// 库行仍为 running，但该次执行在本进程已结束——结果按中断
				// 呈现（与进程重启回收的 interrupted 同语义）。
				ti.LastRun.Result = "interrupted"
				if ti.LastRun.Message == "" {
					ti.LastRun.Message = staleRunInterruptedMessage
				}
			}
			// RoleApplicable 门：从节点上 master-only 族的 LoopOn 仍是主节点
			// 语义的值（引擎侧有意直传，由 RoleApplicable 解释「仅主节点运行」）。
			// 此处是服务层自行推算的第二条路径，必须继承同一约定——否则从节点
			// 对 cert-renewal-scan 等任务展示一个具体「下次执行」时间而实际永不
			// 投递，与同行的角色不适用标注自相矛盾。
			if ti.NextRunAt == "" && m.IntervalSec > 0 && m.LoopOn && m.RoleApplicable && m.Kind == taskengine.KindPeriodic {
				if t, err := time.ParseInLocation("2006-01-02 15:04:05", latestRun.StartedAt, CurrentLocation()); err == nil {
					// 兜底推算只在落在未来时展示：任务长时间停止后（或最近一轮
					// 早于一个周期）推算值已过去，展示过去时刻会让运维误判「该跑
					// 没跑」；过去则留空让 UI 显示「—」（与「下次执行未知」同义）。
					if next := t.Add(time.Duration(m.IntervalSec) * time.Second); next.After(time.Now()) {
						ti.NextRunAt = next.Format("2006-01-02 15:04:05")
					}
				}
			}
		}
		st := runStats[m.ID]
		ti.Runs24h, ti.Success24h, ti.Fail24h = st.Runs, st.Success, st.Fail
		// 常驻族启动时刻——「常驻 · 启动于」。用该 daemon 最近 boot 行时刻
		// （重启后正确更新）；从未运行的常驻任务（角色门未获/调度关闭未拉起）
		// 置零值——UI '—' 兜底，不再回退引擎进程启动时刻
		// （=uptime 语义，与「空闲/已停止」状态矛盾）。两种形态（运行中/
		// 已停止）同取最近一行：Running=true 但 boot 行缺失（插入失败仅 WARN /
		// DB 短窗）保持零值，同样落 UI '—'。
		if m.Kind == taskengine.KindDaemon && latestRun != nil {
			ti.StartedAt = latestRun.StartedAt
		}
		out = append(out, ti)
	}
	return out
}

// staleRunInterruptedMessage 委托引擎单源（taskengine.StaleRunInterruptedMessage）：
// 历史与最近运行（Engine.History/LatestRun）已内置同一归一，列表侧（RunOverview
// 批量行 + DescribeAll 内存快照）用同一文案呈现失败/已中断——同一 run 不得在两个
// 端点给出相反结论。残留判定与年龄门直接调用 taskengine.StaleRunningResidual
// （无可本地状态），不在本包保留第二套常量/包装。
const staleRunInterruptedMessage = taskengine.StaleRunInterruptedMessage

func humanInterval(sec int) string {
	switch {
	case sec%86400 == 0:
		d := sec / 86400
		if d == 1 {
			return "24 小时"
		}
		return fmt.Sprintf("%d 天", d)
	case sec%3600 == 0:
		return fmt.Sprintf("%d 小时", sec/3600)
	case sec%60 == 0:
		return fmt.Sprintf("%d 分钟", sec/60)
	default:
		return fmt.Sprintf("%d 秒", sec)
	}
}

// CertJobRunTimes 把 cert_jobs 行的时间戳映射为执行时间视图（单源）：
// started=created_at、finished=updated_at、duration=两者差；缺失或不可解析
// 保持零值（空串/0）。任务监控列表（collectCertJobRows）与历史
// （handlers.certJobRunHistory）共用，防止两处口径漂移——曾列表把
// updated_at 同时当开始/结束时间且 DurationMs 恒 0，同一行在列表与历史
// 呈现互相矛盾的时间语义。
func CertJobRunTimes(createdAt, updatedAt string) (startedAt, finishedAt string, durationMs int64) {
	started, startedOK := ParseUTCTimeDual(createdAt)
	finished, finishedOK := ParseUTCTimeDual(updatedAt)
	loc := CurrentLocation()
	if startedOK {
		startedAt = started.In(loc).Format("2006-01-02 15:04:05")
	}
	if finishedOK {
		finishedAt = finished.In(loc).Format("2006-01-02 15:04:05")
	}
	if startedOK && finishedOK && finished.After(started) {
		durationMs = finished.Sub(started).Milliseconds()
	}
	return startedAt, finishedAt, durationMs
}
