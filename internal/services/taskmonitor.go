package services

// 任务监控聚合服务（v2.3.4）：统一枚举系统全部定时/后台任务族，聚合各族
// 状态面（DB 行 + manager 内存态）为单一 DTO，供「系统设置 → 任务监控」
// 页面与 /system/tasks 端点消费。纯读聚合——零新表零迁移；操作面（触发/
// 暂停/取消）复用各任务族既有入口（handlers 映射层）。

import (
	"fmt"
	"os"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TaskStatus 任务当前状态。
type TaskStatus string

const (
	TaskStatusRunning  TaskStatus = "running"
	TaskStatusIdle     TaskStatus = "idle"
	TaskStatusFailed   TaskStatus = "failed"
	TaskStatusDisabled TaskStatus = "disabled"
	TaskStatusQueued   TaskStatus = "queued"
	// 方案 A（2026-10-12）：stopped 退役——状态列只承载执行语义（调度语义归
	// 开关列 loop_on&&enabled）；disabled 仅 cert-job 退役行集产出。
	// B1-5（第 74 轮）：cancelled 常量删除——零产出零消费（取消只存在于
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
	LogSizeBytes   int64           `json:"log_size_bytes"`       // 本任务日志文件大小（字节）
	LoopOn         bool            `json:"loop_on"`              // 调度开关当前态（定时/循环/常驻调度列绑定值；用户显式启停持久化于 task_loop_prefs，无记录走默认启动清单）
	BusinessDriven bool            `json:"business_driven"`      // 仅由业务页驱动调度（任务监控 toggle 只读）
	LastRun        *TaskRunInfo    `json:"last_run,omitempty"`
	NextRunAt      string          `json:"next_run_at,omitempty"`
	Runs24h        int             `json:"runs_24h"`
	Success24h     int             `json:"success_24h"`
	Fail24h        int             `json:"fail_24h"`
}

// TaskRunInfo 最近一次运行。
type TaskRunInfo struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	Trigger    string `json:"trigger"`            // manual/auto/startup/caddy-restart/schedule（queue=cert-job 动态行合成值；slave-sync 为历史版本遗留取值，仅展示层保留映射）
	Operator   string `json:"operator,omitempty"` // 手动触发操作者（manual 触发归人；auto/startup=空）
	Result     string `json:"result"`             // success/failed/cancelled/skipped/…
	Message    string `json:"message,omitempty"`
}

// CollectSystemTasks 聚合全部任务族（终态：引擎唯一事实源——全部任务族
// 注册于任务引擎，视图=DescribeAll 元数据+task_runs 真实运行/统计；
// 零收集器零特化）。
func CollectSystemTasks() []TaskInfo {
	te := TaskEngine()
	if te == nil {
		return []TaskInfo{}
	}
	tasks := collectEngineFamilies(te)
	// 证书签发任务动态行（实时非终态 + 24h 内终态——执行状态进任务列表，
	// 队列卡只展示实时队列内容）
	tasks = append(tasks, collectCertJobRows()...)
	return tasks
}

// collectCertJobRows 逐签发任务行：非终态（实时队列内容）+ 24h 内终态
// （结果可见）；id=cert-job:{jobID}，日志走 /certificates/jobs/{id}/logs。
func collectCertJobRows() []TaskInfo {
	// TASK-L3（第 69 轮 P3）：db.DB nil 防护——与引擎侧导出 DB 函数同形
	// （装配顺序变化即 nil panic，曾裸用）。
	if db.DB == nil {
		return nil
	}
	// 2026-10-01 用户裁定：行存在即显示（无状态/时间过滤——曾按
	// 「issued 超 1 天隐藏」窗口过滤致主节点签发行消失）；仅排除从节点
	// 材料物化行（非签发任务，从节点禁签发）。LIMIT 100（U1-P3-2 裁定后
	// 收敛：20 截断「存在即显示」——100 贴近裁定原文且长周期主节点不触顶）。
	//
	// L04-07：镜像行过滤条件绑定「本节点当前为从节点」——曾无条件按 message
	// 前缀过滤，promote 后保留下来的同主节点同步行永久不可见（它们已经是本
	// 节点自己的签发工作项）。读角色失败按主节点处理（行可见：多展示无害，
	// 静默丢行不可恢复）。
	isMaster := 1
	var roleVal int
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&roleVal); err == nil {
		isMaster = roleVal
	}
	rows, err := db.DB.Query(`SELECT id, rule_id, domain, status, COALESCE(message,''), COALESCE(updated_at,created_at)
		FROM cert_jobs
		WHERE ?=1 OR COALESCE(message,'') NOT LIKE '从主节点同步%'
		ORDER BY COALESCE(updated_at,created_at) DESC LIMIT 100`, isMaster)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []TaskInfo
	for rows.Next() {
		var id int
		var ruleID, domain, status, message, updatedAt string
		if err := rows.Scan(&id, &ruleID, &domain, &status, &message, &updatedAt); err != nil {
			continue
		}
		// 终态计数（24h 窗口内 issued=成功 1、failed=失败 1；超窗行显示
		// 但不计数——Runs24h 语义为近 24 小时）。
		success, fail := 0, 0
		if t, perr := time.Parse("2006-01-02 15:04:05", updatedAt); perr == nil && time.Since(t) < 24*time.Hour {
			switch status {
			case "issued":
				success = 1
			case "failed":
				fail = 1
			}
		}
		ti := TaskInfo{
			ID:       fmt.Sprintf("cert-job:%d", id),
			Name:     "ACME 签发 · " + domain,
			Category: "证书",
			Kind:     taskengine.KindOneshot, // 动态签发行=按需触发的工作项
			// 触发语义（2026-10-11 用户裁定）：cert-job 行视为触发任务——可自动
			// 调度（签发守护消费）即可手动调度（证书可重签发）；重试门（在途 409/
			// 退役 429/冷却 429）由 TriggerSystemTask 的 cert-job 分支复用承担。
			// TASK-3（第 70 轮 P4）：disabled 为恒终态退役行——重试门对其恒 429，
			// Triggerable=false 让按钮呈现禁用态（点击必 429 是交互噪音）。
			Triggerable: status != "disabled",
			LastRun: &TaskRunInfo{StartedAt: localDisplayUTC(updatedAt), FinishedAt: localDisplayUTC(updatedAt),
				Trigger: "queue", Result: status, Message: message},
		}
		ti.Success24h, ti.Fail24h = success, fail
		if info, err := os.Stat(CertJobLogPath(ruleID)); err == nil {
			ti.LogSizeBytes = info.Size()
		}
		ti.Status = TaskStatusIdle
		switch status {
		case "failed":
			ti.Status = TaskStatusFailed
		case "issued":
			ti.Status = TaskStatusIdle
		case "queued", "pending":
			ti.Status = TaskStatusQueued
		case "disabled":
			ti.Status = TaskStatusDisabled
		default:
			ti.Status = TaskStatusRunning // 处理中各阶段
		}
		out = append(out, ti)
	}
	if err := rows.Err(); err != nil {
		// U3-P4-4：迭代失败不再静默部分列表（曾 rows.Err 未查）
		Logf("warn", "cert 任务行迭代失败: %v", err)
	}
	return out
}

// collectEngineFamilies 引擎注册族统一视图（终态：零特化零收集器——
// 元数据/开关/下一槽/状态镜像全来自 DescribeAll，最近运行与 24h 统计
// 来自 task_runs，下次时间兜底 last+interval）。
func collectEngineFamilies(te *taskengine.Engine) []TaskInfo {
	var out []TaskInfo
	for _, m := range te.DescribeAll() {
		ti := TaskInfo{
			ID: m.ID, Name: m.Name, Description: m.Description,
			Category: m.Category, Kind: m.Kind,
			Controllable: m.Controllable, Cancellable: m.Cancelable, Triggerable: m.CanTrigger,
			LoopOn: m.LoopOn, BusinessDriven: IsBusinessDrivenTask(m.ID),
		}
		// 节奏：循环=间隔，定时=排程槽，常驻=自管理，触发=手动
		switch m.Kind {
		case taskengine.KindPeriodic:
			if m.IntervalSec > 0 {
				ti.Cadence = "每 " + humanInterval(m.IntervalSec)
			}
		case taskengine.KindScheduled:
			// C2（第 76 轮）：Scheduled 族节奏补显——原缺分支恒空，前端显示「—」；
			// 槽位由 NextSlotFn 按用户配置派生（每日时刻等），具体时间归「下次执行」列。
			ti.Cadence = "定时排程"
		case taskengine.KindDaemon:
			ti.Cadence = "常驻自管理"
		case taskengine.KindOneshot:
			ti.Cadence = "手动触发"
		}
		// TASK-L3（第 69 轮 P3）：db.DB nil 防护（与同层 collectCertJobRows 同形）。
		if m.ID == "cluster-sync" && db.DB != nil {
			var iv int
			if err := db.DB.QueryRow("SELECT COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&iv); err == nil {
				ti.Cadence = fmt.Sprintf("每 %d 秒（用户配置同步间隔）", iv)
			}
		}
		// L1-13：LatestRun 单次查询复用（曾每任务两查）
		latestRun := te.LatestRun(m.ID)
		// 状态分流（方案 A，2026-10-12 用户裁定）：状态列只承载执行语义
		// （运行中/空闲/失败；cert-job 退役行「已禁用」走 cert-job 行集）。
		// 调度语义全部归开关列——调度语义只由 loop_on 表达；business_driven
		// 为只读态（由对应业务页开关驱动调度）。stopped/disabled 不再作为
		// 状态列产出（原「stopped 仅常驻」模型与 disabled 三源混用同轮废除）。
		if m.StatusMirror != "" {
			ti.Status = TaskStatus(m.StatusMirror)
		} else if m.Kind == taskengine.KindDaemon {
			if m.Running {
				ti.Status = TaskStatusRunning
			} else {
				ti.Status = TaskStatusIdle // 未跑=空闲（调度关由开关列表达）
			}
		} else {
			ti.Status = TaskStatusIdle
			if latestRun != nil {
				switch latestRun.Status {
				case "failed":
					ti.Status = TaskStatusFailed
				case "running":
					ti.Status = TaskStatusRunning
				}
			}
		}
		// 下一槽：定时=NextSlotFn（声明式）；循环=last+interval 兜底
		ti.NextRunAt = m.NextSlot
		if m.ID == "cert-waiting-ca" && db.DB != nil {
			// 仅展示「下次 CA 可用时间」，不参与 Periodic 调度；Descriptor 不再携带
			// Scheduled 专用 NextSlotFn。
			var at string
			if err := db.DB.QueryRow(`SELECT COALESCE(MIN(NULLIF(ca_available_after,'')),'') FROM cert_jobs WHERE status='waiting_ca'`).Scan(&at); err == nil {
				if slot := parseUTCSlot(at); !slot.IsZero() {
					ti.NextRunAt = slot.In(CurrentLocation()).Format("2006-01-02 15:04:05")
				}
			}
		}
		if latestRun != nil {
			ti.LastRun = &TaskRunInfo{StartedAt: latestRun.StartedAt, FinishedAt: latestRun.FinishedAt,
				DurationMs: latestRun.DurationMs, Trigger: latestRun.Trigger, Operator: latestRun.Operator,
				Result: latestRun.Status, Message: latestRun.Message}
			if ti.NextRunAt == "" && m.IntervalSec > 0 && m.LoopOn && m.Kind == taskengine.KindPeriodic {
				if t, err := time.ParseInLocation("2006-01-02 15:04:05", latestRun.StartedAt, CurrentLocation()); err == nil {
					ti.NextRunAt = t.Add(time.Duration(m.IntervalSec) * time.Second).Format("2006-01-02 15:04:05")
				}
			}
		}
		// 每任务日志文件大小（tasks/{id}.log stat）
		if info, err := os.Stat(taskengine.TaskLogPath(m.ID)); err == nil {
			ti.LogSizeBytes = info.Size()
		}
		st := te.Stats24h(m.ID)
		ti.Runs24h, ti.Success24h, ti.Fail24h = st.Runs, st.Success, st.Fail
		// 常驻族启动时刻——「常驻 · 启动于」。用该 daemon 最近 boot 行时刻
		// （重启后正确更新）；从未运行的常驻任务（角色门未获/调度关闭未拉起）
		// 置零值——UI '—' 兜底（U1-66-06），不再回退引擎进程启动时刻
		// （=uptime 语义，与「空闲/已停止」状态矛盾）。L1-12（第 65 轮）。
		if m.Kind == taskengine.KindDaemon {
			// 真实运行=本代 boot 行；停用有史=最近一次启动；从未运行且未运行=零值。
			switch {
			case m.Running:
				if latestRun != nil {
					ti.StartedAt = latestRun.StartedAt
				} else {
					ti.StartedAt = te.StartedAt().In(CurrentLocation()).Format("2006-01-02 15:04:05")
				}
			default:
				if latestRun != nil {
					ti.StartedAt = latestRun.StartedAt
				}
			}
		}
		out = append(out, ti)
	}
	return out
}

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

// localDisplayUTC 把 DB datetime('now')/crsTimeLayout 的 UTC 时间串转为
// 配置时区展示（引擎 task_runs 已按配置时区写入——勿二次转换）。
func localDisplayUTC(ts string) string {
	if ts == "" {
		return ts
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.In(CurrentLocation()).Format("2006-01-02 15:04:05")
		}
	}
	return ts
}
