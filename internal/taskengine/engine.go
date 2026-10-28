// Package taskengine 是统一任务引擎（v2.0 四类型标准）：
// 定时(Scheduled)=排程槽驱动 | 常驻(Daemon)=自管理循环 | 循环(Periodic)=固定间隔
// 触发(Oneshot)=手动/代码触发。
// 引擎按 Kind 分流调度/记录/日志——零 flag 零补丁。
package taskengine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
)

// ---- Kind：四类型 ----

type Kind string

const (
	KindScheduled Kind = "scheduled" // 定时：用户配置排程槽，引擎到点执行
	KindDaemon    Kind = "daemon"    // 常驻：自管理循环，引擎仅管生命周期
	KindPeriodic  Kind = "periodic"  // 循环：固定间隔，每轮独立执行
	KindOneshot   Kind = "oneshot"   // 触发：仅手动/代码触发
)

// Role 角色门。
type Role string

const (
	RoleAny        Role = "any"
	RoleMasterOnly Role = "master-only"
	RoleSlaveOnly  Role = "slave-only" // 仅测试注册使用（U1 备注）
)

// RunContext 交给任务体的执行上下文。
type RunContext struct {
	Ctx context.Context
	// Trigger 触发值（开放字符串，调用方声明；task_runs.trigger 列原样落库）：
	// 引擎内建 manual（Trigger/RunSync 手动）、auto（Periodic tick/Daemon）、
	// startup（BootSync）；调用方自声明形态有 caddy-restart（Caddy 崩溃自愈
	// watcher）、schedule（auto-backup 执行器）。前端按值映射展示标签。
	Trigger  string
	Operator string // 手动操作者（审计归人）
	RunID    int64  // 引擎预插行 ID
}

// ---- Descriptor：任务声明 ----

type Descriptor struct {
	ID          string
	Family      string
	Name        string
	Description string
	Category    string
	Kind        Kind

	// Scheduled：返回下一次执行时间（引擎 sleep 到点；zero=无配置）
	NextSlotFn func() time.Time
	// Periodic：返回固定间隔
	IntervalFn func() time.Duration

	// 所有类型：Run 执行业务逻辑
	// Daemon: Run 应阻塞直到 ctx.Done()（自管理循环）
	// 其他: Run 执行一次后返回
	Run func(RunContext) error

	CancelHook func() bool
	// EnabledFn 业务开关门：false=不再调度
	// ——tick 整分支跳过（零执行零落行零节拍推进），开关列显示「已停止」；
	// 手动触发不受此门拦（显式用户意图）。
	EnabledFn func() bool
	// BootSync：Oneshot 任务在引擎初始化尾部同步执行一次（trigger=startup）
	// ——启动型任务的唯一执行通道（曾 main.go 直调+legacy 记录旁路）。
	// 仅允许 RunsOn=RoleAny（注册期强制，启动执行面无角色
	// 语义）；执行面另有 roleAllows 纵深门。
	BootSync   bool
	StatusFn   func() string // 状态镜像
	Cancelable bool
	// RunsOn 角色门唯一事实源（MasterOnly bool 双机制已
	// 收敛删除——调度面 tick 与 Trigger/RunSync 守卫统一走 roleAllows）。
	RunsOn Role
	// RestartOnRoleFlip：Run 体按角色分流时置位（2026-10-03 裁定，
	// cluster-sync 引入）——角色真实翻转即换代重启（旧代 Run 体持旧分支，
	// 不换代则分支与角色脱钩）。未置位的 RoleAny 常驻（如
	// security-events-ingestion）翻转不重启，无换代噪音。
	RestartOnRoleFlip bool
	// LoopRecoveryHint 引擎停调（连续失败达上限）时任务日志给出的恢复入口
	// 提示；空=通用「任务页调度开关或重启进程」。调度层不掌握业务页归属，
	// 业务驱动任务（任务页开关只读）由注册方在装配时注入。
	LoopRecoveryHint string
}

// RunRecord task_runs 行视图。stage/entry_count 两列
// 零写入方（恒零值死列）已随列删除一并移除——DB DDL 与存量库迁移见 db.go
// deadColumnDrops。
type RunRecord struct {
	ID         int64  `json:"id"`
	TaskID     string `json:"task_id"`
	Family     string `json:"family"`
	Trigger    string `json:"trigger"`
	Operator   string `json:"operator,omitempty"` // 手动触发操作者（auto/startup/legacy=空）
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	Message    string `json:"message,omitempty"`
}

var ErrAlreadyRunning = errors.New("taskengine: 任务运行中")
var ErrSchedulingPaused = errors.New("taskengine: 调度已暂停")

// ErrTaskSkipped 任务跳过哨兵：demote 中止等「非故障
// 放弃」语义由 Run 体返回该哨兵，terminalStatus 映射为 task_runs skipped 终态
// （CHECK 约束内既有值，此前零写入方）。
var ErrTaskSkipped = errors.New("taskengine: 任务跳过")

// ErrRunCancelled 用户主动取消哨兵：manager 终态为「已取消」时 Run 体返回
// 本哨兵（terminalStatus 映射 cancelled）。仅靠 ctx.Err() 判定存在竞态窗——
// Cancel 的 hook（manager 取消）先于引擎 ctx 取消返回，Run 若在引擎 ctx
// 取消生效前落定，取消轮会被误记 success。TriggerTaskAsync 对本哨兵与
// context.Canceled 静默分类（不补记「触发失败」）。
var ErrRunCancelled = errors.New("taskengine: 任务已取消")
var ErrNotFound = errors.New("taskengine: 任务未注册")
var ErrEngineStopped = errors.New("taskengine: 引擎已停止")
var ErrNotMaster = errors.New("taskengine: 该操作仅允许在主节点执行")

// ErrUserCancelled 用户显式取消的取消原因（Cancel/CancelHook 通道）。
// 执行侧用 context.Cause(rc.Ctx) 区分「用户取消」与系统性中止
// （demote/导入排空/进程停止）——前者=显式放弃本槽，业务侧据此把排程槽
// 与失败同源推进到下一槽；后者保留「恢复后到期轮补跑」语义，业务侧不动槽
// （引擎侧同样不消费槽，两侧不得只做一半）。
var ErrUserCancelled = errors.New("taskengine: 用户取消")

// errDaemonManualUnsupported 常驻任务手动触发拒绝哨兵（唯一错误源）：
// Trigger/RunSync 入口与 reserveRunInternal 第二道防线同口径——常驻任务仅
// 引擎调度（StartLoop/StopLoop 启停即可），直跑会绕过 startDaemon 生命周期
// 挂钩与常驻循环双跑。
var errDaemonManualUnsupported = errors.New("taskengine: 常驻任务不支持手动触发（启停即可）")

// errDaemonPrematureExit 常驻 Run 未收到取消信号却净返回（实现缺陷/内部
// 条件早退）——按异常退出同口径处理（failed 行 + 有界重拉）。
var errDaemonPrematureExit = errors.New("taskengine: 常驻任务 Run 未收到取消信号却提前返回（实现缺陷或内部条件早退）")
var errPeriodicLoopDisabled = errors.New("taskengine: 周期调度已停止")

// Scheduled admission 同族收口的拒绝哨兵——
// 调度已停止/Kind 错配 与 槽未到期（窗口内被并发改写）分两值，钉测按值断言。
var errScheduledLoopDisabled = errors.New("taskengine: 定时调度已停止")
var errScheduledNotDue = errors.New("taskengine: 定时槽未到期")

// ---- registration ----

type registration struct {
	desc Descriptor

	mu         sync.Mutex
	running    bool
	cancel     context.CancelCauseFunc
	runTrigger string // 在途轮的触发来源（manual/auto/startup/caddy-restart）
	// runTerminalStatus 非空表示 Run 已返回且终态已判定，但 reservation 尚未
	// release；迟到的用户取消不得再把失败轮的待重投槽消费掉。
	runTerminalStatus string
	// runSeq 在途轮代际身份：每次成功占位（reserveRunInternal /
	// tryStartDaemon）自增。CancelHook 先复核代际，执行期间禁止新代占位；
	// 返回后再次复核，旧取消动作（manager hook/c()/槽消费）不得作用于新一轮。
	runSeq            uint64
	cancelHookRunning bool      // CancelHook 执行中禁止新代占位，旧钩子不得触达新 manager 轮
	lastCheck         time.Time // Periodic：最近到期判定基准
	nextScheduledTime time.Time // Scheduled：下一槽（槽缓存+降频求值，见 tick）
	loopEnabled       bool      // 循环/调度开关
	pendingRestart    bool      // daemon restart 意图：旧 Run 退出后自动拉起新代
	// 常驻异常退出有界重拉状态。
	abnormalRestarts int  // 连续异常退出次数（健康运行一段后或显式重启归零）
	relaunchPending  bool // 退避等待中的重拉已排定（防重复排定）
	// restartExhausted 标记「自愈预算用尽且已停止调度」：此时
	// loopEnabled=false，与用户主动停止同形；监控视图需区分两者才能把
	// 「永久停摆」呈现为 failed。用户显式重启/新工作唤醒会复位。
	restartExhausted bool
	// Scheduled 失败退避兜底：Run 早退不推进槽（槽未推进+本轮 failed）时，
	// tick 不得按节拍无限重投（TickInterval=1s 时 ≈8.6 万行 task_runs/天）。
	// 退避 1s→5s→30s 封顶（与常驻重拉 defaultDaemonRestartDelays 同形）；
	// 槽推进（业务侧 advanceSlot）/成功轮即清零。手动触发不经本退避
	// （admission 不查 schedRetryAfter——显式意图优先）。
	schedFailStreak        int
	schedRetryAfter        time.Time
	schedBackoffLastWarnAt time.Time
	// schedStopReason 引擎自行停调的来源标记（ScheduleStopReason*）：
	// 停调时 loopEnabled=false，与用户主动停止同形——监控视图据此把「引擎
	// 停调」与「用户停止」分开呈现，并指向可执行的恢复入口。恢复调度
	// （resetScheduleProgressLocked）即清空。
	schedStopReason string
	// schedDoneSlot 已消费的排程槽：同一槽值只执行一次（success 落定后
	// 业务未把槽推进到未来，或用户在任务监控显式取消**自动轮**的**已到期**
	// 槽——取消=显式放弃本槽）。tick 与 admission 的到期判定要求
	// slot > schedDoneSlot，槽被业务推进/重排为新值后自然恢复到期语义；
	// StartLoop 关→开与业务重排经 ResetScheduleProgress 显式复位。
	// 手动触发轮取消不消费槽（手动执行不改变预约：未来槽是下一次预约，
	// 判定其归属不成立——曾无条件消费未来槽导致自动更新永久停摆）。
	// failed 轮不消费槽（由上方退避兜底重投）；skipped（demote 中止）不消费
	// ——promote 后到期槽补跑语义保留；导入排空取消（CancelInFlightRuns，
	// 不经 Cancel）与进程停止不消费——恢复后到期轮补跑（这些系统性中止的
	// ctx 取消原因不是 ErrUserCancelled，业务侧同样不推进排程槽）。
	schedDoneSlot time.Time
	// schedSlotEvalAt 槽闭包最近求值时刻（Scheduled 降频：槽远期/已消费时
	// 不必每 tick 重读 DB，仅临近到期前导窗或重评地板周期到点才再求值）。
	schedSlotEvalAt time.Time
}

// ---- Engine ----

type Engine struct {
	opts Options
	mu   sync.RWMutex
	regs map[string]*registration

	roleMu sync.RWMutex
	role   bool

	schedStop    chan struct{}
	bootSyncDone atomic.Bool
	schedDone    chan struct{}
	// stopped 原子化：daemon 退出清理路径在 r.mu
	// 临界区外复核——不得为读它反向嵌套 e.mu（Stop 持 e.mu→r.mu）。
	stopped  atomic.Bool
	daemonWG sync.WaitGroup // daemon goroutine 退出等待（2026-10-04 测试污染修复）
	runWG    sync.WaitGroup // Scheduled/Periodic/Oneshot 在途 Run 退出等待
	// inFlight 是 Scheduled/Periodic/Oneshot 在途 Run 计数
	// runWG 无可取消 Wait，配置导入的「暂停 + 有界排空」需要可轮询计数。
	// 与 runWG.Add/Done 严格配对（唯一登记点 reserveRunInternal）。
	inFlight atomic.Int64

	// daemonRestartDelays 常驻异常退出后的有界重拉退避表
	daemonRestartDelays []time.Duration

	// schedPaused 暂停 tick 与新执行登记：装配期 BootSync（startup 触发）
	// 除外；配置导入期间 Trigger/RunSync/runNow 同样拒绝，保证在途只减不增。
	schedPaused atomic.Bool
}

type Options struct {
	TickInterval time.Duration
	// DaemonRestartDelays 常驻任务异常退出（Run 返回错误/panic）后的有界自动
	// 重拉退避：长度=最大重拉次数，逐次消耗。空=引擎
	// 默认 1s/5s/30s（三次用尽后停止调度并留痕，防紧循环）。
	DaemonRestartDelays []time.Duration
	// StartPaused：以暂停调度形态启动——装配方在
	// RunBootSyncTasks 完成后必须调 ResumeScheduling，否则周期/定时任务
	// 与手动/自动执行（startup 豁免）永不投递。
	// 作用域边界（有意设计）：暂停只覆盖 tick 投递与 Trigger/RunSync/runNow
	// 登记，**不覆盖常驻族**——Daemon 的 StartLoop→tryStartDaemon 照常拉起
	// （常驻 Run 体起步即真实接管服务，如 cert-issuance→StartACME→部署重试）。
	// 因此「装配期不写部署面」由装配方的配置屏障承担
	// （services.InitTaskEngine 在默认启动前 BeginConfigImportHold，BootSync
	// 完成后 EndConfigImportHold）。屏障的**实际覆盖范围只有部署面**（证书
	// 签发 lifecycle / CA 队列 / 证书部署重试，见 services.startCertIssuance
	// Lifecycle 与 caqueue 的 configImportHoldActive 门）：security-events-
	// ingestion（只读尾读）与 cluster-sync 仍在 BootSync 前启动，行为与引入
	// 屏障前一致，其终态由各自快照应用/巡检收敛。不得把常驻启停并入
	// schedPaused。
	StartPaused bool
}

// 默认常驻重拉退避（1s/5s/30s）与「健康运行」判定阈值：Run 存活超过该
// 阈值再异常退出视为新故障（重置重拉预算），避免历史抖动永久耗尽预算。
var defaultDaemonRestartDelays = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

const daemonAbnormalResetAfter = time.Minute

// Scheduled 槽闭包降频参数（测试可调——生产装配后不再变更）：
// schedSlotEvalLead=到期前导窗（窗内每 tick 求值，保证到点即投）；
// schedSlotEvalFloor=槽远期/已消费时的重评地板周期（收敛用户重排/带外
// 改库造成的陈旧缓存——生效延迟上界即本周期）。
//
// schedSlotEvalFloor 用原子值承载（纳秒）：测试用「缩短地板」把分钟级周期拉进
// 时间尺度内，并在 cleanup 里写回原值——cleanup 与仍存活的 tick goroutine
// 并发（引擎停止的 cleanup 与地板恢复的 cleanup 之间没有先后保证），普通
// time.Duration 会让 -race 报数据竞争。读侧只多一次原子载入。
var (
	schedSlotEvalLead  = 30 * time.Second
	schedSlotEvalFloor atomic.Int64
)

func init() {
	schedSlotEvalFloor.Store(int64(time.Minute))
}

func NewEngine(opts Options) *Engine {
	if opts.TickInterval <= 0 {
		opts.TickInterval = time.Second
	}
	delays := opts.DaemonRestartDelays
	if len(delays) == 0 {
		delays = defaultDaemonRestartDelays
	}
	e := &Engine{
		opts: opts, regs: map[string]*registration{}, role: true,
		schedStop: make(chan struct{}), schedDone: make(chan struct{}),
		daemonRestartDelays: append([]time.Duration(nil), delays...),
	}
	e.schedPaused.Store(opts.StartPaused)
	go e.scheduleLoop()
	return e
}

// ResumeScheduling 恢复 tick 与手动/自动执行。幂等；与 runNow 登记共用
// e.mu，保证暂停/恢复边界与 inFlight 登记严格定序。
func (e *Engine) ResumeScheduling() {
	e.mu.Lock()
	e.schedPaused.Store(false)
	e.mu.Unlock()
}

// IsStopped 返回引擎是否已停止（测试装配据此避免复用停止实例）。
func (e *Engine) IsStopped() bool { return e.stopped.Load() }

// Done 引擎完全停止信号（调度循环已退出）：供绑定的后台 goroutine（角色
// 对账等）立即退出，而不用等下一个周期轮询 IsStopped。
func (e *Engine) Done() <-chan struct{} { return e.schedDone }

// engineStopDrainTimeout 是 Stop 等待在途 Run/daemon 的兜底上限。
// cert 四 tick / log-cleanup 中尚未上下文化的文件操作段不消费 rc.Ctx；
// audit-retention 已在首段查询、批间和分段间响应取消。无界 Wait 仍可能被
// 未上下文化的任务段拖到容器 grace 期结束后 SIGKILL，造成审计/日志尾部丢失。
const engineStopDrainTimeout = 30 * time.Second

func (e *Engine) Stop() { e.StopWithTimeout(engineStopDrainTimeout) }

// StopWithTimeout 与 Stop 同语义，但有界等待在途 Run/daemon 落定：超时后
// 记录仍未退出的任务并放弃等待（进程退出优先；未落定行由孤儿恢复处理）。
func (e *Engine) StopWithTimeout(timeout time.Duration) {
	e.mu.Lock()
	if e.stopped.Load() {
		e.mu.Unlock()
		return
	}
	e.stopped.Store(true)
	close(e.schedStop)
	for _, r := range e.regs {
		r.mu.Lock()
		if r.cancel != nil {
			// 进程停止=系统性中止（非用户取消）：不带 ErrUserCancelled
			// 原因——业务侧不得因此推进排程槽，重启后到期轮仍补跑。
			r.cancel(nil)
		}
		r.mu.Unlock()
	}
	e.mu.Unlock()
	if timeout <= 0 {
		timeout = engineStopDrainTimeout
	}
	deadline := time.Now().Add(timeout)
	// 调度 goroutine 的等待同样纳入 timeout 预算——
	// tick 在调度 goroutine 内同步调用装配方闭包（IntervalFn/NextSlotFn，
	// 生产为 DB 直读），闭包阻塞（DB 锁/驱动挂起）时 scheduleLoop 永不退出，
	// 无界 <-e.schedDone 会把进程退出拖到容器 grace 后 SIGKILL，与本常量
	// 「审计/日志尾部丢失」的防护目标相悖。
	select {
	case <-e.schedDone:
	case <-time.After(timeout):
		log.Printf("WARNING: taskengine: 引擎停止等待调度循环退出超时（%s），放弃等待继续退出（调度闭包可能阻塞，遗留 goroutine 随进程退出回收）", timeout)
	}
	settled := make(chan struct{})
	go func() {
		e.runWG.Wait()    // 等全部 Scheduled/Periodic/Oneshot 在途 Run 落定终态
		e.daemonWG.Wait() // 等全部 daemon goroutine 退出——防止跨测试/跨引擎残留（2026-10-04）
		close(settled)
	}()
	logUnsettled := func() {
		if ids := e.unsettledTaskIDs(); len(ids) > 0 {
			log.Printf("WARNING: taskengine: 引擎停止等待在途任务超时（%s），放弃等待继续退出；未落定任务: %s",
				timeout, strings.Join(ids, ","))
		}
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		select {
		case <-settled:
		default:
			logUnsettled()
		}
		return
	}
	select {
	case <-settled:
	case <-time.After(remaining):
		logUnsettled()
	}
}

// unsettledTaskIDs 列出 Stop 超时后仍未退出 Run 的任务（诊断用）。
func (e *Engine) unsettledTaskIDs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, 4)
	for id, r := range e.regs {
		r.mu.Lock()
		running := r.running
		r.mu.Unlock()
		if running {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (e *Engine) SetRole(isMaster bool) {
	e.roleMu.Lock()
	flipped := e.role != isMaster
	e.role = isMaster
	e.roleMu.Unlock()
	// Daemon 生命周期随角色翻转：master-only daemon 在 demote 时停止、
	// promote 时拉起（loopEnabled 保持用户调度开关语义）。SetRole 重申
	// （生产启动/翻转期为三连调用）不是重启意图——tryStartDaemon 传
	// false，不再误栽 pendingRestart。Periodic 不启停：角色真实
	// 获得时置零节拍使下一 tick 即到期（原置零分支位于仅收集
	// Daemon 的切片内不可达）；角色不符时中止在途 Run（与
	// Scheduled 同型）。Scheduled/Oneshot 在途 Run
	// 随角色不符中止——demote 后继续跑完会让从节点写版本行/名单/规则树，打破
	// 只读不变量；取消经 rc.Ctx 传播，三库 Run 体据此落 skipped（与起点
	// 角色复查同语义）。promote 无需动作（tick 每轮重读 NextSlotFn 自动
	// 到点触发）。
	e.mu.RLock()
	targets := make([]*registration, 0, len(e.regs))
	for _, r := range e.regs {
		// 全集遍历（原四选 Kind 过滤是恒真条件——Kind 枚举仅
		// Scheduled/Daemon/Periodic/Oneshot 四值且注册期校验，过滤零效果）。
		targets = append(targets, r)
	}
	e.mu.RUnlock()
	for _, r := range targets {
		if r.desc.Kind == KindPeriodic {
			// 角色不符（demote/重申从节点）时取消在途 Run——
			// 与下方 Scheduled 分支同型。Periodic 在途 Run
			// （tick/手动触发）跑完会让从节点写库，打破只读不变量；取消经
			// rc.Ctx 传播，Run 体据此落 skipped。loopEnabled 保留——promote 后
			// tick 自动恢复排程。
			if !e.roleAllows(r.desc.RunsOn) {
				r.mu.Lock()
				r.lastCheck = time.Time{}
				c := r.cancel
				r.mu.Unlock()
				if c != nil {
					c(nil) // demote 中止=系统性中止，非用户取消
				}
				continue
			}
			// 节拍复位只对「权限真实变化」的任务成立：RoleAny 周期族
			// （日志/审计/安全事件保留、指标孤儿清理、配置看门狗）不受角色
			// 门约束，翻转时置零会让每日任务立即多跑一轮（幂等的越档执行）。
			if flipped && r.desc.RunsOn != RoleAny {
				r.mu.Lock()
				r.lastCheck = time.Time{}
				r.mu.Unlock()
			}
			continue
		}
		if r.desc.Kind == KindScheduled || r.desc.Kind == KindOneshot {
			// 角色不符（demote/重申角色）：取消在途 Run。Oneshot 与
			// Scheduled 同守只写角色不变量；RoleAny（含 BootSync）恒通过，
			// 不会因角色翻转被误取消。loopEnabled 保留，后续角色恢复不影响
			// 已完成/已取消的单次历史。
			if !e.roleAllows(r.desc.RunsOn) {
				r.mu.Lock()
				c := r.cancel
				r.mu.Unlock()
				if c != nil {
					c(nil) // demote 中止=系统性中止：不消费槽、业务侧不推进槽
				}
			}
			continue
		}
		if e.roleAllows(r.desc.RunsOn) {
			// 角色真实翻转 × Run 体按角色分流（RestartOnRoleFlip）：换代
			// 重启——旧代持旧分支（2026-10-03 裁定）。三连重申调用仅真实
			// 翻转的第一次触发（flipped 门）；换代走 pendingRestart 通道，
			// 旧代 [done] stopped 后新代接续。
			if flipped && r.desc.RestartOnRoleFlip {
				r.mu.Lock()
				if r.running && r.cancel != nil {
					r.pendingRestart = true
					c := r.cancel
					r.mu.Unlock()
					c(nil) // 换代重启=系统性中止
					continue
				}
				r.mu.Unlock()
			}
			e.tryStartDaemon(r, flipped && (r.desc.RestartOnRoleFlip || r.desc.RunsOn != RoleAny))
			continue
		}
		// 角色不符：仅取消 Run（loopEnabled 保留——promote 后自动拉起，
		// 用户调度开关语义不被角色翻转隐式改写）
		r.mu.Lock()
		c := r.cancel
		r.mu.Unlock()
		if c != nil {
			c(nil) // demote 中止=系统性中止
		}
	}
}

// IsTaskInFlight 任务 Run 是否在途（handler 同步单飞预检）。
func (e *Engine) IsTaskInFlight(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (e *Engine) isMaster() bool {
	e.roleMu.RLock()
	defer e.roleMu.RUnlock()
	return e.role
}

// IsMaster 当前角色（导出——Run 体按角色分流需与角色门同源读取；
// 2026-10-03 cluster-sync 主从分支裁定引入）。
func (e *Engine) IsMaster() bool { return e.isMaster() }

// tryStartDaemon daemon 空闲且调度开时原子启动（锁内 CAS——并发调用方
// 只有一个胜出； 统一入口）。restartIntent 仅在 StartLoop 的
// 关→开真实重启过渡时为 true——SetRole 角色重申恒 false。
func (e *Engine) tryStartDaemon(r *registration, restartIntent bool) {
	e.mu.RLock()
	if e.stopped.Load() {
		e.mu.RUnlock()
		return
	}
	// 角色门内化进 CAS 临界区（锁序 e.mu→roleMu→r.mu，
	// 与 runNow 的 roleMu→r.mu 同向）——此前角色只是调用方预检，预检与
	// running 占位之间存在窗口：demote 在预检后完成 SetRole 的 cancel 遍历、
	// 未及本次登记，master-only daemon 即在 slave 上存活。现角色复查与
	// cancel 登记同属一个 roleMu 读临界区：SetRole 写锁要么先于本门
	// （role=false 直接拒绝启动），要么后于登记（demote 的 cancel 遍历
	// 必命中本次登记的 cancel）。
	e.roleMu.RLock()
	if !e.roleAllowsLocked(r.desc.RunsOn) {
		e.roleMu.RUnlock()
		e.mu.RUnlock()
		return
	}
	r.mu.Lock()
	if !r.loopEnabled {
		r.mu.Unlock()
		e.roleMu.RUnlock()
		e.mu.RUnlock()
		return
	}
	if r.running {
		// 在跑但已请求停止（restart 的 Stop 半程）——记意图，
		// 旧 Run goroutine 退出清理时自动拉起新代
		if restartIntent && r.cancel != nil {
			r.pendingRestart = true
		}
		r.mu.Unlock()
		e.roleMu.RUnlock()
		e.mu.RUnlock()
		return
	}
	// 占位与 cancel 登记同临界区——StopLoop/Stop/角色翻转
	// 不再有「running=true 但 cancel==nil」的首停信号丢失窗口。
	r.running = true
	r.runSeq++
	ctx, cancel := context.WithCancelCause(context.Background())
	r.cancel = cancel
	r.mu.Unlock()
	e.roleMu.RUnlock()
	e.mu.RUnlock()
	e.startDaemon(r.desc.ID, r, ctx, cancel)
}

func (e *Engine) Register(d Descriptor) error {
	if d.ID == "" || d.Family == "" {
		return errors.New("taskengine: ID/Family 必填")
	}
	if d.Name == "" {
		return errors.New("taskengine: Name 必填")
	}
	if d.Run == nil {
		return errors.New("taskengine: Run 必填")
	}
	switch d.Kind {
	case KindScheduled, KindDaemon, KindPeriodic, KindOneshot:
	default:
		return fmt.Errorf("taskengine: %s 的 Kind 非法（仅 scheduled/daemon/periodic/oneshot）", d.ID)
	}
	// BootSync 启动执行面无角色语义，必须显式声明 RoleAny；空值不得
	// 走下方旧任务兼容默认值，否则「未声明」被误当成显式声明。
	if d.BootSync && d.RunsOn != RoleAny {
		return fmt.Errorf("taskengine: %s 为 BootSync 任务，RunsOn 必须显式声明 RoleAny（启动执行面无角色语义）", d.ID)
	}
	if d.RunsOn == "" {
		d.RunsOn = RoleAny
	}
	switch d.RunsOn {
	case RoleAny, RoleMasterOnly, RoleSlaveOnly:
	default:
		return fmt.Errorf("taskengine: %s 的 RunsOn 非法（仅 any/master-only/slave-only）", d.ID)
	}
	if d.BootSync && d.Kind != KindOneshot {
		return fmt.Errorf("taskengine: %s 为 BootSync 任务，Kind 必须为 Oneshot", d.ID)
	}
	// Kind 与 Fn 配套校验——Periodic 缺 IntervalFn 会在
	// tick 处 nil 调用 panic（scheduleLoop goroutine 崩→进程退出），Scheduled 缺
	// NextSlotFn 则永不到期静默停摆。注册期响亮拒绝。
	if d.Kind == KindPeriodic && d.IntervalFn == nil {
		return fmt.Errorf("taskengine: %s 为 Periodic 任务，必须提供 IntervalFn", d.ID)
	}
	if d.Kind == KindScheduled && d.NextSlotFn == nil {
		return fmt.Errorf("taskengine: %s 为 Scheduled 任务，必须提供 NextSlotFn", d.ID)
	}
	// 调度 Fn 按 Kind 白名单：每族只在固定分支消费（IntervalFn 仅 Periodic、
	// NextSlotFn 仅 Scheduled、EnabledFn 仅 Scheduled/Periodic），错配声明
	// 即静默忽略——注册方会误以为调度面/业务门生效，注册期响亮拒绝。
	if d.IntervalFn != nil && d.Kind != KindPeriodic {
		return fmt.Errorf("taskengine: %s 声明 IntervalFn 但 Kind=%s（仅 Periodic 消费，声明即静默忽略）", d.ID, d.Kind)
	}
	if d.NextSlotFn != nil && d.Kind != KindScheduled {
		return fmt.Errorf("taskengine: %s 声明 NextSlotFn 但 Kind=%s（仅 Scheduled 消费，声明即静默忽略）", d.ID, d.Kind)
	}
	// Daemon 不进周期 tick——EnabledFn 在调度面永不消费
	//（静默忽略）。挂 EnabledFn 会让注册方误以为业务门生效，注册期响亮拒绝；
	// 常驻业务门归 Run 体首行（autoban 形态，见 docs/task-engine-standard.md §4）。
	if d.Kind == KindDaemon && d.EnabledFn != nil {
		return fmt.Errorf("taskengine: %s 为常驻任务，EnabledFn 不参与调度（Daemon 不进 tick，静默忽略）——业务门须内置到 Run 体", d.ID)
	}
	// 同族：Oneshot 不进 tick（tick 只派发 Scheduled/Periodic），EnabledFn 声
	// 明在触发形态同样静默忽略。
	if d.EnabledFn != nil && d.Kind != KindScheduled && d.Kind != KindPeriodic {
		return fmt.Errorf("taskengine: %s 声明 EnabledFn 但 Kind=%s（仅 Scheduled/Periodic 在 tick 消费，声明即静默忽略）", d.ID, d.Kind)
	}
	// RestartOnRoleFlip 仅在 daemon 分支消费（角色翻转换代）；声明于
	// Periodic/Scheduled/Oneshot 静默无效——装配错误注册期响亮拒绝（与
	// Daemon∧EnabledFn 同范式）。
	if d.RestartOnRoleFlip && d.Kind != KindDaemon {
		return fmt.Errorf("taskengine: %s 声明 RestartOnRoleFlip 但 Kind=%s（仅常驻族消费角色翻转换代，声明即静默忽略）", d.ID, d.Kind)
	}
	// 常驻族不支持取消：Cancel 只按 Cancelable 路由，被取消的 daemon 走
	// 「非异常退出」分支——loop_on 保持 true 而 running=false，监控判 idle，
	// 常驻采集/签发/同步永久停摆且无任何信号（启停应走 StartLoop/StopLoop）。
	// 与 Daemon∧EnabledFn 同范式：声明即不可达/死态的组注册期响亮拒绝。
	if d.Kind == KindDaemon && d.Cancelable {
		return fmt.Errorf("taskengine: %s 为常驻任务，不支持 Cancelable（取消会永久停止且无异常信号，启停请用 StartLoop/StopLoop）", d.ID)
	}
	// CancelHook 仅在 Cancelable=true 时可达（Cancel 先按 Cancelable 短路）——
	// 未置 Cancelable 的 CancelHook 永不触达，注册期响亮拒绝。
	if d.CancelHook != nil && !d.Cancelable {
		return fmt.Errorf("taskengine: %s 声明 CancelHook 但未置 Cancelable（CancelHook 永不可达，静默忽略）", d.ID)
	}
	// 已停止的引擎不会再有调度 goroutine 判活：注册成功只会得到「已注册但
	// 永不被调度」的静默形态（StartLoop 对 stopped 恒 no-op）。响亮拒绝，
	// 装配方须显式新建引擎。门排在描述符校验之后：停止态下传入非法描述符时
	// 先报真正缺失的字段（排障指向正确），合法描述符仍被 ErrEngineStopped 拒绝。
	if e.stopped.Load() {
		return ErrEngineStopped
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.regs[d.ID]; exists {
		return fmt.Errorf("taskengine: %s 重复注册", d.ID)
	}
	e.regs[d.ID] = &registration{desc: d}
	return nil
}

// Trigger 同步触发任务（pause/角色/daemon 门 + runNow 执行）。
// 测试专供入口：生产手动触发一律走
// RunAsync/RunAsyncResult（taskmonitor/库更新/备份端点经
// services.TriggerTaskAsync 单源）；本函数生产零调用方，保留供测试
// 同步驱动任务体。
func (e *Engine) Trigger(id, trigger, operator string) error {
	if e.schedPaused.Load() && trigger != "startup" {
		return ErrSchedulingPaused
	}
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return ErrNotFound
	}
	// 纵深：常驻族不暴露手动触发（启停即可）——handler CanTrigger 门
	// 之外的第二道防线；此前 Trigger 可直跑 daemon Run 绕过真实生命周期挂钩。
	if r.desc.Kind == KindDaemon {
		return errDaemonManualUnsupported
	}
	// 角色门收敛为 roleAllows(RunsOn) 单机制——与调度面
	// tick 同函数；原 MasterOnly bool 双机制下 cert 族/auto-backup（仅声明
	// RunsOn）的手动触发门在从节点形同虚设。
	if !e.roleAllows(r.desc.RunsOn) {
		return ErrNotMaster
	}
	_, err := e.runNow(id, trigger, operator)
	return err
}

// RunSync 同步执行一次并返回 runID（handler 直调入口——响应需要行视图）。
func (e *Engine) RunSync(id, trigger, operator string) (int64, error) {
	return e.runSync(id, trigger, operator, false)
}

// RunSyncQuiet 与 RunSync 同守卫/同执行语义，但不落 task_runs 行（任务日志
// 仍留痕）。供高频自愈重试使用：连续失败的重试轮由调用方按退避与「状态变化/
// 首次/每 N 轮」策略决定何时走 RunSync 落行，其余轮走本入口执行同一 Run 体——
// 既保持「一切任务统一引擎调度」（不绕过引擎直调 Run 体），又避免每 2s 一条
// 失败行把任务历史淹没。
func (e *Engine) RunSyncQuiet(id, trigger, operator string) (int64, error) {
	return e.runSync(id, trigger, operator, true)
}

func (e *Engine) runSync(id, trigger, operator string, quiet bool) (int64, error) {
	if e.schedPaused.Load() && trigger != "startup" {
		return 0, ErrSchedulingPaused
	}
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return 0, ErrNotFound
	}
	// 与 Trigger 同型守卫——常驻任务仅引擎调度（启停即可），
	// RunSync 直调会绕过 startDaemon 生命周期挂钩与常驻循环双跑（防御缺口：
	// 当前调用面未触达，B 批裁定语义=常驻任务仅引擎调度）。
	if r.desc.Kind == KindDaemon {
		return 0, errDaemonManualUnsupported
	}
	if !e.roleAllows(r.desc.RunsOn) {
		return 0, ErrNotMaster
	}
	res, err := e.reserveRun(id, trigger)
	if err != nil {
		return 0, err
	}
	defer res.release()
	res.suppressRunRow = quiet
	return e.executeRun(res, id, trigger, operator)
}

// RunBootSyncTasks 同步执行全部 BootSync Oneshot（InitTaskEngine 尾部调用
// ——面板监听前完成，保持「载入完成前系统不可达」不变量）。幂等：仅首轮
// 生效（重复调用零动作——启动执行全局恰一次）。
func (e *Engine) RunBootSyncTasks() {
	if !e.bootSyncDone.CompareAndSwap(false, true) {
		return
	}
	e.mu.RLock()
	type item struct {
		id string
		r  *registration
	}
	items := make([]item, 0, 4)
	for id, r := range e.regs {
		if r.desc.BootSync && r.desc.Kind == KindOneshot {
			items = append(items, item{id, r})
		}
	}
	e.mu.RUnlock()
	for _, it := range items {
		// 与 Trigger/RunSync/tick 同款角色门（纵深防御——
		// 注册期已拒绝 BootSync∧RunsOn≠RoleAny，此处拦绕过 Register 的直注
		// 形态）。RoleAny 恒真，现行唯一 BootSync 任务（startup:config-load，
		// RunsOn=RoleAny）行为不变。
		if !e.roleAllows(it.r.desc.RunsOn) {
			continue
		}
		_, _ = e.runNow(it.id, "startup", "")
	}
}

func (e *Engine) Cancel(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil || !r.desc.Cancelable || !e.roleAllows(r.desc.RunsOn) {
		return false
	}
	r.mu.Lock()
	c := r.cancel
	running := r.running
	trigger := r.runTrigger
	// 在途轮代际快照：CancelHook 是任意时长窗口（manager 取消可能阻塞）。
	// hook 前置复核并登记 cancelHookRunning，阻止本轮结束后新代在钩子窗口
	// 内占位；复锁时再次复核，避免旧请求取消/消费新轮。
	seq := r.runSeq
	r.mu.Unlock()
	hook := r.desc.CancelHook
	if hook != nil {
		r.mu.Lock()
		if !r.running || r.runSeq != seq || r.runTrigger != trigger || r.cancelHookRunning {
			r.mu.Unlock()
			return false
		}
		r.cancelHookRunning = true
		r.mu.Unlock()
		ok := hook()
		r.mu.Lock()
		r.cancelHookRunning = false
		if !ok {
			r.mu.Unlock()
			// hook 拒绝=取消未生效：不得消费槽（否则「取消失败」却付出
			// 「本槽不再重投」的代价，退避兜底被 schedDoneSlot 门永久压掉）。
			return false
		}
		// manager 侧取消成功后同步取消引擎 ctx——Run 返回
		// 时 terminalStatus 判 cancelled（曾 manager 取消路径引擎 ctx 不动，
		// 终态落 failed，历史无法区分「用户取消」与「真失败」）。
		// 取消原因=ErrUserCancelled：业务侧据此推进排程槽（与失败同源），
		// 让下一槽正常投递而非永久停摆。
		if c != nil && r.running && r.runSeq == seq && r.runTrigger == trigger {
			c(ErrUserCancelled)
			consumeCancelledSlotLocked(r, trigger)
		}
		r.mu.Unlock()
		return true
	}
	if c == nil || !running {
		return false
	}
	r.mu.Lock()
	if r.running && r.runSeq == seq {
		c(ErrUserCancelled)
		consumeCancelledSlotLocked(r, trigger)
	}
	r.mu.Unlock()
	return true
}

// consumeCancelledSlotLocked 用户取消生效后消费「本轮在途执行所属的已到期
// 自动槽」——取消落定后 tick 不得按「槽仍过期」立即重投同一槽（整轮全量重
// 下载/重复整包备份）。
//
// 边界（两条同时成立才消费）：
//   - 在途轮必须是 auto：手动触发不推进/不改写预约（slotAdvanceIfAuto 契约），
//     取消手动轮自然也不得动预约；未来槽是下一次预约，与手动轮无归属关系。
//   - 槽必须已到期：未来槽被标记已消费后水位永远压住该槽（tick 的
//     slot > schedDoneSlot 门），而槽只会被业务执行推进——下次执行又被
//     本门拦下，形成永久静默停摆。
//
// 仅用户取消路径（本函数）消费；demote（SetRole 直调 cancel）与导入排空
// （CancelInFlightRuns）不消费——两者「恢复后到期轮补跑」语义保留。
// 调用方持 r.mu；r.running/runTrigger 仍在窗口内被并发复核（在途轮已自然
// 结束时由 executeRun 尾部按其终态决定消费语义，失败轮不得被取消动作吞掉
// 重投）。
func consumeCancelledSlotLocked(r *registration, trigger string) {
	if r.desc.Kind != KindScheduled || trigger != "auto" || !r.running || r.runTrigger != trigger || r.runTerminalStatus != "" {
		return
	}
	slot := r.nextScheduledTime
	if slot.IsZero() || slot.After(time.Now()) || !slot.After(r.schedDoneSlot) {
		return
	}
	r.schedDoneSlot = slot
}

// CancelInFlightRuns 取消全部在途 Scheduled/Periodic/Oneshot Run
// 配置导入/还原全量替换的前置排空——证书队列 PauseAndDrain
// 之外的其余任务族在途执行会在导入提交后把旧库状态写回新库
// 。Run 体经 rc.Ctx 收到取消，按既有语义落
// cancelled/skipped 终态。Daemon 不在此列（常驻族取消即停摆、需显式
// 拉起，生命周期归角色门/启停管理）。返回本次取消的在途 Run 数。
func (e *Engine) CancelInFlightRuns() int {
	e.mu.RLock()
	regs := make([]*registration, 0, len(e.regs))
	for _, r := range e.regs {
		if r.desc.Kind != KindDaemon && e.roleAllows(r.desc.RunsOn) {
			regs = append(regs, r)
		}
	}
	e.mu.RUnlock()
	cancelled := 0
	for _, r := range regs {
		r.mu.Lock()
		c := r.cancel
		running := r.running
		r.mu.Unlock()
		if c != nil && running {
			// 导入排空=系统性中止（非用户取消）：不带 ErrUserCancelled
			// 原因——业务侧不推进排程槽，导入完成后到期轮补跑。
			c(nil)
			cancelled++
		}
	}
	return cancelled
}

// PauseScheduling 暂停 tick 投递与 Trigger/RunSync/runNow 新执行
// 配置导入/还原的前置排空。BootSync 的
// startup 触发是装配期唯一豁免；StartLoop 只改调度偏好，不受此门影响。
// 与 runNow 的 inFlight 登记共用 e.mu：函数返回后，在途集合只减不增。
// 必须与 ResumeScheduling 成对使用（导入失败路径也要恢复）。
func (e *Engine) PauseScheduling() {
	e.mu.Lock()
	e.schedPaused.Store(true)
	e.mu.Unlock()
}

// WaitInFlightRuns 等待全部在途 Scheduled/Periodic/Oneshot Run 落定终态，
// 直到 ctx 完成（超时/取消）。返回 true=已排空，false=ctx 先到期（由调用方
// 决定 409/继续并留痕）。Daemon 不计入（常驻族不归导入排空管理）。
//
// 与 CancelInFlightRuns 配合的标准排空序列（handlers/config_import_coordinator）：
//
//	engine.PauseScheduling()          // 关派发（在途集合只减不增）
//	engine.CancelInFlightRuns()       // 发取消信号
//	engine.WaitInFlightRuns(ctx)      // 有界等待落定（ctx 自带 deadline）
//	...导入事务...
//	engine.ResumeScheduling()         // 成功/失败都必须恢复
//
// 注意：Run 体中仍不消费 rc.Ctx 的任务段（log-cleanup 的文件操作段、
// cluster 快照提交后副作用等）取消等价 no-op，等待会跑满该段时长——因此 ctx
// deadline 仍是必需的兜底（建议与证书队列 PauseAndDrain 同量级 30s）。证书
// 四 tick 已全部消费 rc.Ctx（waiting-ca/reconcile/续期扫描/手动巡检），可被
// CancelInFlightRuns 中止。实现为计数轮询
// （runWG 无取消语义；暂停后计数单调递减，无伪排空窗口）。
func (e *Engine) WaitInFlightRuns(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.inFlight.Load() <= 0 {
		return true
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return e.inFlight.Load() <= 0
		case <-ticker.C:
			if e.inFlight.Load() <= 0 {
				return true
			}
		}
	}
}

// ---- StartLoop/StopLoop：循环启停 ----
// Periodic/Scheduled: 设 loopEnabled（引擎按间隔/槽调度）
// Daemon: 启动/停止自管理循环

func (e *Engine) StartLoop(id string) {
	if e.stopped.Load() {
		return
	}
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	// 触发类无调度语义（标准 §4：显示禁用开关）——引擎侧纵深守卫：handler
	// 门是唯一拒绝点时，任何代码路径（自动唤醒/测试装配/未来调用方）都能让
	// loop_on 假开，并触发调度侧副作用（ResetScheduleProgress/lastCheck）。
	if r.desc.Kind == KindOneshot {
		return
	}
	r.mu.Lock()
	wasOn := r.loopEnabled
	r.loopEnabled = true
	if !wasOn {
		// 用户显式重启（关→开）=新一轮预算：清空历史异常重拉计数。
		r.abnormalRestarts = 0
		r.relaunchPending = false
		r.restartExhausted = false
		// Scheduled 同理：关→开=重新接受本任务的预约，清空槽消费水位/
		// 失败退避/求值节拍（否则用户在停摆后重开调度，旧水位仍会压掉
		// 当前槽——显式复位入口，见 ResetScheduleProgress）。
		resetScheduleProgressLocked(r)
		// 节拍复位只属于「关→开」过渡：置零=立刻到期。已开启状态的重复
		// StartLoop 不得重置节拍（否则对运行中的 Periodic 任务重复调用
		// 幂等入口会凭空多跑一轮）；显式补跑归 RearmLoop。
		r.lastCheck = time.Time{}
	}
	r.mu.Unlock()
	// Daemon：CAS 启动。关→开过渡=真实重启意图（背靠背
	// restart 语义保持）；已开启状态的重复 StartLoop 不再栽重启意图。
	if r.desc.Kind == KindDaemon && e.roleAllows(r.desc.RunsOn) {
		e.tryStartDaemon(r, !wasOn)
	}
}

// RearmLoop 重置首轮节拍（依赖服务就绪补跑 / 新工作入队唤醒）。
//
// 两种调用形态
//   - 无实参（服务就绪形态，证书服务注入等）：仅当调度已开启时重置节拍，
//     不改变 loopEnabled——不得覆盖用户明确停止的调度。
//   - 携带 hasWork（业务唤醒形态，cert-waiting-ca 等入队唤醒）：hasWork=false
//     零动作；hasWork=true 表示确有新工作待消费——越过「已停止」态恢复调度
//     并立即补跑（新工作必须有消费通道）。越过即打开 loopEnabled，后续仍以
//     loopEnabled 为唯一调度事实（跨重启的停止来源语义由 task_loop_prefs 承担，
//     引擎内不再保留第二状态位）。
func (e *Engine) RearmLoop(id string, hasWork ...bool) {
	if e.stopped.Load() {
		return
	}
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	// 触发类无调度语义——纵深守卫，见 StartLoop 同位置注释。
	if r.desc.Kind == KindOneshot {
		return
	}
	bypassStop := len(hasWork) > 0
	if bypassStop && !hasWork[0] {
		return
	}
	r.mu.Lock()
	wasOn := r.loopEnabled
	if bypassStop {
		r.loopEnabled = true
		// 新工作唤醒=显式恢复调度：仅在自愈已用尽时重置预算（普通唤醒
		// 不得清零崩溃循环的退避预算）。
		if r.restartExhausted {
			r.abnormalRestarts = 0
			r.restartExhausted = false
		}
		if !wasOn {
			// 越过「已停止」=重新接受本任务的预约：与 StartLoop 的关→开
			// 过渡同口径清空 Scheduled 槽消费水位/失败退避/求值节拍。缺这一步
			// 时，停止前 schedDoneSlot 已等于当前 due 槽（成功落定未推进槽/
			// 用户取消已到期槽）的任务重开后 tick 的到期判定恒拒绝同一槽——
			// loop_on=true 却零投递、零 task_runs 行（静默停摆，只能靠重启
			// 恢复）。非 Scheduled 由 resetScheduleProgressLocked 内建 guard
			// 零动作。
			//
			// 只在「已停止→开启」过渡复位：已开启任务的普通唤醒（hasWork）
			// 不得清空已消费水位——否则同一过期槽被重新视为到期，整轮业务
			// 重复执行（全量下载/整包备份）。
			resetScheduleProgressLocked(r)
		}
	} else if !r.loopEnabled {
		r.mu.Unlock()
		return
	}
	r.lastCheck = time.Time{}
	isDaemon := r.desc.Kind == KindDaemon
	r.mu.Unlock()
	if isDaemon && e.roleAllows(r.desc.RunsOn) {
		// 残留调用方=常驻族尚未接入 RearmLoop，
		// 但入口语义必须与 tryStartDaemon 契约一致——restartIntent 仅在
		// StartLoop 的关→开真实重启过渡时为 true。此处恒 false：运行中的
		// daemon 不再被栽 pendingRestart（避免其正常退出后被误换代=多一条
		// 启动行+服务重启），空闲时仍经 CAS 正常拉起。
		e.tryStartDaemon(r, false)
	}
}

// ResetScheduleProgress 显式复位 Scheduled 的槽消费水位与失败退避。
// 调用场景：用户关→开调度（StartLoop 内部调用）与业务侧重排槽后（配置
// 导入重装首槽等）——否则旧 schedDoneSlot 会继续压住新预约，任务静默停摆
// 只能靠进程重启恢复。非 Scheduled 任务零动作。
func (e *Engine) ResetScheduleProgress(id string) {
	if e.stopped.Load() {
		return
	}
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	resetScheduleProgressLocked(r)
	r.mu.Unlock()
}

// resetScheduleProgressLocked 清空 Scheduled 槽缓存/消费水位/退避与求值节拍
// （调用方持 r.mu）：下一次 tick 重新求值槽，业务预约成为唯一事实。引擎停调
// 来源标记随复位清空——调度重新开启/重排槽即不再有「停调」可言。
func resetScheduleProgressLocked(r *registration) {
	if r.desc.Kind != KindScheduled {
		return
	}
	r.nextScheduledTime = time.Time{}
	r.schedDoneSlot = time.Time{}
	r.schedSlotEvalAt = time.Time{}
	r.schedFailStreak = 0
	r.schedRetryAfter = time.Time{}
	r.schedStopReason = ""
}

func (e *Engine) StopLoop(id string) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.loopEnabled = false
	r.lastCheck = time.Time{}
	// 引擎侧停调归属（来源标记/自愈预算用尽）只在引擎自己停调时成立：
	// 用户显式停止即是最终的停止来源，两者都必须清空——否则视图继续把
	// 这次「用户停止」呈现成「引擎停调/自愈用尽」并给出误导性的恢复入口
	// （自愈用尽标记还会让监控把已由用户停止的任务呈现为 failed）。
	// 重新开启/新工作唤醒本来也会复位这两者，此处只是给出正确的归属。
	r.schedStopReason = ""
	r.restartExhausted = false
	c := r.cancel
	r.mu.Unlock()

	// Daemon：取消 Run 的 ctx（启停管理=系统性中止，非用户取消）
	if r.desc.Kind == KindDaemon && c != nil {
		c(nil)
	}
}

// IsRunning 诊断用状态查询（生产代码零消费——任务视图走
// DescribeAll 的 LoopOn/Running；仅测试与排障断言使用）：Run 存活或
// 「调度开且角色允许」即为 true。
func (e *Engine) IsRunning(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	running, loopOn := r.running, r.loopEnabled
	r.mu.Unlock()
	if running {
		return true
	}
	return loopOn && e.roleAllows(r.desc.RunsOn)
}

// ---- Daemon 生命周期 ----

func (e *Engine) startDaemon(id string, r *registration, ctx context.Context, cancel context.CancelCauseFunc) bool {
	e.mu.RLock()
	if e.stopped.Load() {
		e.mu.RUnlock()
		cancel(nil)
		r.mu.Lock()
		r.running = false
		r.cancel = nil
		r.mu.Unlock()
		return false
	}
	e.daemonWG.Add(1)
	e.mu.RUnlock()
	// 调用方已在锁内完成 running 占位与 cancel 登记。
	runID := globalInsertRun(id, r.desc.Family, "auto")
	taskLogAppend(id, "[start] 常驻启动")
	// 2026-10-01 用户裁定：启动即记 success（启动是既成事实——成功列体现
	// 启动计数；原实现落 running 终态随停止更新，运行期成功列恒 0）
	e.finishRun(runID, "success", 0)

	start := time.Now()
	go func() {
		defer e.daemonWG.Done()
		err := runGuarded(r.desc.Run, RunContext{Ctx: ctx, Trigger: "auto", RunID: runID})
		dur := time.Since(start).Milliseconds()
		// 异常退出（非取消）＝Run 返回错误或 panic；净返回值提前退出
		// （ctx 未取消、调度仍开）同为异常——在 r.mu 临界区内定案
		// （需 loopEnabled 新鲜快照，见下）。
		abnormal := err != nil && ctx.Err() == nil

		var relaunchIntent bool
		// 异常退出有界重拉（退避在锁外等待）。
		var relaunchDelay time.Duration
		var relaunchAttempt int
		var abnormalExhausted bool
		// 锁序：r.mu 内不得取 roleMu（runNow 的反向序为 roleMu→r.mu）。
		// 角色/停止态在进入 r.mu 前快照——退出清理只消费快照，不反向嵌套。
		allows := e.roleAllows(r.desc.RunsOn)
		stopped := e.stopped.Load()
		r.mu.Lock()
		r.running = false
		r.cancel = nil
		if !abnormal && err == nil && ctx.Err() == nil && r.loopEnabled && !stopped && allows {
			// 常驻 Run 未收到取消信号却净返回（实现缺陷/内部条件早退）——
			// 此前按「正常停止」落 [done] stopped，监控呈现「空闲」而任务
			// 永久停摆（不重拉/不告警/不落 failed）。全部常驻装配均阻塞至
			// ctx（daemonLifecycleRun），净返回恒为异常：按异常同口径走
			// 有界重拉 + failed 行 + WARN。
			abnormal = true
			err = errDaemonPrematureExit
		}
		if r.pendingRestart {
			r.pendingRestart = false
			if r.loopEnabled && !abnormal && !stopped && allows {
				// 换代不再在本临界区内联登记 cancel——
				// 快照 allows 与登记之间 demote 可插入（SetRole 的 cancel
				// 遍历未及新登记），master-only daemon 会在 slave 上存活。
				// 改为锁外经 tryStartDaemon 统一 CAS 入口重拉（角色门已
				// 内化进其 CAS 临界区，以新鲜角色复核）。
				relaunchIntent = true
			}
		}
		// 异常退出（非取消）且仍在调度=故障自愈：按有界退避重拉。修复前仅
		// 显式 restart 意图会换代——安全事件采集/证书签发/集群同步任一轮
		// panic 即永久停摆（loop_on 仍 true、状态列恒「空闲」）。
		if abnormal {
			if dur >= daemonAbnormalResetAfter.Milliseconds() {
				// 健康运行一段后再崩=新故障，预算重置（抖动不得永久耗尽）。
				r.abnormalRestarts = 0
			}
			if r.loopEnabled && !stopped && allows && !r.relaunchPending {
				if r.abnormalRestarts < len(e.daemonRestartDelays) {
					relaunchDelay = e.daemonRestartDelays[r.abnormalRestarts]
					r.abnormalRestarts++
					r.relaunchPending = true
					relaunchAttempt = r.abnormalRestarts
				} else {
					abnormalExhausted = true
					// 与日志和监控语义一致：预算用尽即真实停止调度。
					// restartExhausted 让监控视图把「自愈用尽」与用户主动停止
					// 区分开——后者不得呈现 failed。
					// 后续 StartLoop 观察到关→开过渡，才会重置预算并手动恢复。
					r.loopEnabled = false
					r.restartExhausted = true
				}
			}
		}
		r.mu.Unlock()

		if abnormal {
			// 异常退出（非取消）：补记 failed 行（真实时长与错误）
			failID := globalInsertRunAt(id, r.desc.Family, "auto", start.In(engineLocPtr()).Format("2006-01-02 15:04:05"), "")
			e.finishRunWithMessage(failID, "failed", dur, truncMsg(err))
			taskLogAppend(id, fmt.Sprintf("[done] failed 耗时=%dms 触发=auto 错误=%s", dur, err.Error()))
			switch {
			case relaunchDelay > 0:
				taskLogAppend(id, fmt.Sprintf("[restart] 常驻异常退出，%s 后第 %d/%d 次自动重启",
					relaunchDelay, relaunchAttempt, len(e.daemonRestartDelays)))
			case abnormalExhausted:
				taskLogAppend(id, fmt.Sprintf("[done] 常驻任务异常退出，自动重启 %d 次已用尽且已停止调度（需手动重启）",
					len(e.daemonRestartDelays)))
			}
		} else {
			taskLogAppend(id, fmt.Sprintf("[done] stopped 耗时=%dms 触发=auto（取消/正常退出）", dur))
		}
		if relaunchIntent {
			// restart 意图落地——新代经统一 CAS 入口接续
			// （restartIntent=false：pendingRestart 已在本代消费；其间
			// 并发 StartLoop/角色翻转的新占位优先，不重复拉起）。
			e.tryStartDaemon(r, false)
		}
		if relaunchDelay > 0 {
			e.scheduleDaemonRelaunch(r, relaunchDelay)
		}
	}()
	return true
}

// scheduleDaemonRelaunch 常驻异常退出后的有界延迟重拉。退避窗口
// 内 running 保持 false（状态列如实呈现 failed）；到点经 tryStartDaemon 统一
// CAS 入口（重读 loopEnabled/stopped/running），用户启停/角色翻转可随时越过。
func (e *Engine) scheduleDaemonRelaunch(r *registration, delay time.Duration) {
	e.mu.RLock()
	if e.stopped.Load() {
		e.mu.RUnlock()
		r.mu.Lock()
		r.relaunchPending = false
		r.mu.Unlock()
		return
	}
	e.daemonWG.Add(1) // Add 在 stopped 复核后、仍持 e.mu.RLock——Stop 的 Wait 不会漏等
	e.mu.RUnlock()
	go func() {
		defer e.daemonWG.Done()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-e.schedStop:
			r.mu.Lock()
			r.relaunchPending = false
			r.mu.Unlock()
			return
		}
		r.mu.Lock()
		r.relaunchPending = false
		r.mu.Unlock()
		if !e.roleAllows(r.desc.RunsOn) {
			return // 角色不符：promote 时 SetRole 的常驻分支会拉起
		}
		e.tryStartDaemon(r, false)
	}()
}

// runGuarded 隔离任务体 panic：任一任务体 panic 不得杀死
// 进程——转为 failed 终态错误。
func runGuarded(run func(RunContext) error, rc RunContext) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return run(rc)
}

// 调度函数隔离----
// EnabledFn/NextSlotFn/IntervalFn 是装配方闭包（生产为 DB 直读），tick 曾
// 裸调——任一 panic 直接杀死调度 goroutine（引擎永久静默）。三个包装统一
// recover 并 fail-closed 返回零值：
//
//	safeBool     → false（业务门关闭，整分支跳过）
//	safeSlot     → zero（无槽，不投递）
//	safeInterval → 0（tick 按非正周期停止该任务调度）
var (
	schedFnPanicMu sync.Mutex
	// 按调度函数（kind = 任务 ID + Fn 名）分桶：全局单槽时任务 A 每秒 panic
	// 会让任务 B 同期首次 panic 的 ERROR 在最长 1 分钟内被丢弃，多任务同源
	// 故障（同一次 DB 故障触发多个装配闭包 panic）只剩一条告警。桶数上界=
	// 注册任务×Fn 面（调用点固定），有界。
	schedFnPanicLast       = map[string]time.Time{}
	schedFnPanicSuppressed = map[string]int{}
)

// warnSchedFnPanic 限流告警（同一调度函数 1 分钟一条）：panic 闭包每 tick
// 复现时不得刷日志。被抑制的次数不丢——下次放行时随行披露，避免「期间另有
// N 次」在排障面蒸发。
func warnSchedFnPanic(kind string, p any) {
	schedFnPanicMu.Lock()
	defer schedFnPanicMu.Unlock()
	now := time.Now()
	if now.Sub(schedFnPanicLast[kind]) < time.Minute {
		schedFnPanicSuppressed[kind]++
		return
	}
	suppressed := schedFnPanicSuppressed[kind]
	delete(schedFnPanicSuppressed, kind)
	schedFnPanicLast[kind] = now
	if suppressed > 0 {
		log.Printf("ERROR: taskengine: 调度函数 %s panic（本轮 fail-closed 跳过）: %v（期间另有 %d 次同类 panic 未逐条打印）", kind, p, suppressed)
		return
	}
	log.Printf("ERROR: taskengine: 调度函数 %s panic（本轮 fail-closed 跳过）: %v", kind, p)
}

func safeBool(kind string, fn func() bool) (v bool) {
	defer func() {
		if p := recover(); p != nil {
			warnSchedFnPanic(kind, p)
			v = false
		}
	}()
	return fn()
}

func safeSlot(kind string, fn func() time.Time) (v time.Time) {
	defer func() {
		if p := recover(); p != nil {
			warnSchedFnPanic(kind, p)
		}
	}()
	return fn()
}

func safeInterval(kind string, fn func() time.Duration) (v time.Duration) {
	defer func() {
		if p := recover(); p != nil {
			warnSchedFnPanic(kind, p)
		}
	}()
	return fn()
}

// safeString：StatusFn 同族隔离——fail-closed 返回空串
// （状态镜像缺失，视图降级为无镜像，不得让单任务闭包 panic 杀死
// Lookup/DescribeAll 整页）。
func safeString(kind string, fn func() string) (v string) {
	defer func() {
		if p := recover(); p != nil {
			warnSchedFnPanic(kind, p)
			v = ""
		}
	}()
	return fn()
}

// ---- 历史与统计 ----

// StaleRunningGrace 是「残留 running 行」判定的年龄门：行快照与内存快照是两次
// 独立取数，刚写入的行可能在两次快照之间完成（呈现「行 running、内存空闲」），
// 立即判中断会在安全运维页面误报一次失败。终态 UPDATE 失败的残留行一定会变老，
// 短宽限不影响识别。历史/最近运行/任务列表共用本常量与同一判定。
const StaleRunningGrace = 30 * time.Second

// StaleRunInterruptedMessage 残留 running 行归一后的说明（历史与列表同源）。
const StaleRunInterruptedMessage = "运行终态未落库（已按异常结束处理）"

// StaleRunningResidual 判定 task_runs.started_at 是否已超出瞬态宽限（调用方先
// 自行确认本进程无该任务在途执行）。started_at 是配置时区墙钟串，按同一时区
// 解析；不可解析的时间戳维持旧口径（判残留）。
func StaleRunningResidual(startedAt string) bool {
	if startedAt == "" {
		return true
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", startedAt, engineLocPtr())
	if err != nil {
		return true
	}
	return time.Since(t) >= StaleRunningGrace
}

// normalizeStaleRunningRows 把「库行 running 但本进程已无该任务在途执行且行
// 年龄超过宽限」的残留行归一为 interrupted——终态 UPDATE 失败只 WARN，行会
// 留到进程重启才被 RecoverOrphans 回收；不归一的话列表/历史/最近运行会各自
// 呈现相反结论（列表「失败/已中断」而历史/LatestRun 仍称「运行中」）。
func (e *Engine) normalizeStaleRunningRows(taskID string, runs []RunRecord) []RunRecord {
	if len(runs) == 0 || e.IsTaskInFlight(taskID) {
		return runs
	}
	for i := range runs {
		if runs[i].Status != "running" || !StaleRunningResidual(runs[i].StartedAt) {
			continue
		}
		runs[i].Status = "interrupted"
		if runs[i].Message == "" {
			runs[i].Message = StaleRunInterruptedMessage
		}
	}
	return runs
}

// beforeTaskRunsRead 任务历史/统计读前的注入缝（生产恒等 no-op）：关停序列
// 会并发把包级句柄置 nil，回归测试借此在「判定句柄」与「使用句柄」之间注入
// 关停效果，钉住「单次快照」的语义。
var beforeTaskRunsRead = func() {}

func (e *Engine) History(id string, limit int) []RunRecord {
	if limit <= 0 {
		limit = 20
	}
	// 句柄单次快照 + nil 守卫（同文件 taskRunTerminalExec / PurgeTaskRuns 同源）：
	// 关停序列 StopTaskEngine→db.Close 会把包级句柄置 nil，逐次读全局会让
	// 「判 nil 通过、用句柄时已为 nil」的窗口直接 nil 解引用 panic 掉进程。
	database := db.DB
	if database == nil {
		return nil
	}
	beforeTaskRunsRead()
	rows, err := database.Query(
		`SELECT id, task_id, family, trigger, COALESCE(operator,''), status, started_at,
		COALESCE(finished_at,''), COALESCE(duration_ms,0), COALESCE(message,'')
		FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		log.Printf("WARNING: taskengine: 任务历史 %s 查询失败: %v", id, err)
		return nil
	}
	defer rows.Close()
	var out []RunRecord
	for rows.Next() {
		var r RunRecord
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Family, &r.Trigger, &r.Operator, &r.Status, &r.StartedAt, &r.FinishedAt, &r.DurationMs, &r.Message); err != nil {
			// Scan 失败须留痕——静默 continue 会让单行
			// 丢失零信号（页缺行无从排查）。
			log.Printf("WARNING: taskengine: 任务历史 %s 行扫描失败（跳过该行）: %v", id, err)
			continue
		}
		out = append(out, r)
	}
	// 迭代错误须留痕——rows.Next() 因错误（而非 EOF）
	// 返回 false 时表现为「部分历史 + 静默」。返回形状不变（已读行降级展示），
	// 与同文件 Stats24hHourlySeries 同口径。
	if err := rows.Err(); err != nil {
		log.Printf("WARNING: taskengine: 任务历史 %s 迭代失败（部分历史缺失）: %v", id, err)
	}
	return e.normalizeStaleRunningRows(id, out)
}

func (e *Engine) RecoverOrphans() int64 {
	// 与同文件其余 7 处导出 DB 函数同形的 nil 防护
	// （曾唯一裸用 db.DB——装配顺序变化即 nil panic）。
	if db.DB == nil {
		return 0
	}
	res, err := db.DB.Exec(`UPDATE task_runs SET status='interrupted', finished_at=?, message=COALESCE(message,'')||'（进程重启回收）' WHERE status='running'`, engineNowStr())
	if err != nil {
		log.Printf("WARNING: taskengine: 回收中断任务失败（残留 running 行）: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ---- 执行 ----

// runReservation 一次执行占位的句柄：reserveRun 在调用线程完成
// 全部入口门与单飞 CAS；executeRun 执行完成后由 release 统一复位状态。
type runReservation struct {
	engine *Engine
	r      *registration
	ctx    context.Context
	cancel context.CancelCauseFunc
	// suppressRunRow 为 true 时不落 task_runs 行（RunSyncQuiet 高频重试路径）。
	suppressRunRow bool
}

func (res *runReservation) release() {
	res.r.mu.Lock()
	res.r.running = false
	res.r.cancel = nil
	res.r.runTrigger = ""
	res.r.runTerminalStatus = ""
	res.r.mu.Unlock()
	res.cancel(nil) // 执行结束的资源回收，不携带取消原因
	res.engine.inFlight.Add(-1)
	res.engine.runWG.Done()
}

// reserveRun 原子占位：stopped/paused/角色/单飞 CAS 与 runNow 同口径。
// 任何失败同步返回错误（调用方可在写 HTTP 响应前映射状态码）。
func (e *Engine) reserveRun(id, trigger string) (*runReservation, error) {
	return e.reserveRunInternal(id, trigger, "", time.Time{})
}

// reservePeriodicRun 把 Periodic 的节拍推进并入 admission 临界区：
// 只有 paused/role/loop/单飞门全部通过且 running 占位成功才写 lastCheck。
// tick 不再先推进节拍、再让迟到 goroutine 承担 admission 失败。
func (e *Engine) reservePeriodicRun(id string, now time.Time) (*runReservation, error) {
	return e.reserveRunInternal(id, "auto", KindPeriodic, now)
}

// reserveScheduledRun 把 Scheduled 的槽复核并入 admission 临界区
// 与 Periodic 同型收口）：paused/role/loop/单飞门全部通过且槽仍到期才占位。
// StopLoop/业务关闭落在 tick 判定与本调用之间时拒绝派发——不再出现
// 「已停止仍启动一次」；槽被并发改写（手动触发/上一轮完成重算到未来）
// 时按陈旧判定投递会立即多跑一次，一并在临界区内复核。
func (e *Engine) reserveScheduledRun(id string, now time.Time) (*runReservation, error) {
	return e.reserveRunInternal(id, "auto", KindScheduled, now)
}

// reserveRunInternal admission 语义：空值=手动/startup 直排（Trigger/RunSync/
// RunBootSyncTasks——显式意图，不受 loopEnabled 门拦）；KindPeriodic/
// KindScheduled=tick 自动派发的收口准入（复核 loopEnabled，Scheduled 另复核
// 槽到期，Periodic 另推进节拍）。
func (e *Engine) reserveRunInternal(id, trigger string, admission Kind, beat time.Time) (*runReservation, error) {
	e.mu.Lock()
	if e.stopped.Load() {
		e.mu.Unlock()
		return nil, ErrEngineStopped
	}
	// Pause 与登记共用 e.mu：一旦 PauseScheduling 返回，越过 tick 入口
	// 检查的迟到 goroutine 与各手动入口都无法再增加 inFlight。
	// RunBootSyncTasks 的 startup 是装配暂停期的唯一合法豁免。
	if e.schedPaused.Load() && trigger != "startup" {
		e.mu.Unlock()
		return nil, ErrSchedulingPaused
	}
	r := e.regs[id]
	e.runWG.Add(1)
	e.inFlight.Add(1)
	e.mu.Unlock()
	if r == nil {
		e.inFlight.Add(-1)
		e.runWG.Done()
		return nil, ErrNotFound
	}
	// 常驻族拒绝下沉到统一 admission 入口——此前
	// 只有 Trigger/RunSync 显式守卫，RunAsync/RunAsyncResult 直穿 reserveRun
	// 可让 daemon Run 与自管理循环双跑并绕过 startDaemon 生命周期挂钩。所有
	// 手动/异步入口（含未来新增调用方）经此处收口，handler CanTrigger 仍是
	// 第一道防线。
	if r.desc.Kind == KindDaemon {
		e.inFlight.Add(-1)
		e.runWG.Done()
		return nil, errDaemonManualUnsupported
	}
	// 单飞 CAS：全部 Kind 统一拒绝并发（Daemon 无此路径——Trigger 不暴露）
	e.roleMu.RLock()
	if !e.roleAllowsLocked(r.desc.RunsOn) {
		e.roleMu.RUnlock()
		e.inFlight.Add(-1)
		e.runWG.Done()
		return nil, ErrNotMaster
	}
	r.mu.Lock()
	if r.running || r.cancelHookRunning {
		r.mu.Unlock()
		e.roleMu.RUnlock()
		e.inFlight.Add(-1)
		e.runWG.Done()
		return nil, ErrAlreadyRunning
	}
	if admission != "" {
		if r.desc.Kind != admission || !r.loopEnabled {
			r.mu.Unlock()
			e.roleMu.RUnlock()
			e.inFlight.Add(-1)
			e.runWG.Done()
			if admission == KindPeriodic {
				return nil, errPeriodicLoopDisabled
			}
			return nil, errScheduledLoopDisabled
		}
		// Scheduled 槽复核：窗口内手动触发/上一轮完成可能已把
		// 槽重算到未来（executeRun 尾部重算），按 tick 的陈旧判定投递会立即
		// 多跑一次——临界区内复核槽仍到期。
		if admission == KindScheduled && (r.nextScheduledTime.IsZero() || !beat.After(r.nextScheduledTime)) {
			r.mu.Unlock()
			e.roleMu.RUnlock()
			e.inFlight.Add(-1)
			e.runWG.Done()
			return nil, errScheduledNotDue
		}
		// 「同一槽只执行一次」收口复核：窗口内另一轮（手动/自动）完成或
		// 用户取消可能已消费本槽——按 tick 的陈旧快照投递会重复执行同一槽。
		if admission == KindScheduled && !r.nextScheduledTime.After(r.schedDoneSlot) {
			r.mu.Unlock()
			e.roleMu.RUnlock()
			e.inFlight.Add(-1)
			e.runWG.Done()
			return nil, errScheduledNotDue
		}
	}
	r.running = true
	r.runSeq++
	r.runTrigger = trigger
	r.runTerminalStatus = ""
	if admission == KindPeriodic {
		r.lastCheck = beat
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	r.cancel = cancel
	// Stop×runNow 竞态兜底——本临界区登记前 Stop() 可能
	// 已完成 regs 的 cancel 遍历（未及本次登记）；临界区内复核 stopped，
	// 已停即锁外取消，Run 体落 cancelled 终态而非在引擎停止后跑完
	// （与 daemon 退出清理的 stopped 复核同型）。
	stopAfterRegister := e.stopped.Load()
	r.mu.Unlock()
	e.roleMu.RUnlock()
	if stopAfterRegister {
		cancel(nil) // 引擎停止=系统性中止，非用户取消
	}
	return &runReservation{engine: e, r: r, ctx: ctx, cancel: cancel}, nil
}

func (e *Engine) runNow(id, trigger, operator string) (int64, error) {
	res, err := e.reserveRun(id, trigger)
	if err != nil {
		return 0, err
	}
	defer res.release()
	return e.executeRun(res, id, trigger, operator)
}

// RunAsync 原子占位后异步执行一次：入口失败在任何 HTTP 响应
// 之前同步返回（可映射 409/503），成功即已占位——「已受理」不再说谎。
// 测试专供（生产零调用）：生产手动触发唯一入口是
// services.TriggerTaskAsync → RunAsyncResult（需 onDone 补记补偿审计）；
// 本函数是 onDone=nil 的薄包装，保留给测试装配，勿新增生产消费方。
func (e *Engine) RunAsync(id, trigger, operator string) error {
	return e.RunAsyncResult(id, trigger, operator, nil)
}

// RunAsyncResult 与 RunAsync 同语义，另在任务体结束后回调执行结果（供调用方
// 补记成功/失败补偿审计——同步预占位不能吞掉任务体失败）。
func (e *Engine) RunAsyncResult(id, trigger, operator string, onDone func(error)) error {
	res, err := e.reserveRun(id, trigger)
	if err != nil {
		return err
	}
	go func() {
		defer res.release()
		_, runErr := e.executeRun(res, id, trigger, operator)
		if onDone != nil {
			onDone(runErr)
		}
	}()
	return nil
}

// executeRun 执行已占位的运行（原 runNow 主体）。
func (e *Engine) executeRun(res *runReservation, id, trigger, operator string) (int64, error) {
	r := res.r
	ctx := res.ctx
	// 记录策略（按 Kind，零 flag）：
	// Scheduled/Periodic/Oneshot: 每次执行落行；Daemon: 仅 startDaemon 落行
	var runID int64
	if !res.suppressRunRow {
		runID = globalInsertRunAt(id, r.desc.Family, trigger, engineNowStr(), operator)
	}

	rc := RunContext{Ctx: ctx, Trigger: trigger, Operator: operator, RunID: runID}
	start := time.Now()
	// caddy-restart（Caddy 崩溃自愈 watcher 通道）
	// 同样落 [start]——曾仅 manual/startup 放行，自愈轮只有 [done]，排障
	// 看不到执行起点。
	// 声明：auto 轮不写 [start] 是刻意取舍——高频族
	// （security-events-ingestion/config-watchdog 等分钟级轮）每轮补一行
	// [start] 会把任务日志淹成生命周期噪音（[done] 行已带触发与耗时）；
	// 低频触发形态（manual/startup/caddy-restart）保留 [start] 供排障定位
	// 执行起点。
	switch trigger {
	case "manual", "startup":
		taskLogAppend(id, fmt.Sprintf("[start] %s触发", map[bool]string{true: "启动", false: "手动"}[trigger == "startup"]))
	case "caddy-restart":
		taskLogAppend(id, "[start] Caddy重启触发")
	}
	runErr := runGuarded(r.desc.Run, rc)
	status := terminalStatus(ctx, runErr)
	r.mu.Lock()
	r.runTerminalStatus = status
	r.mu.Unlock()
	dur := time.Since(start).Milliseconds()
	msg := fmt.Sprintf("[done] %s 耗时=%dms 触发=%s", status, dur, trigger)
	if status == "failed" && runErr != nil {
		msg += " 错误=" + runErr.Error()
	}
	taskLogAppend(id, msg)

	// Scheduled：Run 已写新槽——重算缓存。 同族收敛：NextSlotFn 含
	// DB 查询——锁外先求值（求值期间 running 仍=true，tick 自然跳过本轮，
	// 零重触发窗口），再回锁一次性落 running/cancel/槽缓存。若新槽仍为过去
	// （业务失败未推进等），running 标志在 CAS 前防重入，此处值供下 tick 判定。
	var nextSlot time.Time
	if r.desc.Kind == KindScheduled && r.desc.NextSlotFn != nil {
		// 与 tick/Lookup/DescribeAll 同口径的
		// panic 隔离——NextSlotFn 是装配方闭包（生产为 DB 直读），裸调
		// panic 会经 runNow 上抛给调用方（tick goroutine/手动触发链）。
		// 求值在锁外是刻意的（NextSlotFn 含 DB 查询）：求值期间 running
		// 仍=true，tick 自然跳过本轮，零重触发窗口；随后回锁一次性落
		// running/cancel/槽缓存。
		nextSlot = safeSlot(id+".NextSlotFn", r.desc.NextSlotFn)
		r.mu.Lock()
		prevSlot := r.nextScheduledTime
		r.nextScheduledTime = nextSlot
		switch {
		case (status == "failed" || status == "skipped") && slotDueForBackoff(nextSlot, prevSlot, time.Now()):
			// 「已到期槽未推进+本轮失败/跳过」兜底退避：业务侧未推进槽的
			// 失败轮（如装配缺陷响亮失败、nil-manager）与降级跳过轮（如
			// Run 体首行角色门 return ErrTaskSkipped）此前每 tick 重投——
			// 1s 节拍下 ≈8.6 万行 task_runs/天。未来槽（手动触发轮在预约
			// 到期前失败）不在退避范围——未来槽本来就不会被 tick 重投，
			// 写「退避后重投」告警是失实信号，且会无谓消耗 streak/5 分钟
			// 告警地板。判据与成功消费分支同口径（槽已到期）。
			//
			// 只有自动轮消耗停调预算（streak）：手动触发轮由用户显式发起、
			// 次数天然有界，不得因几次手动失败让自动排程提前停摆。手动失败
			// 仍沿用当前档位的退避节流（防手动连点把 tick 打进重投风暴），
			// 但不推进 streak、不触发停调。
			auto := trigger == "auto"
			if auto {
				r.schedFailStreak++
			}
			streak := r.schedFailStreak
			delay := scheduledFailBackoff(streak)
			r.schedRetryAfter = time.Now().Add(delay)
			outcome := map[bool]string{true: "失败", false: "跳过"}[status == "failed"]
			// 连续失败/跳过留 WARN 行（节流：非首轮至多每分钟一条——兜底
			// 本身的降噪，不得再制造日志洪峰）。首轮豁免也受
			// scheduledBackoffFirstWarnFloor 地板约束：槽消费机制覆盖
			// success/skipped/cancelled 后，failed 仍会清零重计——交替
			// 「成功(新槽)/失败」形态每轮都是 streak==1，无地板可 1 条/s；
			// 长静默后的首次失败距上次 WARN 远超地板，可见性不变。
			warnDue := time.Since(r.schedBackoffLastWarnAt) >= time.Minute
			if streak == 1 {
				warnDue = time.Since(r.schedBackoffLastWarnAt) >= scheduledBackoffFirstWarnFloor
			}
			if warnDue {
				r.schedBackoffLastWarnAt = time.Now()
				if auto {
					taskLogAppend(id, fmt.Sprintf("[warn] 排程槽未推进且本轮%s，退避 %s 后重投（连续 %d 轮；业务 Run 早退须推进槽，见任务引擎标准）", outcome, delay, streak))
				} else {
					taskLogAppend(id, fmt.Sprintf("[warn] 排程槽未推进且本轮手动%s，退避 %s 后重投（手动轮不计入自动停调预算）", outcome, delay))
				}
			}
			if auto && streak >= scheduledFailStreakStopLimit {
				// 与常驻族「重拉预算用尽即停调」对称的终点：退避只节流不定界，
				// 业务永不推进槽的缺陷形态下 task_runs 会以 30s 节拍无限增长
				// （≈2880 行/日，保留期内单任务数十万行）并把 24h 失败计数放大
				// 到失真。连续 N 轮（含首轮）仍未推进槽=调度侧已无可为，停调
				// 并留痕；StartLoop 关→开（或业务推进槽后重开）即恢复。
				// 停调来源机器可读（schedStopReason）：与用户主动停止同形
				// （loopEnabled=false），视图据此区分来源并指向恢复入口。
				r.loopEnabled = false
				r.schedFailStreak = 0
				r.schedRetryAfter = time.Time{}
				r.schedStopReason = ScheduleStopReasonFailStreak
				recoverHint := r.desc.LoopRecoveryHint
				if recoverHint == "" {
					recoverHint = "任务页调度开关或重启进程"
				}
				taskLogAppend(id, fmt.Sprintf("[error] 排程槽连续 %d 轮未推进且本轮%s，已停止该任务调度（修复失败原因后重新开启调度：%s）", scheduledFailStreakStopLimit, outcome, recoverHint))
			}
		default:
			r.schedFailStreak = 0
			r.schedRetryAfter = time.Time{}
			if status == "success" && !nextSlot.IsZero() && !time.Now().Before(nextSlot) {
				// 同一槽只执行一次：成功落定后重读槽仍已到期（业务未把槽
				// 推进到未来）——消费本槽，tick 不再按「槽过期」重投（含
				// 手动触发轮：手动成功同样消费过期槽）。业务侧成功轮
				// （auto/manual 同权）会自行推进空/过期槽，正常形态下本分支
				// 不触发；走到这里说明业务槽推进写失败（或业务未按契约推进），
				// 消费可避免每 tick 重复整轮执行——人工成功轮重新推进槽后仍能
				// 自愈到下一排程槽。失败轮不进本分支（由退避兜底重投）；
				// skipped/cancelled 的消费语义见 schedDoneSlot 字段注释。
				if nextSlot.After(r.schedDoneSlot) {
					r.schedDoneSlot = nextSlot
				}
			}
		}
		r.mu.Unlock()
	}

	if status == "failed" && runErr != nil {
		e.finishRunWithMessage(runID, status, dur, truncMsg(runErr))
	} else if status == "skipped" && runErr != nil {
		// skipped 终态同样落 message——跳过原因只进
		// 任务日志 [done] 行时，任务历史页丢失「为何跳过」。
		e.finishRunWithMessage(runID, status, dur, truncMsg(runErr))
	} else {
		e.finishRun(runID, status, dur)
	}
	return runID, runErr
}

func truncMsg(err error) string {
	return truncateUTF8(err.Error(), 500, "")
}

// truncateUTF8 把 s 裁到 maxBytes 字节预算内，裁剪点回退到 rune 边界——按
// 字节硬切多字节 UTF-8 会产出非法串（页/编辑器显示乱码，按行解析的工具可能
// 整行丢弃）。suffix 计入预算（suffix="" 即纯裁剪）：调用方显式决定「预算
// 是否含后缀」，两个消费面（task_runs.message 500B 不含后缀、任务日志行
// 4096B 含后缀）语义各自保留，实现单源。
func truncateUTF8(s string, maxBytes int, suffix string) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes - len(suffix)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// scheduledBackoffFirstWarnFloor 退避 WARN「首轮」的最小间隔地板：
// 首轮本为「首次异常必可见」的豁免，但 streak 会被 success/skipped/cancelled
// 清零——交替形态下每轮失败都是首轮，豁免即失效（1 条/s）。首轮也须距上次
// 退避 WARN ≥ 地板才放行；长静默后的首次失败不受影响（距上次远超地板）。
const scheduledBackoffFirstWarnFloor = 5 * time.Minute

// slotDueForBackoff 判定「失败/跳过轮是否属于已到期且未被业务推进的槽」——
// 退避兜底只覆盖这类形态（未来槽/零槽失败不进退避、不写重投告警）：
//   - nextSlot 为零：业务未武装槽（或开关关闭），tick 不会按槽投递，无重投；
//   - nextSlot 在未来：下一次预约尚未到期，本轮是手动/提前执行，无重投；
//   - nextSlot 已推进（> prevSlot）：业务侧已把预约推到下一个周期，无重投。
func slotDueForBackoff(nextSlot, prevSlot time.Time, now time.Time) bool {
	if nextSlot.IsZero() || nextSlot.After(now) {
		return false
	}
	return !nextSlot.After(prevSlot)
}

// scheduledFailStreakStopLimit 是「槽未推进连续失败/跳过」的终点（含首轮，
// 即连续第四次）：退避表三档（1s/5s/30s）用尽——与常驻重拉「三次用尽后停调」
// 同形的对称终点。安全网不得无限重投：长期缺陷态下 30s 节拍会让 task_runs
// 无限增长并失真 24h 统计。停调可被 StartLoop 关→开显式恢复
// （resetScheduleProgressLocked 清 streak），不构成不可恢复状态。
const scheduledFailStreakStopLimit = 4

// ScheduleStopReasonFailStreak 是 Scheduled 引擎停调的来源标记值（任务视图
// schedule_stopped_reason 字段）：连续 N 轮自动轮未推进槽且失败/跳过。
const ScheduleStopReasonFailStreak = "fail-streak"

// scheduledFailBackoff Scheduled「槽未推进+失败」退避表（与常驻重拉
// defaultDaemonRestartDelays 同形 1s/5s/30s，第 3 次起封顶 30s）——节流
// 不是停摆：退避衰减后照常重投（业务修复/槽刷新即恢复常轨），连续到
// scheduledFailStreakStopLimit 才停调。
func scheduledFailBackoff(streak int) time.Duration {
	switch {
	case streak <= 1:
		return time.Second
	case streak == 2:
		return 5 * time.Second
	default:
		return 30 * time.Second
	}
}

// terminalStatus 计算终态：
func terminalStatus(ctx context.Context, err error) string {
	// demote 会同时取消 ctx 并返回跳过哨兵；
	// 非故障放弃必须先于通用 cancelled，才能与用户主动取消区分。
	if errors.Is(err, ErrTaskSkipped) {
		return "skipped"
	}
	if ctx.Err() != nil || errors.Is(err, ErrRunCancelled) {
		return "cancelled"
	}
	if err != nil {
		return "failed"
	}
	return "success"
}

// ---- 调度循环 ----

func (e *Engine) scheduleLoop() {
	defer close(e.schedDone)
	// 顶层 recover——单代 ticker 内任何未预期 panic 不得终止调度
	// goroutine；恢复后重建 ticker 继续（tick 内 Fn 已有 safe* 隔离，本层
	// 兜住其余实现缺陷）。
	for {
		if stopped := e.runScheduleTicker(); stopped {
			return
		}
	}
}

// runScheduleTicker 单代 ticker 循环；返回 true=收到停止信号（正常退出），
// false=本代 panic 已隔离、需重建 ticker。
func (e *Engine) runScheduleTicker() (stopped bool) {
	ticker := time.NewTicker(e.opts.TickInterval)
	defer ticker.Stop()
	defer func() {
		if p := recover(); p != nil {
			log.Printf("ERROR: taskengine: 调度循环 panic（重建 ticker 继续）: %v", p)
		}
	}()
	for {
		select {
		case <-e.schedStop:
			return true
		case <-ticker.C:
			e.tick()
		}
	}
}

func (e *Engine) tick() {
	if e.schedPaused.Load() {
		return // 装配暂停期不投递（BootSync 前置不变量）
	}
	now := time.Now()
	e.mu.RLock()
	ids := make([]string, 0, len(e.regs))
	for id := range e.regs {
		ids = append(ids, id)
	}
	e.mu.RUnlock()

	for _, id := range ids {
		e.mu.RLock()
		r := e.regs[id]
		e.mu.RUnlock()
		if r == nil {
			continue
		}

		switch r.desc.Kind {
		case KindScheduled:
			// 排程感知：槽缓存驱动，到点才触发 Run（中间零执行零落行零日志）；
			// in-flight 不重入。槽闭包（生产=DB 直读）降频求值——槽远期/已消费
			// 时按重评地板周期求值，到期前导窗内每 tick 求值（见下方求值门）。
			// 固有边界（裁定见 docs/task-engine-standard.md「定时」节）：DB 全
			// 不可读时 NextSlotFn fail-closed 零值槽 → 永不到期 → 零落行——
			// 任务历史无 failed 行（没有执行就没有记录），可观测性由应用日志
			// 的排程读取失败 WARN 承担；「槽未推进+本轮 failed」退避兜底
			// （executeRun 尾部）只覆盖 Run 至少执行过的形态。
			// NextSlotFn 含 DB 查询——持 r.mu 调用会把
			// DB 延迟传导到同任务的 Cancel/IsRunning/StopLoop。改为快照→锁外
			// 求值→回锁落缓存并复核状态（窗口内翻转不触发）。
			r.mu.Lock()
			if !r.loopEnabled || r.running || now.Before(r.schedRetryAfter) {
				// schedRetryAfter：「槽未推进+上轮 failed」的退避窗口内不重投
				// （兜底——正常失败轮由业务侧 advanceSlot 推进槽，不进本态）。
				r.mu.Unlock()
				continue
			}
			slotFn := r.desc.NextSlotFn
			enabledFn := r.desc.EnabledFn
			prevSlot := r.nextScheduledTime // 求值窗口起点快照
			doneSlot := r.schedDoneSlot
			// 槽闭包降频求值门（EnabledFn/NextSlotFn 均为装配方 DB 直读闭包，
			// 每 tick 双求值 ≈10 SELECT/s 常驻读放大）：
			//  ① 槽缓存为零（未求值/未武装）→ 仅地板周期到点求值——长期零槽是
			//     生产实态（威胁/爬虫全局开但所有单源关）：每 tick 求值 =
			//     EnabledFn+NextSlotFn ≈3 SELECT/s/任务 的常驻空转。首槽武装的
			//     发现延迟上界=地板周期（武装是低频管理动作，可接受）；
			//  ② 槽已消费（slot ≤ schedDoneSlot：成功落定/用户取消的本槽）→
			//     仅地板周期到点求值——等业务推进/重排为新槽，期间零 DB 读；
			//  ③ 未消费且进入到期前导窗（now ≥ slot-lead）→ 每 tick 求值——
			//     到点即投，新鲜度与降频前一致；
			//  ④ 槽远期 → 仅地板周期到点求值——收敛用户重排/带外改库造成的
			//     陈旧缓存（生效延迟上界=地板周期；排程保存路径本身即重排
			//     next_update，地板内自然收敛）。
			consumed := !prevSlot.IsZero() && !prevSlot.After(doneSlot)
			floorDue := now.Sub(r.schedSlotEvalAt) >= time.Duration(schedSlotEvalFloor.Load())
			needEval := floorDue ||
				(!consumed && !prevSlot.IsZero() && !now.Before(prevSlot.Add(-schedSlotEvalLead)))
			r.mu.Unlock()
			// 角色门前置（与 Periodic 分支 allows 快照同构）：从节点/角色不符时
			// 整分支跳过——EnabledFn/NextSlotFn 是装配方闭包（生产=DB 直读），
			// 此前每 tick 先求值再在 due 判定里筛角色，从节点白付两次 DB 读
			// （promote 后下一 tick 自然恢复求值，无需额外状态）。
			if !e.roleAllows(r.desc.RunsOn) {
				continue
			}
			if !needEval {
				// 槽缓存未到求值时机 ⇒ 槽必未到期（到期槽恒在前导窗内，恒
				// 求值）或已消费——本 tick 零闭包求值零 DB 读。
				continue
			}
			// EnabledFn 业务门——false 时整分支跳过：不评估
			// 槽（省 µs 级 SELECT）、不落槽缓存、零执行零落行零日志；节拍（槽
			// 缓存重读）天然不推进——恢复 true 后下一 tick 重读槽，到期
			// 槽立即投递。闭包 panic 经 safeBool fail-closed 为 false。
			if enabledFn != nil && !safeBool(id+".EnabledFn", enabledFn) {
				continue
			}
			// 求值节拍只在真正求值时推进：角色门/业务门拦下的 tick 不算一次
			// 求值——否则 demote 期间或业务关闭期间「零槽」缓存会把地板耗尽，
			// promote/恢复 true 后要多等一个地板才重新发现槽（恢复应立即投递
			// 到期槽）。
			r.mu.Lock()
			r.schedSlotEvalAt = now
			r.mu.Unlock()
			var next time.Time
			if slotFn != nil {
				next = safeSlot(id+".NextSlotFn", slotFn)
			}
			r.mu.Lock()
			if slotFn != nil {
				// 求值在锁外——窗口内 runNow 可能已回写新槽（手动/自动
				// 执行完成）。仅当槽未被并发改写时才落本次求值，否则保留现值
				// （陈旧求值会把未来槽打回过去，形成重复投递）。
				if r.nextScheduledTime.Equal(prevSlot) {
					r.nextScheduledTime = next
				}
			}
			// 到期判定含「同一槽只执行一次」门：slot ≤ schedDoneSlot 的槽
			// （成功落定未推进/用户取消放弃）不再投递，业务推进/重排为新槽
			// 后自然恢复。
			due := !r.nextScheduledTime.IsZero() && now.After(r.nextScheduledTime) && r.nextScheduledTime.After(r.schedDoneSlot)
			eligible := r.loopEnabled && !r.running
			r.mu.Unlock()
			// 第二次 roleAllows 不是冗余：首道（本分支顶部）只做「快照前
			// 省 DB 读」的前置过滤，而 due 判定到 admission 之间解锁过 mutex
			// 并调用了 NextSlotFn（闭包，可能耗时可观），期间 SetRole/节点角色
			// 翻转可发生——按最新角色复核才能避免在已 demote 的节点上投递。
			// 保留两次调用，勿合并为一次快照。
			if !due || !eligible || !e.roleAllows(r.desc.RunsOn) {
				continue
			}
			// 业务门二次复核——首道 EnabledFn 求值在
			// NextSlotFn（生产为 DB 直读）之前，求值窗口内用户关掉任务时，
			// 「已停止仍派发一轮」与本族「EnabledFn=false=零执行零落行」契约
			// 冲突。与 Periodic 投递前复核同口径（同样只在 due&&allows 路径
			// 复核，避免给未到期 tick 增加 DB 读取）。
			if enabledFn != nil && !safeBool(id+".EnabledFn", enabledFn) {
				continue
			}
			// 与 Periodic 的同型收口——
			// admission 与派发判定同步完成，再异步执行。StopLoop/槽并发改写
			// 落在判定后窗口时 reservation 失败，不再出现「已停止仍启动一次」
			// （旧形态 go runNow 的 admission 由派发 goroutine 承担）。
			// 声明：reservation 只复核 Kind/loopEnabled/槽/角色，不消费
			// EnabledFn——业务门由上方首道 + 投递前二次复核承担，两者都不在
			// admission 临界区内（EnabledFn 是装配方闭包，可能在临界区内做 DB
			// 读，纳入会重演 的锁内 DB 延迟传导）。
			res, err := e.reserveScheduledRun(id, now)
			if err != nil {
				continue
			}
			go func(rid string, reservation *runReservation) {
				defer reservation.release()
				_, _ = e.executeRun(reservation, rid, "auto", "")
			}(id, res)
		case KindPeriodic:
			// 固定间隔：每轮独立执行（Run→exit→记录）；in-flight 跳过本轮。
			// 业务开关关（EnabledFn=false）时置零 lastCheck（不推进节拍）——
			// 业务开启后下一 tick 立即到期。角色节拍复位由 SetRole 的
			// demote/promote 分支承担（原实现在角色门判定前推进节拍，从节点
			// 时钟照常走，promote 后首轮要等残余 interval，最坏 6h/24h）。
			allows := e.roleAllows(r.desc.RunsOn)
			// 角色门前置（与 Scheduled 分支同型对称）：角色不符时整分支
			// 跳过——EnabledFn/IntervalFn 是装配方闭包（可含 DB 直读），
			// 从节点不得每 tick 白付求值。节拍复位由 SetRole 的 demote/promote
			// 分支承担（lastCheck 置零），本分支无需再动 lastCheck。
			if !allows {
				continue
			}
			r.mu.Lock()
			if !r.loopEnabled || r.running {
				r.mu.Unlock()
				continue
			}
			intervalFn := r.desc.IntervalFn
			enabledFn := r.desc.EnabledFn
			r.mu.Unlock()
			// +：EnabledFn 先于
			// IntervalFn 求值——业务关闭时整分支跳过（不再每 tick 执行
			// IntervalFn 的 DB 查询），与 Scheduled 分支「EnabledFn=false
			// 整分支跳过」的省读设计对齐。false 置零 lastCheck（不推进
			// 节拍）——恢复 true 后下一 tick 到期立即跑（镜像
			// 语义不变）。闭包 panic 经 safeBool fail-closed 为
			// false。在途 Run 不受门杀（门只作用于调度判定，当前轮跑完、
			// 下一轮才停）。
			if enabledFn != nil && !safeBool(id+".EnabledFn", enabledFn) {
				r.mu.Lock()
				r.lastCheck = time.Time{}
				r.mu.Unlock()
				continue
			}
			// IntervalFn 锁外求值——同族收敛
			// 补全（Scheduled NextSlotFn 已移锁外）。IntervalFn 若含 DB 读取
			// （wire.go 预告「间隔可配置——读 global_config」形态），持 r.mu
			// 会把延迟传导到同任务 Cancel/IsRunning/StopLoop。回锁后以新鲜
			// lastCheck/loopEnabled/running 复核——窗口内 SetRole 置零节拍
			// 不被陈旧快照覆写。
			var interval time.Duration
			if intervalFn != nil {
				interval = safeInterval(id+".IntervalFn", intervalFn)
			}
			if interval <= 0 {
				// 动态 IntervalFn 只能在 tick 锁外求值（注册期调用会阻塞装配）。
				// 非正周期必须停止该任务调度，否则 due 恒真形成单飞忙循环。
				// 停止来源必须机器可读：只写任务日志行时视图与用户主动停止完全
				// 同形（loop_on=false、状态列 idle、24h 失败计数 0、无 task_runs
				// 痕迹），管理员只能翻 tasks/{id}.log 分辨。故同步落一条 failed
				// 运行行——状态列呈现 failed（含原因），与 executeRun 的失败轮
				// 同形；StartLoop 关→开即可重启该任务（下一轮重新求值）。
				r.mu.Lock()
				r.loopEnabled = false
				r.lastCheck = time.Time{}
				r.mu.Unlock()
				const stopMsg = "调度停止：IntervalFn 必须返回正周期"
				runID := globalInsertRunAt(id, r.desc.Family, "auto", engineNowStr(), "")
				e.finishRunWithMessage(runID, "failed", 0, stopMsg)
				taskLogAppend(id, fmt.Sprintf("[error] %s，实际=%s（引擎已停止该任务调度，重开调度后重新求值）", stopMsg, interval))
				continue
			}
			r.mu.Lock()
			due := r.loopEnabled && !r.running && (r.lastCheck.IsZero() || now.Sub(r.lastCheck) >= interval)
			if !due {
				r.mu.Unlock()
				continue
			}
			r.mu.Unlock()
			// IntervalFn 锁外等待期间业务门可能已翻转。仅在 due && allows
			// 投递路径复核，避免给未到期 tick 增加 DB 读取；false 与首轮门
			// 同口径置零节拍。复核本身也在锁外，返回后重读状态，防止窗口内
			// StopLoop/并发 tick 以陈旧快照投递。
			if enabledFn != nil && !safeBool(id+".EnabledFn", enabledFn) {
				r.mu.Lock()
				r.lastCheck = time.Time{}
				r.mu.Unlock()
				continue
			}
			r.mu.Lock()
			due = r.loopEnabled && !r.running && (r.lastCheck.IsZero() || now.Sub(r.lastCheck) >= interval)
			r.mu.Unlock()
			if !due {
				continue
			}
			// 同步完成 admission 与节拍写入，再异步执行。
			// Pause/角色降级/StopLoop 在窗口内获胜时 reservation 失败，
			// lastCheck 保持未推进；恢复后下一 tick 立即到期。
			res, err := e.reservePeriodicRun(id, now)
			if err != nil {
				continue
			}
			go func(rid string, reservation *runReservation) {
				defer reservation.release()
				_, _ = e.executeRun(reservation, rid, "auto", "")
			}(id, res)

		case KindDaemon:
			// 不进周期 tick——由 StartLoop 启动（Run 阻塞直到取消）
		case KindOneshot:
			// 不进周期 tick——仅 Trigger
		}
	}
}

func (e *Engine) roleAllows(role Role) bool {
	e.roleMu.RLock()
	defer e.roleMu.RUnlock()
	return e.roleAllowsLocked(role)
}

// roleAllowsLocked 在 roleMu 已持锁时判定角色；调用方用于把角色复查与
// Run cancel 注册放进同一临界区，关闭预检→执行入口的 TOCTOU 窗口。
func (e *Engine) roleAllowsLocked(role Role) bool {
	switch role {
	case RoleMasterOnly:
		return e.role
	case RoleSlaveOnly:
		return !e.role
	default:
		return true
	}
}

// ---- 时区 ----

var engineLocAtomic atomic.Value

func init() { engineLocAtomic.Store(time.Local) }

func SetLocation(loc *time.Location) {
	if loc != nil {
		engineLocAtomic.Store(loc)
	}
}

func engineLocPtr() *time.Location { return engineLocAtomic.Load().(*time.Location) }

func engineNowStr() string { return time.Now().In(engineLocPtr()).Format("2006-01-02 15:04:05") }

// engineLogTimeStr 任务日志行时间戳：斜杠形态——与
// TeeTaskLog 业务行统一。engineNowStr 是 DB 写入/datetime() 比较口径
// （SQLite 时间串只认横杠），两者各司其职勿合并。
func engineLogTimeStr() string { return time.Now().In(engineLocPtr()).Format("2006/01/02 15:04:05") }

// ---- 日志 ----

// taskLogConf 任务日志目录/尺寸配置与日志熔断状态（同一把读写锁——装配期
// 写一次、热路径逐行读）。此前为裸全局（taskLogDir/taskLogSizeBytesFn），
// 测试在引擎存活期与任务写日志并发调用 SetLogDir/SetTaskLogSizeBytesFn
// 存在数据竞争。
//
// 熔断分两级，粒度必须与故障粒度一致：
//   - dirDown：目录级故障（MkdirAll 失败=父路径被文件占据/权限/只读挂载）。
//     唯一会波及全部任务日志的形态，按全局熔断收口。
//   - pathDown：单文件故障（rotate/open/write/close 失败=单文件权限/属主/
//     单文件 IO 错误）。按路径熔断，只静默丢弃该文件的行——此前单文件连续
//     失败会把 dirDown 置位，同一目录下其他健康任务日志一并被丢弃最长一个
//     探测周期，且探针时刻仍是坏路径在写时窗口持续续期。
//
// 熔断窗口内任务日志静默丢弃（进入熔断时已留一次性 ERROR），每
// taskLogDirProbeInterval 探测一次，恢复时补 INFO 并退出熔断。
type taskLogPathCircuit struct {
	down      bool
	nextProbe time.Time
	failures  int
}

var taskLogConf = struct {
	sync.RWMutex
	dir    string
	sizeFn func() int64
	// dirDown：目录级不可用（无法创建）。恢复判定=真实写入链全通。
	dirDown      bool
	dirNextProbe time.Time
	// pathCircuit：按任务日志路径的单文件熔断态（仅失败过的路径有条目，
	// 写入成功即删除——键集合恒为「当前失败的文件」，天然有界）。
	pathCircuit map[string]*taskLogPathCircuit
}{}

// taskLogDirProbeInterval 目录熔断恢复探测周期（测试可调；原子值避免测试
// 并发改写与 tick/写入路径读取构成数据竞争）。
var taskLogDirProbeInterval atomic.Int64

func init() { taskLogDirProbeInterval.Store(int64(time.Minute)) }

// taskLogWriteFailureThreshold 连续写失败多少次进入熔断（首次失败仍在
// WARNING 留痕，保留「偶发 EACCES/磁盘抖动」的可观测性；持续失败不再逐行）。
const taskLogWriteFailureThreshold = 3

func taskLogProbeInterval() time.Duration { return time.Duration(taskLogDirProbeInterval.Load()) }

// SetLogDir 设置任务日志目录；换目录即重置熔断（新目录健康状况未知，
// 首行写入重新判定）。
func SetLogDir(dir string) {
	taskLogConf.Lock()
	taskLogConf.dir = dir
	taskLogConf.dirDown = false
	taskLogConf.dirNextProbe = time.Time{}
	taskLogConf.pathCircuit = nil
	taskLogConf.Unlock()
}

// LogDir 当前任务日志目录（certjoblog 子目录挂靠点；空串=未初始化）。
func LogDir() string {
	taskLogConf.RLock()
	defer taskLogConf.RUnlock()
	return taskLogConf.dir
}

// TaskLogPath 返回已注册任务的日志文件路径：任务日志目录之下一个 .log 文件，
// 文件名主体由注册任务 ID 净化而来（同一 ID 恒映射同一文件；未注入日志目录或
// 净化后为空时返回空串，调用方按「无日志」处理）。
//
// 净化用白名单而不是黑名单：只保留注册任务 ID 字母表 [A-Za-z0-9_.:-]，与
// handlers sanitizeRuleID 同族口径（畸形 ID 不再产出黑名单遗漏字符的文件名）。
// 目录穿越需要路径分隔符，白名单剔除后 `:id` 这个用户可控面
// （GetSystemTaskLogs）不可能逃出任务日志目录——该路由位于 business 读组
// （全部登录用户可读，主节点/管理员不是前置条件），因此白名单是路径安全边界
// 而非授权边界；与 certjoblog certJobLogFileComponent（可逆编码）/
// logstats sanitizeRuleID 同族。
func TaskLogPath(taskID string) string {
	dir := LogDir()
	if dir == "" {
		return ""
	}
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '_' || r == '.' || r == ':' || r == '-':
			return r
		default:
			return -1
		}
	}, taskID)
	// 净化后为空（全非法字符 ID）不得拼出共享的 <dir>/.log——与未初始化
	// 同语义返回空串（读路径仅此一个消费面，handlers 按空串=无日志处理）。
	if sanitized == "" {
		return ""
	}
	return filepath.Join(dir, sanitized+".log")
}

// taskLogLineMaxBytes 单行任务日志上限：DB 侧 message 经
// truncMsg 截到 500，日志行此前无上限——Caddy 响应体/长 SQL 错误等巨型
// error 串会让单行直接超过 task_log_size_mb，滚动判定（size+len(line)）
// 先滚动又写出超限活动文件并对后续每行反复触发滚动。统一上限让
// 「日志行」与「DB message」两个消费面口径收敛（4096 远大于正常排障行，
// 又足以容纳完整堆栈首段），截断在 appendTaskLogLine 滚动判定之前完成。
const taskLogLineMaxBytes = 4096

// taskLogTruncSuffix 截断标记：超长行显式告知「内容被裁掉」，避免排障时
// 把截断误读成错误串本身如此。字节预算含后缀，保证截断后 ≤ 上限。
const taskLogTruncSuffix = " …[行已截断]"

// TruncateTaskLogLine 把超长日志行裁到 taskLogLineMaxBytes。裁剪点回退到
// rune 边界——错误串含中文时按字节硬切会产出非法 （页/编辑器
// 显示乱码，且按行解析的工具可能整行丢弃）。
func TruncateTaskLogLine(line string) string {
	return truncateUTF8(line, taskLogLineMaxBytes, taskLogTruncSuffix)
}

// taskLogLineBreaks 日志行的换行归一表（CRLF 先于单字符匹配，一次替换
// 只产出一个空格，不留下空位）。
var taskLogLineBreaks = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ")

// SanitizeTaskLogLine 把一条日志行归一为**单行**：错误串/响应体里的 CR、LF
// 会让单次写入在日志文件里伪造出多条无前缀的行（按行解析的排障工具与保留
// 期清理会把伪造行当成独立条目；裸 CR 还会让后续内容覆盖行首）。换行替换为
// 空格——载荷正文保留，只抹掉行结构。
//
// 调用顺序固定为「先净化、后截断」（TruncateTaskLogLine）：截断预算须按净化
// 后的单行计，否则被裁掉的可能正是换行之后的伪造段、也可能净化让已截断的行
// 重新变长。
func SanitizeTaskLogLine(line string) string {
	if !strings.ContainsAny(line, "\r\n") {
		return line
	}
	return taskLogLineBreaks.Replace(line)
}

// appendTaskLogLine 打开→追加→关闭共享实现（taskLogAppend
// 与 TeeTaskLog 曾双份同形四步；MkdirAll 幂等，保留逐行兜底形态不变）。
func appendTaskLogLine(path, line string) {
	// 换行归一再截断：两者都必须先于滚动判定——否则巨型单行会先
	// 触发滚动、再把超限活动文件写出来，后续每行都反复触发滚动。
	line = SanitizeTaskLogLine(line)
	line = TruncateTaskLogLine(line)
	// 熔断前置判定（在 rotate/open 之前——熔断期二者必然失败，
	// 逐行 WARNING 会淹没运行日志）。目录级熔断（无法创建）对全部任务日志
	// 成立；单文件熔断只对本次 path 成立——其他健康文件照常写入。
	taskLogConf.RLock()
	dir := taskLogConf.dir
	dirDown := taskLogConf.dirDown
	dirProbeAt := taskLogConf.dirNextProbe
	var pathDown bool
	var pathProbeAt time.Time
	if c := taskLogConf.pathCircuit[path]; c != nil {
		pathDown, pathProbeAt = c.down, c.nextProbe
	}
	taskLogConf.RUnlock()
	now := time.Now()
	if dirDown && now.Before(dirProbeAt) {
		return // 目录熔断窗口内静默丢弃（进入熔断时已留一次性 ERROR）
	}
	if pathDown && now.Before(pathProbeAt) {
		return // 本文件熔断窗口内静默丢弃（其他任务日志不受影响）
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			// 不可创建：立即熔断（一次 ERROR；熔断窗口内由上方前置判定静默）。
			taskLogEnterDirDownLocked(dir, "创建目录", err)
			return
		}
	}
	// 阈值必须在取路径锁之前求值：缓存未命中时 taskLogSizeBytes 会读库
	// （最坏占满 busy_timeout）——持「按路径日志锁」读库会让全部任务日志
	// 写入在各自 pathLock 内排队等同一把缓存锁（任务体被日志拖住）。
	sizeLimit := taskLogSizeBytes()
	// 按路径互斥包住「stat→rotate→append」整段——锁只覆盖滚动判定
	// 与本次写入，不同任务日志路径互不阻塞。
	pathLock := lockTaskLogPath(path)
	pathLock.Lock()
	defer pathLock.Unlock()
	// 统一滚动点：taskLogAppend 与 TeeTaskLog 均在此按真实文件大小
	// 先滚动（保留 1 份）再写入，活动文件不因追加突破配置上限。
	writeOK := true
	if _, err := rotateTaskLogBeforeWrite(path, int64(len(line)+1), 1, sizeLimit); err != nil {
		writeOK = false
		taskLogNoteWriteFailure("rotate", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		writeOK = false
		taskLogNoteWriteFailure("open", path, err)
		return
	}
	if _, err := fmt.Fprintln(f, line); err != nil {
		writeOK = false
		taskLogNoteWriteFailure("write", path, err)
	}
	if err := f.Close(); err != nil {
		writeOK = false
		taskLogNoteWriteFailure("close", path, err)
	}
	if writeOK {
		taskLogNoteWriteSuccess(path, dir)
	}
}

// taskLogEnterDirDownLocked 进入/续期日志目录熔断（调用方不持 taskLogConf）。
// 只在 false→true 转换时打 ERROR；熔断窗口内每次探测失败仅续期不重复告警。
func taskLogEnterDirDownLocked(dir, what string, err error) {
	taskLogConf.Lock()
	newly := !taskLogConf.dirDown
	taskLogConf.dirDown = true
	taskLogConf.dirNextProbe = time.Now().Add(taskLogProbeInterval())
	taskLogConf.Unlock()
	if newly {
		log.Printf("ERROR: taskengine: 任务日志目录不可用（%s，%s失败）——进入熔断（每 %s 探测恢复，熔断期任务日志静默丢弃）: %v",
			dir, what, taskLogProbeInterval(), err)
	}
}

// taskLogNoteWriteFailure 记录一次写入链失败（rotate/open/write/close）。
// 熔断与故障粒度一致：这些错误都是**单文件**故障，只把本 path 置为熔断
// （同一目录下其他任务日志不受影响）；连续失败达到阈值即一次 ERROR + 停止
// 逐行 WARNING，已处于熔断态时只续期探测窗口。阈值内的失败仍 WARNING 留痕
// （偶发抖动可见）。
func taskLogNoteWriteFailure(what, path string, err error) {
	taskLogConf.Lock()
	if taskLogConf.pathCircuit == nil {
		taskLogConf.pathCircuit = map[string]*taskLogPathCircuit{}
	}
	c := taskLogConf.pathCircuit[path]
	if c == nil {
		c = &taskLogPathCircuit{}
		taskLogConf.pathCircuit[path] = c
	}
	c.failures++
	trip := !c.down && c.failures >= taskLogWriteFailureThreshold
	if trip {
		c.down = true
		c.failures = 0
	}
	if c.down {
		c.nextProbe = time.Now().Add(taskLogProbeInterval())
	}
	down := c.down
	taskLogConf.Unlock()
	if !down {
		log.Printf("WARNING: taskengine: %s task log %s failed: %v", what, path, err)
		return
	}
	if trip {
		log.Printf("ERROR: taskengine: 任务日志文件不可写（%s，连续 %d 次 %s 失败）——进入熔断（每 %s 探测恢复，熔断期该文件日志静默丢弃）: %v",
			path, taskLogWriteFailureThreshold, what, taskLogProbeInterval(), err)
	}
}

// taskLogNoteWriteSuccess 一次完整写入成功=该文件与目录健康：清该路径的
// 连续失败计数并退出其熔断（探测恢复的唯一判定点——mkdir 成功不等于可写，
// 只有真实写入链全通才算恢复）；目录级熔断同样由真实写入成功解除。
func taskLogNoteWriteSuccess(path, dir string) {
	taskLogConf.Lock()
	var recoveredPath, recoveredDir bool
	if c := taskLogConf.pathCircuit[path]; c != nil {
		recoveredPath = c.down
		delete(taskLogConf.pathCircuit, path)
	}
	recoveredDir = taskLogConf.dirDown
	taskLogConf.dirDown = false
	taskLogConf.dirNextProbe = time.Time{}
	taskLogConf.Unlock()
	if recoveredPath {
		log.Printf("INFO: taskengine: 任务日志文件恢复可写（%s），该文件日志恢复写入", path)
	}
	if recoveredDir {
		log.Printf("INFO: taskengine: 任务日志目录恢复可写（%s），任务日志恢复写入", dir)
	}
}

func taskLogAppend(taskID, line string) {
	path := TaskLogPath(taskID)
	if path == "" {
		return
	}
	appendTaskLogLine(path, engineLogTimeStr()+" "+line)
}

// ---- DB 落库 ----

func globalInsertRun(taskID, family, trigger string) int64 {
	return globalInsertRunAt(taskID, family, trigger, engineNowStr(), "")
}

func globalInsertRunAt(taskID, family, trigger, startedAt, operator string) int64 {
	// 局部快照句柄：`db.DB` 两次读之间可能被 db.Close() 置 nil（关停序列
	// StopTaskEngine→db.Close 时未落定的 Run 仍会走到这里），直接二次解引用
	// 会 nil-deref panic 掉进程（同 services/securityevents_retention.go 先例）。
	database := db.DB
	if database == nil {
		return 0
	}
	res, err := database.Exec(`INSERT INTO task_runs (task_id, family, trigger, operator, status, started_at) VALUES (?,?,?,?, 'running',?)`, taskID, family, trigger, operator, startedAt)
	if err != nil {
		// 插入失败不得静默——runID=0 时后续 finishRun
		// 全系 no-op，该轮执行在任务历史彻底蒸发（零信号）。
		log.Printf("WARNING: taskengine: task_runs 插入失败（%s 本轮无运行记录行）: %v", taskID, err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// updateTaskRunTerminal 任务运行终态的唯一 UPDATE 写点（finishRun /
// finishRunWithMessage / RecordRunFinish 三入口共用，避免 SQL/告警文案三份
// 同形漂移）。nil 库与非法 runID 守卫内置；空 message 不写 message 列
// （既有行语义：无消息=NULL，读侧 COALESCE 归一为空串）。
//
// 更新失败按有界退避重试（SQLITE_BUSY/瞬断）——无条件放弃会让该行滞留
// running 直到进程重启被 RecoverOrphans 回收，任务视图在此期间恒显
// 「运行中」且「运行」按钮被禁用（无失败行、无告警）。重试用尽仍失败只记
// WARNING（兜底归启动回收），不阻塞执行主流程。
const (
	terminalWriteAttempts   = 3
	terminalWriteRetryDelay = 150 * time.Millisecond
)

// taskRunTerminalExec 终态 UPDATE 的执行缝（生产恒等 db.DB.Exec）：
// 重试语义（瞬时失败后成功）需要可注入的首轮失败才能验证，与同包其他
// 故障注入缝同模式。
var taskRunTerminalExec = func(query string, args ...any) (sql.Result, error) {
	// 索引闭合的重试会跨过 db.Close()：句柄已置 nil 时返回明确错误（交由
	// 有界重试/兜底回收），不在闭包内二次解引用 db.DB 造成关停尾 panic。
	database := db.DB
	if database == nil {
		return nil, sql.ErrConnDone
	}
	return database.Exec(query, args...)
}

func updateTaskRunTerminal(runID int64, status string, durMs int64, message string) {
	if runID <= 0 {
		return
	}
	// 这里的 nil 判定只是快路径；真正的关停竞态由 taskRunTerminalExec 内的
	// 句柄快照 + nil 判定兜住（校验后置 nil 的 TOCTOU 不得 panic）。
	if db.DB == nil {
		return
	}
	// finished_at 在首次尝试前定值：重试不改变实际结束时刻。
	finishedAt := engineNowStr()
	var err error
	for attempt := 1; attempt <= terminalWriteAttempts; attempt++ {
		if message != "" {
			_, err = taskRunTerminalExec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=?, message=? WHERE id=?`, status, finishedAt, durMs, message, runID)
		} else {
			_, err = taskRunTerminalExec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=? WHERE id=?`, status, finishedAt, durMs, runID)
		}
		if err == nil {
			return
		}
		if attempt < terminalWriteAttempts {
			time.Sleep(terminalWriteRetryDelay * time.Duration(attempt))
		}
	}
	log.Printf("WARNING: taskengine: task_runs 终态更新失败（run=%d 滞留 running，目标=%s，已重试 %d 次）: %v", runID, status, terminalWriteAttempts, err)
}

func (e *Engine) finishRun(runID int64, status string, durMs int64) {
	updateTaskRunTerminal(runID, status, durMs, "")
}

func (e *Engine) finishRunWithMessage(runID int64, status string, durMs int64, message string) {
	updateTaskRunTerminal(runID, status, durMs, message)
}

// RecordRunStart/Finish 族侧记录（legacy 路径：非引擎调用的直接执行）
func RecordRunStart(taskID, family, trigger string) int64 {
	return globalInsertRun(taskID, family, trigger)
}

func RecordRunFinish(runID int64, status string, durMs int64, message string) {
	// 与同文件其余导出 DB 函数同形的 nil 防护——
	// legacy 直调路径在装配顺序变化/测试环境下 db.DB 可能为 nil（裸 Exec
	// 即 panic）。
	updateTaskRunTerminal(runID, status, durMs, message)
}

// ---- 元数据 ----

type TaskMeta struct {
	ID           string `json:"id"`
	Family       string `json:"family"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Kind         Kind   `json:"kind"`
	IntervalSec  int    `json:"interval_sec"`
	NextSlot     string `json:"next_slot"`
	StatusMirror string `json:"status_mirror"`
	Controllable bool   `json:"controllable"`
	Cancelable   bool   `json:"cancelable"`
	LoopOn       bool   `json:"loop_on"`
	Running      bool   `json:"running"` // Daemon：Run 实际存活（角色门/停止后=false）
	// RestartExhausted：Daemon 自愈预算用尽且已停止调度（此时 LoopOn=false，
	// 与用户主动停止同形——监控据此把永久停摆呈现为 failed）。
	RestartExhausted bool `json:"restart_exhausted,omitempty"`
	// ScheduleStoppedReason 引擎自行停止调度（Scheduled）的来源标记，空=非
	// 引擎停调（用户在调度开关显式停止，或调度仍在开启）。与用户停止同形时
	// 视图据此区分停摆来源并给出恢复入口。
	ScheduleStoppedReason string `json:"schedule_stopped_reason,omitempty"`
	CanTrigger            bool   `json:"can_trigger"`
	// RoleApplicable 本节点角色是否允许该任务运行（RunsOn 派生的只读结论）。
	// 从节点上 master-only 族的 LoopOn/NextSlot 仍是主节点语义的值，视图
	// 据此标注「仅主节点运行」并解释调度开关不可用——不暴露原始角色取值。
	RoleApplicable bool `json:"role_applicable"`
}

// Lookup 单任务元数据（handler 为取单字段跑全量 DescribeAll
// ~12-18 条 SQL——现仅执行该任务的 Fn）。
func (e *Engine) Lookup(id string) (TaskMeta, bool) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return TaskMeta{}, false
	}
	r.mu.Lock()
	loopOn, running, exhausted, stopReason := r.loopEnabled, r.running, r.restartExhausted, r.schedStopReason
	r.mu.Unlock()
	return buildTaskMeta(id, r.desc, loopOn, running, exhausted, stopReason, e.roleAllows(r.desc.RunsOn)), true
}

// buildTaskMeta 元数据构建单源（Lookup 与 DescribeAll 共用）：调用方只负责
// 快照 running/loop_on/自愈态并传入角色判定结果，派生字段与闭包求值集中在此。
// Fn 求值发生在锁外（调用方不持 r.mu），与 tick 同口径经 safe* 隔离 panic——
// 装配闭包单任务缺陷不得让 GET /system/tasks / toggle / detail 整页 500。
// 求值面按 Kind 收窄：IntervalFn 仅 Periodic、NextSlotFn 仅 Scheduled 产出
// 对应字段（错配声明即使绕过注册校验也不产出假 interval_sec/next_slot）。
func buildTaskMeta(id string, d Descriptor, loopOn, running, exhausted bool, stopReason string, roleAllows bool) TaskMeta {
	m := TaskMeta{
		ID: id, Family: d.Family, Name: d.Name,
		Description: d.Description, Category: d.Category, Kind: d.Kind,
		// 类型派生：定时/循环/触发均可手动调度；常驻族恒不可（启停语义，
		// 调度开关+重启承担）。
		CanTrigger:            d.Kind != KindDaemon,
		Cancelable:            d.Cancelable,
		LoopOn:                loopOn,
		Running:               running,
		Controllable:          d.Kind == KindDaemon, // 常驻族可启停（真实生命周期挂钩）
		RestartExhausted:      exhausted,
		ScheduleStoppedReason: stopReason,
		RoleApplicable:        roleAllows,
	}
	if d.Kind == KindPeriodic && d.IntervalFn != nil {
		m.IntervalSec = int(safeInterval(id+".IntervalFn", d.IntervalFn).Seconds())
	}
	if d.Kind == KindScheduled && d.NextSlotFn != nil {
		if t := safeSlot(id+".NextSlotFn", d.NextSlotFn); !t.IsZero() {
			m.NextSlot = t.In(engineLocPtr()).Format("2006-01-02 15:04:05")
		}
	}
	// 状态镜像角色门（2026-10-03 裁定）：任务不在本角色运行时，其
	// StatusFn 读到的常是同步来的业务数据（从节点 cert_jobs/
	// ip2region update_status 均有主端快照镜像）——采纳即伪造本节点
	// running。角色不符一律不采纳（空）→ 视图层呈现本节点实态。
	// StatusFn 不限 Kind（任何族的元数据都消费），闭包 panic 经 safeString
	// 隔离。
	if d.StatusFn != nil && roleAllows {
		m.StatusMirror = safeString(id+".StatusFn", d.StatusFn)
	}
	return m
}

func (e *Engine) DescribeAll() []TaskMeta {
	type snap struct {
		id         string
		desc       Descriptor
		loopOn     bool
		running    bool
		exhausted  bool
		stopReason string
	}
	e.mu.RLock()
	snaps := make([]snap, 0, len(e.regs))
	for id, r := range e.regs {
		r.mu.Lock()
		loopOn, running, exhausted, stopReason := r.loopEnabled, r.running, r.restartExhausted, r.schedStopReason
		r.mu.Unlock()
		snaps = append(snaps, snap{id: id, desc: r.desc, loopOn: loopOn, running: running, exhausted: exhausted, stopReason: stopReason})
	}
	e.mu.RUnlock()

	out := make([]TaskMeta, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, buildTaskMeta(s.id, s.desc, s.loopOn, s.running, s.exhausted, s.stopReason, e.roleAllows(s.desc.RunsOn)))
	}
	// 按「分类固定序 + 类内 ID 字典序」稳定排序——曾直接 range map
	// 输出，连续请求行序随机（前端只做分类排序，类内仍抖动）。
	sortTaskMetas(out)
	return out
}

// taskCategoryOrder 任务分类固定展示序（与任务监控页面分类排序同源口径：
// 安全防护→证书→备份→集群→系统；未知分类排末尾）。
var taskCategoryOrder = map[string]int{
	"安全防护": 0,
	"证书":   1,
	"备份":   2,
	"集群":   3,
	"系统":   4,
}

// sortTaskMetas 稳定输出序：分类固定序优先，同类按 ID 字典序（纯函数，
// 便于测试与复用）。
func sortTaskMetas(metas []TaskMeta) {
	sort.Slice(metas, func(i, j int) bool {
		oi, ok := taskCategoryOrder[metas[i].Category]
		if !ok {
			oi = len(taskCategoryOrder)
		}
		oj, ok := taskCategoryOrder[metas[j].Category]
		if !ok {
			oj = len(taskCategoryOrder)
		}
		if oi != oj {
			return oi < oj
		}
		return metas[i].ID < metas[j].ID
	})
}

// ---- 统计 ----

type TaskRunsStats struct{ Runs, Success, Fail int }

// taskRunsStats24hSelect 24h 统计聚合列单源（Stats24h 逐任务与
// RunOverview 批量共用——同窗口同口径：started_at > now-1day，配置时区
// 墙钟 engineNowStr）。改动窗口/聚合必须只动此处。
const taskRunsStats24hSelect = `COUNT(*),
		COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0)`

// Stats24h 逐任务 24h 统计。测试专供：生产消费方是
// RunOverview 的批量聚合（同 SQL 单源 taskRunsStats24hSelect）。
func (e *Engine) Stats24h(taskID string) TaskRunsStats {
	var st TaskRunsStats
	if db.DB == nil {
		return st
	}
	// Scan 错误不得静默丢弃——与同文件 History/
	// RunOverview 同口径留痕（计数降级为零值，视图仍可用）。
	if err := db.DB.QueryRow(`SELECT `+taskRunsStats24hSelect+`
		FROM task_runs WHERE task_id=? AND started_at > datetime(?, '-1 day')`, taskID, engineNowStr()).Scan(&st.Runs, &st.Success, &st.Fail); err != nil {
		log.Printf("WARNING: taskengine: 24h 统计查询失败（%s 计数降级为零）: %v", taskID, err)
	}
	return st
}

// taskOverviewState 聚合查询失败态（首报/恢复各一条）：/system/tasks 前端
// 5s 轮询，DB 故障期间逐轮 WARNING 会把首因信号淹没。语义与服务层
// logStateTransition 相同（此处不能 import services——依赖方向）。
var taskOverviewState = struct {
	sync.Mutex
	failed map[string]bool
}{failed: map[string]bool{}}

// noteTaskOverviewFailure 返回需要打印的级别（""=状态未变，无需打印）。
func noteTaskOverviewFailure(key string, failed bool) string {
	taskOverviewState.Lock()
	defer taskOverviewState.Unlock()
	prev, seen := taskOverviewState.failed[key]
	if seen && prev == failed {
		return ""
	}
	if !seen && !failed {
		return ""
	}
	taskOverviewState.failed[key] = failed
	if failed {
		return "WARNING"
	}
	return "INFO"
}

func (e *Engine) RunOverview() (map[string]*RunRecord, map[string]TaskRunsStats) {
	latest := map[string]*RunRecord{}
	stats := map[string]TaskRunsStats{}
	// 句柄单次快照 + nil 守卫（关停序列 StopTaskEngine→db.Close 会置 nil；
	// 两次查询必须落在同一个非 nil 句柄上，不得逐次读全局）。
	database := db.DB
	if database == nil {
		return latest, stats
	}
	beforeTaskRunsRead()
	// 最近运行：每任务最大 id（与 History(...,1) 的 ORDER BY id DESC LIMIT 1 同义）。
	// 查询文本单源=db.TaskRunsLatestPerTaskQuery（索引计划钉测同源）。
	latestFailed := false
	rows, err := database.Query(db.TaskRunsLatestPerTaskQuery)
	if err != nil {
		// 降级为空记录（视图仍可用），但不得静默——与同文件其余查询同口径。
		// 5s 轮询下按失败态转换留痕（首报一条 WARNING，故障持续期静默）。
		latestFailed = true
		if level := noteTaskOverviewFailure("latest", true); level != "" {
			log.Printf("%s: taskengine: 最近运行批量查询失败（任务视图无运行记录）: %v", level, err)
		}
	} else {
		for rows.Next() {
			var r RunRecord
			if err := rows.Scan(&r.ID, &r.TaskID, &r.Family, &r.Trigger, &r.Operator, &r.Status, &r.StartedAt,
				&r.FinishedAt, &r.DurationMs, &r.Message); err != nil {
				latestFailed = true
				if level := noteTaskOverviewFailure("latest-scan", true); level != "" {
					log.Printf("%s: taskengine: 最近运行批量行扫描失败（跳过该行）: %v", level, err)
				}
				continue
			}
			rec := r
			latest[rec.TaskID] = &rec
		}
		if err := rows.Err(); err != nil {
			latestFailed = true
			if level := noteTaskOverviewFailure("latest", true); level != "" {
				log.Printf("%s: taskengine: 最近运行批量迭代失败（部分任务缺记录）: %v", level, err)
			}
		}
		rows.Close()
	}
	if !latestFailed {
		if level := noteTaskOverviewFailure("latest", false); level != "" {
			log.Printf("INFO: taskengine: 最近运行批量查询恢复，任务视图恢复运行记录")
		}
		if level := noteTaskOverviewFailure("latest-scan", false); level != "" {
			log.Printf("%s: taskengine: 最近运行批量行扫描恢复，全部任务记录已可解析", level)
		}
	}
	// 24h 统计：与 Stats24h 同窗口/同口径（started_at > now-1day，配置时区墙钟）。
	statFailed := false
	statRows, err := database.Query(`SELECT task_id, `+taskRunsStats24hSelect+`
		FROM task_runs WHERE started_at > datetime(?, '-1 day') GROUP BY task_id`, engineNowStr())
	if err != nil {
		if level := noteTaskOverviewFailure("stats", true); level != "" {
			log.Printf("%s: taskengine: 24h 统计批量查询失败（计数降级为零）: %v", level, err)
		}
		return latest, stats
	}
	defer statRows.Close()
	for statRows.Next() {
		var id string
		var st TaskRunsStats
		if err := statRows.Scan(&id, &st.Runs, &st.Success, &st.Fail); err != nil {
			statFailed = true
			if level := noteTaskOverviewFailure("stats-scan", true); level != "" {
				log.Printf("%s: taskengine: 24h 统计批量行扫描失败（跳过该行）: %v", level, err)
			}
			continue
		}
		stats[id] = st
	}
	if err := statRows.Err(); err != nil {
		statFailed = true
		if level := noteTaskOverviewFailure("stats", true); level != "" {
			log.Printf("%s: taskengine: 24h 统计批量迭代失败（部分任务计数缺失）: %v", level, err)
		}
	}
	if !statFailed {
		if level := noteTaskOverviewFailure("stats", false); level != "" {
			log.Printf("INFO: taskengine: 24h 统计批量查询恢复")
		}
		if level := noteTaskOverviewFailure("stats-scan", false); level != "" {
			log.Printf("%s: taskengine: 24h 统计批量行扫描恢复，全部任务计数已可解析", level)
		}
	}
	return latest, stats
}

// TaskHourlyStat 24h 分小时桶（配置时区墙面小时——engineNowStr/CurrentLocation
// 同基准，与 task_runs 存储串一致；时区基本原则 2026-10-11）。
type TaskHourlyStat struct {
	Hour    string `json:"hour"`
	Success int    `json:"success"`
	Failed  int    `json:"failed"`
}

// Stats24hHourlySeries 最近 24 个墙面小时的成功/失败计数（任务监控图表重构，
// 2026-10-11 用户裁定方案 A：时间序列替代任务名柱状图，高频任务不再压制其他
// 任务）。窗口=now-23h..now 逐小时升序 24 桶，空桶零填。
func (e *Engine) Stats24hHourlySeries() []TaskHourlyStat {
	loc := engineLocPtr()
	// 墙面小时按日历分量取整。Truncate(time.Hour)
	// 按 Unix 纪元绝对时长取整，+05:30 等非整小时偏移时区下产出 :30 桶键，
	// 与 strftime('%H:00:00') 的墙面键永不相交（24 桶全零）。DST 形状：
	// 桶键与 WHERE 界同用本锚点做绝对时长加减——fall-back 重复墙时合并到
	// 后桶（计数不丢）、spring-forward 消失墙时无行可落。
	now := time.Now().In(loc)
	curHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, loc)
	out := make([]TaskHourlyStat, 24)
	idx := map[string]int{}
	for i := 0; i < 24; i++ {
		h := curHour.Add(time.Duration(i-23) * time.Hour).Format("2006-01-02 15:04:05")
		out[i].Hour = h
		idx[h] = i
	}
	// 句柄单次快照 + nil 守卫（同上：关停窗口内不得二次读全局句柄）。
	database := db.DB
	if database == nil {
		return out
	}
	beforeTaskRunsRead()
	rows, err := database.Query(`SELECT strftime('%Y-%m-%d %H:00:00', started_at) AS h,
		COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0)
		FROM task_runs WHERE started_at >= ? GROUP BY h`,
		curHour.Add(-23*time.Hour).Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Printf("WARNING: taskengine: 24h 分小时统计查询失败（小时桶零填）: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		var s, f int
		if err := rows.Scan(&h, &s, &f); err != nil {
			// Scan 失败须留痕（此前 err == nil 才落桶、
			// 失败静默——同批触碰未同步收敛的同族漏点）。
			log.Printf("WARNING: taskengine: 24h 分小时桶行扫描失败（该桶零填）: %v", err)
			continue
		}
		if i, ok := idx[h]; ok {
			out[i].Success, out[i].Failed = s, f
		}
	}
	// 迭代错误须留痕——此前表现为「部分桶 + 静默」。
	// 24 桶零填形状不变（图表降级为空序列）。
	if err := rows.Err(); err != nil {
		log.Printf("WARNING: taskengine: 24h 分小时统计迭代失败（部分小时桶缺失）: %v", err)
	}
	return out
}

func (e *Engine) LatestRun(taskID string) *RunRecord {
	runs := e.History(taskID, 1)
	if len(runs) == 0 {
		return nil
	}
	return &runs[0]
}

// PurgeTaskRuns 删除超过保留天数的任务运行历史。d<=0 或主库不可用时为
// no-op；ctx 贯穿删除语句——取消/关停后不再启动新的不可逆删除，句柄取局部
// 快照（nil 判定与 ExecContext 必须针对同一个 *sql.DB，关停尾部 db.Close()
// 可能在两者之间把包级 db.DB 置 nil）。
func PurgeTaskRuns(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	database := db.DB
	if database == nil {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	res, err := database.ExecContext(ctx, `DELETE FROM task_runs WHERE started_at < datetime(?, ?)`, engineNowStr(), fmt.Sprintf("-%d days", days))
	if err != nil {
		log.Printf("WARNING: taskengine: 清理过期任务记录失败: %v", err)
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("读取任务运行历史删除行数失败: %w", err)
	}
	return n, nil
}

// ---- 业务侧日志 helper ----

func TeeTaskLogTime(taskID, level, stage, message string) {
	TeeTaskLog(taskID, engineLogTimeStr(), level, stage, message)
}

func TeeTaskLog(taskID, timestamp, level, stage, message string) {
	path := TaskLogPath(taskID)
	if path == "" {
		return
	}
	appendTaskLogLine(path, fmt.Sprintf("%s [%s] %s - %s", timestamp, level, stage, message))
}
