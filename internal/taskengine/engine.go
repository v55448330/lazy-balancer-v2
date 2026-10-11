// Package taskengine 是统一任务引擎（v2.0 四类型标准）：
// 定时(Scheduled)=排程槽驱动 | 常驻(Daemon)=自管理循环 | 循环(Periodic)=固定间隔
// 触发(Oneshot)=手动/代码触发。
// 引擎按 Kind 分流调度/记录/日志——零 flag 零补丁。
package taskengine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

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
	RoleSlaveOnly  Role = "slave-only" // 仅测试注册使用（U1 P5 备注）
)

// RunContext 交给任务体的执行上下文。
type RunContext struct {
	Ctx      context.Context
	Trigger  string // manual | auto | startup
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
	EnabledFn  func() bool // false=暂停（引擎不调度）
	// BootSync：Oneshot 任务在引擎初始化尾部同步执行一次（trigger=startup）
	// ——启动型任务的唯一执行通道（曾 main.go 直调+legacy 记录旁路）。
	BootSync   bool
	StatusFn   func() string    // 状态镜像
	ToggleFn   func(bool) error // 调度开关 setter
	ToggleName string
	ManualRun  bool
	Cancelable bool
	RunsOn     Role
	MasterOnly bool
	// RestartOnRoleFlip：Run 体按角色分流时置位（2026-10-03 裁定，
	// cluster-sync 引入）——角色真实翻转即换代重启（旧代 Run 体持旧分支，
	// 不换代则分支与角色脱钩）。未置位的 RoleAny 常驻（如
	// security-events-ingestion）翻转不重启，无换代噪音。
	RestartOnRoleFlip bool
}

// RunRecord task_runs 行视图。TASK-L7（第 69 轮）：stage/entry_count 两列
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

// ErrTaskSkipped 任务跳过哨兵（TASK-L5，第 69 轮 P2）：demote 中止等「非故障
// 放弃」语义由 Run 体返回该哨兵，terminalStatus 映射为 task_runs skipped 终态
// （CHECK 约束内既有值，此前零写入方）。
var ErrTaskSkipped = errors.New("taskengine: 任务跳过")
var ErrNotFound = errors.New("taskengine: 任务未注册")

// ---- registration ----

type registration struct {
	desc Descriptor

	mu                sync.Mutex
	running           bool
	cancel            context.CancelFunc
	lastCheck         time.Time // Periodic：最近到期判定基准
	nextScheduledTime time.Time // Scheduled：下一槽（每 tick 重读——µs 级 SELECT）
	loopEnabled       bool      // 循环/调度开关
	pendingRestart    bool      // daemon restart 意图：旧 Run 退出后自动拉起新代（U1-P2-3）
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
	// stopped 原子化（U1-66-01 第四触发面）：daemon 退出清理路径在 r.mu
	// 临界区外复核——不得为读它反向嵌套 e.mu（Stop 持 e.mu→r.mu）。
	stopped   atomic.Bool
	startedAt time.Time
	daemonWG  sync.WaitGroup // daemon goroutine 退出等待（2026-10-04 测试污染修复）
}

type Options struct {
	TickInterval time.Duration
}

func NewEngine(opts Options) *Engine {
	if opts.TickInterval <= 0 {
		opts.TickInterval = time.Second
	}
	e := &Engine{
		opts: opts, regs: map[string]*registration{}, role: true,
		schedStop: make(chan struct{}), schedDone: make(chan struct{}),
		startedAt: time.Now(),
	}
	go e.scheduleLoop()
	return e
}

func (e *Engine) StartedAt() time.Time { return e.startedAt }

func (e *Engine) Stop() {
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
			r.cancel()
		}
		r.mu.Unlock()
	}
	e.mu.Unlock()
	<-e.schedDone
	e.daemonWG.Wait() // 等全部 daemon goroutine 退出——防止跨测试/跨引擎残留（2026-10-04）
}

func (e *Engine) SetRole(isMaster bool) {
	e.roleMu.Lock()
	flipped := e.role != isMaster
	e.role = isMaster
	e.roleMu.Unlock()
	// Daemon 生命周期随角色翻转：master-only daemon 在 demote 时停止、
	// promote 时拉起（loopEnabled 保持用户调度开关语义）。SetRole 重申
	// （生产启动/翻转期为三连调用）不是重启意图——tryStartDaemon 传
	// false，不再误栽 pendingRestart（U1-66-01）。Periodic 不启停，仅
	// 角色真实获得时置零节拍使下一 tick 即到期（U1-66-02：原置零分支
	// 位于仅收集 Daemon 的切片内不可达）。F-L2-68-01（第 68 轮）：
	// Scheduled 在途 Run 随角色不符中止——demote 后继续跑完会让从节点
	// 写版本行/名单/规则树，打破只读不变量；取消经 rc.Ctx 传播，三库
	// Run 体据此落 skipped（与起点角色复查同语义）。promote 无需动作
	// （tick 每轮重读 NextSlotFn 自动到点触发）。
	e.mu.RLock()
	targets := make([]*registration, 0, len(e.regs))
	for _, r := range e.regs {
		if r.desc.Kind == KindDaemon || r.desc.Kind == KindPeriodic || r.desc.Kind == KindScheduled {
			targets = append(targets, r)
		}
	}
	e.mu.RUnlock()
	for _, r := range targets {
		if r.desc.Kind == KindPeriodic {
			if flipped && e.roleAllows(r.desc.RunsOn) {
				r.mu.Lock()
				r.lastCheck = time.Time{}
				r.mu.Unlock()
			}
			continue
		}
		if r.desc.Kind == KindScheduled {
			// 角色不符（demote/重申从节点）：取消在途 Run——与下方 Daemon
			// 分支同型；loopEnabled 保留（promote 后 tick 自动恢复排程）。
			if !e.roleAllows(r.desc.RunsOn) {
				r.mu.Lock()
				c := r.cancel
				r.mu.Unlock()
				if c != nil {
					c()
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
					c()
					continue
				}
				r.mu.Unlock()
			}
			e.tryStartDaemon(r, false)
			continue
		}
		// 角色不符：仅取消 Run（loopEnabled 保留——promote 后自动拉起，
		// 用户调度开关语义不被角色翻转隐式改写）
		r.mu.Lock()
		c := r.cancel
		r.mu.Unlock()
		if c != nil {
			c()
		}
	}
}

// IsTaskInFlight 任务 Run 是否在途（handler 同步单飞预检——L1-3）。
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
// 只有一个胜出；U1-P2-4 统一入口）。restartIntent 仅在 StartLoop 的
// 关→开真实重启过渡时为 true——SetRole 角色重申恒 false（U1-66-01）。
func (e *Engine) tryStartDaemon(r *registration, restartIntent bool) {
	r.mu.Lock()
	if !r.loopEnabled {
		r.mu.Unlock()
		return
	}
	if r.running {
		// U1-P2-3：在跑但已请求停止（restart 的 Stop 半程）——记意图，
		// 旧 Run goroutine 退出清理时自动拉起新代
		if restartIntent && r.cancel != nil {
			r.pendingRestart = true
		}
		r.mu.Unlock()
		return
	}
	// U1-66-04：占位与 cancel 登记同临界区——StopLoop/Stop/角色翻转
	// 不再有「running=true 但 cancel==nil」的首停信号丢失窗口。
	r.running = true
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.mu.Unlock()
	e.startDaemon(r.desc.ID, r, ctx, cancel)
}

func (e *Engine) Register(d Descriptor) error {
	if d.ID == "" || d.Family == "" {
		return errors.New("taskengine: ID/Family 必填")
	}
	// TASK-L2（第 69 轮 P2）：Kind 与 Fn 配套校验——Periodic 缺 IntervalFn 会在
	// tick 处 nil 调用 panic（scheduleLoop goroutine 崩→进程退出），Scheduled 缺
	// NextSlotFn 则永不到期静默停摆。注册期响亮拒绝。
	if d.Kind == KindPeriodic && d.IntervalFn == nil {
		return fmt.Errorf("taskengine: %s 为 Periodic 任务，必须提供 IntervalFn", d.ID)
	}
	if d.Kind == KindScheduled && d.NextSlotFn == nil {
		return fmt.Errorf("taskengine: %s 为 Scheduled 任务，必须提供 NextSlotFn", d.ID)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.regs[d.ID] = &registration{desc: d}
	return nil
}

// SetManualRun 补设手动触发语义。
func (e *Engine) SetManualRun(id string, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, exist := e.regs[id]; exist {
		r.desc.ManualRun = ok
	}
}

func (e *Engine) Trigger(id, trigger, operator string) error {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return ErrNotFound
	}
	// U1-66-09 纵深：常驻族不暴露手动触发（启停即可）——handler CanTrigger 门
	// 之外的第二道防线；此前 Trigger 可直跑 daemon Run 绕过真实生命周期挂钩。
	if r.desc.Kind == KindDaemon {
		return errors.New("taskengine: 常驻任务不支持手动触发（启停即可）")
	}
	if r.desc.MasterOnly && !e.isMaster() {
		return errors.New("taskengine: 该操作仅允许在主节点执行")
	}
	_, err := e.runNow(id, trigger, operator)
	return err
}

// RunSync 同步执行一次并返回 runID（handler 直调入口——响应需要行视图）。
func (e *Engine) RunSync(id, trigger, operator string) (int64, error) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return 0, ErrNotFound
	}
	// U1-P4-4（第 67 轮）：与 Trigger 同型守卫——常驻任务仅引擎调度（启停即可），
	// RunSync 直调会绕过 startDaemon 生命周期挂钩与常驻循环双跑（防御缺口：
	// 当前调用面未触达，B 批裁定语义=常驻任务仅引擎调度）。
	if r.desc.Kind == KindDaemon {
		return 0, errors.New("taskengine: 常驻任务不支持手动触发（启停即可）")
	}
	if r.desc.MasterOnly && !e.isMaster() {
		return 0, errors.New("taskengine: 该操作仅允许在主节点执行")
	}
	return e.runNow(id, trigger, operator)
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
		_, _ = e.runNow(it.id, "startup", "")
	}
}

func (e *Engine) Cancel(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil || !r.desc.Cancelable {
		return false
	}
	r.mu.Lock()
	c := r.cancel
	running := r.running
	r.mu.Unlock()
	hook := r.desc.CancelHook
	if hook != nil {
		ok := hook()
		// L1-6（第 65 轮）：manager 侧取消成功后同步取消引擎 ctx——Run 返回
		// 时 terminalStatus 判 cancelled（曾 manager 取消路径引擎 ctx 不动，
		// 终态落 failed，历史无法区分「用户取消」与「真失败」）
		if ok && c != nil && running {
			c()
		}
		return ok
	}
	if c == nil || !running {
		return false
	}
	c()
	return true
}

// ---- StartLoop/StopLoop：循环启停 ----
// Periodic/Scheduled: 设 loopEnabled（引擎按间隔/槽调度）
// Daemon: 启动/停止自管理循环

func (e *Engine) StartLoop(id string) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	wasOn := r.loopEnabled
	r.loopEnabled = true
	r.lastCheck = time.Time{}
	r.mu.Unlock()
	// Daemon：CAS 启动（U1-P2-4）。关→开过渡=真实重启意图（背靠背
	// restart 语义保持）；已开启状态的重复 StartLoop 不再栽重启意图。
	if r.desc.Kind == KindDaemon && e.roleAllows(r.desc.RunsOn) {
		e.tryStartDaemon(r, !wasOn)
	}
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
	c := r.cancel
	r.mu.Unlock()

	// Daemon：取消 Run 的 ctx
	if r.desc.Kind == KindDaemon && c != nil {
		c()
	}
}

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

func (e *Engine) startDaemon(id string, r *registration, ctx context.Context, cancel context.CancelFunc) {
	// 调用方已在锁内完成 running 占位与 cancel 登记（U1-66-04）。
	runID := globalInsertRun(id, r.desc.Family, "auto")
	taskLogAppend(id, "[start] 常驻启动")
	// 2026-10-01 用户裁定：启动即记 success（启动是既成事实——成功列体现
	// 启动计数；原实现落 running 终态随停止更新，运行期成功列恒 0）
	e.finishRun(runID, "success", 0)

	start := time.Now()
	e.daemonWG.Add(1)
	go func() {
		defer e.daemonWG.Done()
		err := runGuarded(r.desc.Run, RunContext{Ctx: ctx, Trigger: "auto", RunID: runID})
		dur := time.Since(start).Milliseconds()
		// 异常退出（非取消）＝Run 返回错误或 panic（L1-66-01 隔离）。
		abnormal := err != nil && ctx.Err() == nil

		// 复活门（U1-66-01）：仅真实重启意图 + 调度开 + 引擎未停 + 非
		// 异常退出（防紧循环）才接续新代；意图消费后不复位。
		allows := e.roleAllows(r.desc.RunsOn)
		stopped := e.stopped.Load()
		var relaunchCtx context.Context
		var relaunchCancel context.CancelFunc
		r.mu.Lock()
		r.running = false
		r.cancel = nil
		if r.pendingRestart {
			r.pendingRestart = false
			if r.loopEnabled && !abnormal && !stopped && allows {
				r.running = true
				relaunchCtx, relaunchCancel = context.WithCancel(context.Background())
				r.cancel = relaunchCancel
				// 竞态兜底：首次读 stopped 后、本临界区前 Stop() 恰好
				// 完成（其 cancel 遍历未及本次登记）——临界区内复核。
				if e.stopped.Load() {
					relaunchCancel()
					relaunchCtx = nil
					r.cancel = nil
					r.running = false
				}
			}
		}
		r.mu.Unlock()

		if abnormal {
			// 异常退出（非取消）：补记 failed 行（真实时长与错误）
			failID := globalInsertRunAt(id, r.desc.Family, "auto", start.In(engineLocPtr()).Format("2006-01-02 15:04:05"), "")
			e.finishRun(failID, "failed", dur)
			taskLogAppend(id, fmt.Sprintf("[done] failed 耗时=%dms 触发=auto 错误=%s", dur, err.Error()))
		} else {
			taskLogAppend(id, fmt.Sprintf("[done] stopped 耗时=%dms 触发=auto（取消/正常退出）", dur))
		}
		if relaunchCtx != nil {
			e.startDaemon(id, r, relaunchCtx, relaunchCancel) // U1-P2-3：restart 意图落地——新代接续
		}
	}()
}

// runGuarded 隔离任务体 panic（L1-66-01）：任一任务体 panic 不得杀死
// 进程——转为 failed 终态错误。
func runGuarded(run func(RunContext) error, rc RunContext) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return run(rc)
}

// ---- 历史与统计 ----

func (e *Engine) History(id string, limit int) []RunRecord {
	if limit <= 0 {
		limit = 20
	}
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query(
		`SELECT id, task_id, family, trigger, COALESCE(operator,''), status, started_at,
		COALESCE(finished_at,''), COALESCE(duration_ms,0), COALESCE(message,'')
		FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []RunRecord
	for rows.Next() {
		var r RunRecord
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Family, &r.Trigger, &r.Operator, &r.Status, &r.StartedAt, &r.FinishedAt, &r.DurationMs, &r.Message); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (e *Engine) RecoverOrphans() int64 {
	// TASK-L3（第 69 轮 P3）：与同文件其余 7 处导出 DB 函数同形的 nil 防护
	// （曾唯一裸用 db.DB——装配顺序变化即 nil panic）。
	if db.DB == nil {
		return 0
	}
	res, err := db.DB.Exec(`UPDATE task_runs SET status='interrupted', finished_at=?, message=COALESCE(message,'')||'（进程重启回收）' WHERE status='running'`, engineNowStr())
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ---- 执行 ----

func (e *Engine) runNow(id, trigger, operator string) (int64, error) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return 0, ErrNotFound
	}
	// 单飞 CAS：全部 Kind 统一拒绝并发（Daemon 无此路径——Trigger 不暴露）
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return 0, ErrAlreadyRunning
	}
	r.running = true
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.mu.Unlock()

	// 记录策略（按 Kind，零 flag）：
	// Scheduled/Periodic/Oneshot: 每次执行落行；Daemon: 仅 startDaemon 落行
	runID := globalInsertRunAt(id, r.desc.Family, trigger, engineNowStr(), operator)

	rc := RunContext{Ctx: ctx, Trigger: trigger, Operator: operator, RunID: runID}
	start := time.Now()
	// F-L1-68-04（第 68 轮）：caddy-restart（Caddy 崩溃自愈 watcher 通道）
	// 同样落 [start]——曾仅 manual/startup 放行，自愈轮只有 [done]，排障
	// 看不到执行起点。
	switch trigger {
	case "manual", "startup":
		taskLogAppend(id, fmt.Sprintf("[start] %s触发", map[bool]string{true: "启动", false: "手动"}[trigger == "startup"]))
	case "caddy-restart":
		taskLogAppend(id, "[start] Caddy重启触发")
	}
	runErr := runGuarded(r.desc.Run, rc)
	status := terminalStatus(ctx, runErr)
	dur := time.Since(start).Milliseconds()
	msg := fmt.Sprintf("[done] %s 耗时=%dms 触发=%s", status, dur, trigger)
	if status == "failed" && runErr != nil {
		msg += " 错误=" + runErr.Error()
	}
	taskLogAppend(id, msg)

	// Scheduled：Run 已写新槽——重算缓存。F-L1-68-05 同族收敛：NextSlotFn 含
	// DB 查询——锁外先求值（求值期间 running 仍=true，tick 自然跳过本轮，
	// 零重触发窗口），再回锁一次性落 running/cancel/槽缓存。若新槽仍为过去
	// （业务失败未推进等），running 标志在 CAS 前防重入，此处值供下 tick 判定。
	var nextSlot time.Time
	hasSlotFn := r.desc.Kind == KindScheduled && r.desc.NextSlotFn != nil
	if hasSlotFn {
		nextSlot = r.desc.NextSlotFn()
	}
	r.mu.Lock()
	r.running = false
	r.cancel = nil
	if hasSlotFn {
		r.nextScheduledTime = nextSlot
	}
	r.mu.Unlock()
	cancel()

	if status == "failed" && runErr != nil {
		e.finishRunWithMessage(runID, status, dur, truncMsg(runErr))
	} else {
		e.finishRun(runID, status, dur)
	}
	return runID, runErr
}

func truncMsg(err error) string {
	m := err.Error()
	if len(m) > 500 {
		m = m[:500]
	}
	return m
}

func terminalStatus(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	// TASK-L5：跳过哨兵先于 generic failed 判定——demote 中止等非故障放弃
	// 落 skipped 终态（task_runs CHECK 约束既有值），不再失真为 success。
	if errors.Is(err, ErrTaskSkipped) {
		return "skipped"
	}
	if err != nil {
		return "failed"
	}
	return "success"
}

// ---- 调度循环 ----

func (e *Engine) scheduleLoop() {
	defer close(e.schedDone)
	ticker := time.NewTicker(e.opts.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.schedStop:
			return
		case <-ticker.C:
			e.tick()
		}
	}
}

func (e *Engine) tick() {
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
			// 排程感知：每 tick 重读 NextSlotFn（简单 SELECT——µs 级）；
			// 槽到点才触发 Run（中间零执行零落行零日志）；in-flight 不重入。
			// F-L1-68-05（第 68 轮）：NextSlotFn 含 DB 查询——持 r.mu 调用会把
			// DB 延迟传导到同任务的 Cancel/IsRunning/StopLoop。改为快照→锁外
			// 求值→回锁落缓存并复核状态（窗口内翻转不触发）。
			r.mu.Lock()
			if !r.loopEnabled || r.running {
				r.mu.Unlock()
				continue
			}
			slotFn := r.desc.NextSlotFn
			r.mu.Unlock()
			var next time.Time
			if slotFn != nil {
				next = slotFn()
			}
			r.mu.Lock()
			if slotFn != nil {
				r.nextScheduledTime = next
			}
			due := !r.nextScheduledTime.IsZero() && now.After(r.nextScheduledTime)
			eligible := r.loopEnabled && !r.running
			r.mu.Unlock()
			if due && eligible && e.roleAllows(r.desc.RunsOn) {
				go func(rid string) { _, _ = e.runNow(rid, "auto", "") }(id)
			}
		case KindPeriodic:
			// 固定间隔：每轮独立执行（Run→exit→记录）；in-flight 跳过本轮。
			// 角色不符时置零 lastCheck（不推进节拍）——角色获得后下一 tick
			// 立即到期（U1-66-02：原实现在角色门判定前推进节拍，从节点
			// 时钟照常走，promote 后首轮要等残余 interval，最坏 6h/24h）。
			allows := e.roleAllows(r.desc.RunsOn)
			r.mu.Lock()
			if !r.loopEnabled || r.running {
				r.mu.Unlock()
				continue
			}
			intervalFn := r.desc.IntervalFn
			r.mu.Unlock()
			// TASK-L4（第 69 轮）：IntervalFn 锁外求值——F-L1-68-05 同族收敛
			// 补全（Scheduled NextSlotFn 已移锁外）。IntervalFn 若含 DB 读取
			// （wire.go 预告「间隔可配置——读 global_config」形态），持 r.mu
			// 会把延迟传导到同任务 Cancel/IsRunning/StopLoop。回锁后以新鲜
			// lastCheck/loopEnabled/running 复核——窗口内 SetRole 置零节拍
			// 不被陈旧快照覆写。
			var interval time.Duration
			if intervalFn != nil {
				interval = intervalFn()
			}
			r.mu.Lock()
			due := r.loopEnabled && !r.running && (r.lastCheck.IsZero() || now.Sub(r.lastCheck) >= interval)
			if due {
				if allows {
					r.lastCheck = now
				} else {
					r.lastCheck = time.Time{}
				}
			}
			r.mu.Unlock()
			if due && allows {
				go func(rid string) { _, _ = e.runNow(rid, "auto", "") }(id)
			}

		case KindDaemon:
			// 不进周期 tick——由 StartLoop 启动（Run 阻塞直到取消）
		case KindOneshot:
			// 不进周期 tick——仅 Trigger
		}
	}
}

func (e *Engine) roleAllows(role Role) bool {
	switch role {
	case RoleMasterOnly:
		return e.isMaster()
	case RoleSlaveOnly:
		return !e.isMaster()
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

// engineLogTimeStr 任务日志行时间戳（TASK-L9，第 69 轮）：斜杠形态——与
// TeeTaskLog 业务行统一。engineNowStr 是 DB 写入/datetime() 比较口径
// （SQLite 时间串只认横杠），两者各司其职勿合并。
func engineLogTimeStr() string { return time.Now().In(engineLocPtr()).Format("2006/01/02 15:04:05") }

// ---- 日志 ----

var taskLogDir string

func SetLogDir(dir string) { taskLogDir = dir }

// LogDir 当前任务日志目录（B3：certjoblog 子目录挂靠点；空串=未初始化）。
func LogDir() string { return taskLogDir }

func TaskLogPath(taskID string) string {
	if taskLogDir == "" {
		return ""
	}
	return filepath.Join(taskLogDir, taskID+".log")
}

// appendTaskLogLine 打开→追加→关闭共享实现（TASK-L10，第 69 轮：taskLogAppend
// 与 TeeTaskLog 曾双份同形四步；MkdirAll 幂等，保留逐行兜底形态不变）。
func appendTaskLogLine(path, line string) {
	_ = os.MkdirAll(taskLogDir, 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
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
	if db.DB == nil {
		return 0
	}
	res, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, operator, status, started_at) VALUES (?,?,?,?, 'running',?)`, taskID, family, trigger, operator, startedAt)
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func (e *Engine) finishRun(runID int64, status string, durMs int64) {
	if runID <= 0 || db.DB == nil {
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=? WHERE id=?`, status, engineNowStr(), durMs, runID)
}

func (e *Engine) finishRunWithMessage(runID int64, status string, durMs int64, message string) {
	if runID <= 0 || db.DB == nil {
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=?, message=? WHERE id=?`, status, engineNowStr(), durMs, message, runID)
}

// RecordRunStart/Finish 族侧记录（legacy 路径：非引擎调用的直接执行）
func RecordRunStart(taskID, family, trigger string) int64 {
	return globalInsertRun(taskID, family, trigger)
}

func RecordRunFinish(runID int64, status string, durMs int64, message string) {
	if runID <= 0 {
		return
	}
	if message != "" {
		_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=?, message=? WHERE id=?`, status, engineNowStr(), durMs, message, runID)
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=? WHERE id=?`, status, engineNowStr(), durMs, runID)
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
	Enabled      bool   `json:"enabled"`
	StatusMirror string `json:"status_mirror"`
	Controllable bool   `json:"controllable"`
	Cancelable   bool   `json:"cancelable"`
	Toggleable   bool   `json:"toggleable"`
	ToggleName   string `json:"toggle_name"`
	LoopOn       bool   `json:"loop_on"`
	Running      bool   `json:"running"` // Daemon：Run 实际存活（角色门/停止后=false）
	CanTrigger   bool   `json:"can_trigger"`
}

// Lookup 单任务元数据（U1-P4-2：handler 为取单字段跑全量 DescribeAll
// ~12-18 条 SQL——现仅执行该任务的 Fn）。
func (e *Engine) Lookup(id string) (TaskMeta, bool) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return TaskMeta{}, false
	}
	r.mu.Lock()
	loopOn, running := r.loopEnabled, r.running
	r.mu.Unlock()
	m := TaskMeta{
		ID: id, Family: r.desc.Family, Name: r.desc.Name,
		Description: r.desc.Description, Category: r.desc.Category, Kind: r.desc.Kind,
		CanTrigger:   r.desc.ManualRun,
		Cancelable:   r.desc.Cancelable,
		Toggleable:   r.desc.ToggleFn != nil,
		ToggleName:   r.desc.ToggleName,
		LoopOn:       loopOn,
		Running:      running,
		Enabled:      true,
		Controllable: r.desc.Kind == KindDaemon,
	}
	if r.desc.IntervalFn != nil {
		m.IntervalSec = int(r.desc.IntervalFn().Seconds())
	}
	if r.desc.NextSlotFn != nil {
		if t := r.desc.NextSlotFn(); !t.IsZero() {
			m.NextSlot = t.In(engineLocPtr()).Format("2006-01-02 15:04:05")
		}
	}
	if r.desc.EnabledFn != nil {
		m.Enabled = r.desc.EnabledFn()
	}
	// 状态镜像角色门：与 DescribeAll 同门（2026-10-03 裁定）——角色不符
	// 不采纳，单任务查询不旁路。
	if r.desc.StatusFn != nil && e.roleAllows(r.desc.RunsOn) {
		m.StatusMirror = r.desc.StatusFn()
	}
	return m, true
}

func (e *Engine) DescribeAll() []TaskMeta {
	type snap struct {
		id      string
		desc    Descriptor
		loopOn  bool
		running bool
	}
	e.mu.RLock()
	snaps := make([]snap, 0, len(e.regs))
	for id, r := range e.regs {
		r.mu.Lock()
		loopOn, running := r.loopEnabled, r.running
		r.mu.Unlock()
		snaps = append(snaps, snap{id: id, desc: r.desc, loopOn: loopOn, running: running})
	}
	e.mu.RUnlock()

	out := make([]TaskMeta, 0, len(snaps))
	for _, s := range snaps {
		m := TaskMeta{
			ID: s.id, Family: s.desc.Family, Name: s.desc.Name,
			Description: s.desc.Description, Category: s.desc.Category, Kind: s.desc.Kind,
			CanTrigger:   s.desc.ManualRun,
			Cancelable:   s.desc.Cancelable,
			Toggleable:   s.desc.ToggleFn != nil,
			ToggleName:   s.desc.ToggleName,
			LoopOn:       s.loopOn,
			Running:      s.running,
			Enabled:      true,
			Controllable: s.desc.Kind == KindDaemon, // 常驻族可启停（真实生命周期挂钩——B 完全标准化）
		}
		if s.desc.IntervalFn != nil {
			m.IntervalSec = int(s.desc.IntervalFn().Seconds())
		}
		if s.desc.NextSlotFn != nil {
			if t := s.desc.NextSlotFn(); !t.IsZero() {
				m.NextSlot = t.In(engineLocPtr()).Format("2006-01-02 15:04:05")
			}
		}
		if s.desc.EnabledFn != nil {
			m.Enabled = s.desc.EnabledFn()
		}
		// 状态镜像角色门（2026-10-03 裁定）：任务不在本角色运行时，其
		// StatusFn 读到的常是同步来的业务数据（从节点 cert_jobs/
		// ip2region update_status 均有主端快照镜像）——采纳即伪造本节点
		// running。角色不符一律不采纳（空）→ 视图层呈现本节点实态；
		// 主节点行为不变（StatusFn 保留，主侧为真实业务态）。
		if s.desc.StatusFn != nil && e.roleAllows(s.desc.RunsOn) {
			m.StatusMirror = s.desc.StatusFn()
		}
		out = append(out, m)
	}
	return out
}

// ---- 统计 ----

type TaskRunsStats struct{ Runs, Success, Fail int }

func (e *Engine) Stats24h(taskID string) TaskRunsStats {
	var st TaskRunsStats
	if db.DB == nil {
		return st
	}
	_ = db.DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0)
		FROM task_runs WHERE task_id=? AND started_at > datetime(?, '-1 day')`, taskID, engineNowStr()).Scan(&st.Runs, &st.Success, &st.Fail)
	return st
}

func (e *Engine) LatestRun(taskID string) *RunRecord {
	runs := e.History(taskID, 1)
	if len(runs) == 0 {
		return nil
	}
	return &runs[0]
}

func PurgeTaskRuns(days int) int64 {
	if db.DB == nil || days <= 0 {
		return 0
	}
	res, err := db.DB.Exec(`DELETE FROM task_runs WHERE started_at < datetime(?, ?)`, engineNowStr(), fmt.Sprintf("-%d days", days))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
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
