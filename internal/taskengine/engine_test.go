package taskengine

// lazy-task-engine v2.0 单测：四类型调度/单飞 CAS/取消/历史/崩溃恢复/
// 角色门/动态间隔/Daemon 生命周期/Scheduled 槽位驱动/每轮记录。

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	// 与 services 测试同模式：临时目录初始化全套库（含 task_runs 表迁移）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	e := NewEngine(Options{TickInterval: 10 * time.Millisecond})
	t.Cleanup(e.Stop)
	return e
}

func countRuns(t *testing.T, id string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=?`, id).Scan(&n); err != nil {
		t.Fatalf("count runs: %v", err)
	}
	return n
}

// Given 任务运行中（任何 Kind——v2.0 单飞为引擎 CAS 统一强制）。
// When 再次 Trigger。
// Then 返回 ErrAlreadyRunning（409 语义），不重入。
func TestEngine_SingletonTriggerRejectedWhileRunning(t *testing.T) {
	e := newTestEngine(t)
	release := make(chan struct{})
	started := make(chan struct{})
	e.Register(Descriptor{ID: "t-single", Family: "t", Name: "单飞", Kind: KindPeriodic,
		// TASK-L2（第 69 轮）配套：Periodic 注册必须带 IntervalFn（本测试经
		// Trigger 驱动，间隔值不参与断言）。
		IntervalFn: func() time.Duration { return time.Hour },
		Run: func(rc RunContext) error {
			close(started)
			<-release
			return nil
		}})
	go func() { _ = e.Trigger("t-single", "manual", "") }()
	<-started
	if err := e.Trigger("t-single", "manual", ""); err != ErrAlreadyRunning {
		t.Fatalf("want ErrAlreadyRunning, got %v", err)
	}
	close(release)
}

// Given 可取消任务运行中（阻塞在 ctx.Done）。
// When Cancel。
// Then Run 返回且历史终态=cancelled（非 failed）。
func TestEngine_CancelMarksCancelled(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{})
	e.Register(Descriptor{ID: "t-cancel", Family: "t", Name: "可取消", Kind: KindPeriodic, Cancelable: true,
		IntervalFn: func() time.Duration { return time.Hour }, // TASK-L2 配套（Trigger 驱动）
		Run: func(rc RunContext) error {
			close(started)
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}})
	go func() { _ = e.Trigger("t-cancel", "manual", "") }()
	<-started
	if !e.Cancel("t-cancel") {
		t.Fatal("Cancel 应返回 true")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if lr := e.LatestRun("t-cancel"); lr != nil && lr.Status == "cancelled" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("终态应为 cancelled")
}

// Given task_runs 残留 status=running 行（崩溃现场）。
// When 引擎 RecoverOrphans。
// Then 该行改标 interrupted。
func TestEngine_RecoverOrphansMarksInterrupted(t *testing.T) {
	e := newTestEngine(t)
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at) VALUES ('t-x','t','auto','running',datetime('now'))`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n := e.RecoverOrphans(); n != 1 {
		t.Fatalf("want 1 orphan recovered, got %d", n)
	}
	var st string
	_ = db.DB.QueryRow(`SELECT status FROM task_runs WHERE task_id='t-x'`).Scan(&st)
	if st != "interrupted" {
		t.Fatalf("want interrupted, got %s", st)
	}
}

// Given slave-only 任务 + 当前为主节点。
// When 调度 tick 到期。
// Then 不执行（角色门拦截）。
func TestEngine_RoleGateSlaveOnlyOnMasterSkips(t *testing.T) {
	e := newTestEngine(t)
	ran := false
	e.Register(Descriptor{ID: "t-role", Family: "t", Name: "从节点任务", Kind: KindPeriodic, RunsOn: RoleSlaveOnly,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		Run:        func(rc RunContext) error { ran = true; return nil }})
	e.StartLoop("t-role")
	e.SetRole(true) // 主节点
	time.Sleep(150 * time.Millisecond)
	if ran {
		t.Fatal("主节点不应执行 slave-only 任务")
	}
}

// Given 动态间隔任务(interval=500ms)。
// When IntervalFn 中途返回 20ms（tick 每轮重读间隔——变更自然生效）。
// Then 后续按新间隔执行（300ms 内 ≥2 次）。
func TestEngine_DynamicIntervalReread(t *testing.T) {
	e := newTestEngine(t)
	mu := make(chan struct{}, 32)
	var fast atomic.Bool
	e.Register(Descriptor{ID: "t-dyn", Family: "t", Name: "动态", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration {
			if fast.Load() {
				return 20 * time.Millisecond
			}
			return 500 * time.Millisecond
		},
		Run: func(rc RunContext) error { mu <- struct{}{}; return nil }})
	e.StartLoop("t-dyn")
	e.SetRole(true)
	time.Sleep(80 * time.Millisecond) // 慢间隔期(最多1次)
	fast.Store(true)
	deadline := time.Now().Add(300 * time.Millisecond)
	count := 0
	for time.Now().Before(deadline) {
		select {
		case <-mu:
			count++
		case <-time.After(20 * time.Millisecond):
		}
	}
	if count < 2 {
		t.Fatalf("重排后应至少执行 2 次, got %d", count)
	}
}

// Given 循环任务运行中。
// When StopLoop 后 StartLoop。
// Then 循环停/启真实生效（IsRunning 翻转）。
func TestEngine_LoopStopStart(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-loop", Family: "t", Name: "常驻", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		Run:        func(rc RunContext) error { return nil }})
	e.SetRole(true)
	e.StartLoop("t-loop")
	if !e.IsRunning("t-loop") {
		t.Fatal("启动后应 running")
	}
	e.StopLoop("t-loop")
	if e.IsRunning("t-loop") {
		t.Fatal("停止后应非 running")
	}
}

// Given 成功执行一次。
// Then 历史行含 trigger/status/duration 与 task_id。
func TestEngine_HistoryRecordShape(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-hist", Family: "t", Name: "历史", Kind: KindOneshot,
		Run: func(rc RunContext) error { time.Sleep(30 * time.Millisecond); return nil }})
	if err := e.Trigger("t-hist", "manual", "alice"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	runs := e.History("t-hist", 5)
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	r := runs[0]
	if r.TaskID != "t-hist" || r.Family != "t" || r.Trigger != "manual" || r.Status != "success" {
		t.Fatalf("shape mismatch: %+v", r)
	}
	if r.DurationMs < 20 {
		t.Fatalf("duration 应≥20ms, got %d", r.DurationMs)
	}
	if r.FinishedAt == "" {
		t.Fatal("finished_at 应非空")
	}
}

// ---- v2.0 四类型核心语义 ----

// Given Scheduled 任务，NextSlotFn 先返回未来槽、后返回过去槽。
// When 引擎 tick。
// Then 槽未到=零执行零落行；槽过后=恰执行一次并重算下一槽（不重复触发）。
func TestEngine_ScheduledFiresAtSlotAndRecomputes(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	var slot atomic.Value                        // time.Time
	slot.Store(time.Now().Add(10 * time.Second)) // 远期——slot 翻转前零执行
	e.Register(Descriptor{ID: "t-sched", Family: "t", Name: "定时", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return slot.Load().(time.Time) },
		Run: func(rc RunContext) error {
			runs.Add(1)
			slot.Store(time.Now().Add(10 * time.Second)) // 模拟任务体执行后写新槽
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-sched")
	time.Sleep(150 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("槽未到不应执行, got %d", got)
	}
	if got := countRuns(t, "t-sched"); got != 0 {
		t.Fatalf("槽未到不应落行, got %d 行", got)
	}
	// 槽位翻转：过去槽 → 引擎到点触发
	slot.Store(time.Now().Add(-time.Second))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runs.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if runs.Load() != 1 {
		t.Fatalf("槽过后应恰执行 1 次, got %d", runs.Load())
	}
	// Run 已写远期新槽——不重复触发
	time.Sleep(150 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("新槽远期不应重复执行, got %d", got)
	}
	if got := countRuns(t, "t-sched"); got != 1 {
		t.Fatalf("应恰 1 行, got %d", got)
	}
}

// Given Daemon 任务（Run 阻塞在 ctx.Done）。
// When StartLoop → StopLoop → StartLoop。
// Then Run 每次生命周期恰调用一次（非周期重入）；boot 行=生命周期数；
// StopLoop 取消 ctx 使 Run 返回。
func TestEngine_DaemonLifecycle(t *testing.T) {
	e := newTestEngine(t)
	var starts atomic.Int32
	inLoop := make(chan struct{}, 8)
	e.Register(Descriptor{ID: "t-daemon", Family: "t", Name: "常驻", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			starts.Add(1)
			inLoop <- struct{}{}
			<-rc.Ctx.Done() // 自管理循环——阻塞直到取消
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-daemon")
	<-inLoop
	if got := starts.Load(); got != 1 {
		t.Fatalf("StartLoop 应恰调 Run 1 次, got %d", got)
	}
	time.Sleep(100 * time.Millisecond) // 多个 tick 窗口——验证不重入
	if got := starts.Load(); got != 1 {
		t.Fatalf("Daemon 不应被周期 tick 重入, got %d", got)
	}
	if !e.IsRunning("t-daemon") {
		t.Fatal("Daemon 运行中应 IsRunning=true")
	}
	// 启动即记 success（2026-10-01 用户裁定：成功列体现启动计数——运行期即 +1）
	if st := e.Stats24h("t-daemon"); st.Success != 1 || st.Fail != 0 {
		t.Fatalf("运行期成功列应=1（启动计数）, got %+v", st)
	}
	e.StopLoop("t-daemon")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && e.IsRunning("t-daemon") {
		time.Sleep(10 * time.Millisecond)
	}
	if e.IsRunning("t-daemon") {
		t.Fatal("StopLoop 后应非 running")
	}
	// 取消停止不增行；boot 行终态=success
	if got := countRuns(t, "t-daemon"); got != 1 {
		t.Fatalf("取消停止不应增行, got %d", got)
	}
	if lr := e.LatestRun("t-daemon"); lr == nil || lr.Status != "success" {
		t.Fatalf("boot 行应终态 success, got %+v", lr)
	}
	// 重启：第二个生命周期
	e.StartLoop("t-daemon")
	<-inLoop
	if got := starts.Load(); got != 2 {
		t.Fatalf("重启应第 2 次调用 Run, got %d", got)
	}
	if got := countRuns(t, "t-daemon"); got != 2 {
		t.Fatalf("两生命周期应 2 行, got %d", got)
	}
}

// Given Periodic 任务（30ms 间隔）。
// When 调度运行至 ≥5 轮落行（3s 截止兜底——全量套件并行争抢 CPU 时墙钟
// 300ms 窗口可能只排到 4 轮，第 69 轮修复期两次全量运行实证；契约是
// 「每轮独立执行且每轮落行」，不是 300ms 内的绝对轮数）。
// Then ≥5 行且全部终态 success（无 RFO 静默）。
func TestEngine_PeriodicRecordsEveryCycle(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-per", Family: "t", Name: "循环", Kind: KindPeriodic,
		IntervalFn: func() time.Duration { return 30 * time.Millisecond },
		Run:        func(rc RunContext) error { return nil }})
	e.SetRole(true)
	e.StartLoop("t-per")
	deadline := time.Now().Add(3 * time.Second)
	for countRuns(t, "t-per") < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	e.StopLoop("t-per")
	rows := countRuns(t, "t-per")
	if rows < 5 {
		t.Fatalf("30ms 间隔 3s 内应≥5 轮且每轮落行, got %d 行", rows)
	}
	var success int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='t-per' AND status='success'`).Scan(&success)
	if success != rows {
		t.Fatalf("每轮应终态 success: %d/%d", success, rows)
	}
}

// Given Oneshot 任务。
// When 引擎 tick 多轮（不开 Trigger）。
// Then 零执行零落行；Trigger 后恰 1 行。
func TestEngine_OneshotOnlyByTrigger(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-one", Family: "t", Name: "触发", Kind: KindOneshot,
		Run: func(rc RunContext) error { runs.Add(1); return nil }})
	e.SetRole(true)
	e.StartLoop("t-one") // 即使开循环开关——Oneshot 不进周期调度
	time.Sleep(150 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("Oneshot 不应被周期调度, got %d", got)
	}
	if err := e.Trigger("t-one", "manual", ""); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("Trigger 应执行 1 次, got %d", got)
	}
}

// Given 注册的任务带 EnabledFn/StatusFn/NextSlotFn（含 DB 读取）。
// When DescribeAll 在「跨 goroutine 写者就位」的强制碰撞形态下枚举：
// EnabledFn 首次调用时暂停在探针点，等写者 goroutine 真实 pending 在引擎
// 写锁上再放行——若 DescribeAll 持读锁跨 Fn 调用，写者待命会使 EnabledFn 内
// 的 RLock（IsRunning）永久阻塞（Go RWMutex 写者优先）。同 goroutine 的
// RLock 嵌套因重入性侦破不了该缺陷形态，故必须跨 goroutine 编排（U1-66-10）。
// Then 不自锁；元数据含四类型字段。
func TestEngine_DescribeAllReleasesLockBeforeFnCalls(t *testing.T) {
	e := newTestEngine(t)
	insideFn := make(chan struct{})
	release := make(chan struct{})
	var armed, fnLockStuck atomic.Bool
	armed.Store(true)
	e.Register(Descriptor{ID: "t-meta", Family: "t", Name: "元数据", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return time.Now().Add(time.Hour) },
		EnabledFn: func() bool {
			if armed.CompareAndSwap(true, false) {
				insideFn <- struct{}{} // 探针点：扫描已进入 Fn（变异形态下此刻仍持读锁）
				<-release
				// IsRunning 的 RLock 放独立 goroutine+超时：缺陷形态下它被
				// pending 写者卡死——置位判负信号并放行 DescribeAll，让引擎
				// 锁自然解开（否则 t.Cleanup(e.Stop) 随测试退出被同一死锁
				// 卡住，测试二进制无法干净收场）。
				done := make(chan bool, 1)
				go func() { done <- e.IsRunning("t-meta") }()
				select {
				case v := <-done:
					return v
				case <-time.After(3 * time.Second):
					fnLockStuck.Store(true)
					return false
				}
			}
			return e.IsRunning("t-meta")
		},
		StatusFn: func() string { return "running" },
		Run:      func(rc RunContext) error { return nil }})
	e.StartLoop("t-meta")

	var found *TaskMeta
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		for _, m := range e.DescribeAll() {
			if m.ID == "t-meta" {
				found = &m
			}
		}
	}()
	<-insideFn // 扫描停在探针点

	// 写者就位：持续 Register（写锁）——缺陷形态下此刻 pending 在 e.mu.Lock
	stopWriter := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stopWriter:
				return
			default:
			}
			_ = e.Register(Descriptor{ID: "t-writer", Family: "t", Name: "写者", Kind: KindOneshot,
				Run: func(rc RunContext) error { return nil }})
			runtime.Gosched()
		}
	}()
	time.Sleep(50 * time.Millisecond) // 写者进入写锁等待队列
	close(release)                    // 放行 EnabledFn → IsRunning 的 RLock

	select {
	case <-scanDone:
	case <-time.After(15 * time.Second):
		close(stopWriter)
		t.Fatal("DescribeAll 未在限时内完成（持锁形态异常）")
	}
	close(stopWriter)
	<-writerDone

	// Then：Fn 内 RLock 未被 pending 写者卡死（读锁已在 Fn 调用前释放）
	if fnLockStuck.Load() {
		t.Fatal("DescribeAll 持读锁跨 Fn 调用——写者待命时 Fn 内 RLock 自锁（缺陷形态侦破）")
	}
	if found == nil {
		t.Fatal("未找到任务元数据")
	}
	if found.Kind != KindScheduled || found.NextSlot == "" || found.StatusMirror != "running" || !found.LoopOn {
		t.Fatalf("v2.0 元数据缺失: %+v", found)
	}
}

// Given 任务体捕获 RunContext.Operator。
// When Trigger(id, "manual", "alice")。
// Then 任务体收到 operator=alice（手动操作者身份通道）。
func TestEngine_TriggerCarriesOperator(t *testing.T) {
	e := newTestEngine(t)
	var got string
	done := make(chan struct{})
	e.Register(Descriptor{ID: "t-op", Family: "t", Name: "操作者", Kind: KindOneshot,
		Run: func(rc RunContext) error { got = rc.Operator; close(done); return nil }})
	_ = e.Trigger("t-op", "manual", "alice")
	<-done
	if got != "alice" {
		t.Fatalf("operator 应为 alice, got %q", got)
	}
}

// U1-66-09 纵深：Trigger 对 KindDaemon 拒绝（常驻族启停即可——handler 门之外
// 的引擎侧第二道防线；此前 Trigger 可直跑 daemon Run 绕过真实生命周期挂钩）。
func TestEngine_TriggerRejectsDaemon(t *testing.T) {
	e := newTestEngine(t)
	ran := false
	e.Register(Descriptor{ID: "t-daemon", Family: "t", Name: "常驻", Kind: KindDaemon,
		Run: func(rc RunContext) error { ran = true; return nil }})
	// When/Then：Trigger 返回错误且 Run 不执行（runNow 同步执行——无竞态）
	if err := e.Trigger("t-daemon", "manual", ""); err == nil {
		t.Fatal("Trigger daemon 应被拒绝（启停即可——引擎侧纵深守卫）")
	}
	if ran {
		t.Fatal("daemon Run 不应被 Trigger 执行")
	}
}

// L1-66-03：task_runs.operator 列——手动触发操作者落历史（RunRecord.Operator），
// History SELECT 透出；auto/startup 触发（operator 空）落空串。
func TestEngine_HistoryCarriesOperator(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-op-hist", Family: "t", Name: "历史", Kind: KindOneshot,
		Run: func(rc RunContext) error { return nil }})
	if err := e.Trigger("t-op-hist", "manual", "alice"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	runs := e.History("t-op-hist", 5)
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	if runs[0].Operator != "alice" {
		t.Fatalf("历史行 operator=%q, want alice", runs[0].Operator)
	}
	// 边界形态：auto/startup 形态（operator 空）落空串非 "alice" 残留
	if err := e.Trigger("t-op-hist", "manual", ""); err != nil {
		t.Fatalf("trigger2: %v", err)
	}
	if runs = e.History("t-op-hist", 5); runs[0].Operator != "" {
		t.Fatalf("空操作者应落空串, got %q", runs[0].Operator)
	}
}

// Given 引擎预插行（runNow 开跑即落）。
// When 任务运行 100ms 后失败。
// Then 行 started_at 反映真实开始时刻（started_at+duration 不越过 finished_at）。
func TestEngine_FailedRunStartsAtRealStart(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-fail", Family: "t", Name: "失败", Kind: KindOneshot,
		Run: func(rc RunContext) error { time.Sleep(100 * time.Millisecond); return errors.New("boom") }})
	_ = e.Trigger("t-fail", "manual", "")
	lr := e.LatestRun("t-fail")
	if lr == nil || lr.Status != "failed" {
		t.Fatalf("want failed 终态, got %+v", lr)
	}
	if lr.DurationMs < 90 {
		t.Fatalf("duration 应≥90ms, got %d", lr.DurationMs)
	}
}

// Given master-only Daemon 任务 + 引擎为从节点角色。
// When StartLoop → SetRole(true)（promote）→ SetRole(false)（demote）。
// Then 从节点不启动 Run；promote 自动拉起；demote 停止但 loopEnabled 保留
// （再次 promote 自动恢复）。
func TestEngine_DaemonRoleGateLifecycle(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{}, 8)
	e.Register(Descriptor{ID: "t-md", Family: "t", Name: "主节点常驻", Kind: KindDaemon, RunsOn: RoleMasterOnly,
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			return nil
		}})
	e.SetRole(false) // 从节点
	e.StartLoop("t-md")
	select {
	case <-started:
		t.Fatal("从节点不应启动 master-only daemon")
	case <-time.After(150 * time.Millisecond):
	}
	// promote：自动拉起
	e.SetRole(true)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("promote 后应自动拉起 daemon")
	}
	// demote：Run 取消退出
	e.SetRole(false)
	deadline := time.Now().Add(time.Second)
	running := true
	for time.Now().Before(deadline) {
		for _, m := range e.DescribeAll() {
			if m.ID == "t-md" {
				running = m.Running
			}
		}
		if !running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if running {
		t.Fatal("demote 后 daemon Run 应退出")
	}
	// loopEnabled 保留（再 promote 恢复）
	e.SetRole(true)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("再 promote 应恢复 daemon")
	}
}

// Given 常驻任务 Run 返回错误（非 ctx 取消——异常退出）。
// When startDaemon 生命周期结束。
// Then boot success 行之外补记 1 行 failed（真实时长）——失败列可见。
func TestEngine_DaemonFailureRecordsFailedRow(t *testing.T) {
	e := newTestEngine(t)
	booted := make(chan struct{})
	e.Register(Descriptor{ID: "t-dfail", Family: "t", Name: "异常常驻", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			close(booted)
			time.Sleep(50 * time.Millisecond)
			return errors.New("daemon crashed") // 主动报错退出（非取消路径）
		}})
	e.SetRole(true)
	e.StartLoop("t-dfail")
	<-booted
	if st := e.Stats24h("t-dfail"); st.Success != 1 {
		t.Fatalf("boot 应即记 success, got %+v", st)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if st := e.Stats24h("t-dfail"); st.Fail == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Run 错误返回应补记 failed 行, stats=%+v", e.Stats24h("t-dfail"))
}

// Given daemon 任务未运行，N 个并发 StartLoop（HTTP∥SetRole 同型竞态面）。
// When 全部返回后。
// Then Run 恰被调用一次（startDaemon CAS——U1-P2-4：曾锁外读+无复查=双启动
// 双 boot 行+cancel 覆写致其一永不可取消）。
func TestEngine_StartLoopConcurrentSingleDaemonStart(t *testing.T) {
	e := newTestEngine(t)
	starts := make(chan struct{}, 32)
	e.Register(Descriptor{ID: "t-race", Family: "t", Name: "并发启动", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			starts <- struct{}{}
			<-rc.Ctx.Done()
			return nil
		}})
	e.SetRole(true)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.StartLoop("t-race") }()
	}
	wg.Wait()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(starts) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	var bootRows int
	_ = dbTestCountRuns(t, "t-race", &bootRows)
	if bootRows != 1 {
		t.Fatalf("并发 StartLoop 应恰 1 boot 行, got %d（startDaemon 无 CAS 双启动）", bootRows)
	}
	e.StopLoop("t-race")
}

func dbTestCountRuns(t *testing.T, id string, n *int) error {
	t.Helper()
	return db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=?`, id).Scan(n)
}

// Given daemon 运行中。
// When 背靠背 StopLoop→StartLoop（handlers restart 的精确序列）。
// Then Run 被第二次调用（U1-P2-3：曾 Run goroutine 异步清 running，StartLoop
// 即查仍 true→跳过=「重启」静默变「停止」）。
func TestEngine_DaemonRestartBackToBackStartsSecondRun(t *testing.T) {
	e := newTestEngine(t)
	starts := make(chan struct{}, 4)
	block := make(chan struct{})
	e.Register(Descriptor{ID: "t-rst", Family: "t", Name: "重启", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			starts <- struct{}{}
			<-rc.Ctx.Done()
			<-block // 保证第一代 Run 的清理动作可控后行
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-rst")
	<-starts // 第一代已进 Run
	// 背靠背 restart：Stop 后立即 Start——此刻第一代仍在跑（running=true）
	e.StopLoop("t-rst")
	e.StartLoop("t-rst")
	// 第一代收到取消后自行退出（Run 体不挂死——真实 Run 语义）
	close(block)
	// 契约：第二代必须被自动拉起——不需要任何进一步调用
	// （U1-P2-3 回归形态：StartLoop 见 running=true 静默跳过→永久停止）
	select {
	case <-starts:
	case <-time.After(2 * time.Second):
		t.Fatal("restart 后第二代 Run 未被拉起（restart 竞态：静默变停止）")
	}
	e.StopLoop("t-rst")
}

// Given Cancelable 任务经 CancelHook 取消（threat/crs/ip2region 三族路径）。
// When Cancel 成功。
// Then 终态=cancelled（L1-6：曾 hook 取消后引擎 ctx 不动→落 failed——历史
// 无法区分用户取消与真失败）。
func TestEngine_CancelHookPathLandsCancelled(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{})
	hookFired := make(chan struct{}, 1)
	e.Register(Descriptor{ID: "t-chk", Family: "t", Name: "Hook取消", Cancelable: true,
		CancelHook: func() bool { hookFired <- struct{}{}; return true },
		Run: func(rc RunContext) error {
			close(started)
			<-rc.Ctx.Done() // hook 取消后引擎 ctx 同步取消（L1-6）
			return rc.Ctx.Err()
		}})
	go func() { _ = e.Trigger("t-chk", "manual", "") }()
	<-started
	if !e.Cancel("t-chk") {
		t.Fatal("Cancel 应成功")
	}
	<-hookFired
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if lr := e.LatestRun("t-chk"); lr != nil && lr.Status == "cancelled" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hook 取消路径终态应 cancelled, got %+v", e.LatestRun("t-chk"))
}

// Given BootSync Oneshot 任务注册后。
// When RunBootSyncTasks（InitTaskEngine 尾部同型调用）。
// Then Run 同步执行恰一次、task_runs 记 startup 触发行（B1：启动执行单轨化
// ——曾 main.go 直调+legacy startupPhase 记录旁路）。
func TestEngine_BootSyncTasksRunOnceWithStartupRow(t *testing.T) {
	e := newTestEngine(t)
	ran := 0
	done := make(chan struct{})
	e.Register(Descriptor{ID: "boot-one", Family: "startup", Name: "启动", Kind: KindOneshot, BootSync: true,
		Run: func(rc RunContext) error { ran++; close(done); return nil }})
	e.RunBootSyncTasks()
	<-done
	if ran != 1 {
		t.Fatalf("BootSync 应恰执行一次, got %d", ran)
	}
	lr := e.LatestRun("boot-one")
	if lr == nil || lr.Trigger != "startup" || lr.Status != "success" {
		t.Fatalf("应记 startup/success 行, got %+v", lr)
	}
	// 幂等：再次调用不重跑（BootSync 只在引擎装配尾部触发一次）
	e.RunBootSyncTasks()
	if ran != 1 {
		t.Fatalf("重复 RunBootSyncTasks 不应重跑, got %d", ran)
	}
}

// Given daemon 挂真实生命周期挂钩（B 完全标准化——services 侧
// daemonLifecycleRun 的引擎级形状：start→阻塞 ctx→stop）。
func TestEngine_DaemonLifecycleHooksRealStartStop(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	e.Register(Descriptor{ID: "hook-d", Family: "t", Name: "挂钩", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			stopped <- struct{}{} // 真实服务的 Stop() 落点（B：deferred stop）
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("hook-d")
	<-started
	if !e.IsTaskInFlight("hook-d") {
		t.Fatal("运行中应可查在途")
	}
	e.StopLoop("hook-d")
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("StopLoop 应触发真实 stop 落点（调度开关=真实启停）")
	}
}

// ---- 2026-10-03 用户裁定（与 cluster-sync 生命周期统一同批）：状态镜像
// 角色门——任务不在本角色运行时，其 StatusFn 读到的常是同步来的业务数据
// （从节点 cert_jobs/update_status 均有主端快照镜像），镜像会伪造本节点
// running。角色不符一律不采纳（空）→ 视图层呈现本节点实态；主节点行为
// 不变（三任务 StatusFn 保留，主侧为真实业务态）。 ----

// Given MasterOnly 任务挂恒返 running 的 StatusFn。
// When 从节点角色下聚合，再翻回主节点。
// Then 从节点 StatusMirror 为空（角色门拦截，Lookup/DescribeAll 同门），
// 主节点照常采纳（真实业务态）。
func TestEngine_StatusMirrorRoleGated(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-mirror", Family: "t", Name: "主镜像", Kind: KindPeriodic, RunsOn: RoleMasterOnly,
		IntervalFn: func() time.Duration { return time.Hour },
		StatusFn:   func() string { return "running" },
		Run:        func(rc RunContext) error { return nil }})
	e.SetRole(false)
	for _, m := range e.DescribeAll() {
		if m.ID == "t-mirror" && m.StatusMirror != "" {
			t.Fatalf("从节点不得采纳 MasterOnly 镜像, got %q", m.StatusMirror)
		}
	}
	if m, _ := e.Lookup("t-mirror"); m.StatusMirror != "" {
		t.Fatalf("Lookup 与 DescribeAll 应同受角色门, got %q", m.StatusMirror)
	}
	e.SetRole(true)
	saw := false
	for _, m := range e.DescribeAll() {
		if m.ID == "t-mirror" {
			saw = true
			if m.StatusMirror != "running" {
				t.Fatalf("主节点应采纳真实业务态镜像, got %q", m.StatusMirror)
			}
		}
	}
	if !saw {
		t.Fatal("任务未注册")
	}
	if m, _ := e.Lookup("t-mirror"); m.StatusMirror != "running" {
		t.Fatalf("Lookup 主节点应采纳镜像, got %q", m.StatusMirror)
	}
}

// Given Oneshot 任务与独立任务日志目录。
// When 以 trigger=caddy-restart 同步执行（Caddy 崩溃自愈 watcher 通道）。
// Then 任务日志必须含 [start] 行（F-L1-68-04：[start] 打印条件仅放行
// manual/startup——caddy-restart 轮只有 [done]，排障看不到执行起点）。
func TestEngine_CaddyRestartTriggerWritesStartLine(t *testing.T) {
	e := newTestEngine(t)
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir("") })
	e.Register(Descriptor{ID: "t-restart", Family: "startup", Name: "系统配置载入", Kind: KindOneshot,
		Run: func(rc RunContext) error { return nil }})

	if _, err := e.RunSync("t-restart", "caddy-restart", ""); err != nil {
		t.Fatalf("RunSync: %v", err)
	}

	data, err := os.ReadFile(TaskLogPath("t-restart"))
	if err != nil {
		t.Fatalf("读取任务日志: %v", err)
	}
	if !strings.Contains(string(data), "[start]") {
		t.Fatalf("caddy-restart 触发缺 [start] 行, 日志=%q", string(data))
	}
}

// Given Scheduled 任务的 NextSlotFn 阻塞中（模拟三库排程槽 DB 查询耗时）。
// When tick 求值 NextSlotFn 期间并发调用 IsRunning（需同一把 r.mu）。
// Then IsRunning 不得被阻塞（F-L1-68-05：NextSlotFn 持 r.mu 调用会把 DB 延迟
// 传导到同任务的 Cancel/IsRunning/StopLoop——须快照后锁外求值再回锁落缓存）。
func TestEngine_TickEvaluatesNextSlotOutsideRegistrationLock(t *testing.T) {
	e := newTestEngine(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var entered atomic.Int32
	e.Register(Descriptor{ID: "t-slot", Family: "t", Name: "定时", Kind: KindScheduled,
		NextSlotFn: func() time.Time {
			entered.Store(1)
			<-release
			return time.Now().Add(time.Hour)
		},
		Run: func(RunContext) error { return nil },
	})
	e.StartLoop("t-slot")

	go e.tick()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && entered.Load() != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if entered.Load() != 1 {
		t.Fatal("tick 未进入 NextSlotFn")
	}

	probe := make(chan struct{})
	go func() { _ = e.IsRunning("t-slot"); close(probe) }()
	select {
	case <-probe:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("IsRunning 被 tick 持有的 r.mu 阻塞——NextSlotFn 须锁外求值")
	}
}

// TASK-L3（第 69 轮 P3）：RecoverOrphans 补上与同文件其余导出 DB 函数
// （History/Stats24h/PurgeTaskRuns 等 7 处）同形的 db.DB nil 防护——曾裸用
// db.DB.Exec，nil 时进程级 panic。
func TestEngine_RecoverOrphansNilDBReturnsZero(t *testing.T) {
	// Given 未初始化 DB（db.DB=nil）
	old := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = old })
	e := NewEngine(Options{})
	t.Cleanup(e.Stop)

	// When/Then nil DB 下调用不 panic 且返回 0
	if got := e.RecoverOrphans(); got != 0 {
		t.Fatalf("RecoverOrphans()=%d, want 0（nil DB 防护）", got)
	}
}

// TASK-L4（第 69 轮 P4）：Periodic 的 IntervalFn 与 Scheduled 的 NextSlotFn
// 同形锁外求值（F-L1-68-05 同族收敛补全——IntervalFn 未来改 DB 读取形态时，
// 持 r.mu 求值会把延迟传导到同任务的 Cancel/IsRunning/StopLoop）。
//
// Given Periodic 任务的 IntervalFn 阻塞中（模拟可配置间隔的 DB 读取耗时）。
// When tick 求值 IntervalFn 期间并发调用 IsRunning（需同一把 r.mu）。
// Then IsRunning 不得被阻塞——IntervalFn 须快照后锁外求值再回锁复核。
func TestEngine_TickEvaluatesIntervalOutsideRegistrationLock(t *testing.T) {
	e := newTestEngine(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var entered atomic.Int32
	e.Register(Descriptor{ID: "t-int", Family: "t", Name: "循环", Kind: KindPeriodic,
		IntervalFn: func() time.Duration {
			entered.Store(1)
			<-release
			return time.Hour
		},
		Run: func(RunContext) error { return nil },
	})
	e.StartLoop("t-int")

	go e.tick()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && entered.Load() != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if entered.Load() != 1 {
		t.Fatal("tick 未进入 IntervalFn")
	}

	probe := make(chan struct{})
	go func() { _ = e.IsRunning("t-int"); close(probe) }()
	select {
	case <-probe:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("IsRunning 被 tick 持有的 r.mu 阻塞——IntervalFn 须锁外求值")
	}
}

// TASK-L9（第 69 轮 P5）：生命周期行时间戳与业务行（TeeTaskLog）统一为
// 斜杠形态——曾 [start]/[done] 用横杠、业务行用斜杠，同一 tasks/{id}.log
// 两种时间戳并存。engineNowStr 是 DB datetime 比较口径（SQLite 只认横杠）
// 不改，日志行单独走斜杠。
func TestEngine_LifecycleLogLineUsesSlashTimestamp(t *testing.T) {
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir("") })

	// Given/When 追加一条生命周期行
	taskLogAppend("t-fmt", "[start] 手动触发")

	// Then 行首时间戳为 YYYY/MM/DD HH:MM:SS（斜杠，与业务行同形态）
	data, err := os.ReadFile(TaskLogPath("t-fmt"))
	if err != nil {
		t.Fatalf("读取任务日志: %v", err)
	}
	line := strings.TrimSpace(string(data))
	if len(line) < 20 || line[4] != '/' || line[7] != '/' {
		t.Fatalf("生命周期行时间戳形态=%q，want YYYY/MM/DD HH:MM:SS（斜杠）", line)
	}
}
