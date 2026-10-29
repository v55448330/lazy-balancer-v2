package taskengine

// 排程槽生命周期钉测：①同一槽只执行一次（成功落定未推进=消费本槽）；
// ②用户取消在途定时轮=消费本槽（不立即重投），槽推进后恢复；
// ③槽闭包降频求值（远期/已消费槽不每 tick 读 DB）；④退避 WARN 首轮
// 5 分钟地板；⑤常驻净返回提前退出=异常（failed+有界重拉）；
// ⑥任务日志目录熔断；⑦Periodic 角色门前置。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"lazy-balancer-v2/internal/db"
	"testing"
	"time"
)

// waitRunCeiling：等待「执行发生」的上限。这些 select 是就绪等待而非行为
// 断言（下限由槽地板决定，上限只防挂死），全量套件并行跑包时 SQLite 争用会
// 把 20ms 地板拖到秒级——2s 上限曾在 `scripts/test-all.sh` 全量下假红。
const waitRunCeiling = 15 * time.Second

// 缩短槽重评地板（默认 1min 在测试时间尺度外）——包级单测串行执行；地板是
// 原子值（tick 读 vs 本 cleanup 写回并发，见 engine.go 的声明注释）。
func shrinkSlotEvalFloor(t *testing.T, d time.Duration) {
	t.Helper()
	old := schedSlotEvalFloor.Load()
	schedSlotEvalFloor.Store(int64(d))
	t.Cleanup(func() { schedSlotEvalFloor.Store(old) })
}

// Given Scheduled 任务成功落定但业务未推进槽（槽仍是过期旧值）。
// When tick 循环运转。
// Then 同一槽只执行一次——不再按 tick 频率重投（旧形态 ≈35 次/350ms）。
func TestEngine_ScheduledSuccessConsumesStaleSlot(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	ran := make(chan struct{}, 4)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-once", Family: "t", Name: "成功消费槽", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return pastSlot },
		Run: func(rc RunContext) error {
			runs.Add(1)
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-once")

	// 首轮事件驱动等待（固定 sleep 猜首轮时点在慢机器上会把「还没跑到」
	// 误判成「不重投」）。
	select {
	case <-ran:
	case <-time.After(waitRunCeiling):
		t.Fatal("首槽未执行")
	}
	// 负断言同样事件驱动：观察窗口（≈30 ticks）内再出现一次执行即失败。
	select {
	case <-ran:
		t.Fatalf("同一过期槽成功落定后仍重投（执行 %d 次）", runs.Load())
	case <-time.After(350 * time.Millisecond):
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("同一过期槽成功落定后不得重投, got %d, want 1", got)
	}
	if got := countRuns(t, "t-once"); got != 1 {
		t.Fatalf("task_runs 落行 %d, want 1（重投风暴已收敛为槽消费）", got)
	}
}

// Given 同上，但业务随后把槽推进到新的（仍过期）值。
// When 槽值变化。
// Then 新槽恢复到期语义——再执行一次后再次消费（槽推进=新工作）。
func TestEngine_ScheduledAdvancedPastSlotRefiresOnce(t *testing.T) {
	e := newTestEngine(t)
	shrinkSlotEvalFloor(t, 20*time.Millisecond)
	slot1 := time.Now().Add(-2 * time.Minute)
	var slot atomic.Value
	slot.Store(slot1)
	ran := make(chan struct{}, 4)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-refire", Family: "t", Name: "槽推进再投", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return slot.Load().(time.Time) },
		Run: func(rc RunContext) error {
			runs.Add(1)
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-refire")

	// 恰好两次执行：先收满两次事件，再做「水位不再上涨」的负断言
	// （固定 sleep + 精确计数在慢机器上会把「还没跑到」误判成「不重投」）。
	for i := 0; i < 2; i++ {
		select {
		case <-ran:
		case <-time.After(waitRunCeiling):
			t.Fatalf("第 %d 次执行未发生", i+1)
		}
		// 首槽之后业务推进到新的过期槽（槽值变化=新排程）——地板周期内重评后应再投一次。
		if i == 0 {
			slot.Store(time.Now().Add(-time.Minute))
		}
	}
	select {
	case <-ran:
		t.Fatalf("新槽消费后仍重投（执行 %d 次, want 2）", runs.Load())
	case <-time.After(200 * time.Millisecond):
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("新槽消费后不得再重投, got %d, want 2", got)
	}
}

// Given 在途 Scheduled 自动轮（Run 阻塞）+ 用户点「取消」。
// When Cancel 命中。
// Then 终态落 cancelled 且本槽被消费——tick 不得按「槽仍过期」立即重投
// （旧形态下一 tick 整轮重投：全量重下载/重复整包备份）。
func TestEngine_ScheduledUserCancelConsumesSlot(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	started := make(chan struct{})
	var startOnce sync.Once
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-cancel", Family: "t", Name: "取消消费槽", Kind: KindScheduled,
		Cancelable: true,
		NextSlotFn: func() time.Time { return pastSlot },
		Run: func(rc RunContext) error {
			runs.Add(1)
			startOnce.Do(func() { close(started) })
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-cancel")

	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("首论未启动")
	}
	if !e.Cancel("t-cancel") {
		t.Fatal("在途可取消任务 Cancel 应返回 true")
	}
	waitForEngine(t, "取消落定 cancelled 终态", 2*time.Second, func() bool {
		lr := e.LatestRun("t-cancel")
		return lr != nil && lr.Status == "cancelled"
	})
	// 取消落定后槽仍过期（业务未推进）——本槽已消费，不得重投。
	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("用户取消后同一过期槽不得重投, got %d, want 1", got)
	}
	if got := countRuns(t, "t-cancel"); got != 1 {
		t.Fatalf("task_runs 落行 %d, want 1（仅被取消轮）", got)
	}
}

// Given Scheduled 任务用户取消在途自动轮（引擎消费本槽、业务侧推进排程槽——
// 四个规则库取消路径的语义）。
// When 业务把槽推进到下一槽。
// Then 新槽到点正常投递——取消不会把该任务锁死在已消费水位。
func TestEngine_UserCancelAdvanceDeliversNextSlot(t *testing.T) {
	e := newTestEngine(t)
	shrinkSlotEvalFloor(t, 20*time.Millisecond)
	var current atomic.Value
	current.Store(time.Now().Add(-time.Minute))
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-cancel-next", Family: "t", Name: "取消后下一槽", Kind: KindScheduled,
		Cancelable: true,
		NextSlotFn: func() time.Time { return current.Load().(time.Time) },
		Run: func(rc RunContext) error {
			if runs.Add(1) == 1 {
				<-rc.Ctx.Done()
				return rc.Ctx.Err()
			}
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-cancel-next")
	waitForEngine(t, "首轮启动", 2*time.Second, func() bool { return runs.Load() == 1 })
	if !e.Cancel("t-cancel-next") {
		t.Fatal("在途可取消任务 Cancel 应返回 true")
	}
	waitForEngine(t, "取消落定", 2*time.Second, func() bool {
		lr := e.LatestRun("t-cancel-next")
		return lr != nil && lr.Status == "cancelled"
	})
	// 业务侧取消收口推进到紧邻下一槽（此处压缩为 30ms 后到点）。
	current.Store(time.Now().Add(30 * time.Millisecond))
	waitForEngine(t, "下一槽投递", 2*time.Second, func() bool { return runs.Load() == 2 })
}

// Given 用户取消（Cancel 通道）与系统性中止（demote 角色翻转）两种取消。
// Then 只有用户取消的运行上下文带 ErrUserCancelled 取消原因——业务侧据此
// 区分「显式放弃本槽」与「恢复后到期轮补跑」。
func TestEngine_UserCancelMarksCancellationCause(t *testing.T) {
	e := newTestEngine(t)
	shrinkSlotEvalFloor(t, 20*time.Millisecond)
	started := make(chan context.Context, 4)
	var slot atomic.Value
	slot.Store(time.Now().Add(-time.Minute))
	var causesMu sync.Mutex
	var causes []error
	if err := e.Register(Descriptor{ID: "t-cause", Family: "t", Name: "取消原因", Kind: KindScheduled,
		Cancelable: true, RunsOn: RoleMasterOnly,
		NextSlotFn: func() time.Time { return slot.Load().(time.Time) },
		Run: func(rc RunContext) error {
			select {
			case started <- rc.Ctx:
			default:
			}
			<-rc.Ctx.Done()
			causesMu.Lock()
			causes = append(causes, context.Cause(rc.Ctx))
			causesMu.Unlock()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-cause")
	var firstCtx context.Context
	select {
	case firstCtx = <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("首轮未启动")
	}
	if !e.Cancel("t-cause") {
		t.Fatal("Cancel 应返回 true")
	}
	waitForEngine(t, "用户取消落定", 2*time.Second, func() bool {
		lr := e.LatestRun("t-cause")
		return lr != nil && lr.Status == "cancelled"
	})
	if cause := context.Cause(firstCtx); !errors.Is(cause, ErrUserCancelled) {
		t.Fatalf("用户取消的运行 ctx 原因=%v, want ErrUserCancelled", cause)
	}

	// demote 中止：ctx 取消不带 ErrUserCancelled（业务侧不得推进槽）。
	e.SetRole(false)
	e.SetRole(true)
	slot.Store(time.Now().Add(-time.Minute)) // 业务推进到新的到期槽（本槽已被消费）
	e.StartLoop("t-cause")
	var secondCtx context.Context
	select {
	case secondCtx = <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("demote 场景的自动轮未启动")
	}
	e.SetRole(false)
	select {
	case <-secondCtx.Done():
	case <-time.After(waitRunCeiling):
		t.Fatal("demote 未取消在途轮")
	}
	if cause := context.Cause(secondCtx); errors.Is(cause, ErrUserCancelled) {
		t.Fatalf("demote 中止的 ctx 原因=%v, 不得为用户取消", cause)
	}
}

// Given 用户取消手动轮（trigger=manual）与 demote 中止。
// Then 两者都不消费槽（手动不改变预约；demote 保留补跑语义）。
func TestEngine_ManualAndDemoteCancelKeepDueSlot(t *testing.T) {
	e := newTestEngine(t)
	slot := time.Now().Add(-time.Minute)
	started := make(chan struct{}, 4)
	if err := e.Register(Descriptor{ID: "t-keep", Family: "t", Name: "保留槽", Kind: KindScheduled,
		Cancelable: true, RunsOn: RoleMasterOnly,
		NextSlotFn: func() time.Time { return slot },
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	// 手动轮在途取消：槽不消费。
	manualDone := make(chan error, 1)
	go func() { manualDone <- e.Trigger("t-keep", "manual", "") }()
	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("手动轮未启动")
	}
	if !e.Cancel("t-keep") {
		t.Fatal("Cancel 应返回 true")
	}
	select {
	case <-manualDone:
	case <-time.After(waitRunCeiling):
		t.Fatal("手动轮取消后未退出")
	}
	waitForEngine(t, "手动轮取消落定", 2*time.Second, func() bool {
		lr := e.LatestRun("t-keep")
		return lr != nil && lr.Status == "cancelled"
	})
	// demote 中止：同样不消费槽。
	e.StartLoop("t-keep")
	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("自动轮未启动")
	}
	e.SetRole(false)
	waitForEngine(t, "demote 中止落定", 2*time.Second, func() bool {
		lr := e.LatestRun("t-keep")
		return lr != nil && (lr.Status == "skipped" || lr.Status == "cancelled")
	})
	r := regOf(t, e, "t-keep")
	r.mu.Lock()
	done := r.schedDoneSlot
	r.mu.Unlock()
	if !done.IsZero() {
		t.Fatalf("schedDoneSlot=%v, want 零值（手动轮/demote 中止不得消费槽）", done)
	}
}

// Given Scheduled 槽远期（+1h）/临近（+10s，前导窗内）。
// When 手动驱动 tick。
// Then 远期槽仅首 tick 求值（之后零闭包求值零 DB 读）；前导窗内每 tick
// 求值（到点即投的新鲜度不变）。
func TestEngine_ScheduledFarSlotSkipsClosureEval(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var slotEvals, enabledEvals atomic.Int32
	if err := e.Register(Descriptor{ID: "t-far", Family: "t", Name: "远期槽", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			slotEvals.Add(1)
			return time.Now().Add(time.Hour)
		},
		EnabledFn: func() bool {
			enabledEvals.Add(1)
			return true
		},
		Run: func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-far")

	for range 5 {
		e.tick()
	}
	if got := slotEvals.Load(); got != 1 {
		t.Fatalf("远期槽 NextSlotFn 求值 %d 次, want 1（首 tick 求值后进入降频）", got)
	}
	if got := enabledEvals.Load(); got != 1 {
		t.Fatalf("远期槽 EnabledFn 求值 %d 次, want 1", got)
	}

	// 前导窗内（slot-now < 30s）每 tick 求值。
	var nearEvals atomic.Int32
	if err := e.Register(Descriptor{ID: "t-near", Family: "t", Name: "临近槽", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			nearEvals.Add(1)
			return time.Now().Add(10 * time.Second)
		},
		Run: func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-near")
	e.tick()
	e.tick()
	e.tick()
	if got := nearEvals.Load(); got != 3 {
		t.Fatalf("前导窗内槽每 tick 求值, got %d, want 3", got)
	}
}

// Given 「失败（槽未推进）→ 成功（新槽）→ 再失败」交替形态。
// When 退避 WARN 首轮豁免无地板（旧形态）。
// Then 第二个首轮 WARN 被 5 分钟地板压制——日志仅 1 条退避 WARN
// （旧形态两轮各 1 条；生产交替失败可 1 条/s 刷屏）。
func TestEngine_ScheduledBackoffFirstWarnFloor(t *testing.T) {
	e := newTestEngine(t)
	shrinkSlotEvalFloor(t, 20*time.Millisecond)
	oldDir := LogDir()
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir(oldDir) })

	base := time.Now()
	slot := []atomic.Value{{}, {}, {}}
	slot[0].Store(base.Add(-3 * time.Minute))
	slot[1].Store(base.Add(-2 * time.Minute))
	slot[2].Store(base.Add(-time.Minute))
	var idx atomic.Int32
	var failNext atomic.Bool
	failNext.Store(true)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-warnfloor", Family: "t", Name: "首轮 WARN 地板", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return slot[idx.Load()].Load().(time.Time) },
		Run: func(rc RunContext) error {
			runs.Add(1)
			if failNext.Load() {
				return errors.New("boom")
			}
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-warnfloor")

	// 轮 1：失败（streak=1，首次 WARN 必落）。
	waitForEngine(t, "首轮失败落定", 2*time.Second, func() bool {
		lr := e.LatestRun("t-warnfloor")
		return lr != nil && lr.Status == "failed"
	})
	// 轮 2：推进到新过期槽 + 成功（消费新槽、清零 streak）。
	idx.Store(1)
	failNext.Store(false)
	waitForEngine(t, "第二轮成功落定", 3*time.Second, func() bool {
		lr := e.LatestRun("t-warnfloor")
		return lr != nil && lr.Status == "success"
	})
	// 轮 3：再推进到新过期槽 + 失败——streak 重回 1，距上次 WARN 远小于
	// 5 分钟地板，WARN 被压制。
	idx.Store(2)
	failNext.Store(true)
	waitForEngine(t, "第三轮失败落定", 3*time.Second, func() bool {
		lr := e.LatestRun("t-warnfloor")
		return lr != nil && lr.Status == "failed"
	})
	if got := runs.Load(); got != 3 {
		t.Fatalf("执行轮次=%d, want 3", got)
	}
	body, err := os.ReadFile(TaskLogPath("t-warnfloor"))
	if err != nil {
		t.Fatalf("读任务日志: %v", err)
	}
	if n := strings.Count(string(body), "[warn] 排程槽未推进"); n != 1 {
		t.Fatalf("退避 WARN 行数=%d, want 1（第二个首轮受 5 分钟地板压制）:\n%s", n, body)
	}
}

// Given 常驻任务 Run 未收到取消信号却净返回（实现缺陷/内部条件早退）。
// When 调度开关仍开。
// Then 视为异常退出：落 failed 行 + 按退避有界重拉（旧形态落
// 「[done] stopped」呈现空闲，任务永久停摆零信号）。
func TestEngine_DaemonPrematureCleanExitRelaunches(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{
		TickInterval:        10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond},
	})
	var calls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-premature", Family: "t", Name: "常驻早退", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			if calls.Add(1) == 1 {
				return nil // 早退：ctx 未取消、调度仍开
			}
			<-rc.Ctx.Done()
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-premature")

	waitForEngine(t, "早退后有界重拉", 2*time.Second, func() bool { return calls.Load() >= 2 })
	// 重拉代会再插 boot success 行（id 更大）——按 failed 行计数断言，
	// 不能用 LatestRun（最新行恒为新一代 boot）。
	waitForEngine(t, "早退轮落 failed 行", 2*time.Second, func() bool {
		var n int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=? AND status='failed' AND message LIKE '%提前返回%'`, "t-premature").Scan(&n); err != nil {
			return false
		}
		return n >= 1
	})
	e.StopLoop("t-premature")
}

// Given Periodic 任务挂 EnabledFn+IntervalFn（master-only），节点为从角色。
// When tick 若干轮。
// Then 角色不符整分支跳过——EnabledFn/IntervalFn 零求值（与 Scheduled
// 角色门前置同型对称）；promote 后下一 tick 立即恢复。
func TestEngine_PeriodicRoleGateSkipsClosureEval(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var enabledEvals, intervalEvals, runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-prole", Family: "t", Name: "周期角色门", Kind: KindPeriodic, RunsOn: RoleMasterOnly,
		EnabledFn:  func() bool { enabledEvals.Add(1); return true },
		IntervalFn: func() time.Duration { intervalEvals.Add(1); return time.Hour },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(false)
	e.StartLoop("t-prole")

	for range 5 {
		e.tick()
	}
	if got := enabledEvals.Load(); got != 0 {
		t.Fatalf("从节点 EnabledFn 求值 %d 次, want 0（角色门未前置）", got)
	}
	if got := intervalEvals.Load(); got != 0 {
		t.Fatalf("从节点 IntervalFn 求值 %d 次, want 0（角色门未前置）", got)
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("从节点执行 %d 次, want 0", got)
	}

	// promote：节拍置零→下一 tick 立即到期投递。
	e.SetRole(true)
	e.tick()
	waitForEngine(t, "promote 后首轮投递", 2*time.Second, func() bool { return runs.Load() == 1 })
}

// Given 任务日志目录不可创建（路径被同名文件占用）。
// When 连续写入多行任务日志。
// Then 一次性 ERROR 进入熔断，熔断期静默丢弃（不再逐行 WARNING 刷
// 运行日志）；目录恢复后经探测退出熔断并补 INFO，后续行正常落盘。
func TestEngine_TaskLogDirCircuitBreaker(t *testing.T) {
	buf := captureEngineLog(t)

	oldProbe := taskLogDirProbeInterval.Load()
	taskLogDirProbeInterval.Store(int64(20 * time.Millisecond))
	t.Cleanup(func() { taskLogDirProbeInterval.Store(oldProbe) })

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(blocker, "sub") // MkdirAll 必失败（父路径是文件）
	oldDir := LogDir()
	SetLogDir(badDir)
	t.Cleanup(func() { SetLogDir(oldDir) })

	for range 3 {
		taskLogAppend("t-fuse", "[start] 熔断期行")
	}
	if n := strings.Count(buf.String(), "进入熔断"); n != 1 {
		t.Fatalf("熔断 ERROR 行数=%d, want 1（逐行重试刷屏已熔断）:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "open task log"); n != 0 {
		t.Fatalf("熔断期不得再有逐行 open WARNING, got %d", n)
	}

	// 恢复：解除占用，探测周期到点后下一行触发重探。
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	taskLogAppend("t-fuse", "[done] 恢复行")
	if n := strings.Count(buf.String(), "恢复可写"); n != 1 {
		t.Fatalf("恢复 INFO 行数=%d, want 1:\n%s", n, buf.String())
	}
	body, err := os.ReadFile(TaskLogPath("t-fuse"))
	if err != nil {
		t.Fatalf("恢复后任务日志应落盘: %v", err)
	}
	if !strings.Contains(string(body), "恢复行") {
		t.Fatalf("恢复后写入行缺失: %q", body)
	}
}

// Given Scheduled 未来槽（+700ms）+ 手动触发在途轮 + 用户取消手动轮。
// When 取消落定后 tick 继续运转。
// Then 未来槽不被手动轮取消消费——到期后仍按预约自动投递（旧形态把未来槽
// 写入 schedDoneSlot，水位永久压住该槽，自动更新静默停摆）。
func TestEngine_ManualCancelKeepsFutureScheduledSlot(t *testing.T) {
	e := newTestEngine(t)
	futureSlot := time.Now().Add(700 * time.Millisecond)
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-manual-cancel", Family: "t", Name: "手动取消未来槽", Kind: KindScheduled,
		RunsOn: RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time { return futureSlot },
		Run: func(rc RunContext) error {
			if runs.Add(1) == 1 {
				close(firstStarted)
				<-rc.Ctx.Done()
				return rc.Ctx.Err()
			}
			close(secondStarted)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-manual-cancel")

	go func() { _ = e.Trigger("t-manual-cancel", "manual", "") }()
	select {
	case <-firstStarted:
	case <-time.After(waitRunCeiling):
		t.Fatal("手动触发轮未启动")
	}
	if !e.Cancel("t-manual-cancel") {
		t.Fatal("在途手动轮 Cancel 应返回 true")
	}
	select {
	case <-secondStarted:
	case <-time.After(waitRunCeiling):
		_, done, _, _ := scheduleStateOf(t, e, "t-manual-cancel")
		t.Fatalf("未来槽被手动轮取消消费（schedDoneSlot=%v），到期后未再投递", done)
	}
}

// Given Scheduled 已到期槽的自动轮在途 + CancelHook 返回 false（取消未生效）。
// When 调用 Cancel。
// Then 返回 false 且槽不被消费——失败轮仍可按退避兜底重投（旧形态先消费
// 槽再问 hook，取消失败也付出「本槽不再重投」的代价）。
func TestEngine_CancelHookRejectionKeepsDueSlot(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	started := make(chan struct{})
	release := make(chan struct{})
	if err := e.Register(Descriptor{ID: "t-hook-reject", Family: "t", Name: "hook 拒绝不消费", Kind: KindScheduled,
		RunsOn: RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time { return pastSlot },
		CancelHook: func() bool { return false },
		Run: func(rc RunContext) error {
			close(started)
			<-release
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-hook-reject")
	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("自动轮未启动")
	}
	if e.Cancel("t-hook-reject") {
		t.Fatal("CancelHook 返回 false 时 Cancel 必须返回 false")
	}
	if _, done, _, _ := scheduleStateOf(t, e, "t-hook-reject"); !done.IsZero() {
		t.Fatalf("取消未生效却消费了槽（schedDoneSlot=%v）", done)
	}
	close(release)
}

func TestEngine_CancelAfterFailureDoesNotConsumeDueSlot(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	pastSlot := time.Now().Add(-time.Minute)
	started := make(chan struct{})
	allowReturn := make(chan struct{})
	hookStarted := make(chan struct{})
	allowHook := make(chan struct{})
	terminalComputed := make(chan struct{})
	var slotCalls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-cancel-failed", Family: "t", Name: "失败轮取消竞态", Kind: KindScheduled,
		RunsOn: RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			if slotCalls.Add(1) == 2 {
				close(terminalComputed) // Run 已返回 failed，executeRun 正重算槽
			}
			return pastSlot
		},
		CancelHook: func() bool {
			close(hookStarted)
			<-allowHook
			return true
		},
		Run: func(RunContext) error {
			close(started)
			<-allowReturn
			return errors.New("boom")
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-cancel-failed")
	e.tick()
	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("自动轮未启动")
	}
	cancelDone := make(chan bool, 1)
	go func() { cancelDone <- e.Cancel("t-cancel-failed") }()
	select {
	case <-hookStarted:
	case <-time.After(waitRunCeiling):
		t.Fatal("CancelHook 未进入")
	}
	close(allowReturn)
	select {
	case <-terminalComputed:
	case <-time.After(waitRunCeiling):
		t.Fatal("失败终态未计算")
	}
	close(allowHook)
	if !<-cancelDone {
		t.Fatal("既有裁定保留：hook 成功时 Cancel 返回 true")
	}
	waitForEngine(t, "失败终态落库", 2*time.Second, func() bool {
		latest := e.LatestRun("t-cancel-failed")
		return latest != nil && latest.Status == "failed"
	})
	if _, done, _, _ := scheduleStateOf(t, e, "t-cancel-failed"); !done.IsZero() {
		t.Fatalf("失败轮已落定后取消动作不得消费重投槽, schedDoneSlot=%v", done)
	}
}

func TestEngineUserCancelSlotAdvanceFailureRetriesSameSlot(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	started := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32
	var slotCalls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-cancel-slot-error", Family: "t", Name: "取消槽推进失败重试", Kind: KindScheduled,
		Cancelable: true,
		NextSlotFn: func() time.Time {
			if slotCalls.Add(1) == 2 {
				return time.Time{} // 取消后的排程读取也瞬时失败；恢复后必须重评并重投。
			}
			return pastSlot
		},
		Run: func(RunContext) error {
			if runs.Add(1) == 1 {
				close(started)
				<-release
				return ErrScheduleSlotNotAdvanced
			}
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-cancel-slot-error")
	e.tick()
	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("automatic run did not start")
	}
	if !e.Cancel("t-cancel-slot-error") {
		t.Fatal("cancel must succeed")
	}
	close(release)
	waitForEngine(t, "slot failure retries the consumed slot", 3*time.Second, func() bool { return runs.Load() >= 2 })
}

func TestEngine_CancelEndpointsRespectTaskRole(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{})
	release := make(chan struct{})
	if err := e.Register(Descriptor{ID: "t-cancel-role", Family: "t", Name: "取消角色门", Kind: KindOneshot,
		RunsOn: RoleMasterOnly, Cancelable: true,
		Run: func(RunContext) error {
			close(started)
			<-release // 忽略 demote ctx，保留在途占位以隔离入口角色门
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- e.Trigger("t-cancel-role", "manual", "") }()
	select {
	case <-started:
	case <-time.After(waitRunCeiling):
		t.Fatal("任务未启动")
	}
	e.SetRole(false)
	if e.Cancel("t-cancel-role") {
		t.Fatal("从角色不得取消 master-only 任务")
	}
	if got := e.CancelInFlightRuns(); got != 0 {
		t.Fatalf("从角色 CancelInFlightRuns=%d, want 0", got)
	}
	close(release)
	select {
	case <-runDone:
	case <-time.After(waitRunCeiling):
		t.Fatal("任务未退出")
	}
}

// Given Scheduled 未来槽（+1h）+ 手动触发轮注入失败。
// When 执行落定 failed。
// Then 不进退避、不写「排程槽未推进…重投」失实告警（未来槽本来不会被 tick
// 重投；旧形态消耗 streak/5 分钟告警地板并推迟投递）。
func TestEngine_ManualFailureOnFutureSlotSkipsBackoff(t *testing.T) {
	e := newTestEngine(t)
	buf := captureEngineLog(t)
	futureSlot := time.Now().Add(time.Hour)
	if err := e.Register(Descriptor{ID: "t-future-fail", Family: "t", Name: "未来槽失败", Kind: KindScheduled,
		RunsOn:     RoleMasterOnly,
		NextSlotFn: func() time.Time { return futureSlot },
		Run:        func(RunContext) error { return errors.New("boom") }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-future-fail")
	if err := e.Trigger("t-future-fail", "manual", ""); err == nil {
		t.Fatal("注入失败的任务应返回错误")
	}
	waitForEngine(t, "失败终态", 2*time.Second, func() bool {
		lr := e.LatestRun("t-future-fail")
		return lr != nil && lr.Status == "failed"
	})
	_, _, retry, streak := scheduleStateOf(t, e, "t-future-fail")
	if !retry.IsZero() || streak != 0 {
		t.Fatalf("未来槽失败进入退避（retry=%v streak=%d）", retry, streak)
	}
	if strings.Contains(buf.String(), "排程槽未推进") {
		t.Fatalf("未来槽失败不得写重投告警:\n%s", buf.String())
	}
}

// Given RoleAny 周期任务已跑完一轮（节拍已推进）。
// When 真实角色翻转（demote→promote，flipped=true）。
// Then 节拍不被置零——RoleAny 不受角色门约束，翻转不得让每日任务多跑一轮。
func TestEngine_RoleFlipKeepsRoleAnyPeriodicCadence(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-any-periodic", Family: "t", Name: "RoleAny 周期", Kind: KindPeriodic,
		RunsOn:     RoleAny,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-any-periodic")
	e.tick()
	waitForEngine(t, "首轮完成", 2*time.Second, func() bool { return runs.Load() == 1 })
	e.SetRole(false)
	e.SetRole(true)
	e.tick()
	time.Sleep(50 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("角色翻转重置了 RoleAny 节拍（多跑 %d 轮）", got-1)
	}
}

// Given 零槽 Scheduled（全局开但所有源关）。
// When 连续 tick（未到重评地板）。
// Then 只有首 tick + 地板到点后求值——零槽不得每 tick 读库（旧形态 ≈3 SELECT/s/任务）。
func TestEngine_ZeroSlotEvalHonorsFloor(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	shrinkSlotEvalFloor(t, 150*time.Millisecond)
	var evals atomic.Int32
	if err := e.Register(Descriptor{ID: "t-zero-slot", Family: "t", Name: "零槽降频", Kind: KindScheduled,
		RunsOn:     RoleAny,
		NextSlotFn: func() time.Time { evals.Add(1); return time.Time{} },
		Run:        func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-zero-slot")
	e.tick()
	if got := evals.Load(); got != 1 {
		t.Fatalf("首 tick 求值 %d 次, want 1", got)
	}
	e.tick()
	if got := evals.Load(); got != 1 {
		t.Fatalf("地板内零槽求值 %d 次, want 1（不得每 tick 读库）", got)
	}
	time.Sleep(200 * time.Millisecond)
	e.tick()
	if got := evals.Load(); got != 2 {
		t.Fatalf("地板到点后求值累计 %d 次, want 2", got)
	}
}

// Given 日志目录存在但不可写（0555：MkdirAll 返回 nil，写入链才暴露）。
// When 连续写入超过阈值。
// Then 与前两次失败 WARNING 后进入熔断（一次 ERROR），后续行静默丢弃；
// 目录恢复后经探测补 INFO 并正常落盘（旧形态逐行 open WARNING 淹没运行日志）。
func TestEngine_TaskLogUnwritableDirCircuitBreaker(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受目录权限限制，无法构造不可写目录")
	}
	buf := captureEngineLog(t)
	oldProbe := taskLogDirProbeInterval.Load()
	taskLogDirProbeInterval.Store(int64(20 * time.Millisecond))
	t.Cleanup(func() { taskLogDirProbeInterval.Store(oldProbe) })
	SetTaskLogSizeBytesFn(func(context.Context) int64 { return 1 << 20 })
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	oldDir := LogDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir(oldDir) })

	for range 6 {
		taskLogAppend("t-fuse-ro", "[start] 只读目录行")
	}
	if n := strings.Count(buf.String(), "进入熔断"); n != 1 {
		t.Fatalf("熔断 ERROR 行数=%d, want 1:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "open task log"); n != taskLogWriteFailureThreshold-1 {
		t.Fatalf("阈值内 open WARNING 行数=%d, want %d（持续失败不得逐行刷）:\n%s",
			n, taskLogWriteFailureThreshold-1, buf.String())
	}

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	taskLogAppend("t-fuse-ro", "[done] 恢复行")
	if n := strings.Count(buf.String(), "恢复可写"); n != 1 {
		t.Fatalf("恢复 INFO 行数=%d, want 1:\n%s", n, buf.String())
	}
	body, err := os.ReadFile(TaskLogPath("t-fuse-ro"))
	if err != nil {
		t.Fatalf("恢复后任务日志应落盘: %v", err)
	}
	if !strings.Contains(string(body), "恢复行") {
		t.Fatalf("恢复后写入行缺失: %q", body)
	}
}

// Given 同一任务日志目录下 a.log 不可写（单文件权限故障）、b.log 可写。
// When a 连续写入触发该文件的熔断后继续写 b。
// Then b 仍正常落盘、熔断只覆盖 a（旧形态：单文件连续失败置全局 dirDown，
// 同目录其他健康任务日志一并静默丢弃最长一个探测周期）；a 恢复权限后补
// INFO 并恢复写入。
func TestEngine_TaskLogPathCircuitBreakerIsolatesOtherFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受文件权限限制，无法构造不可写文件")
	}
	buf := captureEngineLog(t)
	oldProbe := taskLogDirProbeInterval.Load()
	taskLogDirProbeInterval.Store(int64(20 * time.Millisecond))
	t.Cleanup(func() { taskLogDirProbeInterval.Store(oldProbe) })
	SetTaskLogSizeBytesFn(func(context.Context) int64 { return 1 << 20 })
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })

	dir := t.TempDir()
	oldDir := LogDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir(oldDir) })

	badPath := TaskLogPath("t-fuse-dup")
	if err := os.WriteFile(badPath, []byte("x\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(badPath, 0o644) })
	goodPath := TaskLogPath("t-fuse-healthy")

	for range taskLogWriteFailureThreshold {
		taskLogAppend("t-fuse-dup", "[start] 坏文件行")
	}
	if n := strings.Count(buf.String(), "任务日志文件不可写"); n != 1 {
		t.Fatalf("单文件熔断 ERROR 行数=%d, want 1:\n%s", n, buf.String())
	}

	taskLogAppend("t-fuse-healthy", "[start] 健康文件行")
	body, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatalf("健康任务日志必须照常落盘（单文件故障不得围堵同目录其他文件）: %v", err)
	}
	if !strings.Contains(string(body), "健康文件行") {
		t.Fatalf("健康任务日志内容缺失: %q", body)
	}

	// 熔断窗口内坏文件静默丢弃（行未写入），窗口后的探测写恢复。
	if err := os.Chmod(badPath, 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	taskLogAppend("t-fuse-dup", "[done] 恢复行")
	if n := strings.Count(buf.String(), "任务日志文件恢复可写"); n != 1 {
		t.Fatalf("单文件恢复 INFO 行数=%d, want 1:\n%s", n, buf.String())
	}
	body, err = os.ReadFile(badPath)
	if err != nil {
		t.Fatalf("恢复后读写任务日志失败: %v", err)
	}
	if !strings.Contains(string(body), "恢复行") {
		t.Fatalf("恢复后写入行缺失: %q", body)
	}
}

// Given 日志尺寸阈值函数可能读库（缓存未命中，最坏占满 busy_timeout）。
// When appendTaskLogLine 写入一行。
// Then 阈值求值发生在「按路径日志锁」之外——持路径锁读库会串行阻塞全部
// 任务日志写入。
func TestEngine_TaskLogSizeThresholdReadOutsidePathLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock-order.log")
	var lockedDuringSize atomic.Bool
	SetTaskLogSizeBytesFn(func(context.Context) int64 {
		lock := lockTaskLogPath(path)
		if lock.TryLock() {
			lock.Unlock()
		} else {
			lockedDuringSize.Store(true)
		}
		return 1 << 20
	})
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })

	appendTaskLogLine(context.Background(), path, "line")
	if lockedDuringSize.Load() {
		t.Fatal("尺寸阈值在持有路径锁时求值（读库会阻塞全部任务日志写入）")
	}
}

// Given 聚合查询连续失败（/system/tasks 5s 轮询）。
// When 失败态不变。
// Then 只在失败态翻转时返回打印级别——故障持续期静默，恢复补一条。
func TestTaskOverviewFailureLogThrottling(t *testing.T) {
	const key = "unit-test-overview"
	reset := func() {
		taskOverviewState.Lock()
		delete(taskOverviewState.failed, key)
		taskOverviewState.Unlock()
	}
	reset()
	t.Cleanup(reset)
	if got := noteTaskOverviewFailure(key, true); got != "WARNING" {
		t.Fatalf("首次失败=%q, want WARNING", got)
	}
	if got := noteTaskOverviewFailure(key, true); got != "" {
		t.Fatalf("持续失败=%q, want 空（不重复打印）", got)
	}
	if got := noteTaskOverviewFailure(key, false); got != "INFO" {
		t.Fatalf("恢复=%q, want INFO", got)
	}
	if got := noteTaskOverviewFailure(key, false); got != "" {
		t.Fatalf("持续健康=%q, want 空", got)
	}
	if got := noteTaskOverviewFailure(key, true); got != "WARNING" {
		t.Fatalf("再次失败=%q, want WARNING", got)
	}
}

// Given Scheduled 任务残留旧槽水位/失败退避（停摆后用户重开调度）。
// When StartLoop 关→开。
// Then 槽消费水位/退避/求值节拍被显式复位（旧水位不得压住新预约）。
func TestEngine_StartLoopResetsScheduleProgress(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	future := time.Now().Add(time.Hour)
	if err := e.Register(Descriptor{ID: "t-reset", Family: "t", Name: "重开复位", Kind: KindScheduled,
		RunsOn: RoleAny, NextSlotFn: func() time.Time { return future },
		Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-reset")
	r := regOf(t, e, "t-reset")
	r.mu.Lock()
	r.nextScheduledTime = future
	r.schedDoneSlot = future
	r.schedFailStreak = 3
	r.schedRetryAfter = time.Now().Add(time.Minute)
	r.schedSlotEvalAt = time.Now()
	r.mu.Unlock()

	e.StopLoop("t-reset")
	e.StartLoop("t-reset")
	slot, done, retry, streak := scheduleStateOf(t, e, "t-reset")
	if !slot.IsZero() || !done.IsZero() || !retry.IsZero() || streak != 0 {
		t.Fatalf("关→开未复位排程进度: slot=%v done=%v retry=%v streak=%d", slot, done, retry, streak)
	}
}

// Given Scheduled 过期槽（固定过去值）+ 手动触发轮成功落定而业务未推进槽。
// When 手动轮完成后自动轮继续运转。
// Then 手动成功同样消费该槽（与自动轮同权）——否则第一次手动成功后 tick 会按
// 「槽仍过期」反复整轮重投。手动形态此前只有取消/失败语义的钉测。
func TestEngine_ManualSuccessConsumesExpiredScheduledSlot(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-manual-consume"
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: id, Family: "t", Name: "手动消费过期槽", Kind: KindScheduled,
		RunsOn:     RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	if _, err := e.RunSync(id, "manual", ""); err != nil {
		t.Fatalf("手动轮应成功: %v", err)
	}
	_, done, _, _ := scheduleStateOf(t, e, id)
	if !done.Equal(pastSlot) {
		t.Fatalf("手动成功未消费过期槽: schedDoneSlot=%v, want %v（tick 会重复整轮执行）", done, pastSlot)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("手动轮执行 %d 次, want 1", got)
	}
}

// Given Scheduled 未来槽（+700ms）+ 手动触发轮成功落定。
// When 手动轮完成后自动轮运转到预约时刻。
// Then 未来槽不被手动成功消费（水位保持零值），到点后仍由 tick 投递一次。
func TestEngine_ManualSuccessKeepsFutureScheduledSlot(t *testing.T) {
	e := newTestEngine(t)
	futureSlot := time.Now().Add(700 * time.Millisecond)
	const id = "t-manual-future"
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: id, Family: "t", Name: "手动保未来槽", Kind: KindScheduled,
		RunsOn:     RoleAny,
		NextSlotFn: func() time.Time { return futureSlot },
		Run:        func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	if _, err := e.RunSync(id, "manual", ""); err != nil {
		t.Fatalf("手动轮应成功: %v", err)
	}
	if _, done, _, _ := scheduleStateOf(t, e, id); !done.IsZero() {
		t.Fatalf("未来槽被手动成功消费（schedDoneSlot=%v）——到期后自动更新将静默停摆", done)
	}
	e.StartLoop(id)
	waitForEngine(t, "预约到点自动投递", 3*time.Second, func() bool { return runs.Load() == 2 })
}
