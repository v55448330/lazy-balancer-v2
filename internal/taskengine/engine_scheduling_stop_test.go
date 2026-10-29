package taskengine

// 调度自动停摆与唤醒复位钉测：
//   - Periodic 的 IntervalFn 返回非正周期必须停调，且停调来源机器可读
//     （failed 运行行 + [error] 日志），不得与用户主动停止同形；
//   - Scheduled「槽未推进+失败」的兜底退避必须有终点：连续 N 轮自动轮仍未
//     推进即停调，不得按 30s 节拍无限落行；
//   - RearmLoop 越过停止态时对 Scheduled 复位槽消费水位——否则旧水位会
//     永久压住当前槽（loop_on=true 却零投递）；
//   - 调度闭包 panic 告警按任务分桶，跨任务不得互相遮蔽。

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given Periodic 任务的 IntervalFn 返回 0（配置读错被映射为零值等形态）。
// When tick 求值间隔。
// Then 停止该任务调度且不执行 Run，同时落一条 failed 运行行（状态列可见、
// 可与用户主动停止区分）与 [error] 日志。
func TestEngine_PeriodicNonPositiveIntervalStopsWithFailedRun(t *testing.T) {
	e := newTestEngine(t)
	const id = "t-nonpositive-interval"
	var runs atomic.Int32
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "非正周期", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 0 },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)

	waitForEngine(t, "非正周期停调", 2*time.Second, func() bool { return !loopEnabledOf(t, e, id) })
	if got := runs.Load(); got != 0 {
		t.Fatalf("非正周期不得执行 Run, got %d 次", got)
	}
	// 停调标记先于运行行落库（LoopEnabled 置 false 与 finishRun 写行是两步），
	// 只等停调会读到「行尚未写入」的瞬时态。
	waitForEngine(t, "停调运行行落库", 2*time.Second, func() bool { return countRuns(t, id) >= 1 })
	var status, message string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT 1`, id).
		Scan(&status, &message); err != nil {
		t.Fatalf("读取停调运行行: %v", err)
	}
	if status != "failed" || !strings.Contains(message, "IntervalFn 必须返回正周期") {
		t.Fatalf("停调应落 failed 行并带原因, got status=%q message=%q", status, message)
	}
	// 停调是终态：再等若干个 tick 不得追加运行行（循环已关闭）。
	time.Sleep(100 * time.Millisecond)
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("停调后仍追加运行行, 共 %d 行（应在停调时恰落一行）", got)
	}
}

// Given Scheduled 任务的自动轮已连续失败且业务永不推进槽（streak 预置到
// 终点前一轮，槽缓存=当前过期槽）。
// When 第 scheduledFailStreakStopLimit 轮自动轮仍失败。
// Then 停止该任务调度（退避兜底必须有终点），留 [error] 日志与失败行；关→开
// 调度可恢复（不是不可恢复状态）。
func TestEngine_ScheduledUnadvancedSlotStopsAfterStreakLimit(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-streak-stop"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "槽未推进停调", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { return os.ErrDeadlineExceeded },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	// 任务日志落盘目录（默认空=不写文件）——本用例断言 [error] 留痕。
	oldLogDir := LogDir()
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir(oldLogDir) })
	// tick 已按该槽求值过（prevSlot=同一过期槽）才会进退避分支——直接预置。
	r := regOf(t, e, id)
	r.mu.Lock()
	r.nextScheduledTime = pastSlot
	r.schedFailStreak = scheduledFailStreakStopLimit - 1
	r.mu.Unlock()

	if _, err := e.RunSync(id, "auto", ""); err == nil {
		t.Fatal("注入失败的任务应记录失败")
	}
	if loopEnabledOf(t, e, id) {
		t.Fatalf("槽连续 %d 轮未推进且自动轮失败，必须停止调度（无终点会按 30s 节拍无限落行）", scheduledFailStreakStopLimit)
	}
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("运行行 %d, want 1（停调轮自身的失败行）", got)
	}
	logBody, err := os.ReadFile(TaskLogPath(id))
	if err != nil {
		t.Fatalf("读取任务日志: %v", err)
	}
	if !strings.Contains(string(logBody), "已停止该任务调度") {
		t.Fatalf("停调必须留 [error] 日志，实际日志:\n%s", string(logBody))
	}
	// 关→开=显式恢复：复位槽水位与退避后照常调度。
	e.StartLoop(id)
	if !loopEnabledOf(t, e, id) {
		t.Fatal("StartLoop 关→开应恢复调度")
	}
	if _, done, retry, streak := scheduleStateOf(t, e, id); !done.IsZero() || !retry.IsZero() || streak != 0 {
		t.Fatalf("恢复后排程进度未复位: done=%v retry=%v streak=%d", done, retry, streak)
	}
}

// Given Scheduled 任务停调前 schedDoneSlot 已等于当前 due 槽（成功落定未推进
// 槽/用户取消已到期槽的形态）。
// When 业务唤醒经 RearmLoop(hasWork=true) 越过停止态。
// Then 槽水位与退避被复位，当前槽可投递（旧水位曾让重开后零投递）。
func TestEngine_RearmLoopResetsScheduledProgress(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	const id = "t-rearm-reset"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "唤醒复位", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	waitForEngine(t, "首轮消费本槽", 2*time.Second, func() bool { return runs.Load() == 1 })
	// 首轮成功后本槽已被消费（水位=槽值），随后用户停止调度。
	waitForEngine(t, "槽被消费", 2*time.Second, func() bool {
		_, done, _, _ := scheduleStateOf(t, e, id)
		return !done.IsZero()
	})
	e.StopLoop(id)

	e.RearmLoop(id, true)
	slot, done, retry, streak := scheduleStateOf(t, e, id)
	if !slot.IsZero() || !done.IsZero() || !retry.IsZero() || streak != 0 {
		t.Fatalf("越过停止态未复位排程进度: slot=%v done=%v retry=%v streak=%d", slot, done, retry, streak)
	}
	waitForEngine(t, "越过停止后补跑", 2*time.Second, func() bool { return runs.Load() == 2 })
}

// Given 两个任务的调度闭包先后 panic。
// When 告警限流判定。
// Then 两个任务各自留一条告警（全局单槽会让后者的首报被前者的 1 分钟窗口
// 吞掉）；同一任务重复 panic 只累计抑制计数、不刷新放行时刻。
func TestWarnSchedFnPanicThrottlesPerKind(t *testing.T) {
	schedFnPanicMu.Lock()
	schedFnPanicLast = map[string]time.Time{}
	schedFnPanicSuppressed = map[string]int{}
	schedFnPanicMu.Unlock()
	t.Cleanup(func() {
		schedFnPanicMu.Lock()
		schedFnPanicLast = map[string]time.Time{}
		schedFnPanicSuppressed = map[string]int{}
		schedFnPanicMu.Unlock()
	})

	warnSchedFnPanic("task-a.IntervalFn", "boom-a")
	warnSchedFnPanic("task-b.NextSlotFn", "boom-b")

	schedFnPanicMu.Lock()
	firstA, okA := schedFnPanicLast["task-a.IntervalFn"]
	_, okB := schedFnPanicLast["task-b.NextSlotFn"]
	schedFnPanicMu.Unlock()
	if !okA || !okB {
		t.Fatalf("按任务分桶失败：a=%v b=%v（跨任务不得互相遮蔽）", okA, okB)
	}

	warnSchedFnPanic("task-a.IntervalFn", "boom-a-again")
	schedFnPanicMu.Lock()
	lastA := schedFnPanicLast["task-a.IntervalFn"]
	suppressed := schedFnPanicSuppressed["task-a.IntervalFn"]
	schedFnPanicMu.Unlock()
	if suppressed != 1 {
		t.Fatalf("同类 panic 抑制计数=%d, want 1（被抑制次数不得丢弃）", suppressed)
	}
	if !lastA.Equal(firstA) {
		t.Fatal("限流窗口内不得刷新放行时刻（否则每分钟洪峰无上限）")
	}
}

// Given Scheduled 任务的自动轮已连续失败（槽未推进），管理员又手动重试也失败。
// When 手动失败次数达到自动停调预算的轮数，随后继续自动轮失败。
// Then 手动轮不消耗自动停调预算：手动失败只保留退避节流，streak 不增、调度
// 不停；自动轮从零累计到预算终点才停调。
func TestEngine_ScheduledManualFailuresDoNotConsumeStopBudget(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-manual-no-budget"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "手动轮不耗预算", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { return os.ErrDeadlineExceeded },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	// 与 tick 同口径预置槽缓存：退避分支只覆盖「槽已到期且未推进」形态。
	r := regOf(t, e, id)
	r.mu.Lock()
	r.nextScheduledTime = pastSlot
	r.mu.Unlock()

	for i := 0; i < scheduledFailStreakStopLimit; i++ {
		if _, err := e.RunSync(id, "manual", "tester"); err == nil {
			t.Fatal("注入失败的手动轮应返回错误")
		}
	}
	if !loopEnabledOf(t, e, id) {
		t.Fatal("手动轮失败不得停止自动调度（次数天然有界）")
	}
	if _, _, retry, streak := scheduleStateOf(t, e, id); streak != 0 || retry.IsZero() {
		t.Fatalf("手动轮不得消耗自动停调预算: streak=%d retry=%v（退避节流须保留）", streak, retry)
	}

	// 自动轮从零开始累计：前 limit-1 轮不停调，第 limit 轮停调。
	for i := 1; i < scheduledFailStreakStopLimit; i++ {
		if _, err := e.RunSync(id, "auto", ""); err == nil {
			t.Fatal("注入失败的自动轮应返回错误")
		}
		if !loopEnabledOf(t, e, id) {
			t.Fatalf("自动轮第 %d 轮未到停调终点，不得提前停调", i)
		}
		if _, _, _, streak := scheduleStateOf(t, e, id); streak != i {
			t.Fatalf("自动轮 streak=%d, want %d", streak, i)
		}
	}
	if _, err := e.RunSync(id, "auto", ""); err == nil {
		t.Fatal("注入失败的自动轮应返回错误")
	}
	if loopEnabledOf(t, e, id) {
		t.Fatalf("自动轮累计到 %d 轮仍应停调", scheduledFailStreakStopLimit)
	}
}

// Given Scheduled 任务已开启且当前槽已被成功消费（水位=槽值）。
// When 业务唤醒经 RearmLoop(hasWork=true) 到达（任务本来就在调度中）。
// Then 槽水位与退避不被复位——已开启任务的普通唤醒不得把已消费的过期槽重新
// 投递（复位只属于「已停止→恢复」过渡）。
func TestEngine_RearmLoopHasWorkKeepsConsumedSlotWhenAlreadyOn(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	const id = "t-rearm-on"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "已开启唤醒", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	waitForEngine(t, "首轮消费本槽", 2*time.Second, func() bool {
		_, done, _, _ := scheduleStateOf(t, e, id)
		return runs.Load() == 1 && !done.IsZero()
	})

	e.RearmLoop(id, true)

	if _, done, _, _ := scheduleStateOf(t, e, id); done.IsZero() {
		t.Fatal("已开启任务的唤醒不得复位槽消费水位（会把过期槽重新投递）")
	}
	time.Sleep(200 * time.Millisecond) // ≈20 个 tick
	if got := runs.Load(); got != 1 {
		t.Fatalf("已开启任务被唤醒后重复投递: runs=%d, want 1", got)
	}
}

// Given 引擎因「槽连续未推进」自行停调。
// When 读取任务元数据；随后用户重新开启调度，再主动停止。
// Then 停调来源机器可读（schedule_stopped_reason=fail-streak），重新开启即清空；
// 用户主动停止不留来源标记——两者可区分。
func TestEngine_ScheduleStopReasonIsMachineReadable(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	previousLogDir := LogDir()
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir(previousLogDir) })
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-stop-reason"
	const recoverHint = "排程测试恢复入口（业务页保存一次）"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "停调来源", Kind: KindScheduled, RunsOn: RoleAny,
		LoopRecoveryHint: recoverHint,
		NextSlotFn:       func() time.Time { return pastSlot },
		Run:              func(RunContext) error { return os.ErrDeadlineExceeded },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	r := regOf(t, e, id)
	r.mu.Lock()
	r.nextScheduledTime = pastSlot
	r.schedFailStreak = scheduledFailStreakStopLimit - 1
	r.mu.Unlock()

	if _, err := e.RunSync(id, "auto", ""); err == nil {
		t.Fatal("注入失败的任务应记录失败")
	}
	m, ok := e.Lookup(id)
	if !ok {
		t.Fatal("任务未注册")
	}
	if m.LoopOn {
		t.Fatal("停调后 LoopOn 应为 false")
	}
	if m.ScheduleStoppedReason != ScheduleStopReasonFailStreak {
		t.Fatalf("停调来源=%q, want %q（视图据此区分引擎停调与用户停止）", m.ScheduleStoppedReason, ScheduleStopReasonFailStreak)
	}
	// 停调日志必须给出恢复入口提示（按业务驱动唯一清单注入的 hint）——只看
	// 停调来源字段无法发现提示文案丢失或回退到通用兜底。
	body, err := os.ReadFile(TaskLogPath(id))
	if err != nil {
		t.Fatalf("停调日志未落盘: %v", err)
	}
	if !strings.Contains(string(body), recoverHint) {
		t.Fatalf("停调日志缺少描述符注入的恢复入口提示: %q", body)
	}
	if strings.Contains(string(body), "任务页调度开关或重启进程") {
		t.Fatalf("停调日志回退到通用兜底提示（描述符 hint 未生效）: %q", body)
	}

	e.StartLoop(id)
	if m, _ := e.Lookup(id); m.ScheduleStoppedReason != "" {
		t.Fatalf("重新开启调度后停调来源应清空, got %q", m.ScheduleStoppedReason)
	}
	e.StopLoop(id)
	if m, _ := e.Lookup(id); m.ScheduleStoppedReason != "" {
		t.Fatalf("用户主动停止不得留下引擎停调来源, got %q", m.ScheduleStoppedReason)
	}
}

// Given 引擎已停止且传入非法描述符。
// When 注册。
// Then 先报字段错误（排障指向真正缺失的字段）；合法描述符仍被 ErrEngineStopped
// 拒绝——停调门的语义不变。
func TestEngine_RegisterAfterStopReportsFieldErrorFirst(t *testing.T) {
	e := NewEngine(Options{TickInterval: time.Hour})
	e.Stop()

	err := e.Register(Descriptor{Family: "t", Name: "缺 ID", Kind: KindOneshot,
		Run: func(RunContext) error { return nil }})
	if errors.Is(err, ErrEngineStopped) {
		t.Fatal("非法描述符应先报字段错误，而不是「引擎已停止」（排障指向错误）")
	}
	if err == nil || !strings.Contains(err.Error(), "ID/Family 必填") {
		t.Fatalf("非法描述符 err=%v, want 字段错误", err)
	}

	err = e.Register(Descriptor{ID: "t-after-stop-field", Family: "t", Name: "合法描述符", Kind: KindOneshot,
		Run: func(RunContext) error { return nil }})
	if !errors.Is(err, ErrEngineStopped) {
		t.Fatalf("合法描述符在已停引擎注册 err=%v, want ErrEngineStopped", err)
	}
}

// Given 引擎因「排程槽连续未推进」自行停调（schedStopReason=fail-streak），且
// 该任务带自愈预算用尽标记。
// When 用户显式停止该任务（不经重新开启）。
// Then 停调来源与自愈用尽标记都随用户停止清空——视图不得把用户主动停止
// 呈现成引擎停调/failed；之后的引擎侧停调仍照常记录来源。
func TestEngine_UserStopClearsEngineStopAttribution(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	previousLogDir := LogDir()
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir(previousLogDir) })
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-user-stop-attribution"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "用户停止清来源", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { return os.ErrDeadlineExceeded },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)

	// engineStop 让引擎自己停调：失败轮 + 已到停调预算前一轮。
	engineStop := func() {
		t.Helper()
		r := regOf(t, e, id)
		r.mu.Lock()
		r.nextScheduledTime = pastSlot
		r.schedFailStreak = scheduledFailStreakStopLimit - 1
		r.mu.Unlock()
		if _, err := e.RunSync(id, "auto", ""); err == nil {
			t.Fatal("注入失败的任务应记录失败")
		}
	}

	e.StartLoop(id)
	engineStop()
	if m, _ := e.Lookup(id); m.ScheduleStoppedReason != ScheduleStopReasonFailStreak {
		t.Fatalf("前置状态错误：引擎停调来源=%q, want %q", m.ScheduleStoppedReason, ScheduleStopReasonFailStreak)
	}

	r := regOf(t, e, id)
	r.mu.Lock()
	r.restartExhausted = true
	r.mu.Unlock()

	e.StopLoop(id)
	m, _ := e.Lookup(id)
	if m.ScheduleStoppedReason != "" {
		t.Fatalf("用户主动停止不得保留引擎停调来源, got %q", m.ScheduleStoppedReason)
	}
	if m.RestartExhausted {
		t.Fatal("用户主动停止不得保留自愈预算用尽标记（视图会误呈现 failed）")
	}

	// 清空只针对用户停止路径：其后引擎侧停调仍须记录来源。
	e.StartLoop(id)
	engineStop()
	if m, _ := e.Lookup(id); m.ScheduleStoppedReason != ScheduleStopReasonFailStreak {
		t.Fatalf("引擎侧停调来源丢失: %q, want %q", m.ScheduleStoppedReason, ScheduleStopReasonFailStreak)
	}
}
