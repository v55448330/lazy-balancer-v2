package taskengine

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 仅显式 pendingRestart 才换代，异常退出后 loop_on 仍 true 但无人运行
// （安全事件采集/证书签发/集群同步永久静默停摆）。
func TestEngine_DaemonAbnormalExitRelaunchesBoundedThenStops(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: 10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{20 * time.Millisecond, 30 * time.Millisecond}})
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-crash", Family: "t", Name: "崩溃常驻", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(RunContext) error { runs.Add(1); return errors.New("boom") }})

	e.StartLoop("t-crash")

	// Then：首次 + 两次有界重拉 = 3 次执行
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && runs.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := runs.Load(); got != 3 {
		t.Fatalf("异常退出后执行次数=%d, want 3（首次+2 次有界重拉）", got)
	}
	// And：用尽后停止（不得无限紧循环）
	time.Sleep(200 * time.Millisecond)
	if got := runs.Load(); got != 3 {
		t.Fatalf("超出有界重拉上限：执行次数=%d, want 恒定 3", got)
	}
	if daemonRunning(e, "t-crash") {
		t.Fatal("有界重拉用尽后 running 位必须为 false")
	}
	// And：每次异常退出落 failed 行（可观测）
	var failed int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='t-crash' AND status='failed'`).Scan(&failed); err != nil {
		t.Fatalf("count failed rows: %v", err)
	}
	if failed != 3 {
		t.Fatalf("failed 行=%d, want 3（每次异常退出各一行）", failed)
	}
	meta, ok := e.Lookup("t-crash")
	if !ok {
		t.Fatal("Lookup must find the exhausted daemon")
	}
	if meta.LoopOn {
		t.Fatal("重拉预算用尽后 loop_on 必须为 false，与已停止调度的日志/状态一致")
	}

	// 用户直接点击恢复（无需先再点一次停止）必须开启新一轮预算并拉起。
	e.StartLoop("t-crash")
	waitForEngine(t, "预算用尽后的手动恢复", 2*time.Second, func() bool { return runs.Load() >= 4 })
}

// 否则一次历史崩溃即让该常驻任务永久失去自愈能力。
func TestEngine_DaemonManualRestartResetsAbnormalBudget(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: 10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{20 * time.Millisecond}})
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-crash2", Family: "t", Name: "崩溃常驻2", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(RunContext) error { runs.Add(1); return errors.New("boom") }})
	e.StartLoop("t-crash2")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && runs.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("首次+1 次重拉执行次数=%d, want 2", got)
	}
	time.Sleep(150 * time.Millisecond)
	if got := runs.Load(); got != 2 {
		t.Fatalf("重拉预算用尽后仍在执行: %d", got)
	}

	// When：用户显式 stop→start（真实重启过渡）
	e.StopLoop("t-crash2")
	e.StartLoop("t-crash2")

	// Then：重拉预算重置，立即重新执行
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runs.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := runs.Load(); got < 3 {
		t.Fatalf("显式重启后未重置重拉预算：执行次数=%d, want ≥3", got)
	}
}

// Given 常驻任务的异常重拉预算已用尽，随后用户停止并由业务侧以新工作唤醒。
// When 新一代首次异常退出。
// Then 它必须获得完整的新预算，而不是沿用上一代计数立即再次停调。
func TestEngine_DaemonRearmAfterStopStartsFreshRestartBudget(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: 10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{20 * time.Millisecond}})
	var runs atomic.Int32
	const id = "t-rearm-fresh-budget"
	e.Register(Descriptor{ID: id, Family: "t", Name: "唤醒后新预算", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(RunContext) error { runs.Add(1); return errors.New("boom") }})

	e.StartLoop(id)
	waitForEngine(t, "上一代首次执行与一次重拉", 2*time.Second, func() bool { return runs.Load() >= 2 })
	waitForEngine(t, "上一代预算用尽停调", 2*time.Second, func() bool {
		meta, ok := e.Lookup(id)
		return ok && !meta.LoopOn
	})

	e.StopLoop(id)
	e.RearmLoop(id, true)

	// 修复前 abnormalRestarts 仍为 2：新一代第 3 次执行后立即再次用尽，
	// 永远等不到第 4 次执行。正确行为是第 3 次后再重拉一次。
	waitForEngine(t, "新一代首次异常后仍按新预算重拉", 2*time.Second, func() bool { return runs.Load() >= 4 })
}

// 任务元数据，不得让任务监控整页 500（修复前裸调 Ever*/NextSlot/EnabledFn）。
func TestEngine_MetadataFnPanicIsolated(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-meta-panic", Family: "t", Name: "元数据 panic", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { panic("interval panic") },
		Run:        func(RunContext) error { return nil }})
	e.Register(Descriptor{ID: "t-meta-slot-panic", Family: "t", Name: "槽 panic", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { panic("slot panic") },
		Run:        func(RunContext) error { return nil }})

	// When/Then：两个函数均不得 panic；panic 闭包 fail-closed 为零值
	m, ok := e.Lookup("t-meta-panic")
	if !ok {
		t.Fatal("Lookup 未命中任务")
	}
	if m.IntervalSec != 0 {
		t.Fatalf("IntervalFn panic 应 fail-closed 零值, got interval=%d", m.IntervalSec)
	}
	slotMeta, ok := e.Lookup("t-meta-slot-panic")
	if !ok {
		t.Fatal("Lookup 未命中槽 panic 任务")
	}
	if slotMeta.NextSlot != "" {
		t.Fatalf("NextSlotFn panic 应返回空槽, got %q", slotMeta.NextSlot)
	}
	metas := e.DescribeAll()
	if len(metas) != 2 {
		t.Fatalf("DescribeAll 行数=%d, want 2（panic 不得中断聚合）", len(metas))
	}
}

func TestEngine_MetadataSkipsUnusedEnabledEvaluation(t *testing.T) {
	e := newTestEngine(t)
	var enabledCalls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-meta-enabled", Family: "t", Name: "冗余业务门", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return time.Minute },
		EnabledFn: func() bool {
			enabledCalls.Add(1)
			return true
		},
		Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}

	if _, ok := e.Lookup("t-meta-enabled"); !ok {
		t.Fatal("Lookup must find the task")
	}
	if metas := e.DescribeAll(); len(metas) != 1 {
		t.Fatalf("DescribeAll len=%d, want 1", len(metas))
	}
	if got := enabledCalls.Load(); got != 0 {
		t.Fatalf("metadata evaluated unused EnabledFn %d times, want 0 DB/business reads", got)
	}
}
