package taskengine

// 并发锁、DescribeAll 稳定序、TaskMeta 诊断字段
// 序列化口径、tick 槽回写并发校验、RearmLoop 用户停止
// 语义。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 注册式调度函数的 panic 不得杀死调度循环——NextSlotFn panic 的
// 任务本 tick 跳过（fail-closed 零值槽），其它任务照常按节拍执行。
func TestEngine_ScheduleFnPanicDoesNotKillLoop(t *testing.T) {
	e := newTestEngine(t)
	var healthyRuns atomic.Int32
	e.Register(Descriptor{ID: "t-panic-slot", Family: "t", Name: "槽 panic", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { panic("injected slot panic") },
		Run:        func(RunContext) error { return nil }})
	e.Register(Descriptor{ID: "t-panic-enabled", Family: "t", Name: "开关 panic", Kind: KindScheduled, RunsOn: RoleAny,
		EnabledFn:  func() bool { panic("injected enabled panic") },
		NextSlotFn: func() time.Time { return time.Now().Add(-time.Minute) },
		Run:        func(RunContext) error { return nil }})
	e.Register(Descriptor{ID: "t-healthy", Family: "t", Name: "健康循环", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 10 * time.Millisecond },
		Run:        func(RunContext) error { healthyRuns.Add(1); return nil }})
	e.StartLoop("t-panic-slot")
	e.StartLoop("t-panic-enabled")
	e.StartLoop("t-healthy")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && healthyRuns.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if healthyRuns.Load() < 3 {
		t.Fatalf("panic 调度函数阻塞了调度循环：健康任务仅执行 %d 次", healthyRuns.Load())
	}
	if e.IsStopped() {
		t.Fatal("调度循环 panic 不得停止引擎")
	}
	// fail-closed：槽 panic 的任务不得被投递执行
	if n := countRuns(t, "t-panic-slot"); n != 0 {
		t.Fatalf("NextSlotFn panic 任务不应投递执行，task_runs=%d", n)
	}
	if n := countRuns(t, "t-panic-enabled"); n != 0 {
		t.Fatalf("EnabledFn panic 应 fail-closed 跳过，task_runs=%d", n)
	}
}

// 多写入方并发跨阈值时，stat→rotate→append 必须整体互斥——.1 存在
// 且活动文件+归档的总行数守恒（并发交错会丢一代）。
func TestAppendTaskLogLine_concurrentRotationKeepsAllLines(t *testing.T) {
	dir := t.TempDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir("") })
	// 200 行 × 50B = 10000B，阈值 6000B → 恰好一次滚动（余量不触发第二次）。
	SetTaskLogSizeBytesFn(func() int64 { return 6000 })
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })

	path := filepath.Join(dir, "concurrent.log")
	line := strings.Repeat("x", 49) // Fprintln 补 1 字节换行，定长 50B
	const writers, perWriter = 2, 100
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWriter {
				appendTaskLogLine(path, line)
			}
		}()
	}
	wg.Wait()

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("并发跨阈值未产生 .1 归档: %v", err)
	}
	total := countFileLines(t, path) + countFileLines(t, path+".1")
	if total != writers*perWriter {
		t.Fatalf("活动+归档总行数=%d want %d（并发轮转丢代）", total, writers*perWriter)
	}
}

func countFileLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读日志 %s: %v", path, err)
	}
	if len(data) == 0 {
		return 0
	}
	return strings.Count(string(data), "\n")
}

// DescribeAll 必须按「分类固定序 + 类内 ID 字典序」稳定输出——
// 曾直接 range map，连续请求行序随机。
func TestEngine_DescribeAllStableCategoryAndIDOrder(t *testing.T) {
	e := newTestEngine(t)
	for _, d := range []struct{ id, category string }{
		{"zeta-system", "系统"},
		{"beta-security", "安全防护"},
		{"mid-cert", "证书"},
		{"zeta-cluster", "集群"},
		{"alpha-security", "安全防护"},
		{"backup-task", "备份"},
		{"unknown-cat", "未知分类"},
	} {
		e.Register(Descriptor{ID: d.id, Family: "t", Name: d.id, Category: d.category,
			Kind: KindOneshot, RunsOn: RoleAny, Run: func(RunContext) error { return nil }})
	}

	want := []string{
		"alpha-security", "beta-security",
		"mid-cert",
		"backup-task",
		"zeta-cluster",
		"zeta-system",
		"unknown-cat",
	}
	for round := range 10 {
		rows := e.DescribeAll()
		got := make([]string, 0, len(rows))
		for _, m := range rows {
			got = append(got, m.ID)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("第 %d 次 DescribeAll 行序=%v want %v（分类固定序+ID 字典序）", round+1, got, want)
		}
	}
}

// TaskMeta 不暴露 enabled 键；调度语义只由 loop_on 表达。
func TestTaskMeta_JSONOmitsEnabled(t *testing.T) {
	raw, err := json.Marshal(TaskMeta{ID: "x", LoopOn: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"enabled"`) {
		t.Fatalf("TaskMeta JSON 不应含 enabled 键（诊断字段，调度语义归 loop_on）: %s", raw)
	}
	if !strings.Contains(string(raw), `"loop_on"`) {
		t.Fatalf("loop_on 必须保留在任务视图: %s", raw)
	}
}

// tick 锁外求值槽期间并发 Run 已完成并回写新槽——陈旧求值不得覆盖
// 新槽（否则会把未来槽打回过去，形成重复投递）。
func TestEngine_TickDoesNotClobberConcurrentlyWrittenSlot(t *testing.T) {
	e := newTestEngine(t)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	fresh := time.Now().Add(time.Hour).Truncate(time.Second)
	e.Register(Descriptor{ID: "t-slot-race", Family: "t", Name: "槽竞态", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			if calls.Add(1) == 1 {
				close(entered)
				<-release
				return time.Now().Add(-time.Hour) // 陈旧求值（求值期间已过期）
			}
			return fresh
		},
		Run: func(RunContext) error { return nil }})
	e.StartLoop("t-slot-race")

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("tick 未进入 NextSlotFn 求值")
	}
	// 并发手动执行：runNow 在 Run 结束后回写 fresh 槽。
	if _, err := e.RunSync("t-slot-race", "manual", ""); err != nil {
		t.Fatalf("手动执行失败: %v", err)
	}
	want, ok := e.Lookup("t-slot-race")
	if !ok || want.NextSlot == "" {
		t.Fatal("手动执行未回写新槽")
	}
	close(release) // 放行陈旧求值
	// 陈旧求值若覆盖新槽，槽立即「到期」→ tick 额外投递一次 Run（task_runs 增行）。
	time.Sleep(300 * time.Millisecond)

	if n := countRuns(t, "t-slot-race"); n != 1 {
		t.Fatalf("tick 用陈旧求值覆盖并发写回的新槽，额外投递执行：task_runs=%d want 1（仅手动）", n)
	}
	if got, _ := e.Lookup("t-slot-race"); got.NextSlot != want.NextSlot {
		t.Fatalf("槽展示被陈旧求值覆盖: got=%q want=%q", got.NextSlot, want.NextSlot)
	}
}

// RearmLoop 不得越过用户停止；仅在明确告知「有活」时越过并立即补跑。
func TestEngine_RearmLoopRespectsUserStopUnlessWork(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	e.Register(Descriptor{ID: "t-rearm", Family: "t", Name: "唤醒", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { runs.Add(1); return nil }})
	e.StartLoop("t-rearm")
	// 等在途首轮落定后再停止（避免把停止前的轮次计入断言）。
	waitForEngine(t, "Rearm 基线首轮落定", 2*time.Second, func() bool { return runs.Load() == 1 && e.inFlight.Load() == 0 })
	e.StopLoop("t-rearm")
	if m, _ := e.Lookup("t-rearm"); m.LoopOn {
		t.Fatal("StopLoop 后 LoopOn 必须为 false")
	}
	base := runs.Load()

	e.RearmLoop("t-rearm", false)
	if m, _ := e.Lookup("t-rearm"); m.LoopOn {
		t.Fatal("无活的唤醒不得越过用户停止")
	}
	e.RearmLoop("t-rearm") // 服务就绪形态（无 hasWork 实参）
	if m, _ := e.Lookup("t-rearm"); m.LoopOn {
		t.Fatal("服务就绪 rearm 不得越过用户停止")
	}
	if runs.Load() != base {
		t.Fatalf("停止态下不得执行：runs=%d base=%d", runs.Load(), base)
	}

	e.RearmLoop("t-rearm", true)
	if m, _ := e.Lookup("t-rearm"); !m.LoopOn {
		t.Fatal("有活唤醒必须越过停止态恢复调度")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runs.Load() <= base {
		time.Sleep(10 * time.Millisecond)
	}
	if runs.Load() <= base {
		t.Fatalf("有活唤醒后未立即补跑：runs=%d base=%d", runs.Load(), base)
	}
}
