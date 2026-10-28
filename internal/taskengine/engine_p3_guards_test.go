package taskengine

// 调度守卫族钉测试：
//   - Scheduled 分支缺「投递前业务门复核」——NextSlotFn（DB 读）窗口内
//     用户关掉业务开关仍派发一轮，违反「EnabledFn=false=零执行零落行」契约。
//   - RearmLoop 对常驻族恒传 restartIntent=true——运行中 daemon 被栽
//     pendingRestart，在随后一次正常退出时被换取新代（RearmLoop 契约是
//     「仅重置节拍，不改变调度」）。
//   - RunAsync/RunAsyncResult 缺 KindDaemon 拒绝——与 Trigger/RunSync
//     的纵深不对称（绕过 startDaemon 生命周期双跑）。
//   - 任务日志行不截断——单行可超 task_log_size_mb 并放大日志体积；
//     DB message 已有 truncMsg(500)，日志行须有统一上限。

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// Given Scheduled 任务：EnabledFn 初值 true，NextSlotFn 求值期间把业务开关翻 false
// （生产形态=槽查询的 DB 读窗口内用户关闭任务）。
// When tick 派发判定。
// Then 零执行零落行（投递前复核与 Periodic 同口径）。
func TestEngine_ScheduledRechecksEnabledFnBeforeDispatch(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var enabled atomic.Bool
	enabled.Store(true)
	var runs atomic.Int32
	const id = "t-sched-window-gate"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "定时窗口业务门",
		Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			// 求值窗口内业务关闭——tick 的首道业务门已通过，不得据此陈旧
			// 结论派发。
			enabled.Store(false)
			return time.Now().Add(-time.Second)
		},
		EnabledFn: func() bool { return enabled.Load() },
		Run: func(rc RunContext) error {
			runs.Add(1)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)

	e.tick()
	// 若旧形态派发了轮次，异步 Run 会在该窗口内执行完毕（断言前留出时间）。
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runs.Load() != 0 || countRuns(t, id) != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("求值窗口内业务关闭后仍派发：执行次数=%d, want 0", got)
	}
	if got := countRuns(t, id); got != 0 {
		t.Fatalf("求值窗口内业务关闭后仍落行：task_runs=%d, want 0", got)
	}
}

// Given 运行中的常驻任务（Run 阻塞于测试通道，退出形态=正常返回）。
// When RearmLoop（无实参形态=服务就绪重置节拍）。
// Then 不栽重启意图、不换代——Run 正常退出后不得拉起新代。
func TestEngine_RearmLoopDoesNotReplaceRunningDaemon(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour, DaemonRestartDelays: []time.Duration{time.Hour}})
	var starts atomic.Int32
	started := make(chan struct{}, 4)
	exit := make(chan struct{})
	const id = "t-daemon-rearm"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "常驻重排",
		Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error {
			starts.Add(1)
			started <- struct{}{}
			<-exit // 正常退出（非取消、非错误）
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("常驻任务未启动")
	}

	e.RearmLoop(id) // 无实参：仅重置节拍，不得栽重启意图

	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	r.mu.Lock()
	pending := r.pendingRestart
	r.mu.Unlock()
	if pending {
		t.Fatal("RearmLoop 对运行中的常驻任务栽下了 pendingRestart——与「仅重置节拍」契约冲突")
	}

	close(exit) // 正常退出：旧形态会按 pendingRestart 换代重启
	if !waitDaemonNotRunning(t, e, id, 2*time.Second) {
		t.Fatal("常驻任务正常退出后 running 位未归零")
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("RearmLoop 后 Run 正常退出仍被换代重启：启动次数=%d, want 1", got)
	}

	// 回归形状：空闲（正常退出后 running=false、调度仍开）时 RearmLoop 仍经
	// CAS 正常拉起——修复不得把常驻启动路径一并关掉。
	e.RearmLoop(id)
	waitForEngine(t, "RearmLoop 直接拉起空闲 daemon", 200*time.Millisecond, func() bool { return starts.Load() == 2 })
	if got := starts.Load(); got != 2 {
		t.Fatalf("空闲常驻任务 RearmLoop 未拉起新代：启动次数=%d, want 2", got)
	}
	e.StopLoop(id)
}

// Given KindDaemon 描述符 + 主节点角色。
// When RunAsync / RunAsyncResult 直调。
// Then 与 Trigger/RunSync 同型拒绝，Run 体零执行零落行（第二道防线）。
func TestEngine_RunAsyncRejectsDaemonKind(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	var done atomic.Int32
	const id = "t-async-daemon"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "常驻异步",
		Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error {
			runs.Add(1)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)

	if err := e.RunAsync(id, "manual", "tester"); err == nil || !strings.Contains(err.Error(), "常驻任务") {
		t.Fatalf("RunAsync 应拒绝常驻任务，得到 err=%v", err)
	}
	if err := e.RunAsyncResult(id, "manual", "tester", func(error) { done.Add(1) }); err == nil || !strings.Contains(err.Error(), "常驻任务") {
		t.Fatalf("RunAsyncResult 应拒绝常驻任务，得到 err=%v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("常驻任务 Run 体不得经 RunAsync 执行，执行次数=%d", got)
	}
	if got := done.Load(); got != 0 {
		t.Fatalf("拒绝路径不得触发 onDone，回调次数=%d", got)
	}
	if got := countRuns(t, id); got != 0 {
		t.Fatalf("拒绝路径不得落 task_runs，got %d 行", got)
	}
}

// Given 超长单行（30 万字节中文错误串）。
// When 写入任务日志。
// Then 单行被截断到统一上限且保持合法 UTF-8（不得出现半个 rune）。
func TestTaskLogAppendTruncatesOversizedLine(t *testing.T) {
	dir := t.TempDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir("") })

	huge := strings.Repeat("错", 100_000) // 300KB
	taskLogAppend("t-long-line", huge)

	data, err := os.ReadFile(filepath.Join(dir, "t-long-line.log"))
	if err != nil {
		t.Fatalf("读取任务日志失败: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("期望单行写入，got %d 行", len(lines))
	}
	if len(lines[0]) > taskLogLineMaxBytes {
		t.Fatalf("单行未截断：%d 字节, 上限 %d", len(lines[0]), taskLogLineMaxBytes)
	}
	if !utf8.ValidString(lines[0]) {
		t.Fatal("截断落在 rune 中间：日志行不是合法 UTF-8")
	}
	if !strings.Contains(lines[0], "截断") {
		t.Fatalf("截断行缺少显式标记: %q", lines[0][:min(80, len(lines[0]))])
	}
}

// Given 阈值 16KiB 的任务日志 + 已有 1KiB 内容。
// When 写入 100KB 单行（截断后 ≤4KiB）。
// Then 滚动判定按截断后长度计算——不得因未截断的巨行先滚动再写出超限活动文件。
func TestTaskLogAppendOversizedLineDoesNotForceRotation(t *testing.T) {
	dir := t.TempDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir("") })
	SetTaskLogSizeBytesFn(func() int64 { return 16 * 1024 })
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })

	path := filepath.Join(dir, "t-long-rot.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 1024)), 0o644); err != nil {
		t.Fatal(err)
	}
	taskLogAppend("t-long-rot", strings.Repeat("x", 100_000))

	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("截断后 1KiB+≤4KiB 不应触发滚动，got err=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 16*1024 {
		t.Fatalf("活动文件超过配置阈值：%d 字节", info.Size())
	}
}
