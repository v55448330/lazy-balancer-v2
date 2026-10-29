package main

// 关停预算与信号注册窗口钉测试：
//   - 关停总预算超出 compose stop_grace_period（HTTP≤10s + drainCaddy≤2s
//     + engine.Stop 30s + StopACME 无界 <-done）。Go 侧单一预算 + 各段派生，
//     最坏路径必须 ≤ grace；StopACME 的 <-done 必须有界。
//   - signal.Notify 注册晚于 BootSync——启动窗口内 SIGTERM 走默认动作
//     立即退出。注册前置后，窗口内到达的信号必须在监听前被识别并走正常关停。

import (
	"bytes"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// composeStopGracePeriod 直读 docker-compose.yml 的 stop_grace_period（单一
// 数据源——此前测试硬编码 30s 常量与 compose 双写易漂移）。取全部
// 服务的最小值（任一服务 grace 收紧都必须反映到预算校验）。
// 注意：本函数的覆盖面只有 compose 形态；README 的 docker run 形态（Docker
// 默认 10s 停止宽限，需显式 --stop-timeout）由 stop_timeout_docs_test.go 单独
// 对账——不要因为本门为绿就认为所有文档化部署形态都覆盖到了。
func composeStopGracePeriod(t *testing.T) time.Duration {
	t.Helper()
	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	matches := regexp.MustCompile(`(?m)^\s*stop_grace_period:\s*(\S+)\s*$`).FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatal("docker-compose.yml 未声明 stop_grace_period")
	}
	grace := time.Duration(0)
	for _, m := range matches {
		d, err := time.ParseDuration(m[1])
		if err != nil {
			t.Fatalf("parse stop_grace_period %q: %v", m[1], err)
		}
		if grace == 0 || d < grace {
			grace = d
		}
	}
	return grace
}

func TestShutdownWorkerStopSharesSingleBudget(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	b := &shutdownBudget{now: func() time.Time { return now }}
	workerStop := newSharedShutdownSegment(b, threatWarmerStopSegmentMax, trailingStopReserve)
	watcher := workerStop()
	now = now.Add(watcher)
	warmer := workerStop()
	now = now.Add(warmer)
	if watcher != threatWarmerStopSegmentMax || warmer != 0 {
		t.Fatalf("watcher=%s warmer=%s, want one shared 2s segment", watcher, warmer)
	}
}

func TestShutdownTrailingReserveMatchesProductionOrder(t *testing.T) {
	want := metricsStopSegmentMax + tzStopSegmentMax + logRotateStopSegmentMax + acmeStopSegmentMax
	if trailingStopReserve != want {
		t.Fatalf("trailing reserve=%s, want %s；IPC 在引擎前排空，不得重复计入后续预留", trailingStopReserve, want)
	}
}

// Given 关停预算（fake clock）。
// When 按真实调用顺序消耗各段（HTTP → Caddy 排水 → watcher/warmer 共享等待 →
// 安全事件 IPC → 引擎排空 → 引擎句柄清理 → metrics 清理等待 →
// metrics/时区/日志轮转等待 → ACME 收尾）。
// Then 各段钳制正确、总和 ≤ processShutdownBudget（且 < compose grace），
// 且 ACME 段必须 > 0——三处不可预算的同步收尾（warmer/引擎句柄/metrics
// 清理）只允许花未用完的预算，不得把收尾段预留挤成 0。
func TestShutdownBudgetWorstCaseFitsComposeGrace(t *testing.T) {
	composeGrace := composeStopGracePeriod(t)
	if processShutdownBudget >= composeGrace {
		t.Fatalf("关停总预算 %s 必须小于 compose stop_grace_period %s", processShutdownBudget, composeGrace)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	b := &shutdownBudget{now: func() time.Time { return now }}

	httpSeg := b.segment(httpShutdownSegmentMax)
	now = now.Add(httpSeg)
	caddySeg := b.segment(caddyDrainSegmentMax)
	now = now.Add(caddySeg)
	workerSeg := b.segmentReserving(threatWarmerStopSegmentMax, trailingStopReserve)
	now = now.Add(workerSeg)
	ipcSeg := b.segment(ipcStopSegmentMax)
	now = now.Add(ipcSeg)
	engineSeg := b.engineDrain()
	now = now.Add(engineSeg)
	engineHandleStopSeg := b.segmentReserving(engineHandleStopSegmentMax, trailingStopReserve)
	now = now.Add(engineHandleStopSeg)
	metricsCleanupSeg := b.segmentReserving(metricsCleanupSegmentMax, trailingStopReserve)
	now = now.Add(metricsCleanupSeg)
	metricsSeg := b.segment(metricsStopSegmentMax)
	now = now.Add(metricsSeg)
	tzSeg := b.segment(tzStopSegmentMax)
	now = now.Add(tzSeg)
	logRotateSeg := b.segment(logRotateStopSegmentMax)
	now = now.Add(logRotateSeg)
	acmeSeg := b.segment(acmeStopSegmentMax)
	now = now.Add(acmeSeg)

	if httpSeg != httpShutdownSegmentMax {
		t.Fatalf("HTTP 段=%s, want %s（预算充足时必须用满段上限）", httpSeg, httpShutdownSegmentMax)
	}
	if caddySeg != caddyDrainSegmentMax {
		t.Fatalf("Caddy 排水段=%s, want %s", caddySeg, caddyDrainSegmentMax)
	}
	if workerSeg != threatWarmerStopSegmentMax {
		t.Fatalf("watcher/warmer 共享等待段=%s, want %s", workerSeg, threatWarmerStopSegmentMax)
	}
	// 引擎排空在共享 worker 等待与 IPC 用满后仍须为真正的后续段预留。
	wantEngine := processShutdownBudget - httpShutdownSegmentMax - caddyDrainSegmentMax - threatWarmerStopSegmentMax - ipcStopSegmentMax - trailingStopReserve
	if engineSeg != wantEngine {
		t.Fatalf("引擎排空=剩余−收尾段预留=%s, got %s", wantEngine, engineSeg)
	}
	if ipcSeg != ipcStopSegmentMax {
		t.Fatalf("安全事件 IPC 关停段=%s, want %s", ipcSeg, ipcStopSegmentMax)
	}
	// 最坏路径下引擎已吃满排空段：后两处不可预算等待只能拿到 0（不得侵占预留）。
	if engineHandleStopSeg != 0 {
		t.Fatalf("引擎句柄清理等待段=%s, want 0（不得侵占收尾段预留）", engineHandleStopSeg)
	}
	if metricsCleanupSeg != 0 {
		t.Fatalf("metrics 清理等待段=%s, want 0（不得侵占收尾段预留）", metricsCleanupSeg)
	}
	if metricsSeg != metricsStopSegmentMax {
		t.Fatalf("metrics 等待段=%s, want %s", metricsSeg, metricsStopSegmentMax)
	}
	if tzSeg != tzStopSegmentMax {
		t.Fatalf("时区刷新等待段=%s, want %s", tzSeg, tzStopSegmentMax)
	}
	if logRotateSeg != logRotateStopSegmentMax {
		t.Fatalf("日志轮转等待段=%s, want %s", logRotateSeg, logRotateStopSegmentMax)
	}
	if acmeSeg != acmeStopSegmentMax {
		t.Fatalf("ACME 段=%s, want %s（收尾段预留不得被前方等待挤成 0）", acmeSeg, acmeStopSegmentMax)
	}
	total := httpSeg + caddySeg + workerSeg + ipcSeg + engineSeg + engineHandleStopSeg + metricsCleanupSeg + metricsSeg + tzSeg + logRotateSeg + acmeSeg
	if total > processShutdownBudget {
		t.Fatalf("最坏路径总和 %s 超出总预算 %s", total, processShutdownBudget)
	}
	if total >= composeGrace {
		t.Fatalf("最坏路径总和 %s 不得达到 compose grace %s（须留退出余量）", total, composeGrace)
	}

	// 引擎排空提前结束（生产常态）：剩余预算充裕，两处固定等待可用满自身上限。
	b = &shutdownBudget{now: func() time.Time { return now }}
	now = now.Add(httpShutdownSegmentMax)
	now = now.Add(b.segmentReserving(threatWarmerStopSegmentMax, trailingStopReserve))
	now = now.Add(b.segment(ipcStopSegmentMax))
	if got := b.segmentReserving(engineHandleStopSegmentMax, trailingStopReserve); got != engineHandleStopSegmentMax {
		t.Fatalf("预算充裕时引擎句柄清理等待段=%s, want %s", got, engineHandleStopSegmentMax)
	}
	now = now.Add(engineHandleStopSegmentMax)
	if got := b.segmentReserving(metricsCleanupSegmentMax, trailingStopReserve); got != metricsCleanupSegmentMax {
		t.Fatalf("预算充裕时 metrics 清理等待段=%s, want %s", got, metricsCleanupSegmentMax)
	}
	now = now.Add(metricsCleanupSegmentMax)

	// 预算耗尽：各段归零，引擎排空不得回落引擎默认 30s（0 会被引擎当作未指定）。
	exhaustedNow := now.Add(processShutdownBudget)
	exhausted := &shutdownBudget{now: func() time.Time { return exhaustedNow }, deadline: exhaustedNow.Add(-time.Second)}
	if got := exhausted.segment(caddyDrainSegmentMax); got != 0 {
		t.Fatalf("预算耗尽后段上限=%s, want 0", got)
	}
	if got := exhausted.segmentReserving(engineHandleStopSegmentMax, trailingStopReserve); got != 0 {
		t.Fatalf("预算耗尽后不可预算等待段=%s, want 0（调用方须跳过等待）", got)
	}
	if got := exhausted.engineDrain(); got <= 0 || got > time.Millisecond {
		t.Fatalf("预算耗尽后引擎排空=%s, want 极小正值（1ms 语义）", got)
	}
}

// Given 引擎有一个不消费取消信号的在途 Run（生产形态：长跑清理任务）。
// When stopTaskEngineWithin 在预算剩余 < ACME 预留时调用。
// Then 立即放弃等待（不得回落 Stop 的 30s 默认），并清除全局引擎句柄。
func TestStopTaskEngineWithinBoundedByRemainingBudget(t *testing.T) {
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	services.SetTaskEngineForTest(te)
	release := make(chan struct{})
	started := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		services.StopTaskEngine()
	})
	if err := te.Register(taskengine.Descriptor{
		ID: "t-shutdown-block", Family: "t", Name: "关停阻塞",
		Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(rc taskengine.RunContext) error {
			close(started)
			<-release // 故意不消费 rc.Ctx（等价于不响应取消的清理任务）
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := te.RunAsync("t-shutdown-block", "manual", ""); err != nil {
		t.Fatalf("RunAsync: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("任务未启动")
	}

	b := &shutdownBudget{now: time.Now, deadline: time.Now().Add(30 * time.Millisecond)}
	begin := time.Now()
	stopTaskEngineWithin(b)
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("引擎排空未受关停预算约束：耗时 %s（预算仅 30ms）", elapsed)
	}
	if services.TaskEngine() != nil {
		t.Fatal("stopTaskEngineWithin 必须清除全局引擎句柄")
	}
}

// Given 证书 worker 停止后不退出（Start 阻塞）。
// When ShutdownWithTimeout 以 50ms 上限调用。
// Then 有界返回并记录 error 日志（不再无界 <-done）。
func TestRuntimeLifecycle_ShutdownWithTimeoutBoundsStuckWorker(t *testing.T) {
	worker := newLifecycleWorkerFake(fakeStartBlocksOnRelease, fakeStopImmediate)
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker { return worker })
	lifecycle.StartACME()
	select {
	case <-worker.started:
	case <-time.After(2 * time.Second):
		t.Fatal("证书 worker 未启动")
	}
	t.Cleanup(worker.releaseNow)

	oldOutput := log.Writer()
	var buf strings.Builder
	log.SetOutput(&buf)
	oldLevel := services.CurrentLogLevel()
	if err := services.ConfigureLogLevel("info"); err != nil {
		t.Fatalf("configure log level: %v", err)
	}
	t.Cleanup(func() {
		log.SetOutput(oldOutput)
		_ = services.ConfigureLogLevel(oldLevel)
	})

	begin := time.Now()
	lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("ShutdownWithTimeout 无界等待 worker 退出：耗时 %s", elapsed)
	}
	if !strings.Contains(buf.String(), "证书服务停止等待超时") {
		t.Fatalf("超时路径缺少 error 日志: %q", buf.String())
	}
	// 幂等：再次 Shutdown 不重复报告（stopped 门）。
	before := buf.Len()
	lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	if buf.Len() != before {
		t.Fatal("第二次 Shutdown 不得重复记录超时日志")
	}
}

// Given 一个永不关闭的通道（可控挂起的 metrics 采集循环形态——collect 阻塞
// 在 http.Client 10s / DB busy_timeout 30s 时 <-metricsDone 的旧形态）。
// When awaitChannelWithin 以 50ms 上限等待。
// Then 按预算放弃等待返回 false；预算耗尽（d<=0）立即放弃不阻塞。
func TestAwaitChannelWithin_givesUpWhenNeverClosed(t *testing.T) {
	never := make(chan struct{})
	begin := time.Now()
	if awaitChannelWithin("测试 worker", never, 50*time.Millisecond) {
		t.Fatal("通道未关闭必须返回 false（放弃等待）")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("等待未受预算约束：耗时 %s（预算 50ms）", elapsed)
	}
	if awaitChannelWithin("测试 worker", never, 0) {
		t.Fatal("预算耗尽必须立即放弃等待")
	}
}

// Given 已关闭的通道（worker 正常退出形态）。
// When awaitChannelWithin 以充裕预算等待。
// Then 立即返回 true——正常路径不等满预算。
func TestAwaitChannelWithin_fastPathWhenClosed(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	begin := time.Now()
	if !awaitChannelWithin("测试 worker", closed, time.Hour) {
		t.Fatal("通道已关闭必须返回 true")
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("正常路径耗时 %s，不得空等预算", elapsed)
	}
}

// Given 启动窗口内到达并缓存在 quit 通道的 SIGTERM。
// When 监听前检查 takePendingSignal。
// Then 识别为已收到信号（走正常关停而非默认终止）。
func TestTakePendingSignal(t *testing.T) {
	quit := make(chan os.Signal, 1)
	if takePendingSignal(quit) {
		t.Fatal("空通道不得报告已收到信号")
	}
	quit <- syscall.SIGTERM
	if !takePendingSignal(quit) {
		t.Fatal("启动窗口内缓存 SIGTERM 未被识别")
	}
	if takePendingSignal(quit) {
		t.Fatal("信号已被消费，不得重复报告")
	}
}

// Given 启动窗口内 SIGTERM 已入 quit 缓冲、监听尚未开始。
// When waitForServerStop 进入等待。
// Then 立即消费该信号并完成正常关停（不等待第二个信号、不阻塞）。
func TestWaitForServerStopConsumesSignalBufferedDuringStartup(t *testing.T) {
	server := newAdminHTTPServer("127.0.0.1:0", nil)
	quit := make(chan os.Signal, 1)
	quit <- syscall.SIGTERM
	restart, _ := newRestartSignal()
	serverErrors := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		err = waitForServerStop(server, serverStopSignals{
			quit: quit, restart: restart, serverErrors: serverErrors,
			caddyAdminURL: "", budget: newShutdownBudget(),
		})
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("启动窗口内缓存的 SIGTERM 未被消费为关停（仍卡在等待）")
	}
	if err != nil {
		t.Fatalf("waitForServerStop: %v", err)
	}
	if got := len(quit); got != 0 {
		t.Fatalf("信号通道未消费干净：残留 %d", got)
	}
}

// runWithin 是关停期「不可预算调用按预算有界执行」的唯一入口（metrics 清理
// 等待段）。四种形状：预算充足且 fn 立即返回、fn 卡住超时放弃、预算已耗尽
// 完全不执行 fn、fn 在后台完成后不影响返回值。
func TestRunWithin_shapes(t *testing.T) {
	t.Run("预算充足时执行并等待完成", func(t *testing.T) {
		ran := make(chan struct{})
		if ok := runWithin("测试收尾", time.Second, func() { close(ran) }); !ok {
			t.Fatal("预算充足且 fn 立即返回时必须报告已完成")
		}
		select {
		case <-ran:
		default:
			t.Fatal("fn 未被调用")
		}
	})

	t.Run("fn 卡住时按预算放弃", func(t *testing.T) {
		var logs bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(previous) })
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })

		started := time.Now()
		if ok := runWithin("卡住的收尾", 20*time.Millisecond, func() { <-block }); ok {
			t.Fatal("fn 卡住时不得报告已完成")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("等待 %s，远超 20ms 预算", elapsed)
		}
		if !strings.Contains(logs.String(), "卡住的收尾") {
			t.Fatalf("超时必须留痕，got %q", logs.String())
		}
	})

	t.Run("预算耗尽时不执行 fn", func(t *testing.T) {
		var logs bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(previous) })
		called := false
		if ok := runWithin("跳过段", 0, func() { called = true }); ok {
			t.Fatal("预算耗尽必须返回 false")
		}
		if called {
			t.Fatal("预算耗尽不得启动收尾 goroutine")
		}
		if !strings.Contains(logs.String(), "跳过等待") {
			t.Fatalf("跳过必须留痕，got %q", logs.String())
		}
	})

	t.Run("负预算与零预算同语义", func(t *testing.T) {
		if ok := runWithin("负预算", -time.Second, func() {}); ok {
			t.Fatal("负预算必须按耗尽处理")
		}
	})
}
