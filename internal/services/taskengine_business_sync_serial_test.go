package services

// 业务驱动调度对齐的两条收敛契约：
//  ① 对齐整轮必须串行——pending 是「本次全量遍历」的结论，并发调用交错时
//     后写的 Store 会覆盖前者（一次全部读成功的遍历可以清掉另一方「某驱动
//     读失败」置位的重试标记，该驱动的调度态从此停在旧值）。
//  ② 读失败必须留痕——autoban 开关读不出来时与「用户关闭」在调度面同形
//     （零执行、零失败行、零日志），排障无从区分库故障与用户选择。

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// replaceBusinessTaskDrivers 用可控驱动清单替换生产清单（测试结束恢复）。
func replaceBusinessTaskDrivers(t *testing.T, drivers []businessTaskDriver) {
	t.Helper()
	previous := businessTaskDrivers
	businessTaskDrivers = drivers
	t.Cleanup(func() {
		businessTaskDrivers = previous
		businessDriverSyncPending.Store(false)
	})
}

// Given 八个并发调用方同时对齐驱动调度（导入提交 + 对账重试同刻）。
// When 各次遍历交错执行。
// Then 任一时刻最多一个遍历在驱动集内推进（整轮串行），全部读成功后 pending
// 清零——覆盖写不再可能丢失待重试标记。
func TestSyncBusinessTaskDrivers_serializesConcurrentPasses(t *testing.T) {
	var inside, maxInside atomic.Int32
	replaceBusinessTaskDrivers(t, []businessTaskDriver{
		{id: "t-probe", stateFn: func() (bool, bool) {
			n := inside.Add(1)
			for {
				cur := maxInside.Load()
				if n <= cur || maxInside.CompareAndSwap(cur, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			inside.Add(-1)
			return false, true
		}},
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SyncBusinessTaskDrivers()
		}()
	}
	wg.Wait()

	if got := maxInside.Load(); got != 1 {
		t.Fatalf("并发进入对齐的最大遍历数=%d, want 1（整轮必须串行，否则 pending 覆盖写会丢重试标记）", got)
	}
	if businessDriverSyncPending.Load() {
		t.Fatal("全部读成功时应清除重试标记")
	}
}

// Given 一次遍历中驱动读失败。When 登记重试后读恢复再对齐一次。
// Then pending 先置位（周期对账会重试）后清除（读恢复即收敛）。
func TestSyncBusinessTaskDrivers_pendingFollowsLastCompletedPass(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	replaceBusinessTaskDrivers(t, []businessTaskDriver{
		{id: "t-flaky", stateFn: func() (bool, bool) {
			if fail.Load() {
				return false, false
			}
			return true, true
		}},
	})

	SyncBusinessTaskDrivers()
	if !businessDriverSyncPending.Load() {
		t.Fatal("读失败必须登记重试（否则一次读失败被固化为调度关闭）")
	}

	fail.Store(false)
	SyncBusinessTaskDrivers()
	if businessDriverSyncPending.Load() {
		t.Fatal("读恢复后的完整对齐必须清除重试标记")
	}
}

// Given 业务驱动整轮对齐持有 businessDriverSyncMu（正在读实态）。
// When 业务开关 setter 的应用段执行。
// Then 必须等待互斥——否则交错后对齐会用旧态覆盖新态，留下「库已新、loop
// 仍旧」且 pending=false（无重试纠正）的持久错态；释放互斥后 setter 立即生效。
func TestBusinessTaskLoopSetterWaitsForDriverSync(t *testing.T) {
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(te.Stop)
	te.Register(taskengine.Descriptor{ID: "threat", Family: "security", Name: "威胁情报库更新",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleAny,
		NextSlotFn: func() time.Time { return time.Time{} },
		Run:        func(taskengine.RunContext) error { return nil }})
	previous := TaskEngine()
	SetTaskEngineForTest(te)
	t.Cleanup(func() { SetTaskEngineForTest(previous) })

	businessDriverSyncMu.Lock()
	applied := make(chan struct{})
	go func() {
		applyBusinessTaskLoop("threat", true)
		close(applied)
	}()
	select {
	case <-applied:
		businessDriverSyncMu.Unlock()
		t.Fatal("setter 的应用段未等待 businessDriverSyncMu：与整轮对齐交错会写回旧态")
	case <-time.After(100 * time.Millisecond):
	}
	if m, ok := te.Lookup("threat"); !ok || m.LoopOn {
		businessDriverSyncMu.Unlock()
		t.Fatalf("互斥持有期间调度开关不得被应用: ok=%v loopOn=%v", ok, m.LoopOn)
	}
	businessDriverSyncMu.Unlock()
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("释放互斥后 setter 未完成调度应用")
	}
	if m, ok := te.Lookup("threat"); !ok || !m.LoopOn {
		t.Fatalf("setter 的调度开关未生效: ok=%v loopOn=%v", ok, m.LoopOn)
	}
}

// Given autoban 开关列读不出来。When 反复求值三态读取。
// Then 不可判定（known=false）且首报一条 warn（不刷屏）；读恢复后补一条 info。
func TestAutobanEnabledState_readFailureLeavesWarnTrace(t *testing.T) {
	newClusterTestService(t)
	isolateMetricsState(t)
	buf := captureLogf(t)

	restore := injectScheduleReadFailure(t, "global_config", "autoban_enabled")
	if enabled, known := autobanEnabledState(); enabled || known {
		t.Fatalf("autobanEnabledState=(%v,%v), want (false,false)（读失败必须不可判定）", enabled, known)
	}
	if AutobanEnabled() {
		t.Fatal("读失败时调度面必须 fail-closed")
	}
	_, _ = autobanEnabledState()
	if got := strings.Count(buf.String(), "schedule-read-autoban-enabled"); got != 1 {
		t.Fatalf("读失败留痕次数=%d, want 1（首报 warn、恢复 info，不得每轮刷屏）\n%s", got, buf.String())
	}

	restore()
	if _, known := autobanEnabledState(); !known {
		t.Fatal("读恢复后必须可判定")
	}
	if got := strings.Count(buf.String(), "读取任务排程已恢复（schedule-read-autoban-enabled）"); got != 1 {
		t.Fatalf("恢复留痕次数=%d, want 1\n%s", got, buf.String())
	}
}

// newBusinessLoopTestEngine 装配只含一个调度任务的引擎并设为全局（测试结束
// 恢复），供调度应用断言直接读 LoopOn。
func newBusinessLoopTestEngine(t *testing.T, id string) *taskengine.Engine {
	t.Helper()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(te.Stop)
	te.Register(taskengine.Descriptor{ID: id, Family: "security", Name: id,
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleAny,
		NextSlotFn: func() time.Time { return time.Time{} },
		Run:        func(taskengine.RunContext) error { return nil }})
	previous := TaskEngine()
	SetTaskEngineForTest(te)
	t.Cleanup(func() { SetTaskEngineForTest(previous) })
	return te
}

// Given 库实态与 setter 入参相反（两个相反方向的开关请求提交顺序与应用顺序
// 交错后的形态）。When 应用段进锁。
// Then 应用结果恒等于锁内读到的库实态——按调用方参数应用会让最后一次应用落在
// 过期意图上，留下「库=开 / loop=关」的持久错态（Scheduled 零投递，且两端读数
// 都成功、60s 对账不纠正）。
func TestBusinessTaskLoopAppliesDatabaseStateOverCallerArg(t *testing.T) {
	te := newBusinessLoopTestEngine(t, "threat")

	// 库=关、调用方参数=开：库为准。
	replaceBusinessTaskDrivers(t, []businessTaskDriver{
		{id: "threat", stateFn: func() (bool, bool) { return false, true }},
	})
	applyBusinessTaskLoop("threat", true)
	if info, ok := te.Lookup("threat"); !ok || info.LoopOn {
		t.Fatalf("库=关时 loopOn=%v（ok=%v）, want false（应用值必须取锁内库实态，不得用调用方入参）", info.LoopOn, ok)
	}

	// 库=开、调用方参数=关：反方向同样以库为准。
	replaceBusinessTaskDrivers(t, []businessTaskDriver{
		{id: "threat", stateFn: func() (bool, bool) { return true, true }},
	})
	applyBusinessTaskLoop("threat", false)
	if info, ok := te.Lookup("threat"); !ok || !info.LoopOn {
		t.Fatalf("库=开时 loopOn=%v（ok=%v）, want true", info.LoopOn, ok)
	}
}

// Given 驱动实态不可判定（提交后紧接着读库失败）。When 应用段执行。
// Then 按调用方刚提交的值应用（该值就是本次提交的意图，且已落库）——若保持
// 旧态不动，库=开/loop=关 的静默停摆将无路径恢复。
func TestBusinessTaskLoopFallsBackToSetterIntentWhenStateUnknown(t *testing.T) {
	te := newBusinessLoopTestEngine(t, "threat")
	replaceBusinessTaskDrivers(t, []businessTaskDriver{
		{id: "threat", stateFn: func() (bool, bool) { return false, false }},
	})
	applyBusinessTaskLoop("threat", true)
	if info, ok := te.Lookup("threat"); !ok || !info.LoopOn {
		t.Fatalf("读库不可判定时必须按调用方提交值应用: loopOn=%v（ok=%v）", info.LoopOn, ok)
	}
}

func TestBusinessTaskLoopUnknownState_retriesUntilDatabaseConverges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fallback  bool
		recovered bool
	}{
		{name: "stale_enable_then_database_disable", fallback: true, recovered: false},
		{name: "stale_disable_then_database_enable", fallback: false, recovered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newBusinessLoopTestEngine(t, "threat")
			known := false
			replaceBusinessTaskDrivers(t, []businessTaskDriver{
				{id: "threat", stateFn: func() (bool, bool) {
					if !known {
						return false, false
					}
					return tc.recovered, true
				}},
			})

			applyBusinessTaskLoop("threat", tc.fallback)
			if info, ok := te.Lookup("threat"); !ok || info.LoopOn != tc.fallback {
				t.Fatalf("immediate fallback loopOn=%v (ok=%v), want %v", info.LoopOn, ok, tc.fallback)
			}
			if !businessDriverSyncPending.Load() {
				t.Fatal("setter read failure must register a reconciliation retry")
			}

			retryPendingBusinessTaskDrivers()
			if info, _ := te.Lookup("threat"); info.LoopOn != tc.fallback {
				t.Fatalf("persistent read failure changed fallback loopOn=%v, want %v", info.LoopOn, tc.fallback)
			}
			if !businessDriverSyncPending.Load() {
				t.Fatal("persistent read failure must keep the retry pending")
			}

			known = true
			retryPendingBusinessTaskDrivers()
			if info, _ := te.Lookup("threat"); info.LoopOn != tc.recovered {
				t.Fatalf("recovered database loopOn=%v, want %v", info.LoopOn, tc.recovered)
			}
			if businessDriverSyncPending.Load() {
				t.Fatal("successful reconciliation must clear the retry marker")
			}
		})
	}
}
