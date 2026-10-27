package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/testsupport"
)

// 包级全局态泄漏守卫：suite 结束后，下列已登记 seam/采样缓存若未回到
// suite 入口快照，就说明某用例的写侧缺少清理（t.Cleanup 已全部执行）。
// 这不再只覆盖导入窗口，也覆盖系统指标与面板抓取的跨用例污染源。
//
// **本守卫的能力边界（必须知道）**：它只比较 suite **终态**。「某用例泄漏 →
// 后续用例顺手把它改回快照值」在固定声明序下判绿（实测：泄漏用例 + 修复用例在默认顺序下 EXIT=0，`-shuffle=2` 才红）。补偿
// 手段两层：
//  1. 写侧隔离：修改已登记 seam 的用例必须调用 withIsolatedGlobal(t)——它在
//     **本用例** cleanup 里立即断言，泄漏当场归因，不依赖后续用例是否修回；
//     「测试函数赋值已登记 seam 却不调用」由 TestHandlerGlobalSeamWritersUse-
//     IsolatedGlobal 静态门拦下（结构性，不靠记忆）。
//  2. 排列面：随机 seed 轮（scripts/test-shuffle.sh，FULL=1 / SHUFFLE_GATE_SEEDS）
//     能暴露该组合；固定 seed 下声明序任意但恒定，「泄漏→修复」永不暴露。
//     默认门禁暂不加随机轮——实测该包存在与本守卫无关的顺序依赖用例，需先单独
//     收敛（见 test-all.sh 同名注释），故当前唯一常开补偿是 1)。
func TestMain(m *testing.M) {
	// 环境护栏：TMPDIR 被沙箱回收时 t.TempDir() 会级联假红（见
	// internal/testsupport.EnsureUsableTempDir 的说明），先收敛成一条显式失败。
	if err := testsupport.EnsureUsableTempDir(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	baseline := captureHandlerGlobalState()
	code := m.Run()

	if code == 0 {
		leaks := handlerSuiteGlobalLeaks(baseline)
		if len(leaks) > 0 {
			fmt.Fprintln(os.Stderr, "全局态泄漏（用例写侧缺少清理）:")
			for _, leak := range leaks {
				fmt.Fprintln(os.Stderr, "  -", leak)
			}
			code = 1
		}
	}

	os.Exit(code)
}

// handlerSuiteGlobalLeaks 汇总「suite 终态 vs 入口快照」的全部泄漏面：
// 导入窗口计数、测试缝钩子与已登记全局态的差异。withIsolatedGlobal 复用同一
// 实现，保证单用例断言与 suite 断言口径一致（两套判据必然漂移）。
func handlerSuiteGlobalLeaks(baseline map[string]any) []string {
	leaks := make([]string, 0, 16)
	if v := importWindowActive.Load(); v != 0 {
		leaks = append(leaks, fmt.Sprintf("importWindowActive=%d（导入窗口未关闭）", v))
	}
	if configImportBeginAttemptHook != nil {
		leaks = append(leaks, "configImportBeginAttemptHook 未复位")
	}
	if configImportBeforePrelockHook != nil {
		leaks = append(leaks, "configImportBeforePrelockHook 未复位")
	}
	if importPostCommitCleanupHook != nil {
		leaks = append(leaks, "importPostCommitCleanupHook 未复位")
	}
	if txCommitForTest != nil {
		leaks = append(leaks, "txCommitForTest 未复位")
	}
	if txRollbackForTest != nil {
		leaks = append(leaks, "txRollbackForTest 未复位")
	}
	return append(leaks, handlerGlobalStateLeaks(baseline)...)
}

// withIsolatedGlobal 把全局态泄漏的判定边界从 suite 末尾收窄到**本用例**：
// 入口 seam 快照 → 用例体（含其自身的 t.Cleanup 复位）→ 本用例 cleanup 断言。
//
// 为什么必须在用例入口调用：cleanup 按注册逆序执行，先注册的断言后跑——因此
// 用例后续注册的复位钩子先于本断言执行，断言看到的是「复位之后」的状态。
//
// 为什么只比 seam：TTL 采样缓存在用例结束时仍热是合法形态（带窗口自愈，终态
// 一致性由 suite 级全量快照负责）；seam 未复位则必然是写侧漏了清理。
//
// 必须与 suite 终态守卫分开的理由：终态比较会被「后续用例把值改回快照」掩盖
// （声明序「泄漏→修复」判绿），而这里泄漏当场归因到真正写它的用例。
func withIsolatedGlobal(t *testing.T) {
	t.Helper()
	baseline := captureHandlerGlobalSeams()
	t.Cleanup(func() {
		if leaks := handlerSuiteGlobalLeaks(baseline); len(leaks) > 0 {
			t.Errorf("全局态泄漏（本用例写侧缺少清理）: %v", leaks)
		}
	})
}

func handlerGlobalPointer(value any) uintptr {
	if value == nil {
		return 0
	}
	reflected := reflect.ValueOf(value)
	if (reflected.Kind() == reflect.Func || reflected.Kind() == reflect.Pointer) && reflected.IsNil() {
		return 0
	}
	return reflected.Pointer()
}

// captureHandlerGlobalState 只保存可比较的快照值，不持有锁或可变 map 别名。
// 函数 seam 以代码指针对账；生产默认函数与测试替身的函数体不同，替换后
// 未恢复会确定性命中。
func captureHandlerGlobalState() map[string]any {
	state := captureHandlerGlobalSeams()

	diskUsageCache.Lock()
	state["diskUsageCache"] = []any{diskUsageCache.total, diskUsageCache.used, diskUsageCache.expiresAt, diskUsageCache.negativeUntil, diskUsageCache.negativeErr}
	diskUsageCache.Unlock()
	connectionStatsCache.Lock()
	state["connectionStatsCache"] = []any{connectionStatsCache.stats, connectionStatsCache.expiresAt, connectionStatsCache.negativeUntil, connectionStatsCache.negativeErr}
	connectionStatsCache.Unlock()
	lastCPUStats.mu.Lock()
	state["lastCPUStats"] = []any{lastCPUStats.snapshot, lastCPUStats.percent, lastCPUStats.sampledAt, lastCPUStats.hasValue}
	lastCPUStats.mu.Unlock()
	// lastNetStats 是带 1s 采样窗口的运行时缓存（非测试缝）：任何调用
	// getRealtimeTraffic 的用例都会留下基线，且下一次调用按窗口自愈。
	// 它不构成跨用例语义污染（与 diskUsageCache 同类缓存，后者由专门
	// reset helper 在断言速率的用例内复位），故不纳入泄漏断言。
	metricsDashboardState.Lock()
	state["metricsDashboardState"] = []any{metricsDashboardState.url, metricsDashboardState.outcome, metricsDashboardState.expiresAt, metricsDashboardState.valid}
	metricsDashboardState.Unlock()
	caddyMetricsSnapshots.Lock()
	entries := make(map[string]caddyMetricsSnapshot, len(caddyMetricsSnapshots.entries))
	for key, entry := range caddyMetricsSnapshots.entries {
		entries[key] = entry
	}
	state["caddyMetricsSnapshots"] = entries
	caddyMetricsSnapshots.Unlock()
	return state
}

// captureHandlerGlobalSeams 只取「测试可直接赋值」的 seam（函数指针 + 数值
// 旋钮），不含 TTL 采样缓存。用例级隔离（withIsolatedGlobal）用它作基线：
// 缓存的「用例结束时仍热」是合法形态（带窗口自愈，suite 级全量快照负责终态
// 一致性），而 seam 未复位必然是写侧漏了清理。
func captureHandlerGlobalSeams() map[string]any {
	return map[string]any{
		"systemMetricsReadFile":           handlerGlobalPointer(systemMetricsReadFile),
		"systemMetricsDFCommand":          handlerGlobalPointer(systemMetricsDFCommand),
		"netstatCommand":                  handlerGlobalPointer(netstatCommand),
		"metricsDashboardFetch":           handlerGlobalPointer(metricsDashboardFetch),
		"caddyMetricsHTTPClient":          handlerGlobalPointer(caddyMetricsHTTPClient),
		"systemMetricsCommandTimeout":     systemMetricsCommandTimeout,
		"systemSampleNegativeTTL":         systemSampleNegativeTTL,
		"cpuSampleWindow":                 cpuSampleWindow,
		"netSampleWindow":                 netSampleWindow,
		"metricsDashboardTTL":             metricsDashboardTTL,
		"metricsDashboardNegativeTTL":     metricsDashboardNegativeTTL,
		"caddyMetricsSnapshotTTL":         caddyMetricsSnapshotTTL,
		"caddyMetricsSnapshotNegativeTTL": caddyMetricsSnapshotNegativeTTL,
		"caddyMetricsFetchTimeout":        caddyMetricsFetchTimeout,
		// 提交后清理的预算检查缝：漏复位会让后续用例的产物清理在循环前即
		// 被当作「预算耗尽」跳过（文件/指标留残），故按 seam 指针判定泄漏。
		"importCleanupShouldStop": handlerGlobalPointer(importCleanupShouldStop),
	}
}

func handlerGlobalStateLeaks(baseline map[string]any) []string {
	current := captureHandlerGlobalState()
	leaks := make([]string, 0)
	for name, before := range baseline {
		if !reflect.DeepEqual(before, current[name]) {
			leaks = append(leaks, name+" 未复位")
		}
	}
	sort.Strings(leaks)
	return leaks
}

func assertHandlerGlobalStateLeak(t *testing.T, name string, mutate func()) {
	t.Helper()
	baseline := captureHandlerGlobalState()
	mutate()
	leaks := handlerGlobalStateLeaks(baseline)
	if !sort.StringsAreSorted(leaks) {
		t.Fatalf("leak names are not deterministic: %v", leaks)
	}
	for _, leak := range leaks {
		if leak == name+" 未复位" {
			return
		}
	}
	t.Fatalf("%s mutation not detected; leaks=%v", name, leaks)
}

func TestGlobalStateGuard_detectsMetricsSeamLeaks(t *testing.T) {
	t.Run("systemMetricsReadFile", func(t *testing.T) {
		old := systemMetricsReadFile
		t.Cleanup(func() { systemMetricsReadFile = old })
		assertHandlerGlobalStateLeak(t, "systemMetricsReadFile", func() {
			systemMetricsReadFile = func(string) ([]byte, error) { return nil, nil }
		})
	})
	t.Run("systemMetricsDFCommand", func(t *testing.T) {
		old := systemMetricsDFCommand
		t.Cleanup(func() { systemMetricsDFCommand = old })
		assertHandlerGlobalStateLeak(t, "systemMetricsDFCommand", func() { systemMetricsDFCommand = nil })
	})
	t.Run("netstatCommand", func(t *testing.T) {
		old := netstatCommand
		t.Cleanup(func() { netstatCommand = old })
		assertHandlerGlobalStateLeak(t, "netstatCommand", func() { netstatCommand = nil })
	})
	t.Run("metricsDashboardFetch", func(t *testing.T) {
		old := metricsDashboardFetch
		t.Cleanup(func() { metricsDashboardFetch = old })
		assertHandlerGlobalStateLeak(t, "metricsDashboardFetch", func() { metricsDashboardFetch = nil })
	})
	t.Run("systemMetricsCommandTimeout", func(t *testing.T) {
		old := systemMetricsCommandTimeout
		t.Cleanup(func() { systemMetricsCommandTimeout = old })
		assertHandlerGlobalStateLeak(t, "systemMetricsCommandTimeout", func() { systemMetricsCommandTimeout++ })
	})
	t.Run("lastCPUStats", func(t *testing.T) {
		resetCPUSampleStateForTest(t)
		assertHandlerGlobalStateLeak(t, "lastCPUStats", func() {
			lastCPUStats.mu.Lock()
			lastCPUStats.hasValue = true
			lastCPUStats.mu.Unlock()
		})
	})
	t.Run("diskUsageCache", func(t *testing.T) {
		resetDiskUsageCacheForTest(t)
		assertHandlerGlobalStateLeak(t, "diskUsageCache", func() {
			diskUsageCache.Lock()
			diskUsageCache.total++
			diskUsageCache.Unlock()
		})
	})
	t.Run("metricsDashboardState", func(t *testing.T) {
		resetMetricsDashboardCacheForTest()
		t.Cleanup(resetMetricsDashboardCacheForTest)
		assertHandlerGlobalStateLeak(t, "metricsDashboardState", func() {
			metricsDashboardState.Lock()
			metricsDashboardState.valid = true
			metricsDashboardState.Unlock()
		})
	})
}

// 静态门的 seam 名单必须与快照键集完全一致：名单漏登一个 seam，该 seam 的
// 测试写入就对静态门不可见（importCleanupShouldStop 曾因此长期逃逸）。
func TestHandlerRegisteredSeamNames_matchSnapshotKeys(t *testing.T) {
	seams := captureHandlerGlobalSeams()
	registered := make(map[string]bool, len(handlerRegisteredSeamNames))
	for _, name := range handlerRegisteredSeamNames {
		registered[name] = true
	}
	for name := range seams {
		if !registered[name] {
			t.Errorf("快照登记的 seam %s 不在静态门名单中（写侧隔离门对它不可见）", name)
		}
	}
	if len(registered) != len(seams) {
		t.Errorf("静态门名单 %d 项, 快照 %d 项（名单含过期条目）", len(registered), len(seams))
	}
	if !sort.StringsAreSorted(handlerRegisteredSeamNames) {
		t.Error("名单必须排序（派生确定性与报错可读性）")
	}
}

// handlerRegisteredSeamNames 是 captureHandlerGlobalState 登记的**可直接赋值**
// 的 seam（函数与数值旋钮）。缓存结构体经锁写、由各自的 reset helper 复位，
// 不在此列（它们的泄漏同样由快照比较覆盖）。
//
// 名单由 captureHandlerGlobalSeams 的键集**派生**（单源），不得手抄：手工维护
// 的第二份名单曾漏登 importCleanupShouldStop，静态门因此对该 seam 的写入完全
// 不可见（现存用例直接赋值 + t.Cleanup 复位，未经 withIsolatedGlobal 也判绿）。
var handlerRegisteredSeamNames = func() []string {
	seams := captureHandlerGlobalSeams()
	names := make([]string, 0, len(seams))
	for name := range seams {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}()

// globalStateGuardSelfTestFile 是守卫自身的自测文件：「故意泄漏 → 立即断言 →
// 同一闭包内复位」是本文件的被测形态，不能反过来要求它使用写侧隔离 helper。
const globalStateGuardSelfTestFile = "global_state_guard_test.go"

// TestHandlerGlobalSeamWritersUseIsolatedGlobal 是「写侧隔离」的静态门：
// 任何测试函数体给已登记 seam 赋值，就必须调用 withIsolatedGlobal(t)。
//
// 为什么需要机器门：suite 终态守卫会被「后续用例把值改回」掩盖（声明序
// 「泄漏→修复」判绿，见 TestMain 的边界说明）。纪律写在注释里靠记忆，写在这里
// 靠编译后的测试失败——新增用例忘记隔离时这门立即红。
func TestHandlerGlobalSeamWritersUseIsolatedGlobal(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	seams := make(map[string]struct{}, len(handlerRegisteredSeamNames))
	for _, name := range handlerRegisteredSeamNames {
		seams[name] = struct{}{}
	}
	fset := token.NewFileSet()
	offenders := make([]string, 0)
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") || name == globalStateGuardSelfTestFile {
			continue
		}
		file, parseErr := parser.ParseFile(fset, name, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			scanned++
			// 只看本函数体内的赋值（含闭包）：子测试/夹具闭包同样算写侧。
			assignsSeam := false
			hasIsolation := false
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.AssignStmt:
					for _, lhs := range typed.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							if _, registered := seams[ident.Name]; registered {
								assignsSeam = true
							}
						}
					}
				case *ast.CallExpr:
					switch fun := typed.Fun.(type) {
					case *ast.Ident:
						if fun.Name == "withIsolatedGlobal" {
							hasIsolation = true
						}
					case *ast.SelectorExpr:
						_ = fun
					}
				}
				return true
			})
			if assignsSeam && !hasIsolation {
				offenders = append(offenders, fmt.Sprintf("%s: %s", name, fn.Name.Name))
			}
		}
	}
	// 扫描面退化保护：解析不到任何测试函数时本门会静默通过。
	if scanned == 0 {
		t.Fatal("未扫描到任何测试函数——门禁扫描面为空（目录/后缀解析漂移）")
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("以下测试函数改写已登记全局 seam 但未调用 withIsolatedGlobal(t)（泄漏无法归因到本用例）:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
