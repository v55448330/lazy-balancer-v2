package handlers

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
)

// 包级全局态泄漏守卫：suite 结束后，下列已登记 seam/采样缓存若未回到
// suite 入口快照，就说明某用例的写侧缺少清理（t.Cleanup 已全部执行）。
// 这不再只覆盖导入窗口，也覆盖系统指标与面板抓取的跨用例污染源。
func TestMain(m *testing.M) {
	baseline := captureHandlerGlobalState()
	code := m.Run()

	if code == 0 {
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
		leaks = append(leaks, handlerGlobalStateLeaks(baseline)...)
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
	state := map[string]any{
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
	}

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
