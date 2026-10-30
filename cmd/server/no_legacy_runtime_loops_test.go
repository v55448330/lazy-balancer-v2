package main

// 运行期生命周期 daemon 归口（task-engine 标准 v2.2 §6.5）的接线守卫：
// main.go 不得再残留任何已归口循环的启动/停止接线——生命周期 daemon 的
// 唯一启动通道是 registerRuntimeLifecycleTasks（InitTaskEngine 装配期调用），
// 停止统一走引擎排空（stopTaskEngineWithin）。守卫 grep 源码而非运行时行为
// ——接线一旦回归（如恢复 metricsService.Start()），本门即红。

import (
	"os"
	"strings"
	"testing"
)

func TestMainGo_hasNoRetiredRuntimeLoopWiring(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)
	for _, pattern := range []string{
		"StartCaddyRestartWatcher",     // caddy-restart-watcher daemon
		"StopCaddyRestartWatcher",      // （停止归引擎排空）
		"StartThreatRollupWarmer",      // threat-rollup-warmer daemon
		"WaitThreatRollupWarmer",       // （在途排空归 RunTicker 同步契约）
		"metricsService.Start()",       // metrics-collector daemon
		"metricsService.Stop",          // （停止归引擎排空）
		"services.StartLogRotate",      // runtime-log-threshold daemon
		"services.StopLogRotate",       // （同上）
		"StartTimezoneRefresh",         // runtime-tz-refresh daemon
		"services.StopTimezoneRefresh", // （同上）
		"startLoginRateLimitCleanup",   // ratelimit-bucket-sweep daemon
		"startAPIKeyLastUsedFlusher",   // apikey-usage-flusher daemon
		"stopAPIKeyLastUsedFlusher",    // （同上）
	} {
		if strings.Contains(src, pattern) {
			t.Fatalf("main.go 残留已归口循环的接线 %q（生命周期归任务引擎，见 taskengine_wire_runtime.go）", pattern)
		}
	}
}
