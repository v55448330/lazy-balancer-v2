package services

// 采集周期里唯一未纳入状态转换日志的 DB 阈值读取（sync_interval → 节点离线
// 阈值）。此前失败分支每轮直接 Logf("warn")：30s 一轮的采集会把同一条 warn
// 刷成日志噪声，而恢复时零信号——与同函数另外三条 DB 派生指标（active-rules/
// total-rules/online-nodes）的口径相反。

import (
	"strings"
	"testing"
)

func TestRefreshDBOverviewMetrics_logsSyncIntervalReadFailureOnceAndRecovers(t *testing.T) {
	database := setupIsolatedDB(t)
	isolateMetricsState(t)
	ResetLogStateTransitionForTest("overview-count-sync-interval")
	out := captureLogf(t)
	service := NewMetricsService("", 30)

	if _, err := database.Exec("ALTER TABLE global_config RENAME TO global_config_bak"); err != nil {
		t.Fatalf("inject read failure: %v", err)
	}
	service.refreshDBOverviewMetrics()
	service.refreshDBOverviewMetrics()
	if got := strings.Count(out.String(), "sync_interval"); got != 1 {
		t.Fatalf("连续两轮读失败留痕次数=%d, want 1（状态转换去重）: %q", got, out.String())
	}

	if _, err := database.Exec("ALTER TABLE global_config_bak RENAME TO global_config"); err != nil {
		t.Fatalf("restore table: %v", err)
	}
	out.Reset()
	service.refreshDBOverviewMetrics()
	if !strings.Contains(out.String(), "读取 sync_interval 已恢复") {
		t.Fatalf("恢复后必须补一条恢复留痕: %q", out.String())
	}
	// 恢复轮不得再报失败（状态已复位，否则下一次真实故障会被去重吃掉）。
	if strings.Contains(out.String(), "读取 sync_interval 失败") {
		t.Fatalf("恢复轮仍报失败: %q", out.String())
	}
}
