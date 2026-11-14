package services

// 任务日志阈值库值 <=0（带外改库/半迁移形态）与读失败同口径 fail-visible：
// 回退默认当轮生效，但必须含库值留痕——静默回落让「面板配置形同虚设」零信号
// （与审计侧 getAuditLogSizeBytesContext 同源）。

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestGetTaskLogSizeBytes_nonPositiveStoredValueFailVisible(t *testing.T) {
	initServicesDB(t)
	t.Cleanup(InvalidateTaskLogSizeCache)
	isolateMetricsState(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET task_log_size_mb=-3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	InvalidateTaskLogSizeCache()
	out := captureLogf(t)

	if got := getTaskLogSizeBytes(context.Background()); got != 10<<20 {
		t.Fatalf("库值 -3 回退=%d, want 10MB", got)
	}
	if !strings.Contains(out.String(), "-3") || !strings.Contains(out.String(), "WARNING") {
		t.Fatalf("log=%q, want 含库值的 warn 留痕（禁止静默回落）", out.String())
	}

	// 状态转换去重：持续同态不得重复留痕。
	InvalidateTaskLogSizeCache()
	out.Reset()
	if got := getTaskLogSizeBytes(context.Background()); got != 10<<20 {
		t.Fatalf("二次读取=%d, want 10MB", got)
	}
	if out.Len() != 0 {
		t.Fatalf("持续同态读取重复留痕: %q", out.String())
	}

	// 恢复合法值：补一条恢复留痕。
	if _, err := db.DB.Exec(`UPDATE global_config SET task_log_size_mb=20 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	InvalidateTaskLogSizeCache()
	out.Reset()
	if got := getTaskLogSizeBytes(context.Background()); got != 20<<20 {
		t.Fatalf("恢复后阈值=%d, want 20MB", got)
	}
	if !strings.Contains(out.String(), "已恢复") {
		t.Fatalf("log=%q, want 恢复后补恢复留痕", out.String())
	}
}
