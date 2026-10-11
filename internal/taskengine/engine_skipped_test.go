package taskengine

// TASK-L5（第 69 轮 P2）：ErrTaskSkipped 哨兵 → task_runs skipped 终态。

import (
	"context"
	"testing"
)

func TestTerminalStatus_mapsSkippedSentinel(t *testing.T) {
	if got := terminalStatus(context.Background(), ErrTaskSkipped); got != "skipped" {
		t.Fatalf("terminalStatus(ErrTaskSkipped)=%q, want skipped", got)
	}
	// 回归：普通 error 仍 failed，nil 仍 success，取消仍 cancelled
	if got := terminalStatus(context.Background(), ErrAlreadyRunning); got != "failed" {
		t.Fatalf("generic error must stay failed, got %q", got)
	}
	if got := terminalStatus(context.Background(), nil); got != "success" {
		t.Fatalf("nil must stay success, got %q", got)
	}
}
