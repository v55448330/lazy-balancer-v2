package taskengine

// ErrTaskSkipped 哨兵 → task_runs skipped 终态。

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestTerminalStatus_mapsSkippedSentinel(t *testing.T) {
	if got := terminalStatus(context.Background(), ErrTaskSkipped); got != "skipped" {
		t.Fatalf("terminalStatus(ErrTaskSkipped)=%q, want skipped", got)
	}
	// 回归：普通 error 仍 failed，nil 仍 success，取消仍 cancelled
	if got := terminalStatus(context.Background(), ErrAlreadyRunning); got != "failed" {
		t.Fatalf("generic error must stay failed, got %q", got)
	}
	if got := terminalStatus(context.Background(), ErrRunCancelled); got != "cancelled" {
		t.Fatalf("ErrRunCancelled must stay cancelled, got %q", got)
	}
	if got := terminalStatus(context.Background(), nil); got != "success" {
		t.Fatalf("nil must stay success, got %q", got)
	}
}

// demote 同时取消 ctx 并返回 ErrTaskSkipped；非故障放弃必须
// 优先于通用 cancelled，才能与用户主动取消区分。
func TestTerminalStatus_demoteSkipPrecedesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := terminalStatus(ctx, fmt.Errorf("角色降级，本轮中止: %w", ErrTaskSkipped)); got != "skipped" {
		t.Fatalf("demote skipped 终态=%q, want skipped", got)
	}
	// 真值表回归：同一 cancelled ctx 下，普通错误与 nil 不得被误归为 skipped。
	if got := terminalStatus(ctx, ErrAlreadyRunning); got != "cancelled" {
		t.Fatalf("普通错误的取消终态=%q, want cancelled", got)
	}
	if got := terminalStatus(ctx, nil); got != "cancelled" {
		t.Fatalf("nil 错误的取消终态=%q, want cancelled", got)
	}
}

// skipped 终态同样落 message——跳过原因此前只进
// 任务日志 [done] 行，task_runs.message 恒空，任务历史页丢失「为何跳过」。
func TestRunNow_skippedRunCarriesSkipReason(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-skip-msg", Family: "t", Name: "跳过留痕", Kind: KindOneshot,
		Run: func(RunContext) error {
			return fmt.Errorf("配置降级中，本轮跳过: %w", ErrTaskSkipped)
		}})
	// runNow 同步落终态后才返回（Trigger 前置 runGuarded→finishRun*）
	if err := e.Trigger("t-skip-msg", "manual", ""); err == nil {
		t.Fatal("包装 ErrTaskSkipped 应原样回传 Trigger 调用方")
	}
	var status, message string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM task_runs WHERE task_id='t-skip-msg' ORDER BY id DESC LIMIT 1`).Scan(&status, &message); err != nil {
		t.Fatalf("读回 run 行: %v", err)
	}
	if status != "skipped" {
		t.Fatalf("终态=%s, want skipped", status)
	}
	if !strings.Contains(message, "配置降级中，本轮跳过") {
		t.Fatalf("skipped run 的 message 应含跳过原因, got %q", message)
	}
}
