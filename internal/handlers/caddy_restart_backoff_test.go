package handlers

// caddy-restart 重试的退避与落行降频：持续失败（Caddy 长期不可达）时每 2s
// 轮询不得每轮落一条 task_runs 失败行——退避指数增长、行数有界。

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

func TestCaddyRestartBackoff_boundsTaskRunsUnderSustainedFailure(t *testing.T) {
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	// Simulate 25 failed attempts. Each iteration fast-forwards the next poll only
	// after asserting that the just-finished attempt scheduled a bounded delay.
	attempts := 0
	recorded := 0
	for range 25 {
		now := time.Now()
		if !caddyRestartShouldAttempt(now) {
			t.Fatal("fast-forwarded retry window must admit the next attempt")
		}
		attempts++
		record, _ := caddyRestartBeginAttempt(now)
		if record {
			recorded++
		}
		caddyRestartEndAttempt(false)
		caddyRestartBackoff.mu.Lock()
		nextAttempt := caddyRestartBackoff.nextAttempt
		caddyRestartBackoff.nextAttempt = time.Time{}
		caddyRestartBackoff.mu.Unlock()
		expectedDelay := caddyRestartBackoffBase
		for i := 1; i < attempts && expectedDelay < caddyRestartBackoffMax; i++ {
			expectedDelay *= 2
		}
		if expectedDelay > caddyRestartBackoffMax {
			expectedDelay = caddyRestartBackoffMax
		}
		if nextAttempt.Before(now.Add(expectedDelay)) || nextAttempt.After(now.Add(expectedDelay+time.Second)) {
			t.Fatalf("第 %d 次失败退避=%s，want 精确档位 %s（指数 2/4/8/16/30/30…，实测窗口 +1s）", attempts, nextAttempt.Sub(now), expectedDelay)
		}
	}

	// 落行 = 首次 + 每 10 轮：必须远小于尝试次数且非零。
	if recorded == 0 || recorded > attempts/5+1 {
		t.Fatalf("落 task_runs 行数=%d（尝试 %d 次）, want 有界且远小于尝试数", recorded, attempts)
	}

	// 成功收敛：退避清零，下一次立即允许尝试。
	caddyRestartEndAttempt(true)
	if !caddyRestartShouldAttempt(time.Now()) {
		t.Fatal("成功后必须清零退避（下一轮立即可尝试）")
	}
}

func TestCaddyRestartBackoff_slowFailureStartsDelayAtAttemptEnd(t *testing.T) {
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	// Given an attempt that started three seconds ago and is only failing now.
	attemptStart := time.Now().Add(-3 * time.Second)
	caddyRestartBeginAttempt(attemptStart)
	beforeEnd := time.Now()
	caddyRestartEndAttempt(false)
	afterEnd := time.Now()

	// Then the full delay starts at the end, not in the past at the start.
	caddyRestartBackoff.mu.Lock()
	nextAttempt := caddyRestartBackoff.nextAttempt
	caddyRestartBackoff.mu.Unlock()
	if nextAttempt.Before(beforeEnd.Add(caddyRestartBackoffBase)) || nextAttempt.After(afterEnd.Add(caddyRestartBackoffBase)) {
		t.Fatalf("next attempt=%s, want end-based window [%s, %s]", nextAttempt, beforeEnd.Add(caddyRestartBackoffBase), afterEnd.Add(caddyRestartBackoffBase))
	}
	if caddyRestartShouldAttempt(time.Now()) {
		t.Fatal("slow failure must not permit an immediate retry")
	}
}

// 集成形状：首次失败落 1 行；紧接着的下一轮（退避窗口内）不得再落行，
// 也不得重复执行。
func TestCaddyRestartWatcher_backoffSkipsImmediateRetry(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	services.SetConfigLoadRerun(nil)
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	h := &Handlers{}
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.WriteFile(trigger, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	processStart := time.Now().Add(-time.Minute)

	h.caddyRestartWatcherOnce(trigger, processStart)
	first := countCaddyRestartRuns(t)
	if first != 1 {
		t.Fatalf("首次失败落行=%d, want 1", first)
	}

	// 退避窗口内（2s 未到）：不执行、不落行。
	h.caddyRestartWatcherOnce(trigger, processStart)
	if got := countCaddyRestartRuns(t); got != first {
		t.Fatalf("退避窗口内新增行：%d → %d, want 不变", first, got)
	}
	if _, err := os.Stat(trigger); err != nil {
		t.Fatalf("失败轮必须保留触发文件: %v", err)
	}
}

// 退避窗口内的「跳过」与「RunSyncQuiet 执行但不落行」必须可区分：
// 注入执行计数证明窗口内根本没有执行（不是执行了却静默）；快进退避后
// 确实执行，且第 2 次尝试按降频契约不落 task_runs 行。
func TestCaddyRestartWatcher_backoffWindowSkipsExecutionAndQuietRoundOmitsRow(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	executions := 0
	services.SetConfigLoadRerun(func(string) error {
		executions++
		return errors.New("caddy unavailable")
	})
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	h := &Handlers{}
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.WriteFile(trigger, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	processStart := time.Now().Add(-time.Minute)

	// 首次尝试：执行 + 落行。
	h.caddyRestartWatcherOnce(trigger, processStart)
	if executions != 1 {
		t.Fatalf("首轮执行次数=%d, want 1", executions)
	}
	rowsAfterFirst := countCaddyRestartRuns(t)
	if rowsAfterFirst != 1 {
		t.Fatalf("首轮落行=%d, want 1", rowsAfterFirst)
	}

	// 退避窗口内：不执行（计数不变）且不落行。
	h.caddyRestartWatcherOnce(trigger, processStart)
	if executions != 1 {
		t.Fatalf("退避窗口内执行次数=%d, want 1（窗口内必须完全跳过）", executions)
	}
	if got := countCaddyRestartRuns(t); got != rowsAfterFirst {
		t.Fatalf("退避窗口内落行：%d → %d, want 不变", rowsAfterFirst, got)
	}

	// 快进退避到点：真实执行（RunSyncQuiet），第 2 次尝试按降频不落行。
	caddyRestartBackoff.mu.Lock()
	caddyRestartBackoff.nextAttempt = time.Now().Add(-time.Second)
	caddyRestartBackoff.mu.Unlock()
	h.caddyRestartWatcherOnce(trigger, processStart)
	if executions != 2 {
		t.Fatalf("退避到点后执行次数=%d, want 2", executions)
	}
	if got := countCaddyRestartRuns(t); got != rowsAfterFirst {
		t.Fatalf("第 2 次尝试（Quiet）落行：%d → %d, want 不新增", rowsAfterFirst, got)
	}
}
