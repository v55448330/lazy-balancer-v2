package handlers

// + 联动：Caddy 重启 watcher 曾先删触发文件
// 再 RunSync——重应用失败即丢失重试机会（下轮无文件可消费）。修复：先 RunSync
// 成功后才删文件（失败保留供下轮重试）；存量文件（mtime 早于进程启动——上一
// 进程生命周期残留）删除不执行（启动应用已在启动流程完成，重放无意义）。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestCaddyRestartWatcherStopWaitsForLoopExit(t *testing.T) {
	oldLoop := caddyRestartWatcherLoop
	started := make(chan struct{})
	caddyRestartWatcherStarted.Store(false)
	caddyRestartWatcherLoop = func(_ *Handlers, ctx context.Context) {
		close(started)
		<-ctx.Done()
	}
	t.Cleanup(func() {
		caddyRestartWatcherStarted.Store(false)
		caddyRestartWatcherLoop = oldLoop
	})

	h := NewHandlers(Dependencies{})
	h.StartCaddyRestartWatcher()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher loop did not start")
	}
	done := h.StopCaddyRestartWatcher()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop must cancel the loop and wait for its exit")
	}
}

func countCaddyRestartRuns(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='startup:config-load' AND trigger='caddy-restart'`).Scan(&n); err != nil {
		t.Fatalf("count caddy-restart runs: %v", err)
	}
	return n
}

// Given 配置重载未接线（RunSync 必失败）。
// When watcher 单轮处理新触发文件。
// Then 触发文件必须保留（下轮重试）且真实执行了一次（现实现先删后跑——RED）。
func TestCaddyRestartWatcher_failureKeepsTriggerFile(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	services.SetConfigLoadRerun(nil)
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })

	h := &Handlers{}
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.WriteFile(trigger, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}

	h.caddyRestartWatcherOnce(trigger, time.Now().Add(-time.Minute))

	if _, err := os.Stat(trigger); err != nil {
		t.Fatalf("重应用失败时触发文件被删（丢失重试机会）: %v", err)
	}
	if n := countCaddyRestartRuns(t); n != 1 {
		t.Fatalf("应真实执行 1 次（失败终态留 task_runs）, got %d", n)
	}
}

// Given 存量触发文件（mtime 早于进程启动——上一进程生命周期残留）。
// When watcher 单轮处理。
// Then 删除不执行（零 task_runs、重载执行体零调用）。
func TestCaddyRestartWatcher_staleTriggerFileRemovedWithoutExecution(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	calls := 0
	services.SetConfigLoadRerun(func(string) error { calls++; return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })

	h := &Handlers{}
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.WriteFile(trigger, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(trigger, stale, stale); err != nil {
		t.Fatal(err)
	}

	h.caddyRestartWatcherOnce(trigger, time.Now())

	if _, err := os.Stat(trigger); !os.IsNotExist(err) {
		t.Fatalf("存量触发文件应被清理, stat err=%v", err)
	}
	if calls != 0 {
		t.Fatalf("存量文件不得执行配置载入, got %d 次", calls)
	}
	if n := countCaddyRestartRuns(t); n != 0 {
		t.Fatalf("存量文件不得产生 task_runs, got %d", n)
	}
}

// 回归形状：新触发文件 + 重载成功 → 执行一次且文件删除（正常消费路径）。
func TestCaddyRestartWatcher_successConsumesTriggerFile(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	calls := 0
	services.SetConfigLoadRerun(func(string) error { calls++; return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })

	h := &Handlers{}
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.WriteFile(trigger, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}

	h.caddyRestartWatcherOnce(trigger, time.Now().Add(-time.Minute))

	if calls != 1 {
		t.Fatalf("新触发应执行配置载入 1 次, got %d", calls)
	}
	if _, err := os.Stat(trigger); !os.IsNotExist(err) {
		t.Fatalf("成功后触发文件应删除, stat err=%v", err)
	}
	if n := countCaddyRestartRuns(t); n != 1 {
		t.Fatalf("应落 1 行 caddy-restart task_runs, got %d", n)
	}
}

// 触发文件删除失败（只读目录/异常挂载）不得演变为每 2s 全量重应用：成功收尾会
// 清零退避，若只按「文件仍存在」判定，下一轮必以 attempts=1 重新执行。同一
// mtime 已应用后只重试删除并留一次 warn。
func TestCaddyRestartWatcher_removalFailureDoesNotReapply(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)
	calls := 0
	services.SetConfigLoadRerun(func(string) error { calls++; return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	logs := captureHandlerLog(t)

	h := &Handlers{}
	// 非空目录：os.Remove 必失败（ENOTEMPTY），模拟「触发文件删不掉」的
	// 挂载/权限形态（不依赖 chmod——root/容器内权限位不可靠）。
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.Mkdir(trigger, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trigger, "keep"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	processStart := time.Now().Add(-time.Minute)

	h.caddyRestartWatcherOnce(trigger, processStart)
	if calls != 1 {
		t.Fatalf("首轮应执行配置载入 1 次, got %d", calls)
	}
	h.caddyRestartWatcherOnce(trigger, processStart)
	if calls != 1 {
		t.Fatalf("触发文件删除失败后不得重复执行配置载入, got %d 次", calls)
	}
	if n := countCaddyRestartRuns(t); n != 1 {
		t.Fatalf("重复轮不得新增 task_runs 行, got %d", n)
	}
	if got := strings.Count(logs.String(), "Caddy 重启触发文件删除失败"); got != 1 {
		t.Fatalf("删除失败 warn=%d 条, want 1（同一触发只留痕一次）: %q", got, logs.String())
	}
}
