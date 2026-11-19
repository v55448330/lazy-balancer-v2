package handlers

// 触发文件探测失败必须可观测：文件不存在是常态（静默），权限/挂载等异常形态
// 会让崩溃自愈链永久停摆——按状态留一条 warn，恢复后补一条 info。

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// captureCaddyTaskLog 隔离任务日志目录并返回读取闭包（watcher 业务行经
// services.TaskLogfState 落 tasks/caddy-restart-watcher.log，不再走标准 log）。
func captureCaddyTaskLog(t *testing.T) func() string {
	t.Helper()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	return func() string {
		d, _ := os.ReadFile(taskengine.TaskLogPath("caddy-restart-watcher"))
		return string(d)
	}
}

func TestCaddyRestartWatcher_statFailureIsVisible(t *testing.T) {
	withIsolatedGlobal(t)
	resetCaddyRestartBackoffForTest()
	oldStat := caddyRestartStat
	t.Cleanup(func() {
		caddyRestartStat = oldStat
		resetCaddyRestartBackoffForTest()
	})
	readLog := captureCaddyTaskLog(t)
	h := &Handlers{}
	const trigger = "/tmp/lb-caddy-restarted-stat-test"

	// Given：探测持续失败（权限收紧/异常只读挂载）。
	caddyRestartStat = func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: trigger, Err: fs.ErrPermission}
	}
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if !strings.Contains(readLog(), "探测失败") {
		t.Fatalf("日志=%q, want stat 失败留痕（否则自愈链停摆无信号）", readLog())
	}

	// 同一状态不重复告警（每 2s 一轮不得刷日志）。
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if got := strings.Count(readLog(), "探测失败"); got != 1 {
		t.Fatalf("stat 失败留痕 %d 条, want 1（同一状态只报一次）", got)
	}

	// When：文件不存在（常态）→ 视为恢复，补一条 info。
	caddyRestartStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if !strings.Contains(readLog(), "探测恢复") {
		t.Fatalf("日志=%q, want 恢复留痕", readLog())
	}

	// 常态 ENOENT 之后不得再刷日志。
	before := len(readLog())
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if len(readLog()) != before {
		t.Fatalf("常态 ENOENT 产生了额外日志: %q", readLog())
	}
}
