package handlers

// 触发文件探测失败必须可观测：文件不存在是常态（静默），权限/挂载等异常形态
// 会让崩溃自愈链永久停摆——按状态留一条 warn，恢复后补一条 info。

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCaddyRestartWatcher_statFailureIsVisible(t *testing.T) {
	withIsolatedGlobal(t)
	resetCaddyRestartBackoffForTest()
	oldStat := caddyRestartStat
	t.Cleanup(func() {
		caddyRestartStat = oldStat
		resetCaddyRestartBackoffForTest()
	})
	logs := captureLog(t)
	h := &Handlers{}
	const trigger = "/tmp/lb-caddy-restarted-stat-test"

	// Given：探测持续失败（权限收紧/异常只读挂载）。
	caddyRestartStat = func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: trigger, Err: fs.ErrPermission}
	}
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if !strings.Contains(logs.String(), "探测失败") {
		t.Fatalf("日志=%q, want stat 失败留痕（否则自愈链停摆无信号）", logs.String())
	}

	// 同一状态不重复告警（每 2s 一轮不得刷日志）。
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if got := strings.Count(logs.String(), "探测失败"); got != 1 {
		t.Fatalf("stat 失败留痕 %d 条, want 1（同一状态只报一次）", got)
	}

	// When：文件不存在（常态）→ 视为恢复，补一条 info。
	caddyRestartStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if !strings.Contains(logs.String(), "探测恢复") {
		t.Fatalf("日志=%q, want 恢复留痕", logs.String())
	}

	// 常态 ENOENT 之后不得再刷日志。
	before := logs.Len()
	h.caddyRestartWatcherOnce(trigger, time.Now())
	if logs.Len() != before {
		t.Fatalf("常态 ENOENT 产生了额外日志: %q", logs.String())
	}
}
