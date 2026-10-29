package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// 任务日志写路径的阈值查询必须消费当前任务 ctx：主库被写事务占住时，
// 取消/关停不能被一次无 ctx 的阈值读拖过任务排空预算。
func TestTaskLogThresholdReadHonorsContext(t *testing.T) {
	newClusterTestService(t)
	logs := captureLogf(t)
	resetLogStateTransitionForTest("task-log-size-refresh")
	dir := t.TempDir()
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	taskLogSizeCache.invalidate()
	taskengine.SetTaskLogSizeBytesFn(getTaskLogSizeBytes)
	t.Cleanup(func() {
		taskengine.SetTaskLogSizeBytesFn(nil)
		taskengine.SetLogDir(oldDir)
		taskLogSizeCache.invalidate()
		resetLogStateTransitionForTest("task-log-size-refresh")
	})

	gate := installBlockableMainDB(t)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		taskengine.TeeTaskLogTimeContext(ctx, "crs", "INFO", "test", "ctx bounded")
		close(done)
	}()

	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("任务日志阈值查询未到达闸门")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("任务 ctx 取消后日志写入仍阻塞在阈值查询")
	}
	release()
	if _, err := os.Stat(filepath.Join(dir, "crs.log")); err != nil {
		t.Fatalf("取消后应按默认阈值完成日志写入: %v", err)
	}
	if strings.Contains(logs.String(), "读取任务日志大小配置失败") {
		t.Fatalf("任务取消不得被记录为配置读取失败: %q", logs.String())
	}
}
