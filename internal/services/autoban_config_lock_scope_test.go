package services

// 配置写锁临界区边界：锁内只做「读旧值 → 写十列 → 内存收敛」，禁用收尾
// AutobanDisableFlush（CaddyOpLock + 全量重载，秒级）必须在释放写锁后执行。
// 旧实现把整段重载放在写锁内，期间所有喂入批（RLock）与 Run 轮被扣住：
// WAF 写侧 2s 超时整批转 spool、人机写入侧无重试直接丢投递。

import (
	"sync"
	"testing"
	"time"
)

func TestAutobanConfigReplace_disableFlushRunsOutsideWriteLock(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 100, 60, "1h", "blocked", false)
	// 有暂存重载 → 禁用收尾必走强制重载回调（测试缝）。
	autobanMu.Lock()
	autobanReloadPending = true
	autobanMu.Unlock()

	oldReloader := autobanReloader
	reloadEntered := make(chan struct{})
	reloadRelease := make(chan struct{})
	var once sync.Once
	autobanReloader = func() error {
		once.Do(func() { close(reloadEntered) })
		<-reloadRelease
		return nil
	}
	t.Cleanup(func() { autobanReloader = oldReloader })

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- SetAutobanConfig(AutobanConfig{
			Enabled: false, Threshold: 100, WindowMinutes: 60, Duration: "1h", Scope: "blocked",
		})
	}()

	select {
	case <-reloadEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("禁用收尾未触发全量重载回调")
	}

	// 重载执行中：喂入侧读锁必须立即可得（旧实现：写锁覆盖整段重载）。
	acquired := make(chan struct{})
	go func() {
		autobanConfigReplaceMu.RLock()
		close(acquired)
		autobanConfigReplaceMu.RUnlock()
	}()
	select {
	case <-acquired:
	case <-time.After(300 * time.Millisecond):
		close(reloadRelease)
		t.Fatal("禁用收尾全量重载期间配置写锁仍被持有：喂入批/配置读被整段阻塞")
	}

	close(reloadRelease)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("SetAutobanConfig: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetAutobanConfig 未在重载完成后返回")
	}

	// 读锁在写路径返回后仍可正常获取（无残留持锁）。
	autobanConfigReplaceMu.RLock()
	autobanConfigReplaceMu.RUnlock()
}
