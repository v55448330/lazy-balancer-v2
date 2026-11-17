package services

// 喂入批与配置替换的跨代互斥：ObserveHumanEvents/autobanObserveBatch 的
// RLock 必须覆盖「读 cfg+写桶」整批——只锁读调用会留下读后写前窄窗口，
// 替换写锁插入清桶后旧口径在途批落入新代桶（窗口收窄时少量误计）。
// 确定性编排：autobanNow 首读（写桶路径第一个 now，读 cfg 已返回）暂停喂入
// goroutine，主 goroutine 并发 SetAutobanConfig——修复后替换写锁必须阻塞至
// 喂入批完成（RLock 持有中），不得先行清桶。

import (
	"testing"
	"time"
)

func TestAutobanFeed_configReplaceWaitsForInFlightBatch(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	// 旧配置：宽窗口 60min、高阈值（只观察计数不封禁）。
	setAutobanConfigRaw(t, true, 100, 60, "1h", "blocked", false)

	feedPaused := make(chan struct{})
	feedRelease := make(chan struct{})
	var injected bool
	oldNow := autobanNow
	autobanNow = func() time.Time {
		if !injected {
			injected = true
			close(feedPaused)
			<-feedRelease // 暂停在写桶前（读 cfg 已返回，RLock 持有中）
		}
		return oldNow()
	}
	t.Cleanup(func() { autobanNow = oldNow })

	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		ObserveHumanEvents([]HumanObserveItem{
			{IP: "45.77.9.10", Kind: "rate_reject", At: clock.Now()},
		})
	}()

	<-feedPaused // 喂入批已读旧 cfg、暂停在写桶前
	replaceDone := make(chan struct{})
	go func() {
		defer close(replaceDone)
		if err := SetAutobanConfig(AutobanConfig{
			Enabled: true, Threshold: 2, WindowMinutes: 1, Duration: "1h", Scope: "blocked",
		}); err != nil {
			t.Errorf("replace config: %v", err)
		}
	}()

	// 修复后：替换写锁被喂入批 RLock 扣住，不得先行完成。
	select {
	case <-replaceDone:
		t.Fatal("跨代窗口未闭合：替换写锁在喂入批写桶前完成清桶（旧口径在途批将落入新代桶）")
	case <-time.After(100 * time.Millisecond):
		// 预期：替换阻塞中
	}

	close(feedRelease) // 放行喂入批写桶
	<-feedDone
	<-replaceDone // 替换随后完成（清桶发生在旧批写完之后）

	// 终态：替换清桶后新代桶为空——旧批计数被清掉（替换后清桶语义），
	// 而非旧批落入新代桶残留。
	autobanMu.Lock()
	n := len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("替换完成后新代桶应空（清桶在旧批写完后），实际 %d 键", n)
	}
}
