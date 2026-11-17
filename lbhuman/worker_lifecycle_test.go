package lbhuman

// 常驻事件 worker 生命周期钉测：stop 必须等待**本代** worker 的退出信号。
// 退出信号若经包级变量在锁外读取，并发 start（reload 期间新请求上报即触发）
// 会在「置 nil 释放锁」与「等待」之间替换它——stop 死等新代信号（新代 worker
// 在跑，其信号永不关闭），FlushHumanEvents/Caddy Cleanup 永久阻塞。

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Given 第一代 worker 存活；stop 释放锁后、close(stop)/等待退出信号前，并发
// start 插入创建第二代 worker 并登记新退出信号（确定性交错，经 stop 等待缝
// 注入；第二代持续存活，新信号永不关闭）。
// When stopHumanEventWorker 继续等待。
// Then 不得挂起——stop 等待的必须是锁内捕获的本代退出信号，而不是被并发
// start 替换后的新代信号。
func TestStopHumanEventWorker_waitsOwnGenerationExited(t *testing.T) {
	stopHumanEventWorkerForTest()
	t.Cleanup(stopHumanEventWorkerForTest)

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer fast.Close()
	resetHumanEventPosterForTest(t, fast.URL) // 排空残留并启动第一代 worker

	// 交错缝：stop 释放锁后、close(stop1) 前——并发 start 创建第二代 worker
	// 并上报（第二代全速消费存活，其退出信号在 stop 等待期间永不关闭）。
	humanEventStopWaitHook = func() {
		startHumanEventWorker()
		reportHumanEvent("lb-worker-gen", "203.0.113.210", http.MethodGet, "/", "challenge")
	}
	t.Cleanup(func() { humanEventStopWaitHook = nil })

	done := make(chan struct{})
	go func() { stopHumanEventWorker(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stopHumanEventWorker 挂起：等待的退出信号被并发 start 替换为新代信号（永不关闭）")
	}
	humanEventStopWaitHook = nil // 后续 stop 不再注入交错

	humanEventWorkerMu.Lock()
	secondGenRunning := humanEventWorkerStop != nil
	humanEventWorkerMu.Unlock()
	if !secondGenRunning {
		t.Fatal("并发 start 创建的第二代 worker 应在运行")
	}
}

// 连续 stop→start→stop 循环：每代 worker 都能被干净停止，退出信号各代新鲜，
// 停机后上报可重启（生产语义：Flush 后新请求上报重启 worker）。
func TestStopHumanEventWorker_stopStartStopCycles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	for i := range 5 {
		reportHumanEvent("lb-worker-cycle", "203.0.113.211", http.MethodGet, "/", "challenge")
		if !drainHumanEventsForTest(5 * time.Second) {
			t.Fatalf("cycle %d: queue must drain", i)
		}
		done := make(chan struct{})
		go func() { stopHumanEventWorker(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("cycle %d: stop 挂起（退出信号串代）", i)
		}
		humanEventWorkerMu.Lock()
		stopped := humanEventWorkerStop == nil
		humanEventWorkerMu.Unlock()
		if !stopped {
			t.Fatalf("cycle %d: stop 后 worker 应已停", i)
		}
	}
}

// 并发 report + Flush（reload 期间新请求持续上报的真实形态）：全部调用必须
// 在有界时间内返回（无死锁），收尾后队列排空。-race 下跑。
func TestFlushHumanEvents_concurrentReportsNoDeadlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 200 {
				reportHumanEvent("lb-flush-conc", "203.0.113.212", http.MethodGet, "/", "challenge")
				if i%50 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			FlushHumanEvents()
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("并发 report + Flush 死锁（stop 等待被替换的退出信号）")
	}
	FlushHumanEvents()
	if len(humanEventQueue) != 0 {
		t.Fatalf("收尾后队列应排空，len=%d", len(humanEventQueue))
	}
}
