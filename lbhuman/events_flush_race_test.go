package lbhuman

// 停机收尾与常驻 worker 的 reload 竞态钉测：Cleanup（FlushHumanEvents）
// 必须先停 worker 再独占排空计 shutdown_lost——worker 活着时并发消费会让
// 尾部事件绕过对账计数（计数失真）。
//
// 确定性形态：poster 注入 nil client（deliver 立即计失败返回，不阻塞），
// worker 全速消费队列。启动 worker 后入队一批尾部事件，然后 Flush。
// 核心断言：Flush 后 worker 必须已停（humanEventWorkerStop==nil）——这是
// 「先停 worker 再排空」契约的直接可观测面。若 Flush 不停 worker，worker
// 存活（humanEventWorkerStop!=nil），后续事件会被竞争消费绕进 deliver_failed
// 而非 shutdown_lost，对账计数失真。
//
// 计数面：Flush 把当时队列内滞留事件计入 shutdown_lost（worker 已停，独占
// 排空）。worker 在 Flush 前可能已消费部分事件（计 deliver_failed），这是
// 正常投递语义——shutdown_lost 只计真正滞留队列的尾部，不重不漏。

import (
	"net/http"
	"testing"
	"time"
)

// Given 常驻 worker 存活（nil client → deliver 立即返回，全速消费）。
// When 入队尾部事件后执行停机收尾 FlushHumanEvents。
// Then Flush 后 worker 已停（humanEventWorkerStop==nil），队列排空，
// 滞留尾部计入 shutdown_lost（worker 不得在 Flush 后继续竞争消费）。
func TestFlushHumanEvents_stopsWorkerBeforeCountingTail(t *testing.T) {
	stopHumanEventWorkerForTest()
	t.Cleanup(stopHumanEventWorkerForTest)
	// nil client：deliver 立即计失败返回（不阻塞），worker 全速消费。
	poster.mu.Lock()
	poster.client = nil
	poster.url = ""
	poster.disabled = false
	poster.mu.Unlock()
	t.Cleanup(func() {
		poster.mu.Lock()
		poster.client = nil
		poster.url = ""
		poster.mu.Unlock()
	})

	// 启动 worker（reportHumanEvent 会启动）。
	reportHumanEvent("lb-flush-race", "203.0.113.100", http.MethodGet, "/", "challenge")
	// 等待 worker 取出首条进入 deliver（在途），确保 worker 活跃。
	time.Sleep(5 * time.Millisecond)

	// 入队尾部（直接入队）。
	const tail = 100
	for range tail {
		select {
		case humanEventQueue <- humanEvent{ruleID: "lb-flush-race", ip: "203.0.113.101", kind: "challenge", ts: time.Now().UnixMilli()}:
		default:
			t.Fatal("queue must accept tail event")
		}
	}

	before := humanEventShutdownLost.Load()
	FlushHumanEvents()

	// 核心断言①：Flush 后 worker 必须已停（先停 worker 再排空）。
	humanEventWorkerMu.Lock()
	stopped := humanEventWorkerStop == nil
	humanEventWorkerMu.Unlock()
	if !stopped {
		t.Fatal("FlushHumanEvents 必须先停常驻 worker（humanEventWorkerStop 应为 nil），否则 worker 竞争消费队列导致 shutdown_lost 计数失真")
	}

	// 核心断言②：队列已排空（Flush 独占排空，worker 已停不再消费）。
	if len(humanEventQueue) != 0 {
		t.Fatalf("Flush 后队列应排空，len=%d", len(humanEventQueue))
	}

	// 核心断言③：shutdown_lost 有增量（滞留尾部被计入；worker 已停，
	// 独占排空保证滞留事件不被竞争消费绕进 deliver_failed）。
	got := humanEventShutdownLost.Load() - before
	if got == 0 {
		t.Fatal("Flush 应把滞留尾部计入 shutdown_lost（增量 > 0）")
	}

	// worker 已停：重复 Flush 幂等（排空后重复调用计 0）。
	FlushHumanEvents()
	if got2 := humanEventShutdownLost.Load() - before; got2 != got {
		t.Fatalf("重复 Flush 应幂等，增量 = %d, want %d", got2, got)
	}
}
