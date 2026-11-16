package lbhuman

// 停机尾部事件对账钉测：FlushHumanEvents 把队列内未投递事件计入
// shutdown_lost（人机通道无 spool 是裁定，但丢失量必须可观测）。

import (
	"testing"
	"time"
)

func TestFlushHumanEvents_countsQueuedTail(t *testing.T) {
	// 直接入队两条（不经 worker 投递），Flush 应计入 shutdown_lost。
	humanEventQueue <- humanEvent{ruleID: "r1", ip: "203.0.113.1", kind: "challenge", ts: time.Now().UnixMilli()}
	humanEventQueue <- humanEvent{ruleID: "r1", ip: "203.0.113.2", kind: "challenge", ts: time.Now().UnixMilli()}
	before := humanEventShutdownLost.Load()
	FlushHumanEvents()
	if got := humanEventShutdownLost.Load() - before; got != 2 {
		t.Fatalf("shutdown_lost 增量 = %d, want 2（队列尾部两条计入对账）", got)
	}
	// 幂等：排空后重复调用计 0。
	FlushHumanEvents()
	if got := humanEventShutdownLost.Load() - before; got != 2 {
		t.Fatalf("重复 Flush 应幂等，增量 = %d, want 2", got)
	}
}

func TestFlushHumanEvents_emptyNoOp(t *testing.T) {
	before := humanEventShutdownLost.Load()
	FlushHumanEvents()
	if humanEventShutdownLost.Load() != before {
		t.Fatal("空队列 Flush 不得计数")
	}
}
