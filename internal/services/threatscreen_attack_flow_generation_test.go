package services

import (
	"testing"
	"time"
)

func TestThreatScreenAttackFlow_generationResetKeepsSequenceMonotonic(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
	if err := AcquireThreatScreenAttackFlowLease("generation-reset", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	threatScreenAttackFlowSeq.Store(41)
	entered := make(chan struct{})
	release := make(chan struct{})
	threatScreenAttackFlowGenerationResetHookForTest = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { threatScreenAttackFlowGenerationResetHookForTest = nil })
	done := make(chan struct{})
	go func() {
		threatScreenAttackFlowResetRingForGeneration()
		close(done)
	}()
	<-entered
	// 复位尚未写回序号时插入一条新代事件；旧实现随后 Store(0)，下一条
	// 事件从 1 重新编号，环内形成 [42,1]。
	threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{at: time.Now(), clientIP: "203.0.113.1", action: "blocked", ruleTriggered: "942100"}})
	close(release)
	<-done
	threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{at: time.Now(), clientIP: "203.0.113.2", action: "blocked", ruleTriggered: "942100"}})

	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()
	if len(threatScreenAttackFlowEvents) != 2 {
		t.Fatalf("events=%d, want 2", len(threatScreenAttackFlowEvents))
	}
	if threatScreenAttackFlowEvents[0].Seq >= threatScreenAttackFlowEvents[1].Seq {
		t.Fatalf("ring sequence is not monotonic: %d then %d", threatScreenAttackFlowEvents[0].Seq, threatScreenAttackFlowEvents[1].Seq)
	}
}
