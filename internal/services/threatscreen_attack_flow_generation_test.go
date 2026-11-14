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

// 代际复位把 Seq 归零重编号：消费者携带的旧代 since 若与新代序号重叠，旧实现
// 会静默跳过新代事件（环溢出判据 since<最老序号 不触发）。修复后跨代游标必须
// 披露空洞并归零重放新代，而不是静默丢弧。
func TestThreatScreenAttackFlow_generationResetDisclosesCrossGenerationCursor(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)

	// 旧代：编号推进到 5，消费者游标停在 5。
	for range 5 {
		ThreatScreenAttackFlowAppendForTest("203.0.113.1", "blocked", "942100")
	}
	const staleCursor = 5

	// 代际复位（metrics 库损坏隔离重建）：环清空、Seq 归零。
	threatScreenAttackFlowResetRingForGeneration()

	// 新代：重放 3 条（Seq 1..3），全部 ≤ 旧代游标 5。
	for range 3 {
		ThreatScreenAttackFlowAppendForTest("203.0.113.2", "blocked", "942100")
	}

	events, next, gap := ThreatScreenAttackFlowSnapshot(staleCursor, 100)
	if gap == 0 {
		t.Fatalf("gap=%d, want >0（跨代游标必须披露空洞，不得静默跳过新代事件）", gap)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d, want 3（跨代游标应归零重放新代全部事件）", len(events))
	}
	if next != 3 {
		t.Fatalf("next=%d, want 3（游标推进到新代末尾）", next)
	}

	// 回归形状：同代后续轮次（游标已在新代内）不得误报空洞。
	_, next2, gap2 := ThreatScreenAttackFlowSnapshot(next, 100)
	if gap2 != 0 {
		t.Fatalf("同代后续轮 gap=%d, want 0（跨代判据不得误报）", gap2)
	}
	if next2 != next {
		t.Fatalf("同代无新事件 next=%d, want %d", next2, next)
	}
}
