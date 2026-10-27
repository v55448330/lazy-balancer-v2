package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// metrics 库代际切换（损坏隔离重建）会把整份 audit.log 从头重放：autoban 计数与
// 请求去重表都已在新库语义下重置，攻击光流环却保留灾前条目——重放事件再次入环
// 后同一批攻击在大屏出现两次（4096 环可被重复历史整体占满）。
func TestSecurityEventsGenerationChange_resetsAttackFlowRing(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	enableAttackFlowSampling(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeNowFixture("tx-gen-flow-a", "0011aabbccddee01", "/gen-a", "blocked", 942100),
		securityEventsDedupeNowFixture("tx-gen-flow-b", "0011aabbccddee02", "/gen-b", "blocked", 942100))
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)
	if events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0); len(events) != 2 {
		t.Fatalf("首轮光流条目=%d, want 2: %+v", len(events), events)
	}

	// When metrics 库隔离重建（新代际）→ 审计日志从头重放
	oldMetrics := db.MetricsDB
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("initialize rebuilt metrics db: %v", err)
	}
	t.Cleanup(func() {
		if db.MetricsDB != nil && db.MetricsDB != oldMetrics {
			_ = db.MetricsDB.Close()
		}
		db.MetricsDB = oldMetrics
	})
	runSecurityEventsDedupeTick(t, tailer)

	// Then 光流环已按新代际重建：仍只有 2 条，序号从 1 起（消费者游标复位）
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0)
	if len(events) != 2 {
		t.Fatalf("重放后光流条目=%d, want 2（旧环不得保留让同一批攻击重复出现）: %+v", len(events), events)
	}
	for i, ev := range events {
		if want := uint64(i + 1); ev.Seq != want {
			t.Fatalf("重放后序号[%d]=%d, want %d（环内序号须随代际复位）", i, ev.Seq, want)
		}
	}
}
