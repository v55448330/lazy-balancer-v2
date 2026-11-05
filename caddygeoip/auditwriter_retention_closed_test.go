package caddygeoip

import (
	"testing"
	"time"
)

// 已终态的计时条目不得占用预检保留区：其分段已被 drain 消费完毕，pre 不会
// 再有迟到终态需要回填。若一并转入保留区，它们会与真正的长请求公平竞争并
// 基本占满上限（保留区稳态容量≈条目转入速率 13.7 条/s），高 rps 部署下慢
// 请求的 pre_us 反而永远保留不下来。
func TestAuditTimingRegistry_closedEntryDoesNotOccupyPreRetention(t *testing.T) {
	useTestAuditPipeline(t)
	origRetention := auditPreRetentionTTLNs.Load()
	auditPreRetentionTTLNs.Store(int64(time.Hour))
	t.Cleanup(func() { auditPreRetentionTTLNs.Store(origRetention) })

	const id = "aaaabbbbccccdddd"
	auditTimingRecord(id, "pre", 4321)
	auditTimingClose(id) // 终态：不会再有分段写点

	// 越过条目 TTL（useTestAuditPipeline 置 50ms）后清扫。
	time.Sleep(80 * time.Millisecond)
	auditTimingSweepExpired(time.Now())
	_, retained := auditTimingRetainedPreLookupForTest(id)

	if retained {
		t.Fatal("已终态条目不得转入预检保留区（高 rps 下会把保留区占满，慢请求 pre 反而永久缺失）")
	}
}
