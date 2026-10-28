package services

// 安全事件采集任务只是「尾读 + spool 补采 + 审计日志轮转 + 健康记账」的所有者；
// 实时 IPC 主路径（IngestSecurityEventBatch）不经任务调度，提交钩子仍直接喂入
// 自动封禁计数器。因此任务停止/补采非健康都不得推断「自动封禁计数不再增长」：
// 降级原因必须说明补采/轮转暂停而实时入库仍在运行，否则用户按错误前提做
// 容量与排障决策。

import (
	"strings"
	"testing"
)

func assertFeedReasonKeepsRealtimeFeeding(t *testing.T, reason string) {
	t.Helper()
	for _, forbidden := range []string{"计数不再更新", "不会增长", "不再增长"} {
		if strings.Contains(reason, forbidden) {
			t.Fatalf("降级原因=%q 不得声称计数停止增长（实时 IPC 入库仍在喂入计数器）", reason)
		}
	}
	if !strings.Contains(reason, "补采") || !strings.Contains(reason, "IPC") {
		t.Fatalf("降级原因=%q 必须说明补采/轮转暂停且实时 IPC 入库仍在运行", reason)
	}
}

func TestAutobanFeedHealth_stoppedTaskKeepsRealtimeFeedingNote(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	installFeedHealthTestEngine(t)

	degraded, reason := AutobanFeedHealth()
	if !degraded {
		t.Fatal("补采任务停止必须可见（否则用户以为后台补采仍在跑）")
	}
	assertFeedReasonKeepsRealtimeFeeding(t, reason)
}

func TestAutobanFeedHealth_unhealthyIngestionKeepsRealtimeFeedingNote(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	te := installFeedHealthTestEngine(t)
	te.StartLoop(AutobanFeedTaskID)
	t.Cleanup(func() {
		te.StopLoop(AutobanFeedTaskID)
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	// 调度正常但补采 tick 连续失败：计数可能偏少，但不得说成「不再更新」。
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{
		Observed: true, Healthy: false, ConsecutiveFailures: 3, LastError: "metrics db unavailable",
	})
	degraded, reason := AutobanFeedHealth()
	if !degraded || !strings.Contains(reason, "metrics db unavailable") {
		t.Fatalf("degraded=%v reason=%q, want 补采降级并携带底层原因", degraded, reason)
	}
	assertFeedReasonKeepsRealtimeFeeding(t, reason)

	// 无 last_error 的非健康形态（如任务停止叠加写侧失败）同样不得推断计数停止。
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: false})
	degraded, reason = AutobanFeedHealth()
	if !degraded {
		t.Fatalf("非健康且无底层原因也必须降级: reason=%q", reason)
	}
	assertFeedReasonKeepsRealtimeFeeding(t, reason)
}
