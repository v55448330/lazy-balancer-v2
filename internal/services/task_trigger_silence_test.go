package services

// 触发结果审计的静默清单：admission 语义的拒绝（并发/跳过/取消/引擎已停止）
// 不补记「触发失败」，真实执行失败仍必须记。

import (
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// Given 引擎已停止的 admission 拒绝（ErrEngineStopped）。
// When 记录触发结果。
// Then 不得补记「触发失败」审计——admission 被拒不是任务失败（关停窗口的
// 误点不应在台账里留下与任务执行无关的失败记录）。
func TestRecordTaskTriggerResult_engineStoppedIsSilent(t *testing.T) {
	setupIsolatedDB(t)
	count := func() int {
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发失败'`).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		return n
	}
	before := count()
	RecordTaskTriggerResult("log-cleanup", TriggerAuditContext{Operator: "admin", Family: "任务监控", Name: "日志清理"}, taskengine.ErrEngineStopped)
	if after := count(); after != before {
		t.Fatalf("ErrEngineStopped 不得记「触发失败」审计（before=%d after=%d）", before, after)
	}
	// 契约对照：真实执行失败仍必须记（静默清单不得吞掉真失败）。
	RecordTaskTriggerResult("log-cleanup", TriggerAuditContext{Operator: "admin", Family: "任务监控", Name: "日志清理"}, errors.New("boom"))
	if after := count(); after != before+1 {
		t.Fatalf("真实失败必须记「触发失败」审计（before=%d after=%d）", before, after)
	}
}
