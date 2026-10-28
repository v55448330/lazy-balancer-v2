package services

// 触发结果审计的静默清单：admission 语义的拒绝（并发/跳过/取消/引擎已停止）
// 不补记「触发失败」，真实执行失败仍必须记。

import (
	"context"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestRecordTaskTriggerResult_admissionAndCancellationAreSilent(t *testing.T) {
	setupIsolatedDB(t)
	count := func() int {
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发失败'`).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		return n
	}
	before := count()
	for _, err := range []error{
		taskengine.ErrAlreadyRunning,
		taskengine.ErrTaskSkipped,
		taskengine.ErrRunCancelled,
		context.Canceled,
		taskengine.ErrEngineStopped,
	} {
		RecordTaskTriggerResult("log-cleanup", TriggerAuditContext{Operator: "admin", Family: "任务监控", Name: "日志清理"}, err)
	}
	if after := count(); after != before {
		t.Fatalf("静默清单五类错误不得记「触发失败」（before=%d after=%d）", before, after)
	}
	RecordTaskTriggerResult("log-cleanup", TriggerAuditContext{Operator: "admin", Family: "任务监控", Name: "日志清理"}, errors.New("boom"))
	if after := count(); after != before+1 {
		t.Fatalf("真实失败必须记「触发失败」审计（before=%d after=%d）", before, after)
	}
}
