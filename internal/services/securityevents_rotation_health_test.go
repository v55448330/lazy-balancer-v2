package services

// 审计日志轮转失败必须进入采集健康态——此前
// rotateAuditLogIfNeeded 的所有失败分支只经 60s 限流日志留痕，不参与
// SecurityEventsPollOnce 的健康快照记账，磁盘写满/copy 持续失败时事件页
// 健康位恒 healthy、任务监控零痕迹。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// 目标形状：注入 copy 失败 → 连续 tick 后 ingestion.healthy=false 且
// last_error 指向轮转失败；恢复后健康位复位；「补采失败不截断」语义不变。
func TestSecurityEventsPollOnce_rotationFailureEntersHealthSnapshot(t *testing.T) {
	// Given：一条已摄取事件 + 超阈活文件（每 tick 触发轮转）。
	// 库夹具必须保存/还原全局指针并 Close（同包
	// stallSetup/setupSecurityEventsRetentionTestDB 口径）——裸 Initialize 会让
	// 包级 DB 指向已删除的临时目录。
	logPath, offsetPath := stallSetup(t)
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	resetSecurityEventsPollState(t)
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	// When：copy 持续失败（磁盘写满形态）→ 每轮轮转中止，错误随返回值暴露。
	auditLogCopyFile = func(src, dst string) error { return errors.New("injected copy failure") }
	for range securityEventsIngestionFailureThreshold {
		if _, rotErr := SecurityEventsPollOnce(); rotErr == nil {
			t.Fatal("轮转失败必须随 SecurityEventsPollOnce 返回值暴露")
		}
	}

	// Then：健康快照连续失败达阈值 → unhealthy，last_error 指向轮转失败。
	status := SecurityEventsIngestionHealthSnapshot()
	if !status.Observed || status.Healthy || status.ConsecutiveFailures != securityEventsIngestionFailureThreshold {
		t.Fatalf("轮转失败健康快照=%+v, want observed+unhealthy+%d failures", status, securityEventsIngestionFailureThreshold)
	}
	if !strings.Contains(status.LastError, "injected copy failure") {
		t.Fatalf("last_error=%q, want 含注入的轮转失败", status.LastError)
	}
	// 「copy 失败绝不截断」语义不变：活文件内容完好。
	info, err := os.Stat(logPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("copy 失败后活文件 size=%v err=%v, want 未截断", info, err)
	}

	// When：copy 恢复 → 下一轮成功轮转。
	auditLogCopyFile = copyAuditLogTo
	if _, rotErr := SecurityEventsPollOnce(); rotErr != nil {
		t.Fatalf("copy 恢复后轮转仍报错: %v", rotErr)
	}

	// Then：健康位复位、连续失败清零；活文件已截断（轮转真实发生）。
	status = SecurityEventsIngestionHealthSnapshot()
	if !status.Healthy || status.ConsecutiveFailures != 0 {
		t.Fatalf("恢复后健康快照=%+v, want healthy+0 failures", status)
	}
	if info, err := os.Stat(logPath); err != nil || info.Size() != 0 {
		t.Fatalf("恢复后活文件未截断: size=%v err=%v", info, err)
	}
}

// 轮转顺延（活文件尾部尚未摄取）不得计入采集失败：持续写入期每轮都会返回
// 该哨兵，按失败记账会让三面健康位在数轮内误报「采集异常」，真实失败反而被
// 容量噪音掩盖。顺延轮次按成功 tick 记账，另以 RotationDeferred 单列披露。
func TestSecurityEventsRecordPollResult_rotationDeferredStaysHealthy(t *testing.T) {
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() { SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{}) })
	raw := func() SecurityEventsIngestionStatus {
		securityEventsIngestionHealth.Lock()
		defer securityEventsIngestionHealth.Unlock()
		return securityEventsIngestionHealth.status
	}

	// When：连续多轮（> 失败阈值）都只是轮转顺延。
	for range securityEventsIngestionFailureThreshold + 2 {
		securityEventsRecordPollResult(fmt.Errorf("%w: 活文件尾部尚未摄取", errAuditRotationDeferred))
	}

	// Then：健康位保持健康、连续失败为 0、延迟状态单列。
	status := raw()
	if !status.Observed || !status.Healthy || status.ConsecutiveFailures != 0 {
		t.Fatalf("顺延轮次健康快照=%+v, want observed+healthy+0 failures", status)
	}
	if !status.RotationDeferred || status.RotationLastDeferredAt == "" {
		t.Fatalf("延迟状态未记录: %+v", status)
	}
	if status.LastError != "" || status.LastErrorAt != "" {
		t.Fatalf("顺延不得写成 last_error: %q/%q", status.LastError, status.LastErrorAt)
	}

	// 真失败仍必须降级——延迟记账不得掩盖采集异常。
	for range securityEventsIngestionFailureThreshold {
		securityEventsRecordPollResult(errors.New("injected tick failure"))
	}
	if status = raw(); status.Healthy || status.ConsecutiveFailures != securityEventsIngestionFailureThreshold {
		t.Fatalf("真实失败未降级: %+v", status)
	}

	// 恢复后的成功 tick 复位延迟标记。
	securityEventsRecordPollResult(nil)
	if status = raw(); !status.Healthy || status.RotationDeferred || status.RotationLastDeferredAt == "" {
		t.Fatalf("成功 tick 未复位延迟标记: %+v", status)
	}
}
