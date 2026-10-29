package services

// 失败标记按代际判定：上一代进程留下的标记不得让本代永久显示「写侧计数不可用」
// （侧车只在计数变化时写盘，本代无失败时标记不会被成功路径删除）；失败时刻取
// 标记内时间，不再每 tick 刷新成「现在」。

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolationForWriterHealth 隔离侧车路径与进程级健康状态（测试间共享全局）。
func isolationForWriterHealth(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	oldStart := securityEventsProcessStart
	// 侧车 written_at 是秒级 RFC3339：进程启动时刻回拨一分钟，避免「本代写入」
	// 因秒截断被判成上一代（代际判定边界属于该判据自身的测试范围）。
	securityEventsProcessStart = time.Now().Add(-time.Minute)
	reset := func() {
		securityEventsWriterHealth.mu.Lock()
		securityEventsWriterHealth.baselineDropped = 0
		securityEventsWriterHealth.baselineIO = 0
		securityEventsWriterHealth.droppedTotal = 0
		securityEventsWriterHealth.ioTotal = 0
		securityEventsWriterHealth.window.start = time.Time{}
		securityEventsWriterHealth.window.counter = 0
		securityEventsWriterHealth.lastFailureAt = time.Time{}
		securityEventsWriterHealth.sidecarReadFailures = 0
		securityEventsWriterHealth.sidecarWriteFailureHits = 0
		securityEventsWriterHealth.mu.Unlock()
	}
	reset()
	t.Cleanup(func() {
		auditLogPath = oldPath
		securityEventsProcessStart = oldStart
		reset()
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
}

func writeWriterStatsFailureMarker(t *testing.T, at time.Time) {
	t.Helper()
	body := "writer-stats sidecar write failed at " + at.UTC().Format(time.RFC3339) + ": disk full\n"
	if err := os.WriteFile(securityEventsAuditWriterStatsFailurePath(), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWriterStatsFailureMarker_staleGenerationIsIgnored(t *testing.T) {
	isolationForWriterHealth(t)
	securityEventsProcessStart = time.Now()
	writeWriterStatsFailureMarker(t, time.Now().Add(-48*time.Hour))

	for range securityEventsWriterFailureThreshold + 2 {
		securityEventsObserveAuditWriterStats()
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterStatsUnavailable {
		t.Fatal("上一代进程的失败标记不得让本代判「写侧计数不可用」")
	}
	if status.WriterLastFailureAt != "" {
		t.Fatalf("上一代标记不应写入失败时刻: %q", status.WriterLastFailureAt)
	}
	if !status.Healthy {
		t.Fatal("忽略陈旧标记后健康位不得降级")
	}
}

func TestWriterStatsFailureMarker_currentGenerationCountsAndKeepsMarkerTime(t *testing.T) {
	isolationForWriterHealth(t)
	securityEventsProcessStart = time.Now().Add(-time.Hour)
	markerAt := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	writeWriterStatsFailureMarker(t, markerAt)

	securityEventsObserveAuditWriterStats()
	status := SecurityEventsIngestionHealthSnapshot()
	want := markerAt.UTC().Format(time.RFC3339)
	if status.WriterLastFailureAt != want {
		t.Fatalf("失败时刻应取标记内时间 %q，得到 %q（旧实现每 tick 刷新为现在）", want, status.WriterLastFailureAt)
	}
	if status.WriterStatsUnavailable {
		t.Fatal("单轮观测未达阈值不得判不可用")
	}

	for i := 1; i < securityEventsWriterFailureThreshold; i++ {
		securityEventsObserveAuditWriterStats()
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if !status.WriterStatsUnavailable || status.Healthy {
		t.Fatalf("本代标记连续 %d 轮后应判不可用: unavailable=%v healthy=%v",
			securityEventsWriterFailureThreshold, status.WriterStatsUnavailable, status.Healthy)
	}
}
