package caddyl4sec

// L4 事件管线生产收尾冲刷钉测：FlushL4Pipeline 必须有生产收尾冲刷，
// 进程退出/Cleanup 时环内+批内尾部行不得静默丢失（镜像 HTTP FlushAuditPipelines）。

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// FlushL4Pipeline 冲刷进程级管线尾部行（不关闭管线，进程级单例裁决不变）。
func TestFlushL4Pipeline_drainsTailEvents(t *testing.T) {
	socket, bodies := startUnixIngestServer(t, http.StatusNoContent)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	defer p.resetForTest()

	l1 := buildL4EventLine(2, "IP 黑名单拒绝", "r1", "203.0.113.1", time.Unix(1, 11), [4]byte{1, 2, 3, 4}, true)
	p.enqueueEvent(l1)
	// 不手动 flushQuiescedForTest，直接调生产收尾函数——尾部行必须送达。
	FlushL4Pipeline()

	got := bodies()
	if len(got) == 0 {
		t.Fatal("FlushL4Pipeline 必须冲刷尾部行到 ingest（停机静默丢失回归钉）")
	}
	sent, _, _, _ := p.shipperCounters()
	if sent != 1 {
		t.Fatalf("sent = %d, want 1（尾部行经 FlushL4Pipeline 送达）", sent)
	}
}

// 无管线时 FlushL4Pipeline 安全 no-op（未创建=nil）。
func TestFlushL4Pipeline_nilSafe(t *testing.T) {
	FlushL4Pipeline() // 不得 panic
}
