package services

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 轮转阈值读取必须可取消：轮转由安全事件摄取的 2s tick 驱动，tick 处在有界
// 关停/导入排空预算内。此前这里是无 ctx 的 QueryRow——主库被写事务占住时这
// 一读最坏阻塞整个 busy_timeout，把关停拖过预算。
//
// 夹具：主库挂「查询闸门」句柄（installBlockableMainDB），阈值查询到达闸门后
// 取消 ctx——读取必须立即按 ctx 返回（回退默认阈值，本轮不轮转）。
func TestRotateAuditLog_thresholdReadHonorsContext(t *testing.T) {
	// 阈值读走真实主库（db.DB 必须已装配）：blockableConnector 换的是主库句柄。
	newClusterTestService(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte("{\"client_ip\":\"10.0.0.1\"}\n"), 0o644); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}
	oldLog, oldOffset, oldSize := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath = logPath
	securityEventsOffsetPath = filepath.Join(dir, "security-events.offset")
	// 本用例要真实走「读库取阈值」路径：复位注入缝并失效 60s TTL 缓存。
	auditLogSizeBytes = getAuditLogSizeBytesContext
	auditLogSizeValueCache.invalidate()
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLog, oldOffset, oldSize
		auditLogSizeValueCache.invalidate()
	})

	gate := installBlockableMainDB(t)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := rotateAuditLogIfNeeded(ctx)
		done <- err
	}()

	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("阈值查询未到达闸门（缓存未失效或读取路径已变化，夹具失效）")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("ctx 取消后轮转仍阻塞在阈值读取（读库未走 QueryRowContext）")
	}
	release()

	// 阈值未知时不得轮转（回退默认阈值当轮生效的既有语义）：
	// 归档代际不得推进、活文件不得被截断。
	if _, err := os.Stat(logPath + ".1"); err == nil {
		t.Fatal("阈值读取被取消时不得轮转（归档 .1 不应出现）")
	}
	content, err := os.ReadFile(logPath)
	if err != nil || len(content) == 0 {
		t.Fatalf("活文件不得被截断: err=%v len=%d", err, len(content))
	}
}
