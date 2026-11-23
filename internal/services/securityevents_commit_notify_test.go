package services

// （回归）：摄取通知副作用（拦截聚合/挑战计数/CC 触发）必须等到批次事务
// 提交成功后再执行。提交失败会回滚并重放同一批——旧实现已提前计数，重放
// 让阈值提前达成/重复 CC 通知。

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestSecurityEventsIngestion_notifySideEffectsOnlyAfterCommit(t *testing.T) {
	dataDir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	originalMetrics := db.MetricsDB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	})
	driverStub := registerCommitFailDriver(t)
	driverStub.fail.Store(false)
	wrapped, err := sql.Open(commitFailDriverName, filepath.Join(dataDir, db.MetricsDBFilename)+"?_pragma=busy_timeout(30000)")
	if err != nil {
		t.Fatal(err)
	}
	wrapped.SetMaxOpenConns(1)
	db.MetricsDB = wrapped
	t.Cleanup(func() {
		_ = wrapped.Close()
		db.MetricsDB = originalMetrics
	})

	// 通知副作用计数替身（生产为 notify 包实现）。
	oldBlocked := notifyRecordBlockedEvent
	var blockedCalls atomic.Int64
	notifyRecordBlockedEvent = func(string, string, string) { blockedCalls.Add(1) }
	t.Cleanup(func() { notifyRecordBlockedEvent = oldBlocked })

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatalf("write audit fixture: %v", err)
	}
	oldAuditLog, oldAuditOffset := auditLogPath, securityEventsOffsetPath
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	resetSecurityEventsPollState(t)
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath = oldAuditLog, oldAuditOffset
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	// 提交失败轮：行插入成功但事务回滚 → 通知副作用必须为零（旧实现在
	// INSERT 后立即计数，这里会是 1）。
	driverStub.fail.Store(true)
	if got, _ := securityEventsPollOnce(context.Background()); got != 0 {
		t.Fatalf("提交失败轮摄取=%d, want 0", got)
	}
	if got := blockedCalls.Load(); got != 0 {
		t.Fatalf("提交失败轮拦截聚合计数=%d, want 0（副作用不得先于提交）", got)
	}

	// 恢复轮重放同一事务：计数恰好 1（不因重放重复）。
	driverStub.fail.Store(false)
	if got, _ := securityEventsPollOnce(context.Background()); got != 1 {
		t.Fatalf("恢复轮摄取=%d, want 1", got)
	}
	if got := blockedCalls.Load(); got != 1 {
		t.Fatalf("恢复轮拦截聚合计数=%d, want 1（重放不得重复计数）", got)
	}
}
