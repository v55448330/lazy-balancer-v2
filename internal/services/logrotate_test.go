package services

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestRotatingFileWriter_Write_returns_rotation_reopen_error(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "runtime.log")
	writer, err := NewRotatingFileWriter(path)
	if err != nil {
		t.Fatalf("create rotating writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	runtimeLogSizeMB.Store(0)
	t.Cleanup(func() { runtimeLogSizeMB.Store(100) })
	writer.path = filepath.Join(path, "missing", "runtime.log")

	// When
	n, err := writer.Write([]byte("entry"))

	// Then
	if err == nil || n != 0 {
		t.Fatalf("rotation failure write n=%d err=%v, want no write and an error", n, err)
	}
	if !strings.Contains(err.Error(), "rotate log file") || strings.Contains(err.Error(), "file already closed") {
		t.Fatalf("write error=%q, want reopen failure", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("original log file disappeared: %v", statErr)
	}
}

// SECLB23-P3-1(第 23 轮审计):LogFileEnabled 恒 true 的用户裁定意图在裸二进制
// 部署落空——open() 不建父目录,/app/logs 不存在时恒回退 stdout。必须 MkdirAll。
func TestNewRotatingFileWriter_createsParentDirs(t *testing.T) {
	// Given: 不存在的嵌套父目录(模拟裸二进制无 /app/logs)
	path := filepath.Join(t.TempDir(), "app", "logs", "lazy-balancer.log")

	// When
	w, err := NewRotatingFileWriter(path)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter with missing parent dirs: %v", err)
	}
	defer w.Close()

	// Then: 文件可写(父目录已建)
	if _, err := w.Write([]byte("test\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log file not created: %v", err)
	}
}

// Given tasks 目录存在：超保留期文件 + 超大小上限文件 + 正常文件。
// When taskLogsHousekeeping。
// Then 删除/轮转明细如实上报（文件名+大小对比+上限值——2026-10-01 用户
// 裁定：清理了哪个文件必须在任务日志可见）；大小上限遵循 task_log_size_mb。
func TestTaskLogsHousekeeping_reportsDetails(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	tasksDir := filepath.Join(dir, "tasks")
	if err := os.MkdirAll(tasksDir, 0755); err != nil {
		t.Fatal(err)
	}
	// 配置上限 1MB + 保留 3 月
	if _, err := db.DB.Exec(`UPDATE global_config SET task_log_size_mb=1, audit_retention_months=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 强制刷新大小缓存（5min TTL 会命中旧值）
	certJobLogSizeCachedAt.Store(0)
	// 超期文件（4 个月前）
	old := filepath.Join(tasksDir, "stale.log")
	if err := os.WriteFile(old, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, time.Now().AddDate(0, -4, 0), time.Now().AddDate(0, -4, 0)); err != nil {
		t.Fatal(err)
	}
	// 超限文件（2MB > 1MB）
	if err := os.WriteFile(filepath.Join(tasksDir, "big.log"), bytes.Repeat([]byte("y"), 2*1024*1024), 0644); err != nil {
		t.Fatal(err)
	}
	// 正常文件
	if err := os.WriteFile(filepath.Join(tasksDir, "ok.log"), []byte("z"), 0644); err != nil {
		t.Fatal(err)
	}

	res := RuntimeLogCleanupOnce(logFile)

	if len(res.TaskLogs.Deleted) != 1 || res.TaskLogs.Deleted[0] != "stale.log" {
		t.Fatalf("Deleted=%v, want [stale.log]", res.TaskLogs.Deleted)
	}
	// 摘要含保留期清理要素，且不再声称由清理任务做尺寸滚动
	s := res.TaskLogs.Summary()
	if !strings.Contains(s, "stale.log") || !strings.Contains(s, "尺寸滚动由写入侧统一执行") {
		t.Fatalf("Summary 缺要素: %q", s)
	}
	// 文件终态：stale 删、big 保留且不得被二次轮转、ok 保留
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("stale.log 应已删除")
	}
	if _, err := os.Stat(filepath.Join(tasksDir, "big.log.1")); !os.IsNotExist(err) {
		t.Fatal("big.log 不得由保留期清理再次轮转为 big.log.1")
	}
	if _, err := os.Stat(filepath.Join(tasksDir, "ok.log")); err != nil {
		t.Fatal("ok.log 应保留")
	}
}

// F-L3-68-01（第 68 轮审计）：security-events-ingestion daemon 停机时
// audit.log 无守护无界增长（写侧在 Caddy 进程内持续追加，轮转仅由 daemon
// 2s tick 驱动）——log-cleanup 任务体补 waf-audit 超阈兜底：audit.log 走
// SecurityEventsPollOnce 全套安全链（daemon 在场时等价一次普通 tick）。
// （第 76 轮：侧车退役，耗时随审计行内嵌流转。）
func TestRuntimeLogCleanupOnce_wafAuditFallbackWhenIngestionStopped(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1024 }
	resetSecurityEventsPollState(t)
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})

	// daemon 停机形态：audit.log 超阈（2KB > 1KB 阈值）且无人轮转。
	if err := os.WriteFile(logPath, bytes.Repeat([]byte("x"), 2048), 0644); err != nil {
		t.Fatal(err)
	}
	res := RuntimeLogCleanupOnce(filepath.Join(dir, "app.log"))

	// audit.log 经完整安全链轮转为 .1、活文件截断归零，明细如实上报。
	if st, err := os.Stat(logPath); err != nil || st.Size() != 0 {
		sz := int64(-1)
		if st != nil {
			sz = st.Size()
		}
		t.Fatalf("audit.log 兜底后 size=%d err=%v，应已轮转截断为 0", sz, err)
	}
	if len(res.WafAudit) == 0 {
		t.Fatal("WafAudit 明细为空——兜底动作必须可见（2026-10-01 用户裁定口径）")
	}
}
