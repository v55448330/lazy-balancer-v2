package services

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
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

func TestRotatingFileWriter_Write_reopensAfterCloseFailure(t *testing.T) {
	// Given a writer whose descriptor has already been closed underneath it;
	// rotateLocked observes a real os.File.Close error on the second close.
	path := filepath.Join(t.TempDir(), "runtime.log")
	writer, err := NewRotatingFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	oldSizeMB := runtimeLogSizeMB.Load()
	runtimeLogSizeMB.Store(100)
	t.Cleanup(func() { runtimeLogSizeMB.Store(oldSizeMB) })
	if err := writer.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.rotateLocked(); err == nil {
		t.Fatal("second close must fail to exercise the recovery path")
	}

	// When the next write arrives after that close failure.
	n, err := writer.Write([]byte("recovered\n"))

	// Then the poisoned descriptor is forgotten and the file is reopened.
	if err != nil || n != len("recovered\n") {
		t.Fatalf("write after close failure n=%d err=%v, want successful reopen", n, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "recovered\n") {
		t.Fatalf("log content=%q, want recovered entry", data)
	}
}

// LogFileEnabled 恒 true 的用户裁定意图在裸二进制
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
	InvalidateTaskLogSizeCache()
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

	res := RuntimeLogCleanupOnce(context.Background(), logFile)

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

// security-events-ingestion daemon 停机时
// audit.log 无守护无界增长（写侧在 Caddy 进程内持续追加，轮转仅由 daemon
// 2s tick 驱动）——log-cleanup 任务体补 waf-audit 超阈兜底：audit.log 走
// SecurityEventsPollOnce 全套安全链（daemon 在场时等价一次普通 tick）。
// （侧车退役，耗时随审计行内嵌流转。）
func TestTaskLogsHousekeeping_waitsForCertJobWriteLock(t *testing.T) {
	setupIsolatedDB(t)
	if months, err := auditRetentionMonths(t.Context()); err != nil {
		t.Fatalf("前置：审计保留月数口径不可用（保留期清理会被整体跳过，本用例测不到写锁等待）: %v", err)
	} else if months < 1 {
		t.Fatalf("前置：审计保留月数=%d，保留期清理不会删任何文件", months)
	}
	base := t.TempDir()
	logFile := filepath.Join(base, "app.log")
	certDir := filepath.Join(base, "tasks", "certjobs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(certDir, "certjob-lb_lock.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, -6, 0)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	lock := lockCertJobLog("lb_lock")
	lock.Lock()
	done := make(chan TaskLogHousekeepingResult, 1)
	go func() { done <- taskLogsHousekeeping(logFile) }()

	// 持锁期间清理不得删除（等待写入侧锁）。
	select {
	case res := <-done:
		lock.Unlock()
		t.Fatalf("清理未等待写入锁即删除: %+v", res)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := os.Stat(path); err != nil {
		lock.Unlock()
		t.Fatalf("持锁期间过期文件被删除: %v", err)
	}

	// 解锁后清理继续并删除过期文件（保留期用例回归）。
	lock.Unlock()
	select {
	case res := <-done:
		if len(res.Deleted) != 1 || res.Deleted[0] != "certjob-lb_lock.log" {
			t.Fatalf("解锁后应删除过期文件, got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("解锁后清理未完成")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("过期文件应已删除, stat err=%v", err)
	}
}

// 日志尺寸阈值读取必须在路径写锁之外完成（缓存未命中会读库，最坏占满
// busy_timeout）——写入方阻塞在尺寸求值时不持路径锁，保留期清理不得被它
// 阻塞；清理在锁内重读 ModTime，写入方随后新建/追加的文件保持 fresh 行。
//
// 与写锁用例同理：保留月数口径由本用例自己装配，否则保留期门跳过删除，
// 断言会把「保留期门未通过」误报成「尺寸求值阻塞了清理」。
func TestTaskLogsHousekeeping_runsWhileSizeEvalInFlight(t *testing.T) {
	setupIsolatedDB(t)
	if months, err := auditRetentionMonths(t.Context()); err != nil {
		t.Fatalf("前置：审计保留月数口径不可用（保留期清理会被整体跳过）: %v", err)
	} else if months < 1 {
		t.Fatalf("前置：审计保留月数=%d，保留期清理不会删任何文件", months)
	}
	base := t.TempDir()
	logFile := filepath.Join(base, "app.log")
	tasksDir := filepath.Join(base, "tasks")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(tasksDir)
	t.Cleanup(func() {
		taskengine.SetLogDir(oldDir)
		taskengine.SetTaskLogSizeBytesFn(nil)
	})
	path := taskengine.TaskLogPath("lock-root")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, -6, 0)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	taskengine.SetTaskLogSizeBytesFn(func() int64 {
		close(entered)
		<-release
		return int64(^uint64(0) >> 1)
	})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		taskengine.TeeTaskLog("lock-root", "2026/01/02 03:04:05", "INFO", "test", "fresh")
	}()
	<-entered // writer 正在尺寸求值（未持路径锁）。

	cleaned := make(chan TaskLogHousekeepingResult, 1)
	go func() { cleaned <- taskLogsHousekeeping(logFile) }()
	select {
	case res := <-cleaned:
		if len(res.Deleted) == 0 {
			close(release)
			<-writerDone
			t.Fatalf("清理应能删除陈旧文件（尺寸求值不持路径锁）: %+v", res)
		}
	case <-time.After(2 * time.Second):
		close(release)
		<-writerDone
		t.Fatal("尺寸求值阻塞了保留期清理（阈值求值必须在路径写锁之外）")
	}

	close(release)
	<-writerDone
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "fresh") {
		t.Fatalf("写入后的活动日志必须保留, err=%v body=%q", err, data)
	}
}

// 运行日志清理口径——

// writeStaleAppLogCopy 在 dir 下写入一份超保留期的 app.log.* 副本。
func writeStaleAppLogCopy(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("write stale log: %v", err)
	}
	old := time.Now().AddDate(0, -13, 0)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

// log-cleanup 摘要行的「保留 N 月」必须来自单源 auditRetentionMonths
// （经 RuntimeCleanupResult.RetentionMonths 回填），不得在 wire/摘要层另行查库
// 复算——同值两实现会在默认值/钳位逻辑变更时分裂（用户看到的保留期≠实际口径）。
func TestRuntimeLogCleanupOnce_reportsRetentionMonthsSingleSource(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=6 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	writeStaleAppLogCopy(t, dir, "app.log.1")

	// When
	res := RuntimeLogCleanupOnce(context.Background(), logFile)

	// Then：保留月数=单源取值，且与实际删除口径一致（13 月前副本超 6 月保留期）
	wantMonths, monthsErr := auditRetentionMonths(t.Context())
	if monthsErr != nil {
		t.Fatalf("读取保留月数: %v", monthsErr)
	}
	if got := res.RetentionMonths; got != wantMonths || got != 6 {
		t.Fatalf("RetentionMonths=%d, want %d（单源 auditRetentionMonths）", got, wantMonths)
	}
	if res.AppRemoved != 1 {
		t.Fatalf("AppRemoved=%d, want 1（13 月前副本超 6 月保留期须删除）", res.AppRemoved)
	}

	// Then：摘要行直接展示该单源值
	if summary := logCleanupSummaryLine(logFile); !strings.Contains(summary, "保留 6 月") {
		t.Fatalf("摘要行未使用单源保留月数: %q", summary)
	}
}

// （回归形状）：保留月数配置越界（<1）时单源回退默认 3 月——摘要行与
// 删除口径必须同回退（此前两处各自实现，一侧漏改即分裂）。
func TestRuntimeLogCleanupOnce_outOfRangeRetentionFallsBackToDefault(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")

	res := RuntimeLogCleanupOnce(context.Background(), logFile)
	if res.RetentionMonths != 3 {
		t.Fatalf("RetentionMonths=%d, want 3（越界回退默认）", res.RetentionMonths)
	}
	if summary := logCleanupSummaryLine(logFile); !strings.Contains(summary, "保留 3 月") {
		t.Fatalf("摘要行未体现默认回退: %q", summary)
	}
}

// 库未初始化/已关闭时保留月数口径未知：保留期删除（应用日志副本与任务日志）
// 一律跳过——nil 覆盖的正是「关停后 db.Close()、在途清理轮仍在跑」的形态，
// 按默认 3 月删除会把用户更长保留期内的日志不可逆删掉。不依赖保留期口径的
// 清理段（waf-audit 兜底、规则日志孤儿）仍在保留期门之前执行并各自留痕。
func TestRuntimeLogCleanupOnce_nilDBSkipsRetentionDeletion(t *testing.T) {
	oldDB, oldMetrics, oldAudit := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	db.DB, db.MetricsDB, db.AuditDB = nil, nil, nil
	db.SetDB(nil) // GetDB() 与 db.DB 是两个句柄来源，必须同时清空才是真实 nil 库形态
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetrics, oldAudit
		db.SetDB(oldCurrent)
	})

	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	writeStaleAppLogCopy(t, dir, "app.log.1")
	tasksDir := filepath.Join(dir, "tasks")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	staleTaskLog := filepath.Join(tasksDir, "stale.log")
	if err := os.WriteFile(staleTaskLog, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().AddDate(0, -13, 0)
	if err := os.Chtimes(staleTaskLog, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	oldAuditLogPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log") // 不存在：兜底 stat 不算失败
	t.Cleanup(func() { auditLogPath = oldAuditLogPath })

	res := RuntimeLogCleanupOnce(context.Background(), logFile)
	if res.RetentionError == "" {
		t.Fatal("nil 库时保留月数口径未知，必须记入 RetentionError")
	}
	if res.AppRemoved != 0 {
		t.Fatalf("nil 库时 AppRemoved=%d, want 0（口径未知时不得按默认保留期删除）", res.AppRemoved)
	}
	if len(res.TaskLogs.Deleted) != 0 {
		t.Fatalf("nil 库时 TaskLogs.Deleted=%v, want 空（口径未知时不得删除）", res.TaskLogs.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatalf("应用日志副本必须保留: %v", err)
	}
	if _, err := os.Stat(staleTaskLog); err != nil {
		t.Fatalf("任务日志必须保留: %v", err)
	}
	if err := res.Err(); err == nil {
		t.Fatal("保留期口径未知必须让本轮失败（不得静默成功）")
	}
	// 不依赖保留期口径的清理段仍执行：nil 库时孤儿规则日志扫描进错误面且不删除。
	if res.RuleLogs.ScanError == "" {
		t.Fatal("规则日志孤儿清理应在保留期门之前执行并留痕（nil 库=无可判定存活规则）")
	}
}

// 运行日志文件未打开（runtimeLogFile 为空）时摘要行必须是显式
// 「未启用」形态，而非静默零动作。
func TestLogCleanupSummaryLine_disabledShape(t *testing.T) {
	// 摘要行会带库派生段（孤儿规则日志扫描）：库未初始化时前缀变成
	// 「日志清理未完成」——本用例只钉「未启用」形态，必须显式装配库，
	// 不能依赖前序用例遗留的连接（-shuffle 下顺序一变即红）。
	initServicesDB(t)
	got := logCleanupSummaryLine("")
	if !strings.HasPrefix(got, "日志清理未启用") {
		t.Fatalf("logFile 为空时摘要=%q, want 「日志清理未启用…」", got)
	}
}

// Given 一个永不退出的日志尺寸刷新 worker（可控挂起：done 永不关闭——等价于
// refresh 阻塞在 DB busy_timeout 的生产形态）。
// When StopLogRotateWithin 以 50ms 上限调用。
// Then 按 deadline 放弃等待并返回 false（不再无界 <-done）；字段保留，
// worker 最终退出后可再次 Stop 完成清零（可重启语义不变）。
func TestStopLogRotateWithin_givesUpWhenWorkerStuck(t *testing.T) {
	// 包 init 不再自启 worker（首次刷新改由 main 在 db.Initialize 后触发）——
	// 本测试直接安装受控挂起的 worker 形态。
	stuck := make(chan struct{}) // 永不关闭
	runtimeLogSizeRefresh.Lock()
	runtimeLogSizeRefresh.cancel = func() {}
	runtimeLogSizeRefresh.done = stuck
	runtimeLogSizeRefresh.Unlock()

	begin := time.Now()
	if StopLogRotateWithin(50 * time.Millisecond) {
		t.Fatal("卡住的 worker 必须返回 false（放弃等待）")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("等待未受预算约束：耗时 %s（预算 50ms）", elapsed)
	}

	close(stuck)
	if !StopLogRotateWithin(2 * time.Second) {
		t.Fatal("worker 退出后 Stop 必须返回 true")
	}
	runtimeLogSizeRefresh.Lock()
	cleared := runtimeLogSizeRefresh.cancel == nil && runtimeLogSizeRefresh.done == nil
	runtimeLogSizeRefresh.Unlock()
	if !cleared {
		t.Fatal("worker 退出后字段必须清零（可重启语义不变）")
	}
}

// Given 正常运行的日志尺寸刷新 worker（init 形态，空闲 select 循环）。
// When StopLogRotateWithin 以充裕预算调用。
// Then 快速返回 true——正常路径不等满预算。
func TestStopLogRotateWithin_fastPathDoesNotConsumeBudget(t *testing.T) {
	StopLogRotateWithin(0)
	StartLogRotate(context.Background())
	t.Cleanup(func() {
		StopLogRotateWithin(0)
		StartLogRotate(context.Background())
	})

	begin := time.Now()
	if !StopLogRotateWithin(5 * time.Second) {
		t.Fatal("正常 worker 必须在预算内退出")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("正常路径耗时 %s，不得在预算内空等", elapsed)
	}
}

// 清理失败必须聚合进结果并让日志行不称「完成」：waf-audit 兜底轮转错误
// （daemon 停机 + 复制失败）此前被完全丢弃——任务日志仍称「日志清理完成」、
// task_runs 恒绿，磁盘被审计文件填满后才由写侧被动暴露。
func TestRuntimeLogCleanupOnce_skipsRetentionDeletionWhenReadFails(t *testing.T) {
	// Given：陈旧副本 + 陈旧任务日志 + 主库查询恒失败
	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	writeStaleAppLogCopy(t, dir, "app.log.1")
	tasksDir := filepath.Join(dir, "tasks")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	staleTaskLog := filepath.Join(tasksDir, "stale.log")
	if err := os.WriteFile(staleTaskLog, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().AddDate(0, -13, 0)
	if err := os.Chtimes(staleTaskLog, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	oldAuditLogPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log") // 不存在：兜底 stat 不算失败
	t.Cleanup(func() { auditLogPath = oldAuditLogPath })
	swapBrokenDB(t)

	// When
	res := RuntimeLogCleanupOnce(context.Background(), logFile)

	// Then：一条都不删，失败原因可见
	if res.RetentionError == "" {
		t.Fatal("保留月数读取失败必须记入 RetentionError")
	}
	if res.AppRemoved != 0 {
		t.Fatalf("AppRemoved=%d, want 0（口径未知时不得删除）", res.AppRemoved)
	}
	if len(res.TaskLogs.Deleted) != 0 {
		t.Fatalf("TaskLogs.Deleted=%v, want 空（口径未知时不得删除）", res.TaskLogs.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatalf("应用日志副本必须保留: %v", err)
	}
	if _, err := os.Stat(staleTaskLog); err != nil {
		t.Fatalf("任务日志必须保留: %v", err)
	}
	if err := res.Err(); err == nil {
		t.Fatal("保留月数读取失败必须让本轮失败")
	}
	if _, line := logCleanupRound(context.Background(), logFile); !strings.Contains(line, "保留月数读取失败") {
		t.Fatalf("摘要行必须披露保留月数读取失败: %q", line)
	}
}

// 任务日志单文件删除失败必须计数并进摘要（旧实现 err 直接忽略，摘要看起来
// 只是「没有过期文件」）。
func TestTaskLogsHousekeeping_countsDeletionFailures(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	tasksDir := filepath.Join(dir, "tasks")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(tasksDir, "stale.log")
	if err := os.WriteFile(stale, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().AddDate(0, -13, 0)
	if err := os.Chtimes(stale, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	// 扫描与删除之间没有测试缝，普通文件候选无法确定性地改写成
	// ENOTDIR 路径；保留权限注入，并显式排除会忽略权限位的 root。
	if os.Geteuid() == 0 {
		t.Skip("root 忽略目录权限位，无法构造任务日志删除失败")
	}
	// 目录只读：可列出/stat，非 root 下删除必然失败（权限形态）。
	if err := os.Chmod(tasksDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tasksDir, 0o755) })

	// When
	res := taskLogsHousekeeping(logFile)

	// Then
	if res.RemoveFailed != 1 {
		t.Fatalf("RemoveFailed=%d, want 1（删除失败必须计数）", res.RemoveFailed)
	}
	if summary := res.Summary(); !strings.Contains(summary, "删除失败 1 个") {
		t.Fatalf("摘要必须披露删除失败数: %q", summary)
	}
}

// 任务日志目录不可读必须进结果错误面（与应用日志侧 AppCleanupError 同口径）：
// 目录缺失是正常空目录（首次运行），ENOTDIR/权限等真实读失败不得静默成
// 「超期删除 0 个」+ 任务 success。
func TestTaskLogsHousekeeping_scanFailureEntersErrorSurface(t *testing.T) {
	base := t.TempDir()
	logFile := filepath.Join(base, "app.log")
	// tasks 路径被普通文件占据 → os.ReadDir 返回 ENOTDIR（非 NotExist）。
	if err := os.WriteFile(filepath.Join(base, "tasks"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := taskLogsHousekeepingWithRetention(logFile, 3, nil)
	if res.ScanError == "" {
		t.Fatalf("目录读取失败必须记录 ScanError: %+v", res)
	}
	if !strings.Contains(res.ScanError, "tasks") {
		t.Fatalf("ScanError=%q 必须含失败目录路径", res.ScanError)
	}
	agg := RuntimeCleanupResult{TaskLogs: res}
	if err := agg.Err(); err == nil || !strings.Contains(err.Error(), "任务日志目录读取失败") {
		t.Fatalf("Err()=%v，目录读取失败必须聚合进错误面", err)
	}
	if summary := res.Summary(); !strings.Contains(summary, "目录读取失败") {
		t.Fatalf("摘要必须披露目录读取失败: %q", summary)
	}
}

// 目录不存在＝尚未产生任务日志，属正常空目录，不得计为扫描失败。
func TestTaskLogsHousekeeping_missingDirIsNotScanFailure(t *testing.T) {
	base := t.TempDir()
	res := taskLogsHousekeepingWithRetention(filepath.Join(base, "app.log"), 3, nil)
	if res.ScanError != "" {
		t.Fatalf("缺失目录不得计为扫描失败: %+v", res)
	}
	if res.InfoFailed != 0 {
		t.Fatalf("InfoFailed=%d, want 0", res.InfoFailed)
	}
}

// 运行日志 writer 打开失败时 waf-audit 兜底仍须执行（不同目录、独立失败面）：
// 旧实现因 logFile=="" 直接跳过兜底，daemon 停机场景下 audit.log 无界增长。
func TestRuntimeLogCleanupOnce_countsAppMetadataFailures(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logFile := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logFile, []byte("current\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := logFile + ".2020-01-01"
	if err := os.WriteFile(stale, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().AddDate(0, -13, 0)
	if err := os.Chtimes(stale, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	// Given：副本的元数据采集恒失败
	oldInfo := appLogEntryInfo
	appLogEntryInfo = func(os.DirEntry) (os.FileInfo, error) { return nil, errors.New("injected stat failure") }
	t.Cleanup(func() { appLogEntryInfo = oldInfo })

	// When
	res := RuntimeLogCleanupOnce(context.Background(), logFile)

	// Then：失败计数、错误面、摘要三处可见，且本轮未删除
	if res.AppInfoFailed != 1 {
		t.Fatalf("AppInfoFailed=%d, want 1", res.AppInfoFailed)
	}
	if res.AppRemoved != 0 {
		t.Fatalf("AppRemoved=%d, want 0（无法判定过期不得删除）", res.AppRemoved)
	}
	if err := res.Err(); err == nil || !strings.Contains(err.Error(), "应用日志副本元数据读取失败 1 个") {
		t.Fatalf("Err()=%v，元数据读取失败必须聚合进错误面", err)
	}
	if detail := logCleanupDetail(res); !strings.Contains(detail, "元数据读取失败 1 个") {
		t.Fatalf("摘要必须披露元数据读取失败: %q", detail)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("无法判定过期的副本不得被删除: %v", err)
	}
}

// Close 必须弃句柄：关停顺序/热切换中 Close 先于最后几条日志时，后续 Write
// 不得命中 file already closed（标准 log 会丢该错误 → 静默丢日志），须自愈重开。
func TestRotatingFileWriter_Write_reopensAfterExplicitClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	writer, err := NewRotatingFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	oldSizeMB := runtimeLogSizeMB.Load()
	runtimeLogSizeMB.Store(100)
	t.Cleanup(func() { runtimeLogSizeMB.Store(oldSizeMB) })

	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	n, err := writer.Write([]byte("after-close\n"))
	if err != nil || n != len("after-close\n") {
		t.Fatalf("Close 后 Write n=%d err=%v, want 自愈重开", n, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "after-close\n") {
		t.Fatalf("log content=%q, want after-close entry", data)
	}
}

// B 形态后 audit.log 仅是兜底缓存，由摄取链路负责；log-cleanup 不得再轮转/截断它。
func TestRuntimeLogCleanupOnce_doesNotTouchWafAuditFallback(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes := auditLogPath, auditLogSizeBytes
	auditLogPath = logPath
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes = oldLogPath, oldSizeBytes })

	content := []byte(`{"transaction":{"id":"legacy-fallback"}}` + "\n")
	if err := os.WriteFile(logPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = RuntimeLogCleanupOnce(context.Background(), filepath.Join(dir, "app.log"))
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("audit.log must remain readable: %v", err)
	}
	if string(after) != string(content) {
		t.Fatalf("log-cleanup 不得改写/截断 audit.log: got %q want %q", string(after), string(content))
	}
	if _, err := os.Stat(logPath + ".1"); !os.IsNotExist(err) {
		t.Fatalf("log-cleanup 不得轮转 audit.log（.1 不应存在）: %v", err)
	}
}
