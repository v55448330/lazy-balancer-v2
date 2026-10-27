package services

// B 形态（IPC 主路径 + fallback spool）的服务侧验收：
//   - IngestSecurityEventBatch：入库成功/transaction_id 去重/请求级去重复用；
//   - spool 补采：commit 后才删除、失败保留并退避、active 不删不截断、孤儿封存；
//   - spool 状态：条目/字节/上限/不可读，健康位与「待补采≠丢失」口径；
//   - 旧 audit.log 兼容：仍可被消费一次，之后不再新增。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// setupSecurityEventsSpoolTest 初始化隔离库 + 独立 spool 目录，并复位进程级
// 缓存/退避状态（顺序依赖下上一用例的退避会让本轮 drain 直接跳过）。
func setupSecurityEventsSpoolTest(t *testing.T) string {
	t.Helper()
	setupIsolatedDB(t)
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	spoolDir := filepath.Join(t.TempDir(), "security-events-spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SecurityEventsSpoolDirEnv, spoolDir)
	ResetSecurityEventsSpoolStateForTest()
	t.Cleanup(ResetSecurityEventsSpoolStateForTest)
	return spoolDir
}

// securityEventsTestAuditLine 构造一行写侧形态的 audit JSON（caddygeoip
// auditwriter 输出形态：messages 是 transaction 的顶层兄弟）。
func securityEventsTestAuditLine(txID, clientIP, timingID, uri string, blocked bool, ts int64) string {
	headers := map[string][]string{"host": {"example.com"}}
	if timingID != "" {
		headers["x-lb-security-timing-id"] = []string{timingID}
	}
	rawHeaders, err := json.Marshal(headers)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`{"transaction":{"unix_timestamp":%d,"id":%q,"client_ip":%q,"server_id":"example.com","request":{"method":"GET","uri":%q,"headers":%s},"is_interrupted":%t},"messages":[{"message":"test rule matched","data":{"id":"942100","raw":"SecRule ARGS"}}]}`,
		ts, txID, clientIP, uri, rawHeaders, blocked)
}

func securityEventsTestRowCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&n); err != nil {
		t.Fatalf("count security_events: %v", err)
	}
	return n
}

func TestIngestSecurityEventBatch_insertsAndDedupesTransactionID(t *testing.T) {
	setupSecurityEventsSpoolTest(t)
	raw := []byte(securityEventsTestAuditLine("tx-ipc-1", "203.0.113.10", "", "/a", false, 1786447018) + "\n" +
		securityEventsTestAuditLine("tx-ipc-2", "203.0.113.11", "", "/b", true, 1786447019) + "\n")

	// 临时输入文件必须清理：记录入参前的同前缀文件数。
	before := securityEventsBatchTempFiles(t)

	n, err := IngestSecurityEventBatch(context.Background(), raw)
	if err != nil {
		t.Fatalf("ingest batch: %v", err)
	}
	if n != 2 {
		t.Fatalf("ingested=%d, want 2", n)
	}
	if got := securityEventsTestRowCount(t); got != 2 {
		t.Fatalf("rows=%d, want 2", got)
	}

	// 重复投递同一批（写侧重试/spool 补采重放）：transaction_id 唯一索引去重，
	// 返回新增 0，不重复入库。
	n, err = IngestSecurityEventBatch(context.Background(), raw)
	if err != nil {
		t.Fatalf("re-ingest batch: %v", err)
	}
	if n != 0 {
		t.Fatalf("re-ingest inserted=%d, want 0 (dedupe by transaction_id)", n)
	}
	if got := securityEventsTestRowCount(t); got != 2 {
		t.Fatalf("rows after replay=%d, want 2", got)
	}
	if after := securityEventsBatchTempFiles(t); after > before {
		t.Fatalf("批量入库遗留临时文件：before=%d after=%d", before, after)
	}
}

// securityEventsBatchTempFiles 统计批量入库临时文件残留（受限临时文件必须
// 处理完即删；同名前缀只有本路径会创建）。
func securityEventsBatchTempFiles(t *testing.T) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "lb-security-events-batch-*.jsonl"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	return len(matches)
}

func TestIngestSecurityEventBatch_reusesRequestDedupe(t *testing.T) {
	setupSecurityEventsSpoolTest(t)
	// 同一请求（共享 X-Lb-Security-Timing-Id）的两个引擎事务：先 logged 后
	// blocked——必须归并为一行且结论升级为 blocked（复用既有请求级去重语义，
	// 不得变成两行或保留 logged 结论）。
	raw := []byte(securityEventsTestAuditLine("tx-engine-1", "203.0.113.20", "req-key-1", "/dup", false, 1786447020) + "\n" +
		securityEventsTestAuditLine("tx-engine-2", "203.0.113.20", "req-key-1", "/dup", true, 1786447021) + "\n")

	n, err := IngestSecurityEventBatch(context.Background(), raw)
	if err != nil {
		t.Fatalf("ingest batch: %v", err)
	}
	if n != 1 {
		t.Fatalf("ingested=%d, want 1 (same request merged)", n)
	}
	var action string
	if err := db.MetricsDB.QueryRow(`SELECT action FROM security_events WHERE client_ip='203.0.113.20'`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "blocked" {
		t.Fatalf("action=%q, want blocked（后到的拦截结论必须覆盖先到的检测）", action)
	}
}

func TestIngestSecurityEventBatch_dbFailureReturnsError(t *testing.T) {
	setupSecurityEventsSpoolTest(t)
	// 关闭 metrics 库句柄模拟入库不可用（DB busy/损坏同属「本次失败、可重试」）。
	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatalf("close metrics db: %v", err)
	}
	n, err := IngestSecurityEventBatch(context.Background(), []byte(securityEventsTestAuditLine("tx-fail-1", "203.0.113.30", "", "/x", false, 1786447022)+"\n"))
	if err == nil {
		t.Fatal("ingest with closed metrics DB must fail")
	}
	if n != 0 {
		t.Fatalf("ingested=%d, want 0 on failure", n)
	}
}

func TestDrainSecurityEventsSpool_removesSealedAfterCommit(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	sealedOne := filepath.Join(spoolDir, "sealed-1700000000000000001.jsonl")
	sealedTwo := filepath.Join(spoolDir, "sealed-1700000000000000002.jsonl")
	active := filepath.Join(spoolDir, "active-"+fmt.Sprint(os.Getpid())+"-1.jsonl")
	for i, path := range []string{sealedOne, sealedTwo} {
		line := securityEventsTestAuditLine(fmt.Sprintf("tx-spool-%d", i), "203.0.113.40", "", "/spool", false, 1786447030+int64(i))
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// active：写侧仍在追加的形态（不完整末行也存在），补采绝不能动它。
	activeContent := securityEventsTestAuditLine("tx-active-1", "203.0.113.41", "", "/active", false, 1786447040) + "\n"
	if err := os.WriteFile(active, []byte(activeContent), 0o600); err != nil {
		t.Fatal(err)
	}

	ingested, err := drainSecurityEventsSpool(context.Background())
	if err != nil {
		t.Fatalf("drain spool: %v", err)
	}
	if ingested != 2 {
		t.Fatalf("ingested=%d, want 2 (sealed files only)", ingested)
	}
	if got := securityEventsTestRowCount(t); got != 2 {
		t.Fatalf("rows=%d, want 2", got)
	}
	for _, path := range []string{sealedOne, sealedTwo} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("sealed 文件必须在 commit 成功后删除: %s err=%v", path, err)
		}
	}
	// active 不删不截断：内容逐字节保留（写侧还在追加）。
	data, err := os.ReadFile(active)
	if err != nil {
		t.Fatalf("active file must be preserved: %v", err)
	}
	if string(data) != activeContent {
		t.Fatalf("active 文件被改写：%q", string(data))
	}
	// 统计：active 仍计为待补采（未入库），sealed 已清空。
	status := SecurityEventsSpoolSnapshot()
	if status.SealedFiles != 0 || status.ActiveFiles != 1 || status.Entries != 1 {
		t.Fatalf("spool status=%+v, want sealed=0 active=1 entries=1", status)
	}
}

func TestDrainSecurityEventsSpool_keepsFailedFileAndBacksOff(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	sealed := filepath.Join(spoolDir, "sealed-1700000000000000003.jsonl")
	if err := os.WriteFile(sealed, []byte(securityEventsTestAuditLine("tx-spool-fail", "203.0.113.50", "", "/fail", false, 1786447050)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := drainSecurityEventsSpool(context.Background()); err == nil {
		t.Fatal("drain must fail when DB unavailable")
	}
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("入库失败的 sealed 文件必须保留（待下一轮补采）: %v", err)
	}
	// 退避窗口内不再重试（本轮返回成功且不触碰文件），待补采条目仍在统计里。
	securityEventsSpoolState.mu.Lock()
	backoff := time.Until(securityEventsSpoolState.nextAttempt)
	failures := securityEventsSpoolState.drainFailures
	securityEventsSpoolState.mu.Unlock()
	if failures != 1 || backoff <= 0 {
		t.Fatalf("failures=%d backoff=%s, want 1 次失败且已进入退避", failures, backoff)
	}
	ingested, err := drainSecurityEventsSpool(context.Background())
	if err != nil || ingested != 0 {
		t.Fatalf("退避窗口内 drain=(%d,%v), want (0,nil)", ingested, err)
	}
	status := SecurityEventsSpoolSnapshot()
	if status.Entries != 1 || status.SealedFiles != 1 {
		t.Fatalf("spool status=%+v, want 1 条待补采仍在", status)
	}
	if status.LastError == "" || status.ConsecutiveFailures != 1 {
		t.Fatalf("spool status 必须披露补采失败: %+v", status)
	}
}

func TestDrainSecurityEventsSpool_sealsOrphanedActiveAndLeavesLiveOne(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	// 孤儿：pid 不可能存在（~4M 超出常见 pid_max 且不会被分配），mtime 静默。
	orphan := filepath.Join(spoolDir, "active-4194000-1.jsonl")
	if err := os.WriteFile(orphan, []byte(securityEventsTestAuditLine("tx-orphan", "203.0.113.60", "", "/orphan", false, 1786447060)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(orphan, old, old); err != nil {
		t.Fatal(err)
	}
	// 存活 pid（本进程）：即使静默也不得封存。
	live := filepath.Join(spoolDir, "active-"+fmt.Sprint(os.Getpid())+"-1.jsonl")
	if err := os.WriteFile(live, []byte(securityEventsTestAuditLine("tx-live", "203.0.113.61", "", "/live", false, 1786447061)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(live, old, old); err != nil {
		t.Fatal(err)
	}

	n, err := drainSecurityEventsSpool(context.Background())
	if err != nil {
		t.Fatalf("drain spool: %v", err)
	}
	if n != 1 {
		t.Fatalf("ingested=%d, want 1 (只有孤儿 active 被补采)", n)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("孤儿 active 应封存后补采删除: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("存活进程的 active 不得被移动/删除: %v", err)
	}
}

func TestSecurityEventsSpoolSnapshot_reportsEntriesBytesAndLimits(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	t.Setenv(SecurityEventsSpoolMaxEntriesEnv, "10")
	t.Setenv(SecurityEventsSpoolMaxBytesEnv, "4096")
	line := securityEventsTestAuditLine("tx-count-1", "203.0.113.70", "", "/count", false, 1786447070) + "\n"
	// 2 条 sealed（含一个空行）+ 1 条 active（末行无换行也要计入）。
	writeSpoolFile(t, filepath.Join(spoolDir, "sealed-1700000000000000011.jsonl"), line+"\n"+line)
	writeSpoolFile(t, filepath.Join(spoolDir, "active-4194001-1.jsonl"), line[:len(line)-1])

	status := SecurityEventsSpoolSnapshot()
	if status.SealedFiles != 1 || status.ActiveFiles != 1 {
		t.Fatalf("files=(sealed %d, active %d), want (1,1)", status.SealedFiles, status.ActiveFiles)
	}
	if status.Entries != 3 {
		t.Fatalf("entries=%d, want 3（空行不计，末行无换行计入）", status.Entries)
	}
	if status.Bytes <= 0 {
		t.Fatalf("bytes=%d, want >0", status.Bytes)
	}
	if status.LimitEntries != 10 || status.LimitBytes != 4096 {
		t.Fatalf("limits=(%d,%d), want (10,4096)", status.LimitEntries, status.LimitBytes)
	}
	if status.Unavailable || status.Saturated {
		t.Fatalf("status=%+v, want neither unavailable nor saturated", status)
	}

	// 上限压到 1 条：已达上限必须标饱和（写侧可能正在丢弃新事件）。
	t.Setenv(SecurityEventsSpoolMaxEntriesEnv, "1")
	status = securityEventsSpoolStatusFresh()
	if !status.Saturated {
		t.Fatalf("status=%+v, want saturated（entries>=limit）", status)
	}
}

func writeSpoolFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityEventsSpoolSnapshot_unreadableDirIsUnavailableNotZero(t *testing.T) {
	setupSecurityEventsSpoolTest(t)
	// 目录路径被普通文件占用：ReadDir 失败 → 必须标 unavailable（不得报 0 条）。
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SecurityEventsSpoolDirEnv, filePath)
	status := securityEventsSpoolStatusFresh()
	if !status.Unavailable {
		t.Fatalf("status=%+v, want unavailable", status)
	}
}

func TestSecurityEventsIngestionHealth_exposesSpoolAsPendingNotLoss(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	resetSecurityEventsPollState(t)
	writeSpoolFile(t, filepath.Join(spoolDir, "sealed-1700000000000000021.jsonl"),
		securityEventsTestAuditLine("tx-health-1", "203.0.113.80", "", "/h", false, 1786447080)+"\n")

	status := SecurityEventsIngestionHealthSnapshot()
	if status.SpoolPendingEntries != 1 || status.SpoolFiles != 1 || status.SpoolPendingBytes <= 0 {
		t.Fatalf("health spool fields=%+v, want 1 条/1 文件/正字节", status)
	}
	if status.DataLoss {
		t.Fatal("待补采条目不得被报告为永久丢失（data_loss）")
	}

	// 连续补采失败达阈值 → 健康位降级（积压未入库必须可见）。
	securityEventsSpoolState.mu.Lock()
	securityEventsSpoolState.drainFailures = securityEventsIngestionFailureThreshold
	securityEventsSpoolState.drainErr = "database is locked"
	securityEventsSpoolState.drainErrAt = time.Now()
	securityEventsSpoolState.mu.Unlock()
	status = SecurityEventsIngestionHealthSnapshot()
	if status.Healthy {
		t.Fatalf("health=%+v, want unhealthy（补采连续失败达阈值）", status)
	}
	if status.SpoolConsecutiveFailures != securityEventsIngestionFailureThreshold || status.SpoolLastError == "" {
		t.Fatalf("health spool failure fields=%+v, want failures=%d 且带 last_error", status, securityEventsIngestionFailureThreshold)
	}
}

func TestDrainSecurityEventsSpool_clearsDirectoryAfterBackfill(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	for i := range 3 {
		writeSpoolFile(t, filepath.Join(spoolDir, fmt.Sprintf("sealed-170000000000000003%d.jsonl", i)),
			securityEventsTestAuditLine(fmt.Sprintf("tx-clear-%d", i), "203.0.113.90", "", "/clear", false, 1786447090+int64(i))+"\n")
	}
	if _, err := drainSecurityEventsSpool(context.Background()); err != nil {
		t.Fatalf("drain spool: %v", err)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("补采后 spool 目录必须为空, 残留=%v", names)
	}
	if got := securityEventsTestRowCount(t); got != 3 {
		t.Fatalf("rows=%d, want 3", got)
	}
}

// 旧 audit.log 兼容：既有尾读路径仍可消费一次存量文件，且不再产生新内容后
// 不会重复入库（offset 持久化 + transaction_id 唯一索引）。
func TestSecurityEventsLegacyAuditLog_consumedOnceThenStable(t *testing.T) {
	setupSecurityEventsSpoolTest(t)
	dir := t.TempDir()
	oldLog, oldOffset := auditLogPath, securityEventsOffsetPath
	auditLogPath = filepath.Join(dir, "audit.log")
	securityEventsOffsetPath = filepath.Join(dir, "security-events.offset")
	t.Cleanup(func() { auditLogPath, securityEventsOffsetPath = oldLog, oldOffset })
	resetSecurityEventsPollState(t)

	line := securityEventsTestAuditLine("tx-legacy-1", "203.0.113.99", "", "/legacy", false, 1786447100) + "\n"
	if err := os.WriteFile(auditLogPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	ingested, rotErr := SecurityEventsPollOnce()
	if rotErr != nil {
		t.Fatalf("legacy poll: %v", rotErr)
	}
	if ingested != 1 {
		t.Fatalf("ingested=%d, want 1（旧 audit.log 仍可被消费）", ingested)
	}
	if got := securityEventsTestRowCount(t); got != 1 {
		t.Fatalf("rows=%d, want 1", got)
	}

	// 第二轮：文件不再增长 → 无新增、无重复（offset 已持久化）。
	ingested, rotErr = SecurityEventsPollOnce()
	if rotErr != nil {
		t.Fatalf("second legacy poll: %v", rotErr)
	}
	if ingested != 0 {
		t.Fatalf("ingested=%d, want 0（存量只消费一次）", ingested)
	}
	if got := securityEventsTestRowCount(t); got != 1 {
		t.Fatalf("rows=%d, want 1 (no duplicate)", got)
	}
	if data, err := os.ReadFile(securityEventsOffsetPath); err != nil || strings.TrimSpace(string(data)) == "" {
		t.Fatalf("摄取 offset 必须持久化（存量只消费一次的依据）: data=%q err=%v", string(data), err)
	}
}

func TestDrainSecurityEventsSpool_recoversAfterBackoff(t *testing.T) {
	spoolDir := setupSecurityEventsSpoolTest(t)
	sealed := filepath.Join(spoolDir, "sealed-1700000000000000041.jsonl")
	writeSpoolFile(t, sealed, securityEventsTestAuditLine("tx-recover", "203.0.113.100", "", "/recover", false, 1786447400)+"\n")

	// 首轮失败（模拟 DB busy）：文件保留并进入退避。
	metricsDB := db.MetricsDB
	if err := metricsDB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := drainSecurityEventsSpool(context.Background()); err == nil {
		t.Fatal("drain must fail while DB unavailable")
	}
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("失败后 sealed 必须保留: %v", err)
	}

	// 依赖恢复（换用新的可用库句柄）+ 退避窗口结束：下一轮补采成功并删除文件。
	setupSecurityEventsSpoolRecoveredDB(t)
	securityEventsSpoolState.mu.Lock()
	securityEventsSpoolState.nextAttempt = time.Time{}
	securityEventsSpoolState.mu.Unlock()
	n, err := drainSecurityEventsSpool(context.Background())
	if err != nil {
		t.Fatalf("drain after recovery: %v", err)
	}
	if n != 1 {
		t.Fatalf("ingested=%d, want 1", n)
	}
	if _, err := os.Stat(sealed); !os.IsNotExist(err) {
		t.Fatalf("补采成功后 sealed 必须删除: %v", err)
	}
	if got := securityEventsTestRowCount(t); got != 1 {
		t.Fatalf("rows=%d, want 1", got)
	}
	if status := SecurityEventsSpoolSnapshot(); status.Entries != 0 || status.ConsecutiveFailures != 0 {
		t.Fatalf("恢复后 spool status=%+v, want 0 条且失败计数清零", status)
	}
}

// setupSecurityEventsSpoolRecoveredDB 为恢复场景换一个新的 metrics 库句柄
// （上一个已 Close），保留同包其余夹具的 teardown 语义。
func setupSecurityEventsSpoolRecoveredDB(t *testing.T) {
	t.Helper()
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("reinitialize metrics database: %v", err)
	}
}

// 并发形态：多个 IPC 批次 + 健康快照并发读取（IPC 与 spool 共用批量入库
// 状态、健康位读 spool 状态缓存）不得 data race，且所有事务都落库。
func TestIngestSecurityEventBatch_concurrentWithHealthSnapshot(t *testing.T) {
	setupSecurityEventsSpoolTest(t)
	const batches = 8
	var wg sync.WaitGroup
	errs := make(chan error, batches*2)
	for i := range batches {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			line := securityEventsTestAuditLine(fmt.Sprintf("tx-conc-%d", i), "203.0.113.110", "", "/conc", false, 1786447500+int64(i)) + "\n"
			if _, err := IngestSecurityEventBatch(context.Background(), []byte(line)); err != nil {
				errs <- err
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = securityEventsOverlayIngestionHealth(SecurityEventsIngestionStatus{})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent ingest: %v", err)
	}
	if got := securityEventsTestRowCount(t); got != batches {
		t.Fatalf("rows=%d, want %d", got, batches)
	}
}
