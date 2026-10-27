package services

import (
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

// useCertSweepTickTestEnv 注入独立 DB 与任务日志目录，并清空活动证书服务
// （清理恢复原值）。供孤儿清扫计数与证书循环空转日志测试共用。
func useCertSweepTickTestEnv(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "logs", "tasks"))
	t.Cleanup(func() {
		// 指针还原前先关掉本用例初始化的库：只还原指针会让每个用例泄漏
		// 一个 sqlite 句柄与临时目录（同 newClusterTestService 的收尾口径）。
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
		taskengine.SetLogDir(oldDir)
		SetActiveCertificateService(nil)
		lastCertServiceMissing.Store(false)
	})
	SetActiveCertificateService(nil)
	lastCertServiceMissing.Store(false)
}

func seedOrphanCertJob(t *testing.T, ruleID, domain, status string) int {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,?)`, ruleID, domain, status)
	if err != nil {
		t.Fatalf("seed cert job (%s,%s,%s): %v", ruleID, domain, status, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read seeded job id: %v", err)
	}
	return int(id)
}

func TestCertJobsActive_nilDBSkipsWithoutMaskingQueryErrors(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedOrphanCertJob(t, "lb_nil_guard", "nil-guard.example.test", "queued")
	if !certJobsActive() {
		t.Fatal("non-terminal certificate job was not reported active")
	}

	// Given/When：DB 尚未装配的启动窗口。
	database := db.DB
	db.DB = nil

	// Then：按无活处理并静默跳过，不得 nil dereference。
	if certJobsActive() {
		t.Fatal("nil database must not report certificate work as runnable")
	}
	CertWaitingCATickOnce(context.Background())

	// 回归：普通查询错误仍维持「宁扫勿漏」，不被 nil 守卫吞掉。
	db.DB = database
	if err := database.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}
	if !certJobsActive() {
		t.Fatal("query errors must retain fail-visible active=true safety semantics")
	}
}

// sweepOrphanedCertJobs 返回值必须等于实际收敛的孤儿任务数——
// CertReconcileOnce 的「孤儿清理 %d 个」任务日志行直接消费该值，swept 恒 0
// 使对账轮永远上报「清理 0 个」。
func TestSweepOrphanedCertJobs_countsDisabledOrphans(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// Given：两条指向不存在规则的孤儿任务（queued + waiting_ca），外加一条
	// 已 disabled 的孤儿（终态：不扫、不计数）
	queuedID := seedOrphanCertJob(t, "lb_ghost_a", "ghost-a.example.test", "queued")
	waitingID := seedOrphanCertJob(t, "lb_ghost_b", "ghost-b.example.test", "waiting_ca")
	disabledID := seedOrphanCertJob(t, "lb_ghost_c", "ghost-c.example.test", "disabled")

	// When
	swept, err := sweepOrphanedCertJobs(context.Background())

	// Then：计数=实际翻转行数；disabled 行不被触碰；健康库无错误
	if err != nil {
		t.Fatalf("sweep orphaned cert jobs: %v", err)
	}
	if swept != 2 {
		t.Fatalf("swept=%d, want 2（返回值必须等于实际收敛的孤儿任务数）", swept)
	}
	for _, tc := range []struct {
		id   int
		want string
	}{
		{queuedID, "disabled"},
		{waitingID, "disabled"},
		{disabledID, "disabled"},
	} {
		var status string
		if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", tc.id).Scan(&status); err != nil {
			t.Fatalf("read job %d: %v", tc.id, err)
		}
		if status != tc.want {
			t.Fatalf("job %d status=%q, want %q", tc.id, status, tc.want)
		}
	}
}

// 停止「证书签发」调度后：续期扫描每轮必须留可见业务行并落 skipped 终态
// （不假成功）；手动证书巡检不依赖服务实例，照常执行且不得写「服务未运行」。
// 旧口径把两者都折成 success + 一条共享状态行：手动证书的告警（手动证书没有
// 自动续签，告警是唯一信号）随调度停止而静默消失，任务监控全绿。
func TestCertTicks_skippedRenewalScanIsVisibleAndManualPollStillRuns(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// 连续两轮缺失：每轮都要留痕（续期停摆是持续风险，不做状态变化收敛）
	for round := 1; round <= 2; round++ {
		if err := CertRenewalScanOnce(); !errors.Is(err, taskengine.ErrTaskSkipped) {
			t.Fatalf("round %d err=%v, want ErrTaskSkipped", round, err)
		}
	}
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if got := strings.Count(string(data), "续期扫描已跳过"); got != 2 {
		t.Fatalf("skip lines=%d, want 2（每轮留痕）: %q", got, string(data))
	}

	// 手动巡检：无服务实例仍照常执行，且不得写「证书服务未运行」
	if err := CertManualCheckOnce(); err != nil {
		t.Fatalf("manual check without service: %v", err)
	}
	if data, err := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll")); err == nil && strings.Contains(string(data), "证书服务未运行") {
		t.Fatalf("cert-manual-poll 不得再以服务缺失为由跳过: %q", string(data))
	}
}

// （cert-waiting-ca 形态）+ 收敛：门控放行（有非终态任务）但服务
// 未运行时记一次跳过行（状态门新文案）；门控拦截（全部终态）时保持静默
// （2026-09-29 裁定的零扫描门控不得被空转日志破坏）。
func TestCertWaitingCATickOnce_skipLineGatedOnActiveJobs(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// 有非终态任务：门控放行，服务未运行 → 跳过行
	jobID := seedOrphanCertJob(t, "lb_ghost_tick", "ghost-tick.example.test", "queued")
	CertWaitingCATickOnce(context.Background())
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-waiting-ca"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务未运行，跳过本轮"); got != 1 {
		t.Fatalf("skip lines=%d, want 1（有非终态任务且服务未运行须记一行）: %q", got, string(data))
	}

	// 全部终态：门控静默退出，不追加跳过行
	if _, err := db.DB.Exec("UPDATE cert_jobs SET status='disabled' WHERE id=?", jobID); err != nil {
		t.Fatalf("disable job: %v", err)
	}
	CertWaitingCATickOnce(context.Background())
	data, err = os.ReadFile(taskengine.TaskLogPath("cert-waiting-ca"))
	if err != nil {
		t.Fatalf("reread task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务未运行，跳过本轮"); got != 1 {
		t.Fatalf("skip lines=%d, want 1（全终态时门控静默，不得追加空转行）", got)
	}
}

// 证书周期任务体此前把扫描/对账错误吞成日志（Once 无返回
// 值、Run 恒 return nil），DB 抖动时任务监控显示 success；reconcileMissingCertFiles
// 查询失败后摘要还报「状态对账完成 0」。修复后：读失败上抛 + 失败轮摘要写
// 「状态对账失败」而非「完成」。
func TestCertReconcileOnce_propagates_read_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	// Given：cert_jobs 读故障（表缺失=迁移中断/库损坏形态）
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// When
	err := CertReconcileOnce(context.Background())

	// Then 1：读失败上抛（Run 随之返回 error → task_runs 失败终态）
	if err == nil {
		t.Fatal("CertReconcileOnce err=nil, want 对账读故障上抛（fail-visible）")
	}
	// Then 2：失败轮摘要不得写「完成」
	data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-reconcile"))
	if readErr != nil {
		t.Fatalf("read task log: %v", readErr)
	}
	if strings.Contains(string(data), "状态对账完成") {
		t.Fatalf("失败轮摘要谎报完成: %q", string(data))
	}
	if !strings.Contains(string(data), "状态对账失败") {
		t.Fatalf("失败轮摘要缺失「状态对账失败」: %q", string(data))
	}
}

// 回归形状：健康库上对账轮必须返回 nil 且照常写「完成」摘要——上抛改造不得把
// 正常轮次变成失败轮。
func TestCertReconcileOnce_healthy_round_reports_completion(t *testing.T) {
	useCertSweepTickTestEnv(t)

	if err := CertReconcileOnce(context.Background()); err != nil {
		t.Fatalf("CertReconcileOnce err=%v, want nil", err)
	}
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-reconcile"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if !strings.Contains(string(data), "状态对账完成") {
		t.Fatalf("健康轮摘要缺失「状态对账完成」: %q", string(data))
	}
}

// 续期扫描的候选查询/遍历失败必须上抛（此前只落任务日志，Run 恒 nil）。
func TestCertRenewalScanOnce_propagates_scan_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// Given：cert_jobs 读故障（CheckExpiration 候选查询失败）
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// When
	err := CertRenewalScanOnce()

	// Then：扫描失败上抛，且摘要不得写「扫描完成」
	if err == nil {
		t.Fatal("CertRenewalScanOnce err=nil, want 扫描读故障上抛（fail-visible）")
	}
	if data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan")); readErr == nil && strings.Contains(string(data), "扫描完成") {
		t.Fatalf("失败轮摘要谎报完成: %q", string(data))
	}
}

// 服务缺失时续期扫描必须落 skipped 终态（并留可见业务行），不得记成功：
// 停用「证书签发」期间自动续签完全停摆，成功终态会让任务监控假健康。
func TestCertRenewalScanOnce_service_missing_landsSkipped(t *testing.T) {
	useCertSweepTickTestEnv(t)

	err := CertRenewalScanOnce()
	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（服务未运行=跳过，不是成功）", err)
	}
	data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if readErr != nil {
		t.Fatalf("read task log: %v", readErr)
	}
	if !strings.Contains(string(data), "续期扫描已跳过") {
		t.Fatalf("跳过轮必须留可见业务行: %q", string(data))
	}
}

// Run 体必须上抛 Once 的失败——task_runs 终态与任务监控依赖该返回值。
func TestTaskEngineWire_certTasksPropagateRunFailures(t *testing.T) {
	te := newWireTestEngine(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// Given：cert_jobs 读故障（上述两条 Read 路径必然失败；task_runs 写入不受影响）
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// Then：周期任务的 Run 都必须返回 error
	if err := te.Trigger("cert-reconcile", "manual", ""); err == nil {
		t.Fatal("cert-reconcile Run 未上抛对账读失败（任务监控会显示 success）")
	}
	if err := te.Trigger("cert-renewal-scan", "manual", ""); err == nil {
		t.Fatal("cert-renewal-scan Run 未上抛扫描失败（任务监控会显示 success）")
	}
	// 30s 补扫承担 waiting_ca 冷却重排 / 滞留 queued 重入队 / 断链部署重试的
	// 唯一属主：三路读失败同样必须上抛（此前 Run 恒 return nil）。
	if err := te.Trigger("cert-waiting-ca", "manual", ""); err == nil {
		t.Fatal("cert-waiting-ca Run 未上抛补扫读失败（任务监控会显示 success）")
	}
}

// 30s 补扫三路扫描的读失败必须上抛并留失败摘要行——持续性读故障（schema 漂移/
// 长期 SQLITE_BUSY）下证书自动恢复会完全停摆，而任务监控此前全绿。
func TestCertWaitingCATickOnce_propagates_scan_read_failures(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	// Given：存在非终态任务（越过「无活跳过」门）+ cert_jobs 读故障
	seedOrphanCertJob(t, "lb_waiting_scan", "waiting-scan.example.test", "waiting_ca")
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// When
	err := CertWaitingCATickOnce(context.Background())

	// Then 1：读失败上抛（Run 返回 error → task_runs 失败终态）
	if err == nil {
		t.Fatal("CertWaitingCATickOnce err=nil, want 补扫读故障上抛（fail-visible）")
	}
	// Then 2：失败轮任务日志必须写失败摘要（不得谎报「补扫完成」）
	data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-waiting-ca"))
	if readErr != nil {
		t.Fatalf("read task log: %v", readErr)
	}
	if !strings.Contains(string(data), "补扫失败") {
		t.Fatalf("失败轮摘要缺失「补扫失败」: %q", string(data))
	}
	if strings.Contains(string(data), "补扫完成") {
		t.Fatalf("失败轮摘要谎报完成: %q", string(data))
	}
}

// 手动证书到期巡检读失败必须上抛（此前仅应用日志 Logf+return，
// Run 恒 nil，task_runs 落 success——任务监控呈现假健康）。对齐
// cert-renewal-scan/cert-reconcile 同族口径。
func TestCertManualCheckOnce_propagates_query_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	// Given：lb_rules 读故障（巡检候选查询必然失败）
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}

	// When
	err := CertManualCheckOnce()

	// Then 1：读失败上抛（Run 随之返回 error → task_runs 失败终态）
	if err == nil {
		t.Fatal("CertManualCheckOnce err=nil, want 巡检读故障上抛（fail-visible）")
	}
	// Then 2：失败轮任务日志必须有失败行
	data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll"))
	if readErr != nil {
		t.Fatalf("read task log: %v", readErr)
	}
	if !strings.Contains(string(data), "巡检失败") {
		t.Fatalf("失败轮任务日志缺失失败行: %q", string(data))
	}
}

// 接线钉：cert-manual-poll 的 Run 必须上抛 Once 的失败——
// task_runs 终态与任务监控依赖该返回值（此前 Run 恒 return nil）。
func TestTaskEngineWire_certManualPollPropagatesRunFailure(t *testing.T) {
	te := newWireTestEngine(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// Given：lb_rules 读故障（巡检查询必然失败；task_runs 写入不受影响）
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}

	// Then
	if err := te.Trigger("cert-manual-poll", "manual", ""); err == nil {
		t.Fatal("cert-manual-poll Run 未上抛巡检读失败（任务监控会显示 success）")
	}
}

// 30s 补扫节拍的摘要行只在有真实动作时落盘并带分项计数——waiting_ca
// 冷却期（1-3h）内的空转轮不得写行（无条件写 ≈2880 行/日，掩盖真正动作行）。
func TestCertWaitingCATickOnce_summaryLineOnlyOnActions(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	oldManager := caQueueManager
	caQueueManager = &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
		active:       true,
		reloader:     func() error { return nil },
	}
	t.Cleanup(func() { caQueueManager.Stop(); caQueueManager = oldManager })

	// Given：适用规则 + 一条冷却未到期的 waiting_ca 任务
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_tick_quiet','tick-quiet','quiet.example.test','http',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'tick CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	jobID := seedOrphanCertJob(t, "lb_tick_quiet", "quiet.example.test", "waiting_ca")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET ca_provider_id=7, ca_available_after=datetime('now','+1 hour') WHERE id=?`, jobID); err != nil {
		t.Fatalf("park job: %v", err)
	}

	// When：冷却期内的补扫轮（零动作）
	CertWaitingCATickOnce(context.Background())

	// Then：无摘要行
	logPath := taskengine.TaskLogPath("cert-waiting-ca")
	if data, err := os.ReadFile(logPath); err == nil && strings.Contains(string(data), "补扫完成") {
		t.Fatalf("零动作轮不得写补扫摘要行: %q", string(data))
	}

	// When：冷却到期后的补扫轮（有动作）
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET ca_available_after=datetime('now','-1 minute') WHERE id=?`, jobID); err != nil {
		t.Fatalf("expire cooling: %v", err)
	}
	CertWaitingCATickOnce(context.Background())

	// Then：摘要行携带分项计数
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if !strings.Contains(string(data), "补扫完成：CA 冷却重排 1") {
		t.Fatalf("动作轮摘要行须带分项计数: %q", string(data))
	}
}

// sweepOrphanedCertJobs 的读失败/中止必须经返回值上抛（fail-visible）——
// 吞掉会让对账轮摘要写「孤儿清理 0 个」假健康（与 reconcileMissingCertFiles
// 的读失败上抛同口径）。
func TestSweepOrphanedCertJobs_propagatesContextCancellation(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedOrphanCertJob(t, "lb_ghost_cancel", "ghost-cancel.example.test", "queued")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sweepOrphanedCertJobs(ctx); err == nil {
		t.Fatal("中止的 sweep 必须返回错误（失败轮结果不可信）")
	}
}

// jobLogger 进度迁移的 from 集合不得含终态——并发部署回调先把行提交为
// issued 时，进度日志不得把它拉回 in-flight（终态不可逆的静态防线）；
// 快速重部署路径的 issued→downloaded 由显式白名单放行。
func TestJobLogger_Log_neverMovesTerminalJobBackToInflight(t *testing.T) {
	useCertSweepTickTestEnv(t)
	jobID := seedOrphanCertJob(t, "lb_logger_guard", "logger-guard.example.test", "issued")

	logger := &jobLogger{jobID: jobID, ruleID: "lb_logger_guard", file: NewCertJobFileLogger("lb_logger_guard")}
	logger.Log("creating_account", "并发进度写")

	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "issued" {
		t.Fatalf("status=%q, want issued（终态不得被进度日志拉回）", status)
	}

	// 白名单形态：from={issued,downloaded} 时 issued→downloaded 合法
	// （redeployDownloadedInLock 快速路径语义）。
	whitelist := &jobLogger{jobID: jobID, ruleID: "lb_logger_guard", file: NewCertJobFileLogger("lb_logger_guard"), from: []string{"issued", "downloaded"}}
	whitelist.Log("downloaded", "快速路径重部署")
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("re-read job status: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（白名单 from 必须放行快速路径）", status)
	}
}

// 手动证书巡检不依赖证书服务实例：停止「证书签发」调度后，手动证书没有
// 自动续签，10 分钟一次的到期巡检是唯一信号，必须照常执行并产出摘要行。
func TestCertManualCheckOnce_runsWithoutCertificateService(t *testing.T) {
	useCertSweepTickTestEnv(t)
	certPEM, _ := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour), "manual-poll.example.test")
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_manual_poll','manual-poll','http','manual-poll.example.test',8080,1,1,'manual',?)`, certPEM); err != nil {
		t.Fatalf("seed manual TLS rule: %v", err)
	}

	// When：无活动证书服务
	if err := CertManualCheckOnce(); err != nil {
		t.Fatalf("manual check without service: %v", err)
	}

	// Then：巡检真实执行并落摘要（1 张临期）
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if !strings.Contains(string(data), "1 张临期") {
		t.Fatalf("task log=%q, want 「1 张临期」（巡检不得因服务缺失停摆）", string(data))
	}
}

// 从节点零写（降级窗口收口）：30s 补扫的三路写路径（CA 冷却重排 / 滞留重入队 /
// 断链部署重建）原先只有准入时的引擎角色门——本轮窗口内降级/换主后，从节点
// 仍会改写 cert_jobs、登记部署 timer（到期写证书文件并重载 Caddy）。
// 本用例在写点前门注入降级：必须落 skipped 且零写入。
func TestCertWaitingCATickOnce_skipsWritesWhenDemotedMidRound(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	oldManager := caQueueManager
	caQueueManager = &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
		active:       true,
		reloader:     func() error { return nil },
	}
	t.Cleanup(func() { caQueueManager.Stop(); caQueueManager = oldManager })

	// Given：适用规则 + 一条冷却已到期的 waiting_ca 任务（扫描会判定为可重排）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_gate_demote','gate-demote','demote.example.test','http',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (8,'gate CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	jobID := seedOrphanCertJob(t, "lb_gate_demote", "demote.example.test", "waiting_ca")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET ca_provider_id=8, ca_available_after=datetime('now','-1 minute') WHERE id=?`, jobID); err != nil {
		t.Fatalf("expire cooling: %v", err)
	}

	// When：写前门内注入降级（等价于本轮开始后管理员切从节点）
	demoted := false
	certReconcileRoleRecheckHook = func() {
		if demoted {
			return
		}
		demoted = true
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Errorf("demote node: %v", err)
		}
	}
	t.Cleanup(func() { certReconcileRoleRecheckHook = nil })

	err := CertWaitingCATickOnce(context.Background())

	// Then 1：落 skipped（降级不是失败轮，也不得记成功）
	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want taskengine.ErrTaskSkipped（降级后必须中止本轮）", err)
	}
	if !demoted {
		t.Fatal("写前门未执行（降级注入未发生，用例前提不成立）")
	}
	// Then 2：零写入——任务仍停在 waiting_ca
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "waiting_ca" {
		t.Fatalf("status=%q, want waiting_ca（从节点不得改写任务态）", status)
	}
}
