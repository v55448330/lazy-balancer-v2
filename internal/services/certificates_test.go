package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// resetCertificateServiceForTest 测试后复位 certificateService 全局单例——
// NewCertificateService 会覆写该全局，不复位则旧 service（含其定时器与闭包
// 通道）泄漏进后续测试，包级函数（scheduleCertificateDeploymentRetry 等）会
// 作用在死测试的对象上。
func resetCertificateServiceForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		certificateServiceMu.Lock()
		certificateService = nil
		certificateServiceMu.Unlock()
	})
}

// Given 一张 20 天后过期的手动证书（异常持续期）与同一告警门。
// When 连续两轮手动证书巡检。
// Then 任务日志只留一条摘要行（与按日去重门同源），不把同任务的事件行挤掉。
func TestRunManualCertExpiryCheck_taskLogSummaryDeduped(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	certPEM, _ := expiredShapeCertAndKey(t, "manual-dedupe.test", time.Now().Add(20*24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_manual_dedupe','manual-dedupe','manual-dedupe.test','http',8080,1,1,'manual',?)`, certPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=30 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	gate := newManualCertExpiryAlertGate()
	for round := range 2 {
		if err := runManualCertExpiryCheck(gate); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	logContent := readTaskLog(t, "cert-manual-poll")
	if got := strings.Count(logContent, "手动证书到期检查"); got != 1 {
		t.Fatalf("摘要行出现 %d 次, want 1（重复轮必须与告警去重门同源）:\n%s", got, logContent)
	}
}

// Given issued 任务材料在库但 expires_at 缺失（历史/导入遗留）。
// When 6h 对账的到期回填执行。
// Then 按 PEM 派生回填 NotAfter，且幂等（第二轮回填 0 条）。
func TestBackfillIssuedCertExpiry_fillsMissingExpiry(t *testing.T) {
	_, database := newClusterTestService(t)
	notAfter := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	certPEM, keyPEM := expiredShapeCertAndKey(t, "backfill.test", notAfter)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_backfill_expiry','backfill','backfill.test','http',8443,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,updated_at)
		VALUES ('lb_backfill_expiry','backfill.test','issued',?,?,NULL,datetime('now','-2 days'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	filled, err := backfillIssuedCertExpiry(context.Background())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if filled != 1 {
		t.Fatalf("filled=%d, want 1", filled)
	}
	var expiresAt sql.NullTime
	if err := database.QueryRow("SELECT expires_at FROM cert_jobs WHERE rule_id='lb_backfill_expiry'").Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Valid || expiresAt.Time.Sub(notAfter).Abs() > time.Minute {
		t.Fatalf("expires_at=%v valid=%v, want ≈%v（PEM 派生回填）", expiresAt.Time, expiresAt.Valid, notAfter)
	}

	filled, err = backfillIssuedCertExpiry(context.Background())
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if filled != 0 {
		t.Fatalf("second filled=%d, want 0（幂等：只碰 NULL 行）", filled)
	}
}

// checkManualCertExpiration 是测试夹具（生产入口为 CertManualCheckOnce →
// runManualCertExpiryCheck）：保留实例方法形态，让用例能断言实例的
// expiryAlertGate 参与去重。生产代码不得调用。
func (s *CertificateService) checkManualCertExpiration() error {
	return runManualCertExpiryCheck(s.expiryAlertGate)
}

// Given 一次性部署重试正常执行完毕。
// When 回调收尾。
// Then 该登记的子 context 必须已取消（否则每 30 分钟一次的重试会让
// s.ctx.children 无界累积到服务停止）。
func TestCertificateService_deploymentRetryCallbackCancelsChildContext(t *testing.T) {
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	t.Cleanup(service.pauseDeploymentRetries)
	ctxCh := make(chan context.Context, 1)
	service.retryDeployment = func(ctx context.Context, _ int) error {
		ctxCh <- ctx
		return nil
	}
	if err := service.scheduleDeploymentRetry(7, "lb_ctx", 0); err != nil {
		t.Fatalf("schedule deployment retry: %v", err)
	}
	var callbackCtx context.Context
	select {
	case callbackCtx = <-ctxCh:
	case <-time.After(5 * time.Second):
		t.Fatal("部署回调未执行")
	}
	deadline := time.Now().Add(5 * time.Second)
	for callbackCtx.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if callbackCtx.Err() == nil {
		t.Fatal("部署回调结束后子 context 未取消（父 ctx children 将持续累积）")
	}
}

// Given 规则处于补偿屏障（BlockJobsForRule 租约期内）。
// When 手动「立即部署」（RetryCertificateDeploymentNow）。
// Then 与包级入口/补扫同判据：拒绝登记并返回 ErrCertificateDeploymentRetryBlocked，
// 不创建 timer（屏障期不调度）。
func TestRetryCertificateDeploymentNow_respectsRuleBarrier(t *testing.T) {
	newClusterTestService(t)
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	t.Cleanup(service.pauseDeploymentRetries)
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)
	InitCAQueueManager(func() error { return nil }, t.TempDir())
	manager := GetCAQueueManager()
	manager.Start()
	token := manager.BlockJobsForRule("lb_barrier")
	t.Cleanup(func() { manager.UnblockJobsForRule("lb_barrier", token) })

	err := RetryCertificateDeploymentNow(7, "lb_barrier")
	if !errors.Is(err, ErrCertificateDeploymentRetryBlocked) {
		t.Fatalf("err=%v, want ErrCertificateDeploymentRetryBlocked（屏障期不得登记部署）", err)
	}
	service.timerMu.Lock()
	_, hasTimer := service.deploymentTimers[7]
	service.timerMu.Unlock()
	if hasTimer {
		t.Fatal("屏障期不得为手动部署创建 timer")
	}
}

func TestCanonicalACMEDomains_rejectsTrailingDot(t *testing.T) {
	// The audit's trailing-dot example is not a valid alternate canonical form:
	// the single-source helper rejects it just like the SQL revival gate does.
	if _, err := CanonicalACMEDomains("example.com."); err == nil {
		t.Fatal("trailing-dot ACME domain must remain invalid")
	}
	// Regression: case, surrounding whitespace, and root/www ordering still
	// canonicalize through the single-source helper.
	got, err := CanonicalACMEDomains(" WWW.Example.COM , example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.com,www.example.com" {
		t.Fatalf("canonical domains=%q, want example.com,www.example.com", got)
	}
}

func TestCreateOrRequeueCertJob_returns_persisted_job_id(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_job_id','job-id','example.com','http',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	t.Cleanup(manager.Stop)

	// When
	jobID, err := CreateOrRequeueCertJob("lb_job_id", "example.com", 1, manager)

	// Then
	if err != nil || jobID <= 0 {
		t.Fatalf("create result jobID=%d err=%v, want persisted ID", jobID, err)
	}
	var storedID int
	if err := database.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_job_id'").Scan(&storedID); err != nil {
		t.Fatalf("read persisted job: %v", err)
	}
	if storedID != jobID {
		t.Fatalf("stored job ID=%d, returned %d", storedID, jobID)
	}
}

func TestCreateOrRequeueCertJob_resets_retry_fields_before_enqueue(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_retry_reset','retry','retry.example','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs
		(rule_id,domain,status,renewal_attempts,ca_available_after,last_error_code)
		VALUES ('lb_retry_reset','retry.example','failed',4,datetime('now','-1 hour'),'rate_limited')`); err != nil {
		t.Fatalf("seed retry job: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	t.Cleanup(manager.Stop)

	if _, err := CreateOrRequeueCertJob("lb_retry_reset", "retry.example", 1, manager); err != nil {
		t.Fatalf("create or requeue job: %v", err)
	}

	var attempts int
	var availableAfter, errorCode *string
	if err := database.QueryRow(`SELECT renewal_attempts,ca_available_after,last_error_code FROM cert_jobs
		WHERE rule_id='lb_retry_reset'`).Scan(&attempts, &availableAfter, &errorCode); err != nil {
		t.Fatalf("read reset retry job: %v", err)
	}
	if attempts != 0 || availableAfter != nil || errorCode != nil {
		t.Fatalf("retry fields=(%d,%v,%v), want zero and NULLs", attempts, availableAfter, errorCode)
	}
}

func TestCreateOrRequeueCertJob_requeues_disabled_job_for_reenabled_rule(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_reenabled','reenabled','example.com','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_provider_id)
		VALUES ('lb_reenabled','example.com','disabled',NULL,1);
	`); err != nil {
		t.Fatalf("seed reenabled certificate job: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	transitioned := make(chan struct{})
	release := make(chan struct{})
	manager.beforeEnqueue = func() {
		close(transitioned)
		<-release
	}
	t.Cleanup(manager.Stop)
	done := make(chan error, 1)
	go func() {
		_, err := CreateOrRequeueCertJob("lb_reenabled", "example.com", 1, manager)
		done <- err
	}()
	<-transitioned

	// When
	var status string
	err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_reenabled'").Scan(&status)
	close(release)

	// Then
	if err != nil {
		t.Fatalf("read reenabled certificate job: %v", err)
	}
	if enqueueErr := <-done; enqueueErr != nil {
		t.Fatalf("requeue disabled certificate job: %v", enqueueErr)
	}
	if status != "queued" {
		t.Fatalf("reenabled job status=%q, want queued", status)
	}
}

func TestCreateOrRequeueCertJob_requeues_downloaded_job(t *testing.T) {
	// Given：已部署（downloaded）任务——用户再次触发签发必须重新排队，
	// 不能静默空转
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_downloaded','downloaded','downloaded.example','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs
		(rule_id,domain,status,ca_provider_id)
		VALUES ('lb_downloaded','downloaded.example','downloaded',1)`); err != nil {
		t.Fatalf("seed downloaded job: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	queue := newCAQueue(models.CAProvider{ID: 1}, nil)
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	go queue.loop()
	manager.queues[1] = queue
	t.Cleanup(manager.Stop)

	// When：触发签发路径（与 handlers/certificates.go 相同调用）
	jobID, changed, err := CreateOrRequeueCertJobWithChange("lb_downloaded", "downloaded.example", 1, manager)

	// Then：downloaded 任务转为 queued 重新排队
	if err != nil {
		t.Fatalf("requeue downloaded job: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false, want true（downloaded 任务必须重新排队）")
	}
	if jobID <= 0 {
		t.Fatalf("jobID=%d, want > 0", jobID)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read requeued job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued", status)
	}
}

func TestCreateOrRequeueCertJobWithChange_preservesTransitionSignalOnEnqueueError(t *testing.T) {
	// Given：既有 failed 行会真实转为 queued，但入队时没有任何可用 CA。
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_changed_error','changed','changed.example','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_changed_error','changed.example','failed')`); err != nil {
		t.Fatalf("seed existing job: %v", err)
	}
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("remove CA providers: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	t.Cleanup(manager.Stop)

	// When
	jobID, changed, err := CreateOrRequeueCertJobWithChange("lb_changed_error", "changed.example", 999, manager)

	// Then：错误来自入队阶段，不得抹掉前面已经发生的 DB transition 信号。
	if err == nil {
		t.Fatal("enqueue unexpectedly succeeded without a CA provider")
	}
	if jobID <= 0 || !changed {
		t.Fatalf("result jobID=%d changed=%v err=%v, want persisted ID and changed=true", jobID, changed, err)
	}
}

func TestCreateOrRequeueCertJobVerified_rejectsExistingJobThatWasNotQueued(t *testing.T) {
	// Given：既有 queued 行不在活动队列中（滞留形态），队列本身处于运行态。
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_stranded_verify','stranded','stranded.example','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (77,'lb_stranded_verify','stranded.example','queued')`); err != nil {
		t.Fatalf("seed stranded job: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}

	// When
	jobID, changed, err := CreateOrRequeueCertJobVerified("lb_stranded_verify", "stranded.example", 1, manager)

	// Then：未入队必须如实报错，不能被当作成功。
	if err == nil || jobID != 77 || changed {
		t.Fatalf("result jobID=%d changed=%v err=%v, want existing ID and not-queued error", jobID, changed, err)
	}
}

func TestCreateOrRequeueCertJob_paused_queue_does_not_upsert(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs
		(rule_id,domain,status,renewal_attempts,last_error_code)
		VALUES ('lb_paused','paused.example','failed',4,'rate_limited')`); err != nil {
		t.Fatalf("seed paused job: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: false}

	jobID, err := CreateOrRequeueCertJob("lb_paused", "paused.example", 1, manager)

	if err == nil || jobID != 0 {
		t.Fatalf("result jobID=%d err=%v, want paused error without ID", jobID, err)
	}
	var status, errorCode string
	var attempts int
	if err := database.QueryRow(`SELECT status,renewal_attempts,last_error_code FROM cert_jobs
		WHERE rule_id='lb_paused'`).Scan(&status, &attempts, &errorCode); err != nil {
		t.Fatalf("read paused job: %v", err)
	}
	if status != "failed" || attempts != 4 || errorCode != "rate_limited" {
		t.Fatalf("paused job=(%q,%d,%q), want original values", status, attempts, errorCode)
	}
}

func TestRequeueNonTerminalCertJobs_schedules_downloaded_deployment(t *testing.T) {
	// Given
	jobID, _ := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem='cert', key_pem='key' WHERE id=?", jobID); err != nil {
		t.Fatalf("attach certificate material: %v", err)
	}
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	retried := make(chan int, 1)
	service.retryDeployment = func(_ context.Context, gotJobID int) error {
		retried <- gotJobID
		return nil
	}

	// When
	err := RequeueNonTerminalCertJobs()

	// Then
	if err != nil {
		t.Fatalf("requeue non-terminal jobs: %v", err)
	}
	if gotJobID := <-retried; gotJobID != jobID {
		t.Fatalf("retried job ID=%d, want %d", gotJobID, jobID)
	}
	service.pauseDeploymentRetries()
}

func TestRequeueNonTerminalCertJobs_pausedQueueLeavesDownloadedJobUntouched(t *testing.T) {
	// 恢复排队走 EnqueueIfActive：暂停的队列管理器在 transition 之前即拒绝
	//（与 PauseAndDrain 门控同语义），任务保持原状态等待下次恢复——不写库、
	// 不入队、不报错。本用例断言的是**暂停门**（材料分支在暂停期同样不执行，
	// 二者在此形态下不可区分）；材料缺失行的回收通道见
	// TestRescanDroppedDeploymentRetries_requeuesLostMaterialJob。
	// Given
	jobID, _ := seedCertificateJob(t, "cleanup_dns")
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	GetCAQueueManager().PauseAndDrain()
	t.Cleanup(ResetCAQueueManagerForTest)
	retried := make(chan int, 1)

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) error {
		retried <- gotJobID
		return nil
	})

	// Then：无证书材料的 downloaded 任务不得走部署重试；暂停期不入队也不写库
	if err != nil {
		t.Fatalf("paused recovery must skip without error, got %v", err)
	}
	select {
	case gotJobID := <-retried:
		t.Fatalf("deployment retry scheduled for job %d without certificate material", gotJobID)
	default:
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read recovered job: %v", err)
	}
	if status != "cleanup_dns" {
		t.Fatalf("job status=%q, want cleanup_dns（暂停期不得迁移状态）", status)
	}
}

// requeueNonTerminalCertJobs 必须经 EnqueueIfActive 在途守卫——退役队列
// 中的滞行执行（zombie）仍持有 jobID 时，恢复流程不得 transition+Enqueue，否则
// 同 jobID 双执行（zombie 晚退 requeueCanceledJob 打回新执行状态，同型）。
func TestRequeueNonTerminalCertJobs_skips_job_still_active_in_retired_queue(t *testing.T) {
	// Given：适用规则 + 提供商；job 42 'creating_order' 仍被退役队列持有（zombie），
	// job 43 同形态但无任何在途执行（对照组，应正常恢复排队）
	_, database := newClusterTestService(t)
	for _, rule := range []struct{ id, domain string }{
		{id: "lb_recover_zombie", domain: "zombie.example.com"},
		{id: "lb_recover_normal", domain: "normal.example.com"},
	} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, rule.id, rule.id, rule.domain); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'recovery CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	for _, job := range []struct {
		id             int64
		ruleID, domain string
	}{
		{id: 42, ruleID: "lb_recover_zombie", domain: "zombie.example.com"},
		{id: 43, ruleID: "lb_recover_normal", domain: "normal.example.com"},
	} {
		if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (?,?,?,'creating_order',7)`, job.id, job.ruleID, job.domain); err != nil {
			t.Fatal(err)
		}
	}
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	manager := GetCAQueueManager()
	retired := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	retired.mu.Lock()
	retired.active[42] = struct{}{}
	retired.mu.Unlock()
	manager.mu.Lock()
	manager.retiredQueues = []retiredCAQueue{{queue: retired, retiredAt: time.Now()}}
	manager.mu.Unlock()

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) error {
		t.Errorf("deployment retry scheduled for non-downloaded job %d", gotJobID)
		return nil
	})

	// Then：无错误；zombie job 42 状态不变、未二次入队、不记审计；对照 job 43
	// 正常恢复排队（审计为证——active map 会被瞬时执行退出擦除，不宜断言）。
	if err != nil {
		t.Fatalf("recover non-terminal jobs: %v", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=42").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "creating_order" {
		t.Fatalf("zombie job status=%q, want creating_order（在途任务不得被恢复流程迁移）", status)
	}
	manager.mu.Lock()
	for _, q := range manager.queues {
		q.mu.Lock()
		_, zombieEnqueued := q.active[42]
		q.mu.Unlock()
		if zombieEnqueued {
			t.Fatal("zombie job 42 was enqueued by recovery（双执行缺口）")
		}
	}
	manager.mu.Unlock()
	var detail string
	err = db.AuditDB.QueryRow("SELECT COALESCE(detail,'') FROM audit_log WHERE action='恢复排队'").Scan(&detail)
	if err != nil {
		t.Fatalf("control job 43 recovery audit entry missing: %v", err)
	}
	if !strings.Contains(detail, "任务 43") || strings.Contains(detail, "任务 42") {
		t.Fatalf("recovery audit detail=%q, want 仅任务 43（在途任务跳过不得记审计）", detail)
	}
}

func TestCertificateService_deployment_retry_replacesPendingTimer(t *testing.T) {
	// 同 jobID 的重排语义是「替换」而非「拒绝」：旧 timer 必须被取消（不得
	// 之后又执行一次延迟部署），新 timer 恰执行一次回调，且不残留 timer/回调。
	// 断言必须可观测——旧实现只裸等一个 channel，若实现改为「忽略重复调度」
	// 会阻塞到 1h timer 到期（测试挂起而非明确失败）。
	// Given
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	calls := make(chan int, 2)
	service.retryDeployment = func(_ context.Context, jobID int) error {
		calls <- jobID
		return nil
	}
	if err := service.scheduleDeploymentRetry(42, "lb_retry", time.Hour); err != nil {
		t.Fatalf("schedule initial retry: %v", err)
	}
	service.timerMu.Lock()
	original := service.deploymentTimers[42]
	service.timerMu.Unlock()
	if original == nil {
		t.Fatal("precondition: pending timer not registered")
	}

	// When
	if err := service.scheduleDeploymentRetry(42, "lb_retry", 0); err != nil {
		t.Fatalf("reschedule retry: %v", err)
	}

	// Then 1：旧 timer 被取消（done 关闭），不会再执行回调
	select {
	case <-original.done:
	case <-time.After(time.Second):
		t.Fatal("replaced timer was not canceled")
	}
	// Then 2：新 timer 恰执行一次回调
	select {
	case jobID := <-calls:
		if jobID != 42 {
			t.Fatalf("retry job ID=%d, want 42", jobID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replacement retry was never executed")
	}
	// Then 3：无残留 timer / 在途回调（回调自摘在有界窗口内完成）
	waitDeadline := time.Now().Add(2 * time.Second)
	for {
		service.timerMu.Lock()
		_, hasTimer := service.deploymentTimers[42]
		hasCallback := len(service.deploymentCallbacks[42]) > 0
		service.timerMu.Unlock()
		if !hasTimer && !hasCallback {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatalf("deployment retry state not released (timer=%v callback=%v)", hasTimer, hasCallback)
		}
		time.Sleep(5 * time.Millisecond)
	}
	service.pauseDeploymentRetries()
	select {
	case jobID := <-calls:
		t.Fatalf("duplicate retry ran for job %d", jobID)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCertificateService_scheduleDeploymentRetry_waits_for_inflight_callback_before_rescheduling(t *testing.T) {
	// 重试回调在途（Caddy reload 挂起超 30s 暂停等待上限）时，
	// Resume/Unblock 补扫会对同 jobID 重新 schedule——去重只查 pending timer
	// （回调启动即自摘），不查在途回调，必然放行第二个并发回调部署同一证书。
	// 不变量：同 jobID 永不并发部署——补扫必须取消并等待退出后才创建新
	// timer（串行重试，而非并发重试）。
	// Given
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := make(chan int, 2)
	var firstOnce sync.Once
	service.retryDeployment = func(_ context.Context, jobID int) error {
		calls <- jobID
		firstOnce.Do(func() {
			close(entered)
			<-release
		})
		return nil
	}
	service.scheduleDeploymentRetry(42, "lb_retry", 0)
	<-entered
	if jobID := <-calls; jobID != 42 {
		t.Fatalf("first retry job ID=%d, want 42", jobID)
	}
	rescheduled := make(chan struct{})
	go func() {
		service.scheduleDeploymentRetry(42, "lb_retry", 0)
		close(rescheduled)
	}()

	// When：在途期间补扫重排
	// Then：不得返回、不得放行第二个并发回调
	select {
	case <-rescheduled:
		t.Fatal("scheduleDeploymentRetry returned while the first callback was still in-flight")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case jobID := <-calls:
		t.Fatalf("second callback ran concurrently with the in-flight one (job %d)", jobID)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)

	// 退出后重排完成，新 timer 触发第二个回调（与串行）
	<-rescheduled
	if jobID := <-calls; jobID != 42 {
		t.Fatalf("rescheduled retry job ID=%d, want 42", jobID)
	}
	service.pauseDeploymentRetries()
	select {
	case jobID := <-calls:
		t.Fatalf("unexpected extra retry for job %d", jobID)
	default:
	}
}

func TestCertificateService_cancelDeploymentRetry_waits_for_running_callback(t *testing.T) {
	// Given
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	service.retryDeployment = func(_ context.Context, _ int) error {
		close(entered)
		<-release
		return errors.New("ignored test failure")
	}
	service.scheduleDeploymentRetry(42, "lb_retry", 0)
	<-entered
	cancelStarted := make(chan struct{})
	cancelDone := make(chan struct{})
	go func() {
		close(cancelStarted)
		service.cancelDeploymentRetry(42)
		close(cancelDone)
	}()
	<-cancelStarted

	// When
	select {
	case <-cancelDone:
		t.Fatal("cancel returned while retry callback was running")
	default:
	}
	close(release)

	// Then
	<-cancelDone
}

func TestCertificateService_cancelDeploymentRetry_boundedWaitOnStuckCallback(t *testing.T) {
	// 发现3：回调链条调到非 context-aware 的 caddyReloader，Caddy admin 异常
	// 挂起时 HTTP 调用方必须能在 cancelWaitTimeout 内返回，不能永久阻塞。
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.cancelWaitTimeout = 50 * time.Millisecond
	entered := make(chan struct{})
	service.retryDeployment = func(_ context.Context, _ int) error {
		close(entered)
		select {} // 永久阻塞，模拟 Caddy admin 请求挂起
	}
	service.scheduleDeploymentRetry(42, "lb_stuck", 0)
	<-entered

	start := time.Now()
	done := make(chan struct{})
	go func() {
		service.cancelDeploymentRetry(42)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelDeploymentRetry 未在 5s 内返回（stuck 回调应触发有界超时）")
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("cancelDeploymentRetry 过早返回（%s），应至少等待 cancelWaitTimeout", elapsed)
	}
}

func TestCertificateService_Stop_waits_for_deployment_retry_callback(t *testing.T) {
	// Given
	_, _ = newClusterTestService(t)
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.recoverJobs = func(context.Context) {}
	callbackEntered := make(chan struct{})
	cancellationObserved := make(chan struct{})
	releaseCallback := make(chan struct{})
	service.retryDeployment = func(ctx context.Context, _ int) error {
		close(callbackEntered)
		<-ctx.Done()
		close(cancellationObserved)
		<-releaseCallback
		return ctx.Err()
	}
	go service.Start()
	service.scheduleDeploymentRetry(42, "lb_stop", 0)
	<-callbackEntered
	stopDone := make(chan struct{})
	go func() {
		service.Stop()
		close(stopDone)
	}()
	<-cancellationObserved

	// When
	select {
	case <-stopDone:
		t.Fatal("stop returned while deployment retry callback was running")
	default:
	}
	close(releaseCallback)

	// Then
	<-stopDone
}

func TestSetActiveCertificateService_rearmsPeriodicTasks(t *testing.T) {
	// Given：两个长间隔证书周期任务已完成首轮，lastCheck 已推进。
	te := taskengine.NewEngine(taskengine.Options{TickInterval: 5 * time.Millisecond})
	SetTaskEngineForTest(te)
	t.Cleanup(func() {
		StopTaskEngine()
		SetActiveCertificateService(nil)
	})
	counts := map[string]*atomic.Int32{}
	for _, id := range []string{"cert-renewal-scan", "cert-manual-poll"} {
		id := id
		counts[id] = &atomic.Int32{}
		mustRegisterTask(te, taskengine.Descriptor{
			ID: id, Family: "certificates", Name: id, Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
			IntervalFn: func() time.Duration { return time.Hour },
			Run: func(taskengine.RunContext) error {
				counts[id].Add(1)
				return nil
			},
		})
		te.StartLoop(id)
	}
	waitForCond(t, 2*time.Second, func() bool {
		return counts["cert-renewal-scan"].Load() == 1 && counts["cert-manual-poll"].Load() == 1
	})

	// When：证书服务就绪（active 指针注入）后再次 tick。
	SetActiveCertificateService(NewCertificateService())
	waitForCond(t, 100*time.Millisecond, func() bool {
		return counts["cert-renewal-scan"].Load() == 2 && counts["cert-manual-poll"].Load() == 2
	})

	// Then：服务就绪必须重置节拍并立即补首轮，不得静默等到 6h/10min 后。
	for _, id := range []string{"cert-renewal-scan", "cert-manual-poll"} {
		if got := counts[id].Load(); got != 2 {
			t.Errorf("%s 服务就绪后执行次数=%d, want 2（重置首轮）", id, got)
		}
	}
}

func TestSetActiveCertificateService_preservesStoppedTasks(t *testing.T) {
	// Given：用户明确停止两个非业务驱动周期任务。
	te := taskengine.NewEngine(taskengine.Options{TickInterval: 5 * time.Millisecond})
	SetTaskEngineForTest(te)
	t.Cleanup(func() {
		StopTaskEngine()
		SetActiveCertificateService(nil)
	})
	var runs atomic.Int32
	for _, id := range []string{"cert-renewal-scan", "cert-manual-poll"} {
		id := id
		mustRegisterTask(te, taskengine.Descriptor{
			ID: id, Family: "certificates", Name: id, Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
			IntervalFn: func() time.Duration { return time.Hour },
			Run:        func(taskengine.RunContext) error { runs.Add(1); return nil },
		})
		te.StopLoop(id)
	}

	// When：cert-issuance 就绪触发 active 注入。
	SetActiveCertificateService(NewCertificateService())

	// Then：只能重置已开启任务的节拍，不得重新打开用户停止的调度或执行 Run。
	for _, id := range []string{"cert-renewal-scan", "cert-manual-poll"} {
		meta, ok := te.Lookup(id)
		if !ok || meta.LoopOn {
			t.Errorf("%s 被 active 注入重新启用（用户停止态被覆盖）", id)
		}
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("停止任务被执行 %d 次, want 0", got)
	}
}

func TestCertificateService_periodic_scans_do_not_mutate_jobs_while_queue_paused(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	manager := GetCAQueueManager()
	manager.PauseAndDrain()
	t.Cleanup(ResetCAQueueManagerForTest)
	for _, ruleID := range []string{"lb_paused_renewal", "lb_paused_waiting"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?, 'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed paused rule %s: %v", ruleID, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_provider_id) VALUES ('lb_paused_renewal','lb_paused_renewal.example.com','issued',datetime('now','+1 day'),1)`); err != nil {
		t.Fatalf("seed paused renewal job: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id) VALUES ('lb_paused_waiting','lb_paused_waiting.example.com','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatalf("seed paused waiting job: %v", err)
	}
	service := NewCertificateService()
	resetCertificateServiceForTest(t)

	// When
	// 返回值必须断言：角色读失败/查询崩溃同样「状态未变」，只看状态无法
	// 区分「暂停门生效」与「扫描整体失败」。
	if err := service.renewExpiringCertificates(); err != nil {
		t.Fatalf("续期扫描在队列暂停时不得失败: %v", err)
	}
	if requeued, disabled, err := service.requeueWaitingCAJobs(); err != nil {
		t.Fatalf("waiting_ca 重排在队列暂停时不得失败: %v", err)
	} else if requeued != 0 || disabled != 0 {
		t.Fatalf("requeued=%d disabled=%d, want 0/0（暂停门必须拦住全部重排）", requeued, disabled)
	}

	// Then
	for ruleID, wantStatus := range map[string]string{"lb_paused_renewal": "issued", "lb_paused_waiting": "waiting_ca"} {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
			t.Fatalf("read paused job %s: %v", ruleID, err)
		}
		if status != wantStatus {
			t.Fatalf("paused job %s status=%q, want %q", ruleID, status, wantStatus)
		}
	}
}

func TestCertificateService_renewExpiringCertificates_retries_failed_first_issuance_after_cooldown(t *testing.T) {
	// Given：三个首次签发失败（expires_at 为 NULL）的任务——已过冷却、仍在冷却、已达重试上限
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
	for _, ruleID := range []string{"lb_first_retry", "lb_first_cooling", "lb_first_capped"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,renewal_attempts,updated_at,ca_provider_id) VALUES
		('lb_first_retry','lb_first_retry.example.com','failed',1,datetime('now','-31 minutes'),1),
		('lb_first_cooling','lb_first_cooling.example.com','failed',1,datetime('now','-5 minutes'),1),
		('lb_first_capped','lb_first_capped.example.com','failed',?,datetime('now','-31 minutes'),1)`, maxAttempts); err != nil {
		t.Fatalf("seed failed first-issuance jobs: %v", err)
	}
	transitioned := make(chan struct{})
	release := make(chan struct{})
	manager.beforeEnqueue = func() {
		close(transitioned)
		<-release
	}
	done := make(chan struct{})
	resetCertificateServiceForTest(t)
	go func() {
		NewCertificateService().renewExpiringCertificates()
		close(done)
	}()

	// When：巡检重新排队过冷却任务（beforeEnqueue 在状态迁移后、入队前阻塞）
	<-transitioned

	// Then
	for ruleID, wantStatus := range map[string]string{
		"lb_first_retry":   "queued",
		"lb_first_cooling": "failed",
		"lb_first_capped":  "failed",
	} {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&status); err != nil {
			t.Fatalf("read job %s: %v", ruleID, err)
		}
		if status != wantStatus {
			t.Fatalf("job %s status=%q, want %q", ruleID, status, wantStatus)
		}
	}
	close(release)
	<-done
}

func TestCertificateService_renewExpiringCertificates_usesRenewalFlowForIssuedMissingExpiry(t *testing.T) {
	// Given：expires_at 缺失并不表示首次签发失败；issued 行必须走续期状态与文案。
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_issued_null_flow','issued-null-flow','issued-null-flow.example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(time.Hour), "issued-null-flow.example.com")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id)
		VALUES ('lb_issued_null_flow','issued-null-flow.example.com','issued',NULL,?,?,1)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	transitioned := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseEnqueue := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseEnqueue)
	manager.beforeEnqueue = func() {
		close(transitioned)
		<-release
	}
	done := make(chan struct{})
	resetCertificateServiceForTest(t)
	service := NewCertificateService()
	if jobs, _, err := service.CheckExpiration(); err != nil || len(jobs) != 1 || jobs[0].RuleID != "lb_issued_null_flow" {
		t.Fatalf("renewal candidates=%v err=%v, want issued NULL job", jobs, err)
	}
	go func() {
		service.renewExpiringCertificates()
		close(done)
	}()

	// When：续期巡检应完成状态迁移并在入队钩子前停下，便于检查真实 DB 终态。
	select {
	case <-transitioned:
	case <-time.After(2 * time.Second):
		releaseEnqueue()
		<-done
		t.Fatal("issued + NULL expires_at 未进入续期入队")
	}

	// Then
	var status, message string
	if err := database.QueryRow("SELECT status,message FROM cert_jobs WHERE rule_id='lb_issued_null_flow'").Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || message != "等待排队续期" {
		t.Fatalf("job=(%q,%q), want queued/等待排队续期", status, message)
	}
	releaseEnqueue()
	<-done
}

// 已达最大重试的 issued/failed 任务每轮续签扫描都会被
// 重复选出并入摘要后静默 continue——至少要留 warn 痕，操作者可见「仅手动
// 重试可达」（waiting_ca 有终局转换+审计，同条件 issued/failed 零痕迹）。
func TestCertificateService_renewExpiringCertificates_logs_capped_skip(t *testing.T) {
	// Given：临期 issued 任务已达最大续签重试次数
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	ruleID := "lb_capped_warn"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id) VALUES (?,?, 'issued', datetime('now','+1 day'),?,1)`, ruleID, ruleID+".example.com", maxAttempts); err != nil {
		t.Fatalf("seed capped job: %v", err)
	}
	var buf strings.Builder
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})

	// When
	resetCertificateServiceForTest(t)
	NewCertificateService().renewExpiringCertificates()

	// Then：静默跳过必须留 warn 痕（含任务号与上限值）
	if !strings.Contains(buf.String(), "已达最大重试次数") {
		t.Fatalf("capped job skipped without warn trace, log=%q", buf.String())
	}
	var attempts int
	if err := database.QueryRow("SELECT renewal_attempts FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&attempts); err != nil {
		t.Fatalf("read capped job: %v", err)
	}
	if attempts != maxAttempts {
		t.Fatalf("capped job attempts=%d, want unchanged %d", attempts, maxAttempts)
	}
}

// 续期摘要分档——已达上限任务每轮仍被选出
// warn 形态，自动重试不可达），摘要不得把它们无声计入「待重试」；须标注
// 「其中 M 个已达重试上限，仅手动重签可达」。
func TestCertificateService_renewExpiringCertificates_summaryTiersCappedJobs(t *testing.T) {
	// Given：一条临期未达上限（会入队重试）+ 一条临期已达上限（仅 warn）
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	for _, ruleID := range []string{"lb_sum_normal", "lb_sum_capped"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id) VALUES
		('lb_sum_normal','lb_sum_normal.example.com','issued',datetime('now','+1 day'),0,1),
		('lb_sum_capped','lb_sum_capped.example.com','issued',datetime('now','+1 day'),?,1)`, maxAttempts); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	logDir := filepath.Join(t.TempDir(), "tasks")
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldDir) })

	// When
	resetCertificateServiceForTest(t)
	NewCertificateService().renewExpiringCertificates()

	// Then：N=2 其中 M=1 分档可见（修复前两任务混入同一「待重试」口径）
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	want := "检测到 2 个临期/待重试证书任务（其中 1 个已达重试上限，仅手动重签可达）"
	if !strings.Contains(string(data), want) {
		t.Fatalf("摘要未分档: %q", string(data))
	}
	// 摘要行在入队循环之前输出——只比对文案时「该入队的不入队/该跳过的不
	// 跳过」仍为绿。这里补 DB 侧调度结果：已达上限的任务保持 issued 且预算
	// 不变；未达上限的任务必须真正离开 issued（入队由 worker 继续推进）。
	var cappedStatus string
	var cappedAttempts int
	if err := database.QueryRow("SELECT status, COALESCE(renewal_attempts,0) FROM cert_jobs WHERE rule_id='lb_sum_capped'").Scan(&cappedStatus, &cappedAttempts); err != nil {
		t.Fatalf("read capped job: %v", err)
	}
	if cappedStatus != "issued" || cappedAttempts != maxAttempts {
		t.Fatalf("capped job status=%q attempts=%d, want issued/%d（已达上限不得入队）", cappedStatus, cappedAttempts, maxAttempts)
	}
	var normalJobID int
	if err := database.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_sum_normal'").Scan(&normalJobID); err != nil {
		t.Fatalf("read normal job: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", normalJobID).Scan(&status); err != nil {
			t.Fatalf("read normal job status: %v", err)
		}
		if status != "issued" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("未达上限的临期任务仍为 issued：扫描未真正入队重试")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 反向形状：全部未达上限时保持原摘要文案（不追加空分档括注）。
func TestCertificateService_renewExpiringCertificates_summaryKeepsPlainFormWithoutCappedJobs(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	ruleID := "lb_sum_plain"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id) VALUES (?,?, 'issued', datetime('now','+1 day'),0,1)`, ruleID, ruleID+".example.com"); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	logDir := filepath.Join(t.TempDir(), "tasks")
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldDir) })

	resetCertificateServiceForTest(t)
	NewCertificateService().renewExpiringCertificates()

	data, err := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if !strings.Contains(string(data), "检测到 1 个临期/待重试证书任务：") {
		t.Fatalf("原摘要文案缺席: %q", string(data))
	}
	if strings.Contains(string(data), "已达重试上限") {
		t.Fatalf("无上限任务时不得追加空分档括注: %q", string(data))
	}
}

func TestCertificateService_waitingCALogsScanAndIterationFailures(t *testing.T) {
	t.Run("scan error", func(t *testing.T) {
		_, database := newClusterTestService(t)
		ResetCAQueueManagerForTest()
		InitCAQueueManager(func() error { return nil })
		t.Cleanup(ResetCAQueueManagerForTest)
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id)
			VALUES ('lb_bad_waiting','bad.example','waiting_ca',datetime('now','-1 minute'),'not-an-integer')`); err != nil {
			t.Fatal(err)
		}
		logs := captureApplicationLogs(t)
		resetCertificateServiceForTest(t)

		requeued, _, err := NewCertificateService().requeueWaitingCAJobs()

		if !strings.Contains(logs.String(), "waiting_ca scan: scan row failed") {
			t.Fatalf("scan failure must be visible, logs=%q", logs.String())
		}
		// 单行读取失败必须上抛：只打日志会让补扫按成功轮记账（监控看不到
		// 「结果不完整」），该畸形行也就永远等不到人工介入。
		if err == nil {
			t.Fatal("requeueWaitingCAJobs err=nil, want 单行读取失败上抛")
		}
		if !strings.Contains(err.Error(), "1 行读取失败") {
			t.Fatalf("err=%v, want 失败行数", err)
		}
		if requeued != 0 {
			t.Fatalf("requeued=%d, want 0（唯一候选行不可读）", requeued)
		}
	})
	t.Run("scan error keeps processing readable rows", func(t *testing.T) {
		_, database := newClusterTestService(t)
		// active=true 但不起 worker：入队路径生效（requeued 计数可信），执行链
		// 不运行——否则测试会真实访问 CA 目录并让行终态取决于网络。
		oldManager := caQueueManager
		caQueueManager = &CAQueueManager{
			queues:       make(map[int]*caQueue),
			blockedRules: make(map[string]map[RuleBlockToken]struct{}),
			active:       true,
			reloader:     func() error { return nil },
		}
		t.Cleanup(func() { caQueueManager.Stop(); caQueueManager = oldManager })
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES ('lb_waiting_ok','waiting-ok','ok.example.test','http',8443,1,1,'acme_dns')`); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
		// 畸形行（ca_provider_id 为文本）+ 可读行同轮存在。
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id)
			VALUES ('lb_bad_waiting','bad.example','waiting_ca',datetime('now','-1 minute'),'not-an-integer')`); err != nil {
			t.Fatal(err)
		}
		goodID := seedOrphanCertJob(t, "lb_waiting_ok", "ok.example.test", "waiting_ca")
		if _, err := database.Exec(`UPDATE cert_jobs SET ca_provider_id=1, ca_available_after=datetime('now','-1 minute') WHERE id=?`, goodID); err != nil {
			t.Fatalf("arm readable row: %v", err)
		}
		resetCertificateServiceForTest(t)

		requeued, _, err := NewCertificateService().requeueWaitingCAJobs()

		if err == nil {
			t.Fatal("err=nil, want 读取失败上抛")
		}
		if requeued != 1 {
			t.Fatalf("requeued=%d, want 1（可读行必须照常处置，不得因他人失败一并放弃）", requeued)
		}
		// 不启动队列 worker：断言只钉「该行已离开 waiting_ca」（排队后由 worker
		// 决定后续终态，与本次扫描语义无关，且会给测试引入真实网络依赖）。
		var status string
		if scanErr := database.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, goodID).Scan(&status); scanErr != nil {
			t.Fatalf("read job status: %v", scanErr)
		}
		if status == "waiting_ca" {
			t.Fatalf("readable job status=%q, want 已离开 waiting_ca（可读行必须照常处置）", status)
		}
	})
	t.Run("iteration error", func(t *testing.T) {
		newClusterTestService(t)
		ResetCAQueueManagerForTest()
		InitCAQueueManager(func() error { return nil })
		t.Cleanup(ResetCAQueueManagerForTest)
		logs := captureApplicationLogs(t)
		realDB := db.DB
		fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "FROM cert_jobs"})
		db.DB = fake
		t.Cleanup(func() { db.DB = realDB; _ = fake.Close() })
		resetCertificateServiceForTest(t)

		if _, _, err := NewCertificateService().requeueWaitingCAJobs(); err == nil {
			t.Fatal("iterating rows failure must be returned, got nil")
		}

		if !strings.Contains(logs.String(), "waiting_ca scan: iterate rows failed") {
			t.Fatalf("rows.Err failure must be visible, logs=%q", logs.String())
		}
	})
}

// 单行扫描失败必须让 30s 补扫落失败终态：畸形行被跳过时若仍写「补扫完成」，
// 任务监控对「本次扫描不完整」完全不可见（带外改库/异常旧快照是唯一来源）。
func TestCertWaitingCATickOnce_scanRowFailureWritesFailureSummary(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	t.Cleanup(ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id)
		VALUES ('lb_tick_bad_row','bad.example','waiting_ca',datetime('now','-1 minute'),'not-an-integer')`); err != nil {
		t.Fatalf("seed malformed waiting job: %v", err)
	}

	// When
	err := CertWaitingCATickOnce(context.Background())

	// Then 1：扫描不完整必须上抛（task_runs 记失败）
	if err == nil {
		t.Fatal("CertWaitingCATickOnce err=nil, want 单行扫描失败上抛")
	}
	// Then 2：失败轮摘要不得谎报「补扫完成」
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

func TestCertificateService_requeueWaitingCAJobs_disables_orphaned_waiting_job(t *testing.T) {
	// Given：waiting_ca 任务的规则已不存在（无 lb_rules 行），守卫应按孤儿
	// 转 disabled 而不是重排签发（与 6h 孤儿 sweep 同口径）。
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id) VALUES ('lb_gone','gone.example.com','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatalf("seed orphan waiting job: %v", err)
	}

	// When
	resetCertificateServiceForTest(t)
	NewCertificateService().requeueWaitingCAJobs()

	// Then
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_gone'").Scan(&status); err != nil {
		t.Fatalf("read orphan job: %v", err)
	}
	if status != "disabled" {
		t.Fatalf("orphan job status=%q, want disabled", status)
	}
}

func TestCertificateService_requeueWaitingCAJobs_pause_after_scan_start_leaves_job_waiting(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
	// 自此 requeue 守卫要求任务仍被启用中的 acme_dns TLS 规则引用，
	// 否则按孤儿转 disabled，不会进入 EnqueueIfActive 钩子路径。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_pause_scan','lb_pause_scan','example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id) VALUES ('lb_pause_scan','example.com','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatalf("seed waiting job: %v", err)
	}
	scanReady := make(chan struct{})
	resumeScan := make(chan struct{})
	manager.beforeActiveEnqueue = func() {
		close(scanReady)
		<-resumeScan
	}
	scanDone := make(chan struct{})
	resetCertificateServiceForTest(t)
	go func() {
		NewCertificateService().requeueWaitingCAJobs()
		close(scanDone)
	}()
	<-scanReady
	pauseDone := make(chan struct{})
	go func() {
		manager.PauseAndDrain()
		close(pauseDone)
	}()
	<-pauseDone
	close(resumeScan)
	<-scanDone

	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_pause_scan'").Scan(&status); err != nil {
		t.Fatalf("read waiting job: %v", err)
	}
	if status != "waiting_ca" {
		t.Fatalf("job status=%q, want waiting_ca", status)
	}
}

func TestRequeueNonTerminalCertJobs_disables_jobs_outside_acme_rule_gate(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	for _, rule := range []struct {
		id, domain, source string
		enabled, tls       int
	}{
		{id: "lb_recover_disabled", domain: "disabled.example.com", source: "acme_dns", enabled: 0, tls: 1},
		{id: "lb_recover_no_tls", domain: "plain.example.com", source: "acme_dns", enabled: 1, tls: 0},
		{id: "lb_recover_manual", domain: "manual.example.com", source: "manual", enabled: 1, tls: 1},
		{id: "lb_recover_changed", domain: "new.example.com", source: "acme_dns", enabled: 1, tls: 1},
	} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,?,8080,?,?,?)`, rule.id, rule.id, rule.domain, "http", rule.enabled, rule.tls, rule.source); err != nil {
			t.Fatalf("seed recovery rule %s: %v", rule.id, err)
		}
	}
	for _, job := range []struct{ ruleID, domain string }{
		{ruleID: "lb_recover_disabled", domain: "disabled.example.com"},
		{ruleID: "lb_recover_no_tls", domain: "plain.example.com"},
		{ruleID: "lb_recover_manual", domain: "manual.example.com"},
		{ruleID: "lb_recover_changed", domain: "old.example.com"},
		{ruleID: "lb_recover_missing", domain: "missing.example.com"},
	} {
		if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,'queued')", job.ruleID, job.domain); err != nil {
			t.Fatalf("seed recovery job %s: %v", job.ruleID, err)
		}
	}

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) error { return nil })

	// Then
	if err != nil {
		t.Fatalf("recover non-terminal jobs: %v", err)
	}
	var remaining int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE status!='disabled'").Scan(&remaining); err != nil {
		t.Fatalf("count non-disabled recovery jobs: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("non-disabled ineligible recovery jobs=%d, want 0", remaining)
	}
}

// 恢复循环内任一任务的 CAS 冲突（快照 SELECT 后并发写入方迁移了
// 状态）不得中止整个循环——冲突任务由并发写入方收尾，其后任务照常恢复，
// 与 sweepOrphanedCertJobs/requeueWaitingCAJobs 的冲突语义同型（creating_*/
// downloading 状态无周期巡检救援，中止即滞留到下次重启）。
func TestRequeueNonTerminalCertJobs_continues_past_disable_transition_conflict(t *testing.T) {
	// Given：job 1（downloaded+证书材料）触发部署重试回调，在回调内把 job 2
	// 的 DB 状态并发改为终态 failed——job 2（孤儿，快照状态 presenting_dns）的
	// disable 恢复转换随即 CAS 冲突；job 3 为排在冲突任务之后的对照任务。
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_conflict_hook','hook','hook.example.com','http',8443,1,1,'acme_dns'),
		('lb_conflict_tail','tail','tail.example.com','http',8445,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed hook rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES
		(1,'lb_conflict_hook','hook.example.com','downloaded','cert','key'),
		(2,'lb_missing_rule','orphan.example.com','presenting_dns','',''),
		(3,'lb_conflict_tail','tail.example.com','downloaded','cert','key')`); err != nil {
		t.Fatalf("seed recovery jobs: %v", err)
	}
	var retried []int

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) error {
		retried = append(retried, gotJobID)
		if gotJobID == 1 {
			if _, mutateErr := database.Exec("UPDATE cert_jobs SET status='failed' WHERE id=2"); mutateErr != nil {
				t.Errorf("mutate conflicting job status: %v", mutateErr)
			}
		}
		return nil
	})

	// Then：冲突不得返回错误，job 3 仍被处理；job 2 保持并发写入方的终态。
	if err != nil {
		t.Fatalf("recover non-terminal jobs: %v", err)
	}
	if len(retried) != 2 || retried[0] != 1 || retried[1] != 3 {
		t.Fatalf("retried jobs=%v, want [1 3]（冲突后的任务必须仍被恢复）", retried)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=2").Scan(&status); err != nil {
		t.Fatalf("read conflicting job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("conflicting job status=%q, want failed（不得覆写并发写入方的终态）", status)
	}
}

// 同上——"检测到已有有效证书"转 issued 的恢复转换（第二处 return
// 站点）同样不得因单任务 CAS 冲突中止循环。
func TestRequeueNonTerminalCertJobs_continues_past_existing_cert_transition_conflict(t *testing.T) {
	// Given：job 2 在途（creating_order）且携带 90 天有效证书（valid-cert 恢复
	// 优化适用）；job 1 的部署重试回调先把它并发置为 failed，job 2 转 issued
	// 即 CAS 冲突；job 3 为冲突后的对照任务。
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "conflict-issued.example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_conflict_hook','hook','hook.example.com','http',8443,1,1,'acme_dns'),
		('lb_conflict_issued','issued','conflict-issued.example.com','http',8444,1,1,'acme_dns'),
		('lb_conflict_tail','tail','tail.example.com','http',8445,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,cert_pem,key_pem,updated_at) VALUES
		(1,'lb_conflict_hook','hook.example.com','downloaded',NULL,'cert','key',datetime('now')),
		(2,'lb_conflict_issued','conflict-issued.example.com','creating_order',datetime('now','+90 days'),?,?,datetime('now')),
		(3,'lb_conflict_tail','tail.example.com','downloaded',NULL,'cert','key',datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed recovery jobs: %v", err)
	}
	var retried []int

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) error {
		retried = append(retried, gotJobID)
		if gotJobID == 1 {
			if _, mutateErr := database.Exec("UPDATE cert_jobs SET status='failed' WHERE id=2"); mutateErr != nil {
				t.Errorf("mutate conflicting job status: %v", mutateErr)
			}
		}
		return nil
	})

	// Then：冲突不得返回错误，job 3 仍被处理；job 2 保持并发写入方的终态。
	if err != nil {
		t.Fatalf("recover non-terminal jobs: %v", err)
	}
	if len(retried) != 2 || retried[0] != 1 || retried[1] != 3 {
		t.Fatalf("retried jobs=%v, want [1 3]（冲突后的任务必须仍被恢复）", retried)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=2").Scan(&status); err != nil {
		t.Fatalf("read conflicting job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("conflicting job status=%q, want failed（不得覆写并发写入方的终态）", status)
	}
}

func TestCertificateService_CheckExpiration_returns_only_current_enabled_acme_domain(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	for _, rule := range []struct {
		id, domain, source string
		enabled, tls       int
	}{
		{id: "lb_current", domain: "current.example.com", source: "acme_dns", enabled: 1, tls: 1},
		{id: "lb_disabled", domain: "disabled.example.com", source: "acme_dns", enabled: 0, tls: 1},
		{id: "lb_manual", domain: "manual.example.com", source: "manual", enabled: 1, tls: 1},
		{id: "lb_no_tls", domain: "plain.example.com", source: "acme_dns", enabled: 1, tls: 0},
		{id: "lb_changed", domain: "new.example.com", source: "acme_dns", enabled: 1, tls: 1},
		{id: "lb_changed_failed", domain: "new-failed.example.com", source: "acme_dns", enabled: 1, tls: 1},
		{id: "lb_changed_waiting", domain: "new-waiting.example.com", source: "acme_dns", enabled: 1, tls: 1},
	} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,?,8080,?,?,?)`, rule.id, rule.id, rule.domain, "http", rule.enabled, rule.tls, rule.source); err != nil {
			t.Fatalf("seed rule %s: %v", rule.id, err)
		}
	}
	for _, job := range []struct{ ruleID, domain, status string }{
		{ruleID: "lb_current", domain: "current.example.com", status: "issued"},
		{ruleID: "lb_disabled", domain: "disabled.example.com", status: "failed"},
		{ruleID: "lb_manual", domain: "manual.example.com", status: "waiting_ca"},
		{ruleID: "lb_no_tls", domain: "plain.example.com", status: "issued"},
		{ruleID: "lb_changed", domain: "old.example.com", status: "issued"},
		{ruleID: "lb_changed_failed", domain: "old-failed.example.com", status: "failed"},
		{ruleID: "lb_changed_waiting", domain: "old-waiting.example.com", status: "waiting_ca"},
	} {
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,last_error_code) VALUES (?,?,?,datetime('now','+1 day'),'')`, job.ruleID, job.domain, job.status); err != nil {
			t.Fatalf("seed job %s: %v", job.ruleID, err)
		}
	}

	// When
	resetCertificateServiceForTest(t)
	jobs, _, scanErr := NewCertificateService().CheckExpiration()
	if scanErr != nil {
		t.Fatalf("CheckExpiration: %v", scanErr)
	}

	// Then
	if len(jobs) != 1 || jobs[0].RuleID != "lb_current" {
		t.Fatalf("renewal jobs=%v, want only lb_current", jobs)
	}
}

func TestCertificateService_CheckExpiration_includes_issued_missing_expiry(t *testing.T) {
	// Given：历史 issued 行缺失 expires_at；证书临期/材料缺失都必须重新进入续期，
	// 已有证书仍远超续期窗口时则保持跳过，避免每轮无谓重签。
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	for _, ruleID := range []string{"lb_issued_null_due", "lb_issued_null_future", "lb_issued_null_missing", "lb_issued_timestamp_future"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	seed := func(ruleID string, notAfter time.Time, withMaterial bool, expiresAt any) {
		t.Helper()
		certPEM, keyPEM := "", ""
		if withMaterial {
			certPEM, keyPEM = certificatePairForDomains(t, now.Add(-time.Hour), notAfter, ruleID+".example.com")
		}
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem)
			VALUES (?,?,'issued',?,?,?)`, ruleID, ruleID+".example.com", expiresAt, certPEM, keyPEM); err != nil {
			t.Fatalf("seed job %s: %v", ruleID, err)
		}
	}
	seed("lb_issued_null_due", now.Add(time.Hour), true, nil)
	seed("lb_issued_null_future", now.Add(90*24*time.Hour), true, nil)
	seed("lb_issued_null_missing", time.Time{}, false, nil)
	seed("lb_issued_timestamp_future", now.Add(90*24*time.Hour), true, now.Add(90*24*time.Hour))

	// When
	resetCertificateServiceForTest(t)
	jobs, _, scanErr := NewCertificateService().CheckExpiration()
	if scanErr != nil {
		t.Fatalf("CheckExpiration: %v", scanErr)
	}

	// Then
	found := make(map[string]bool, len(jobs))
	for _, job := range jobs {
		found[job.RuleID] = true
	}
	for _, ruleID := range []string{"lb_issued_null_due", "lb_issued_null_missing"} {
		if !found[ruleID] {
			t.Errorf("%s missing from renewal candidates: %v", ruleID, jobs)
		}
	}
	for _, ruleID := range []string{"lb_issued_null_future", "lb_issued_timestamp_future"} {
		if found[ruleID] {
			t.Errorf("%s unexpectedly selected for renewal: %v", ruleID, jobs)
		}
	}
}

func TestCertificateService_CheckExpiration_compares_offset_and_fractional_timestamps_as_datetimes(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=1 WHERE id=1"); err != nil {
		t.Fatalf("set renewal window: %v", err)
	}
	threshold := time.Now().UTC().Add(24 * time.Hour)
	positiveOffset := time.FixedZone("plus-fourteen", 14*60*60)
	negativeOffset := time.FixedZone("minus-twelve", -12*60*60)
	tests := []struct {
		ruleID    string
		expiresAt string
		want      bool
	}{
		{ruleID: "lb_due_positive_offset", expiresAt: threshold.Add(-30 * time.Minute).In(positiveOffset).Format("2006-01-02 15:04:05-07:00"), want: true},
		{ruleID: "lb_future_negative_offset", expiresAt: threshold.Add(30 * time.Minute).In(negativeOffset).Format("2006-01-02 15:04:05-07:00"), want: false},
		{ruleID: "lb_due_fraction", expiresAt: threshold.Add(-time.Hour).Format("2006-01-02 15:04:05.999"), want: true},
		{ruleID: "lb_future_fraction", expiresAt: threshold.Add(time.Hour).Format("2006-01-02 15:04:05.001"), want: false},
	}
	for _, test := range tests {
		domain := test.ruleID + ".example.com"
		if _, err := database.Exec(`INSERT INTO lb_rules
			(caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, test.ruleID, test.ruleID, domain); err != nil {
			t.Fatalf("seed rule %s: %v", test.ruleID, err)
		}
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at)
			VALUES (?,?,'issued',?)`, test.ruleID, domain, test.expiresAt); err != nil {
			t.Fatalf("seed job %s: %v", test.ruleID, err)
		}
	}

	// When
	resetCertificateServiceForTest(t)
	jobs, _, scanErr := NewCertificateService().CheckExpiration()
	if scanErr != nil {
		t.Fatalf("CheckExpiration: %v", scanErr)
	}

	// Then
	found := make(map[string]bool, len(jobs))
	for _, job := range jobs {
		found[job.RuleID] = true
	}
	for _, test := range tests {
		if found[test.ruleID] != test.want {
			t.Fatalf("job %s included=%v, want %v for expires_at %q", test.ruleID, found[test.ruleID], test.want, test.expiresAt)
		}
	}
}

func TestCertificateService_CheckExpiration_respects_ca_cooldown_for_waiting_ca(t *testing.T) {
	// Given：三个临期 waiting_ca 任务——冷却中（未来 ca_available_after）、
	// 冷却已过（过去 ca_available_after）、无冷却（NULL）。
	_, database := newClusterTestService(t)
	for _, ruleID := range []string{"lb_cooling", "lb_cooling_done", "lb_no_cooldown"} {
		domain := ruleID + ".example.com"
		if _, err := database.Exec(`INSERT INTO lb_rules
			(caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, domain); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	for _, job := range []struct{ ruleID, status, caAvailableAfter string }{
		{ruleID: "lb_cooling", status: "waiting_ca", caAvailableAfter: "datetime('now','+1 hour')"},
		{ruleID: "lb_cooling_done", status: "waiting_ca", caAvailableAfter: "datetime('now','-1 hour')"},
		{ruleID: "lb_no_cooldown", status: "waiting_ca", caAvailableAfter: "NULL"},
	} {
		domain := job.ruleID + ".example.com"
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_available_after)
			VALUES (?,?,'waiting_ca',datetime('now','+1 day'),`+job.caAvailableAfter+`)`, job.ruleID, domain); err != nil {
			t.Fatalf("seed job %s: %v", job.ruleID, err)
		}
	}

	// When
	resetCertificateServiceForTest(t)
	jobs, _, scanErr := NewCertificateService().CheckExpiration()
	if scanErr != nil {
		t.Fatalf("CheckExpiration: %v", scanErr)
	}

	// Then：冷却中的任务不得被续期扫描捕获，冷却已过与无冷却的正常捕获
	found := make(map[string]bool, len(jobs))
	for _, job := range jobs {
		found[job.RuleID] = true
	}
	if found["lb_cooling"] {
		t.Fatalf("cooling waiting_ca job must not be re-enqueued by renewal scan: %v", jobs)
	}
	for _, ruleID := range []string{"lb_cooling_done", "lb_no_cooldown"} {
		if !found[ruleID] {
			t.Fatalf("job %s should be included in renewal scan", ruleID)
		}
	}
}

func TestCertJobsSnapshot_restore_replaces_upserted_and_new_rows(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const ruleID = "lb_snapshot"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'snapshot', 'old.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,ca_provider_id,renewal_attempts) VALUES (?, 'old.example.com', 'failed', 'old message', 7, 3)`, ruleID)
	if err != nil {
		t.Fatalf("seed old job: %v", err)
	}
	oldID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read old job ID: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}
	if _, err := database.Exec(`UPDATE cert_jobs SET status='queued', message='overwritten', ca_provider_id=9, renewal_attempts=0 WHERE id=?`, oldID); err != nil {
		t.Fatalf("overwrite old job: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?, 'new.example.com', 'queued')`, ruleID); err != nil {
		t.Fatalf("seed new job: %v", err)
	}

	// When
	err = RestoreCertJobsForRule(snapshot)

	// Then
	if err != nil {
		t.Fatalf("restore jobs: %v", err)
	}
	var count, gotID, providerID, attempts int
	var status, message string
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&count); err != nil {
		t.Fatalf("count restored jobs: %v", err)
	}
	if err := db.DB.QueryRow("SELECT id,status,message,ca_provider_id,renewal_attempts FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&gotID, &status, &message, &providerID, &attempts); err != nil {
		t.Fatalf("read restored job: %v", err)
	}
	if count != 1 || int64(gotID) != oldID || status != "failed" || message != "old message" || providerID != 7 || attempts != 3 {
		t.Fatalf("restored count=%d id=%d status=%q message=%q provider=%d attempts=%d", count, gotID, status, message, providerID, attempts)
	}
}

func TestRestoreCertJobs_skips_when_rule_deleted(t *testing.T) {
	// 规则在补偿退避窗口内被并发删除时，restore 必须按补偿完成收尾
	// （返回 nil），且不得写入幽灵 cert_jobs 行（cert_jobs 对 lb_rules 无外键，
	// 无条件 DELETE+INSERT 会把旧快照行插给已删除的规则）。
	// Given：快照后规则与其任务被另一路径整体删除
	_, database := newClusterTestService(t)
	const ruleID = "lb_restore_deleted"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'deleted', 'gone.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?, 'gone.example.com', 'creating_order', 7)`, ruleID); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM cert_jobs WHERE rule_id=?`, ruleID); err != nil {
		t.Fatalf("delete jobs: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM lb_rules WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("delete rule: %v", err)
	}

	// When
	err = RestoreCertJobsForRule(snapshot)

	// Then
	if err != nil {
		t.Fatalf("restore err=%v, want nil（规则已删除即无可补偿对象，按成功收尾）", err)
	}
	var ghostJobs int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&ghostJobs); err != nil {
		t.Fatal(err)
	}
	if ghostJobs != 0 {
		t.Fatalf("ghost cert_jobs=%d, want 0（不得给已删除规则写入幽灵行）", ghostJobs)
	}
}

func TestRestoreCertJobs_skips_when_rule_recreated_with_different_domain(t *testing.T) {
	// 补偿退避窗口内同一 caddy_id 被重建为新域名（新化身）时，
	// restore 不得摧毁新化身的 cert_jobs——其域名与快照时代不一致，必须跳过
	// DELETE+INSERT 并按补偿完成收尾（返回 nil，调用方释放租约）。
	// Given：快照时代规则域名为 old.example.com；删除后以同 caddy_id 重建为
	// new.example.com 并获得自己的新任务
	_, database := newClusterTestService(t)
	const ruleID = "lb_restore_era"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'era', 'old.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?, 'old.example.com', 'issued', 7)`, ruleID); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}
	for _, stmt := range []string{
		`DELETE FROM cert_jobs WHERE rule_id='` + ruleID + `'`,
		`DELETE FROM lb_rules WHERE caddy_id='` + ruleID + `'`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("simulate delete: %v", err)
		}
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'era', 'new.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("recreate rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?, 'new.example.com', 'queued', 7)`, ruleID); err != nil {
		t.Fatalf("seed new incarnation job: %v", err)
	}

	// When
	err = RestoreCertJobsForRule(snapshot)

	// Then
	if err != nil {
		t.Fatalf("restore err=%v, want nil（时代不匹配按补偿完成收尾）", err)
	}
	var count int
	var domain, status string
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT domain,status FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&domain, &status); err != nil {
		t.Fatal(err)
	}
	if count != 1 || domain != "new.example.com" || status != "queued" {
		t.Fatalf("cert_jobs count=%d row=(%q,%q), want 新化身任务 (new.example.com,queued) 原样存活、旧时代任务不得复活", count, domain, status)
	}
}

// 放弃语义的直接覆盖：requeueCertJobsSnapshot 的
// 四个跳过分支——规则行 ErrNoRows、规则 disabled/非 acme_dns、快照任务域名与规则
// 当前域名时代不符、规则域名不可规范化（导入产生的非法 ACME 域）——均必须按成功
// 收尾（返回 nil）且零入队。任一退化为返回错误都会
// 把补偿拖入永久退避循环且 blockedRules 租约永不释放（证书静默停发），而既有
// 测试全部绿灯。manager 预置合法租约与 provider：一旦某分支错误放行入队，
// beforeEnqueue 探针与 queues 创建立即可观测。
func TestRequeueCertJobsSnapshot_giveUpSemantics(t *testing.T) {
	seedRuleAndJob := func(t *testing.T, database *sql.DB, ruleID, domain string, enabled int) CertJobsSnapshot {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'requeue CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
			t.Fatalf("seed CA provider: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'requeue', ?, 'http', 8080, ?, 1, 'acme_dns')`, ruleID, domain, enabled); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?, ?, 'creating_order', 7)`, ruleID, domain); err != nil {
			t.Fatalf("seed job: %v", err)
		}
		snapshot, err := SnapshotCertJobsForRule(ruleID)
		if err != nil {
			t.Fatalf("snapshot jobs: %v", err)
		}
		return snapshot
	}
	newProbeManager := func(ruleID string) (*CAQueueManager, *atomic.Int32) {
		var enqueues atomic.Int32
		manager := &CAQueueManager{
			queues:       make(map[int]*caQueue),
			active:       true,
			blockedRules: map[string]map[RuleBlockToken]struct{}{ruleID: {1: {}}},
		}
		manager.beforeEnqueue = func() { enqueues.Add(1) }
		return manager, &enqueues
	}
	assertNilAndNoEnqueue := func(t *testing.T, err error, manager *CAQueueManager, enqueues *atomic.Int32) {
		t.Helper()
		if err != nil {
			t.Fatalf("requeue err=%v, want nil（无可补偿对象按成功收尾，返回错误会拖入永久退避）", err)
		}
		if got := enqueues.Load(); got != 0 {
			t.Fatalf("enqueue attempts=%d, want 0（跳过分支不得放行入队）", got)
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if len(manager.queues) != 0 {
			t.Fatal("a queue was created（跳过分支不得触达 enqueueLocked）")
		}
	}

	t.Run("rule deleted", func(t *testing.T) {
		// Given：快照后规则与其任务被并发删除（ErrNoRows 分支）
		_, database := newClusterTestService(t)
		const ruleID = "lb_requeue_gone"
		snapshot := seedRuleAndJob(t, database, ruleID, "gone.example.com", 1)
		if _, err := database.Exec(`DELETE FROM cert_jobs WHERE rule_id=?`, ruleID); err != nil {
			t.Fatalf("delete jobs: %v", err)
		}
		if _, err := database.Exec(`DELETE FROM lb_rules WHERE caddy_id=?`, ruleID); err != nil {
			t.Fatalf("delete rule: %v", err)
		}
		manager, enqueues := newProbeManager(ruleID)

		// When
		err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

		// Then
		assertNilAndNoEnqueue(t, err, manager, enqueues)
	})

	t.Run("rule disabled", func(t *testing.T) {
		// Given：规则存在但已禁用（enabled 门分支）
		_, database := newClusterTestService(t)
		const ruleID = "lb_requeue_disabled"
		snapshot := seedRuleAndJob(t, database, ruleID, "disabled.example.com", 0)
		manager, enqueues := newProbeManager(ruleID)

		// When
		err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

		// Then
		assertNilAndNoEnqueue(t, err, manager, enqueues)
	})

	t.Run("snapshot era mismatches recreated rule domain", func(t *testing.T) {
		// Given：规则以同 caddy_id 重建为新域名（canonicalJob≠canonicalRule 分支）
		_, database := newClusterTestService(t)
		const ruleID = "lb_requeue_era"
		snapshot := seedRuleAndJob(t, database, ruleID, "old.example.com", 1)
		if _, err := database.Exec(`UPDATE lb_rules SET domain='new.example.com' WHERE caddy_id=?`, ruleID); err != nil {
			t.Fatalf("recreate rule with new domain: %v", err)
		}
		manager, enqueues := newProbeManager(ruleID)

		// When
		err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

		// Then
		assertNilAndNoEnqueue(t, err, manager, enqueues)
	})

	t.Run("rule domain not canonicalizable", func(t *testing.T) {
		// Given：导入产生的非法 ACME 域规则（3 域——导入校验不验 ACME 域合法性，
		// 仅保存侧校验）。该规则本就无法重排队（createOrRequeue 同样拒绝非法域），
		// canonicalize 失败必须与 ErrNoRows/禁用分支同为放弃语义——返回错误会把
		// 补偿拖入永久退避循环且租约永不释放。
		_, database := newClusterTestService(t)
		const ruleID = "lb_requeue_badacme"
		snapshot := seedRuleAndJob(t, database, ruleID, "a.example.com,b.example.com,c.example.com", 1)
		manager, enqueues := newProbeManager(ruleID)

		// When
		err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

		// Then
		assertNilAndNoEnqueue(t, err, manager, enqueues)
	})
}

// 补偿重排队路径必须在入队前把在途快照任务落库为 'queued'。快照保留
// 快照时刻的在途状态（waiting_ca/creating_order/validating 等），不归一化直接入队
// 会让 provider 失效 drain 的 queuedJobStillExists 复核因 status≠'queued' 跳过
// failJob，任务滞留队列外直到重启。
//
// 观测设计：beforeEnqueue 探针是唯一确定性的「入队时刻」观测点——真实队列的 loop
// goroutine 在 enqueue 后即刻被 wakeCh 唤醒，其后的任何断言都可能被在途执行
// （preflight/状态转换）覆盖。drain 半程按 N+7 测试同款复刻 tick 排空后状态，用
// 手工队列（无 loop）驱动 failPendingProviderUnavailable，零调度竞态。
// ACME directory 指向本地挂起端点（TCP 连上但永不响应），保证 PauseAndDrain 的
// 取消到达时在途执行必然停留在 preflight——取消统一把行收敛回 'queued'
// （requeueCanceledJob），drain 前置状态确定。
func TestRequeueCertJobsSnapshot_midflight_jobs_enter_queue_as_queued_and_survive_provider_drain(t *testing.T) {
	for _, seedStatus := range []string{"waiting_ca", "creating_order", "validating"} {
		t.Run(seedStatus, func(t *testing.T) {
			// Given：规则 + 在途任务 + 挂起端点上的 CA provider
			_, database := newClusterTestService(t)
			const ruleID = "lb_requeue_midflight"
			const domain = "midflight.example.com"
			if _, err := database.Exec(`UPDATE global_config SET acme_email='audit@example.com' WHERE id=1`); err != nil {
				t.Fatalf("seed acme email: %v", err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen hang endpoint: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					// 永不响应：让 ACME preflight 一直挂在 HTTP 等待上，直到执行 ctx 被取消
					buf := make([]byte, 1024)
					_, _ = conn.Read(buf)
				}
			}()
			if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'requeue CA','letsencrypt',?,1)`, "http://"+listener.Addr().String()+"/directory"); err != nil {
				t.Fatalf("seed CA provider: %v", err)
			}
			if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, domain); err != nil {
				t.Fatalf("seed rule: %v", err)
			}
			jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?,?,?,7)`, ruleID, domain, seedStatus)
			if err != nil {
				t.Fatalf("seed job: %v", err)
			}
			jobID, err := jobResult.LastInsertId()
			if err != nil {
				t.Fatalf("read job ID: %v", err)
			}
			snapshot, err := SnapshotCertJobsForRule(ruleID)
			if err != nil {
				t.Fatalf("snapshot jobs: %v", err)
			}
			manager := &CAQueueManager{
				queues:       make(map[int]*caQueue),
				active:       true,
				blockedRules: map[string]map[RuleBlockToken]struct{}{ruleID: {1: {}}},
				dataDir:      t.TempDir(),
			}
			t.Cleanup(manager.Stop)
			var statusAtEnqueue atomic.Value
			manager.beforeEnqueue = func() {
				var status string
				if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err == nil {
					statusAtEnqueue.Store(status)
				}
			}

			// When：补偿重排队
			err = requeueCertJobsSnapshot(context.Background(), snapshot, manager)

			// Then 1：入队时刻 DB 状态必须为 'queued'（所有入队路径落库 queued 不变量）
			if err != nil {
				t.Fatalf("requeue err=%v, want nil", err)
			}
			if got, _ := statusAtEnqueue.Load().(string); got != "queued" {
				t.Fatalf("status at enqueue=%q, want queued（在途快照任务入队前必须归一化为 queued，否则 provider 失效 drain 跳过 failJob 滞留至重启）", got)
			}
			// Then 2：任务真实占用队列槽位
			manager.mu.Lock()
			queue, ok := manager.queues[7]
			var inQueue bool
			if ok {
				queue.mu.Lock()
				_, inQueue = queue.active[int(jobID)]
				queue.mu.Unlock()
			}
			manager.mu.Unlock()
			if !ok || !inQueue {
				t.Fatalf("job %d in queue: ok=%v inQueue=%v, want enqueued", jobID, ok, inQueue)
			}

			// Then 3：provider 失效 drain——先停真实队列取消在途执行（行收敛回
			// 'queued'），再复刻 tick 排空后状态跑 provider 失效处置
			manager.PauseAndDrain()
			var status string
			if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
				t.Fatalf("read status after drain: %v", err)
			}
			if status != "queued" {
				t.Fatalf("status after drain=%q, want queued", status)
			}
			drainQueue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, func() error { return nil })
			t.Cleanup(drainQueue.cancel)
			drainQueue.enqueue(queueItem{jobID: int(jobID), ruleID: ruleID, domains: domain})
			// 复刻 tick 排空后状态：pending 已排空、active 已摘除
			drainQueue.mu.Lock()
			drainQueue.pending = nil
			delete(drainQueue.active, int(jobID))
			drainQueue.mu.Unlock()
			manager.failPendingProviderUnavailable([]queueItem{{jobID: int(jobID), ruleID: ruleID, domains: domain}}, "CA Provider 不可用：配置已禁用或删除（ID 7）")

			// Then 4：任务被标记 failed 而非跳过（不得滞留至重启）
			var attempts int
			var message string
			if err := database.QueryRow("SELECT status, COALESCE(renewal_attempts,0), COALESCE(message,'') FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts, &message); err != nil {
				t.Fatalf("read drained job: %v", err)
			}
			if status != "failed" || !strings.Contains(message, "CA Provider 不可用") {
				t.Fatalf("drain result status=%q attempts=%d message=%q, want failed + CA Provider 不可用", status, attempts, message)
			}
		})
	}
}

func TestRequeueNonTerminalCertJobs_does_not_resurrect_failed_job(t *testing.T) {
	// Given：failed 任务虽持有之前签发的有效证书，也不得在启动恢复时被复活；
	// queued 任务是用户显式触发的重签请求（RetryCertJob 全量重签语义、不清
	// cert_pem/key_pem），旧有效证书不得吞掉请求——保持 queued 重新排队，
	// 不得迁移 issued。
	_, database := newClusterTestService(t)
	failedCert, failedKey := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "failed.example.com")
	queuedCert, queuedKey := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "queued.example.com")
	for _, rule := range []struct{ id, domain string }{
		{id: "lb_recover_failed", domain: "failed.example.com"},
		{id: "lb_recover_queued", domain: "queued.example.com"},
	} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, rule.id, rule.id, rule.domain); err != nil {
			t.Fatalf("seed recovery rule %s: %v", rule.id, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'recovery CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id) VALUES (42,'lb_recover_failed','failed.example.com','failed',datetime('now','+90 days'),?,?,7)`, failedCert, failedKey); err != nil {
		t.Fatalf("seed failed job: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id) VALUES (43,'lb_recover_queued','queued.example.com','queued',datetime('now','+90 days'),?,?,7)`, queuedCert, queuedKey); err != nil {
		t.Fatalf("seed queued job: %v", err)
	}
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	manager := GetCAQueueManager()
	var enqueues atomic.Int32
	manager.beforeEnqueue = func() { enqueues.Add(1) }
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	go queue.loop()
	manager.mu.Lock()
	manager.queues[7] = queue
	manager.mu.Unlock()

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) error { return nil })

	// Then
	if err != nil {
		t.Fatalf("recover non-terminal jobs: %v", err)
	}
	statuses := make(map[string]string)
	rows, err := database.Query("SELECT rule_id,status FROM cert_jobs")
	if err != nil {
		t.Fatalf("query recovered jobs: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ruleID, status string
		if err := rows.Scan(&ruleID, &status); err != nil {
			t.Fatalf("scan recovered job: %v", err)
		}
		statuses[ruleID] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate recovered jobs: %v", err)
	}
	if statuses["lb_recover_failed"] != "failed" {
		t.Fatalf("failed job was resurrected to %q, want failed", statuses["lb_recover_failed"])
	}
	if statuses["lb_recover_queued"] != "queued" {
		t.Fatalf("queued job status=%q, want queued（显式重签请求不得被吞成 issued）", statuses["lb_recover_queued"])
	}
	if got := enqueues.Load(); got != 1 {
		t.Fatalf("enqueue attempts=%d, want 1（queued 任务必须重新排队）", got)
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT COALESCE(detail,'') FROM audit_log WHERE action='恢复排队'").Scan(&detail); err != nil {
		t.Fatalf("queued job recovery audit entry missing: %v", err)
	}
	if !strings.Contains(detail, "任务 43") || strings.Contains(detail, "任务 42") {
		t.Fatalf("recovery audit detail=%q, want 仅任务 43（failed 任务不得恢复排队）", detail)
	}
}

// 'queued' 是用户显式触发的重签请求（RetryCertJob
// 全量重签语义，旧 cert_pem/key_pem 保留在行上），启动恢复不得以"检测到已有
// 有效证书"将其静默转为 issued——请求必须经重新排队存活到重启之后。
func TestRequeueNonTerminalCertJobs_requeues_queued_job_despite_valid_stored_cert(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "reissue.example.com")
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'reissue CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, "lb_reissue", "lb_reissue", "reissue.example.com"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id) VALUES ('lb_reissue','reissue.example.com','queued',datetime('now','+90 days'),?,?,7)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed queued job holding valid stored certificate: %v", err)
	}
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	manager := GetCAQueueManager()
	var enqueues atomic.Int32
	manager.beforeEnqueue = func() { enqueues.Add(1) }
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	go queue.loop()
	manager.mu.Lock()
	manager.queues[7] = queue
	manager.mu.Unlock()

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) error {
		t.Error("deployment retry scheduled for non-downloaded job")
		return nil
	})

	// Then
	if err != nil {
		t.Fatalf("recover non-terminal jobs: %v", err)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_reissue'").Scan(&status); err != nil {
		t.Fatalf("read recovered job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("queued job status=%q, want queued（显式重签请求不得被有效证书吞成 issued）", status)
	}
	if got := enqueues.Load(); got != 1 {
		t.Fatalf("enqueue attempts=%d, want 1（重签请求必须重新排队）", got)
	}
}

func TestCertificateService_resumeDeploymentRetries_reschedulesDroppedRetries(t *testing.T) {
	// Given：暂停期间被丢弃的部署重试：任务 A 窗口已过且材料齐全（应重排），
	// 任务 B 窗口在未来（不重排），任务 C 缺证书材料（不重排），
	// 任务 D 规则已删除（不重排）
	_, database := newClusterTestService(t)
	for _, rule := range []struct{ id, domain string }{
		{id: "lb_resume_retry", domain: "example.com"},
		{id: "lb_resume_retry_future", domain: "future.example.com"},
		{id: "lb_resume_retry_nomaterial", domain: "nomaterial.example.com"},
	} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, rule.id, rule.id, rule.domain); err != nil {
			t.Fatal(err)
		}
	}
	certPEM, keyPEM := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "example.com")
	jobs := []struct {
		id                                int
		ruleID, domain, window, cert, key string
	}{
		{id: 1, ruleID: "lb_resume_retry", domain: "example.com", window: "datetime('now','-1 hour')", cert: certPEM, key: keyPEM},
		{id: 2, ruleID: "lb_resume_retry_future", domain: "future.example.com", window: "datetime('now','+1 hour')", cert: certPEM, key: keyPEM},
		{id: 3, ruleID: "lb_resume_retry_nomaterial", domain: "nomaterial.example.com", window: "datetime('now','-1 hour')", cert: "", key: ""},
		{id: 4, ruleID: "lb_deleted_rule", domain: "example.com", window: "datetime('now','-1 hour')", cert: certPEM, key: keyPEM},
	}
	for _, job := range jobs {
		if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,deployment_available_after,cert_pem,key_pem,ca_provider_id) VALUES (?,?,?,?,`+job.window+`,?,?,7)`, job.id, job.ruleID, job.domain, "downloaded", job.cert, job.key); err != nil {
			t.Fatal(err)
		}
	}
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	var scheduled []int
	var delays []time.Duration
	service.deploymentRetry = func(jobID int, _ issuedCertificate, delay time.Duration) error {
		scheduled = append(scheduled, jobID)
		delays = append(delays, delay)
		return nil
	}
	service.pauseDeploymentRetries()

	// When
	service.resumeDeploymentRetries()

	// Then：材料齐全且规则适用的任务被重排——窗口已过的 A 以 delay=0 立即，
	// 窗口在未来的 B 以剩余等待 delay 重排（与启动恢复同口径，
	// 不再静默丢弃至重启）；缺材料的 C 与规则已删除的 D 仍不重排。
	if len(scheduled) != 2 || scheduled[0] != 1 || scheduled[1] != 2 {
		t.Fatalf("scheduled=%v, want jobs 1 and 2", scheduled)
	}
	if len(delays) != 2 || delays[0] != 0 {
		t.Fatalf("job 1 delay=%v, want 0 (window passed)", delays[0])
	}
	if delays[1] <= 0 {
		t.Fatalf("job 2 delay=%v, want remaining backoff window (future)", delays[1])
	}
	if delays[1] > time.Hour {
		t.Fatalf("job 2 delay=%v, want <= remaining 1h window", delays[1])
	}
}

// seedRequeueMaterialFixture 建立补偿重排队测试夹具：规则 + enabled provider(id 7)
// + 指定状态/材料的任务 + 快照，并返回带租约与 stub 执行队列的探针 manager
// （入队路径不触网络、执行不写库，状态断言零竞态）。
func seedRequeueMaterialFixture(t *testing.T, domain, seedStatus, certPEM, keyPEM string) (*sql.DB, CertJobsSnapshot, *CAQueueManager, int64, *atomic.Value) {
	t.Helper()
	_, database := newClusterTestService(t)
	const ruleID = "lb_requeue_material"
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'requeue CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,ca_provider_id) VALUES (?,?,?,?,?,7)`, ruleID, domain, seedStatus, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := jobResult.LastInsertId()
	if err != nil {
		t.Fatalf("read job ID: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		active:       true,
		blockedRules: map[string]map[RuleBlockToken]struct{}{ruleID: {1: {}}},
	}
	// 预置 stub 执行队列（loop 在跑、executeFn no-op）：避免真实 Issue 执行触网，
	// 也保证执行不写库——补偿路径自身的状态转换就是被测对象。
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, func() error { return nil })
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	go queue.loop()
	manager.mu.Lock()
	manager.queues[7] = queue
	manager.mu.Unlock()
	t.Cleanup(manager.Stop)
	var statusAtEnqueue atomic.Value
	manager.beforeEnqueue = func() {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err == nil {
			statusAtEnqueue.Store(status)
		}
	}
	return database, snapshot, manager, jobID, &statusAtEnqueue
}

// （2b68044a）为 requeueCertJobsSnapshot 引入「downloaded+材料保持
// 原状态直接入队」例外分支时，只补了无材料在途任务的归一化测试，例外分支本身
// 缺直接测试。锁定：downloaded+材料的快照任务入队时刻与入队后均保持 'downloaded'
// （Issue 快速路径重部署），不得被归一化为 'queued' 触发整轮重签（丢弃已签发证书）。
func TestRequeueCertJobsSnapshot_downloaded_with_material_stays_fast_path(t *testing.T) {
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "material.example.com")
	database, snapshot, manager, jobID, statusAtEnqueue := seedRequeueMaterialFixture(t, "material.example.com", "downloaded", certPEM, keyPEM)

	// When
	err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

	// Then
	if err != nil {
		t.Fatalf("requeue err=%v, want nil", err)
	}
	if got, _ := statusAtEnqueue.Load().(string); got != "downloaded" {
		t.Fatalf("status at enqueue=%q, want downloaded（材料例外分支不得归一化为 queued 触发整轮重签）", got)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("final status=%q, want downloaded（保持快速路径状态等待重部署）", status)
	}
}

// 部署生命周期（cleanup_dns/cleanup_warning）+ 材料在身的快照任务同样
// 只差部署——材料已落库、证书已签发（retryCertificateDeployment 从这些状态装载
// 材料即为证）。补偿重排队必须归一化为 'downloaded' 走 Issue 快速路径重部署，
// 不得转 'queued' 整轮重签（浪费 CA 配额并丢弃有效证书）。
// 'queued'+材料为负对照：确立 queued 是显式重签请求
// （RetryCertJob 全量重签 BY-DESIGN，材料为上轮残留），补偿不得借材料例外吞掉。
func TestRequeueCertJobsSnapshot_deploy_stage_with_material_redeploys_not_reissues(t *testing.T) {
	for _, tc := range []struct {
		name, seedStatus, wantStatus string
	}{
		{name: "cleanup_dns with material goes fast path", seedStatus: "cleanup_dns", wantStatus: "downloaded"},
		{name: "cleanup_warning with material goes fast path", seedStatus: "cleanup_warning", wantStatus: "downloaded"},
		{name: "queued with material stays full reissue", seedStatus: "queued", wantStatus: "queued"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "redeploy.example.com")
			database, snapshot, manager, jobID, statusAtEnqueue := seedRequeueMaterialFixture(t, "redeploy.example.com", tc.seedStatus, certPEM, keyPEM)

			// When
			err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

			// Then
			if err != nil {
				t.Fatalf("requeue err=%v, want nil", err)
			}
			if got, _ := statusAtEnqueue.Load().(string); got != tc.wantStatus {
				t.Fatalf("status at enqueue=%q, want %q（部署生命周期+材料走 downloaded 快速路径；queued 是显式重签请求不得被材料例外吞掉）", got, tc.wantStatus)
			}
			var status string
			if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if status != tc.wantStatus {
				t.Fatalf("final status=%q, want %q", status, tc.wantStatus)
			}
			// 任务必须真实入队（例外分支只换目标状态，不得跳过入队）
			manager.mu.Lock()
			queue, hasQueue := manager.queues[7]
			var inQueue bool
			if hasQueue {
				queue.mu.Lock()
				_, inQueue = queue.active[int(jobID)]
				queue.mu.Unlock()
			}
			manager.mu.Unlock()
			if !hasQueue || !inQueue {
				t.Fatalf("job %d in queue: hasQueue=%v inQueue=%v, want enqueued", jobID, hasQueue, inQueue)
			}
		})
	}
}

// referenced CA provider 不可用（禁用/删除且无 enabled 回退）时，
// enqueueCompensation→enqueueLocked 已同步 failJob（任务置 failed + job 日志 +
// 审计——现有 job-status/audit 通道即最终处置）。补偿不得把该错误上抛：否则
// StartRuleDeletionCompensation 的退避循环永久重试（每轮 restore 复活 failed 行
// 再重新失败 + 问题 日志噪声），且规则租约（blockedRules）永不释放——该规则
// 的所有证书操作（EnqueueIfActive）持续 409。语义：provider 不可用按「该任务
// 已定局」跳过，补偿一轮收敛、租约释放；provider 恢复后由手动重试/续签接管。
func TestCompensateRuleDeletion_provider_unavailable_fails_job_and_releases_lease(t *testing.T) {
	_, database := newClusterTestService(t)
	const ruleID = "lb_comp_provider_gone"
	const domain = "providergone.example.com"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?,?,'creating_order',7)`, ruleID, domain)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := jobResult.LastInsertId()
	if err != nil {
		t.Fatalf("read job ID: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}
	// 库迁移默认 seed 两个 enabled provider（ZeroSSL/Let's Encrypt）——全部禁用，
	// loadCAProvider(7) 无行且无 enabled 回退，才会走 provider 不可用路径
	if _, err := database.Exec(`UPDATE ca_providers SET enabled=0`); err != nil {
		t.Fatalf("disable seeded providers: %v", err)
	}
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		active:       true,
		blockedRules: map[string]map[RuleBlockToken]struct{}{ruleID: {9: {}}},
	}
	t.Cleanup(manager.Stop)
	var enqueues atomic.Int32
	manager.beforeEnqueue = func() { enqueues.Add(1) }

	// When：整条 compensateRuleDeletion（drain→restore→requeue→Unblock）
	err = manager.compensateRuleDeletion(context.Background(), RuleDeletionCompensation{
		RuleID:   ruleID,
		Token:    9,
		Snapshot: snapshot,
	})

	// Then 1：按成功收尾——返回错误会把补偿拖入永久退避循环
	if err != nil {
		t.Fatalf("compensation err=%v, want nil（provider 不可用须按任务已定局收敛，上抛会永久退避）", err)
	}
	// Then 2：租约已释放（该规则证书操作不再 409）
	if manager.IsRuleBlocked(ruleID) {
		t.Fatal("rule lease still held after compensation, want released")
	}
	// Then 3：任务经现有 job-status/audit 通道定局为 failed + 明确归因
	var status, message string
	var attempts int
	if err := database.QueryRow("SELECT status, COALESCE(message,''), COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message, &attempts); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || !strings.Contains(message, "CA Provider 不可用") {
		t.Fatalf("job status=%q message=%q, want failed + CA Provider 不可用（现有通道已定局）", status, message)
	}
	// Then 4：未建队列、未真正入队（provider 缺失在入队前置检查即定局）
	if got := enqueues.Load(); got != 0 {
		t.Fatalf("enqueue attempts=%d, want 0", got)
	}
	manager.mu.Lock()
	queues := len(manager.queues)
	manager.mu.Unlock()
	if queues != 0 {
		t.Fatalf("queues=%d, want 0（provider 不可用不得创建队列）", queues)
	}
}

func TestRestoreCertJobs_roundtripsCanonicalDatetimeFormat(t *testing.T) {
	// restore 不得让 DATETIME 列漂移为驱动 `+00:00` 布局——
	// rescan 的 time.Parse("2006-01-02 15:04:05") 是唯一解析点，漂移即
	// 丢一个部署退避窗口。
	_, database := newClusterTestService(t)
	const ruleID = "lb_dt_roundtrip"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'dt', 'dt.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,deployment_available_after,expires_at,ca_available_after) VALUES (?, 'dt.example.com', 'downloaded', 7, datetime('now','+5 minutes'), datetime('now','+90 days'), datetime('now','-1 minutes'))`, ruleID); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM cert_jobs WHERE rule_id=?`, ruleID); err != nil {
		t.Fatalf("clear jobs: %v", err)
	}
	if err := RestoreCertJobsForRule(snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, col := range []string{"deployment_available_after", "expires_at", "ca_available_after", "created_at", "updated_at"} {
		var raw sql.NullString
		if err := db.DB.QueryRow(fmt.Sprintf("SELECT CAST(%s AS TEXT) FROM cert_jobs WHERE rule_id=?", col), ruleID).Scan(&raw); err != nil {
			t.Fatalf("read %s raw text: %v", col, err)
		}
		if !raw.Valid || raw.String == "" {
			continue // 该列在快照行中本就为 NULL——合法
		}
		if _, err := time.Parse("2006-01-02 15:04:05", raw.String); err != nil {
			t.Fatalf("%s drifted to non-canonical format %q: %v (历史问题 regression)", col, raw.String, err)
		}
	}
}

func TestCertificateService_rescanLogsScanAndIterationFailures(t *testing.T) {
	t.Run("scan error", func(t *testing.T) {
		_, database := newClusterTestService(t)
		if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,deployment_attempts,deployment_available_after)
			VALUES ('lb_bad_rescan','bad.example','downloaded','x','y','not-an-integer',datetime('now'))`); err != nil {
			t.Fatal(err)
		}
		logs := captureApplicationLogs(t)
		resetCertificateServiceForTest(t)

		if _, err := NewCertificateService().rescanDroppedDeploymentRetries(); err == nil {
			t.Fatalf("scan failure must be reported to the task engine (err=nil → 任务监控假绿), logs=%q", logs.String())
		}

		if !strings.Contains(logs.String(), "resume deployment retries: scan row failed") {
			t.Fatalf("scan failure must be visible, logs=%q", logs.String())
		}
	})
	t.Run("iteration error", func(t *testing.T) {
		newClusterTestService(t)
		logs := captureApplicationLogs(t)
		realDB := db.DB
		fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "FROM cert_jobs"})
		db.DB = fake
		t.Cleanup(func() { db.DB = realDB; _ = fake.Close() })
		resetCertificateServiceForTest(t)

		if _, err := NewCertificateService().rescanDroppedDeploymentRetries(); err == nil {
			t.Fatalf("rows.Err failure must be reported to the task engine (err=nil → 任务监控假绿), logs=%q", logs.String())
		}

		if !strings.Contains(logs.String(), "resume deployment retries: iterate rows failed") {
			t.Fatalf("rows.Err failure must be visible, logs=%q", logs.String())
		}
	})
}

// rescanDroppedDeploymentRetries 周期化(30s ticker)——
// 已持活跃 timer 的任务必须跳过,否则每 30s 取消重建会把退避窗口无限推后
// (timer 永不到期,重试链名存实亡)。
func TestCertificateService_rescanSkipsJobsWithActiveTimer(t *testing.T) {
	// Given:DB 中一条 downloaded+available_after 任务
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_rescan_skip", false)
	if _, err := database.Exec("UPDATE lb_rules SET enable_tls=1,tls_source='acme_dns' WHERE caddy_id='lb_rescan_skip'"); err != nil {
		t.Fatal(err)
	}
	availableAfter := time.Now().UTC().Add(2 * time.Minute).Format("2006-01-02 15:04:05")
	res, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,deployment_available_after) VALUES ('lb_rescan_skip','example.test','downloaded','x','y',?)`, availableAfter)
	if err != nil {
		t.Fatal(err)
	}
	jobID64, _ := res.LastInsertId()
	jobID := int(jobID64)

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	rescheduled := make(chan int, 4)
	service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
		rescheduled <- id
		return nil
	}

	// 已有活跃 timer(模拟正常重试链在跑)
	service.scheduleDeploymentRetry(jobID, "lb_rescan_skip", time.Hour)
	service.timerMu.Lock()
	original := service.deploymentTimers[jobID]
	service.timerMu.Unlock()
	if original == nil {
		t.Fatal("precondition: timer not registered")
	}

	// When:周期补扫
	service.rescanDroppedDeploymentRetries()

	// Then:timer 未被替换/取消,且未触发重排
	service.timerMu.Lock()
	current := service.deploymentTimers[jobID]
	service.timerMu.Unlock()
	if current != original {
		t.Fatal("active timer was replaced by periodic rescan — backoff window would never expire")
	}
	if original.canceled {
		t.Fatal("active timer was canceled by periodic rescan")
	}
	select {
	case id := <-rescheduled:
		t.Fatalf("rescan rescheduled job %d despite active timer", id)
	case <-time.After(100 * time.Millisecond):
	}
	service.pauseDeploymentRetries()
}

// 对偶:断链任务(无活跃 timer)必须被周期补扫重排。
func TestCertificateService_rescanPicksUpDroppedRetry(t *testing.T) {
	// Given:DB 中一条 downloaded+available_after 任务,无任何 timer(断链态)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_rescan_pick", false)
	if _, err := database.Exec("UPDATE lb_rules SET enable_tls=1,tls_source='acme_dns' WHERE caddy_id='lb_rescan_pick'"); err != nil {
		t.Fatal(err)
	}
	availableAfter := time.Now().UTC().Add(-time.Minute).Format("2006-01-02 15:04:05")
	res, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,deployment_available_after) VALUES ('lb_rescan_pick','example.test','downloaded','x','y',?)`, availableAfter)
	if err != nil {
		t.Fatal(err)
	}
	jobID64, _ := res.LastInsertId()
	jobID := int(jobID64)

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	rescheduled := make(chan int, 4)
	service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
		rescheduled <- id
		return nil
	}

	// When:周期补扫
	service.rescanDroppedDeploymentRetries()

	// Then:断链任务被重排
	select {
	case id := <-rescheduled:
		if id != jobID {
			t.Fatalf("rescheduled job=%d, want %d", id, jobID)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("dropped retry was not rescheduled")
	}
	service.pauseDeploymentRetries()
}

func TestCertificateService_rescanPicksUpCleanupAfterWritebackFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_rescan_cleanup", false)
	if _, err := database.Exec("UPDATE lb_rules SET enable_tls=1,tls_source='acme_dns' WHERE caddy_id='lb_rescan_cleanup'"); err != nil {
		t.Fatal(err)
	}
	res, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,deployment_available_after)
		VALUES ('lb_rescan_cleanup','example.test','cleanup_dns','x','y',NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	jobID64, _ := res.LastInsertId()
	jobID := int(jobID64)
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	rescheduled := make(chan int, 4)
	service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
		rescheduled <- id
		return nil
	}
	service.rescanDroppedDeploymentRetries()
	select {
	case id := <-rescheduled:
		if id != jobID {
			t.Fatalf("rescheduled job=%d, want %d", id, jobID)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleanup job with failed status writeback was not rescheduled")
	}
	service.pauseDeploymentRetries()
}

// 首签发 confirm/persist 瞬时失败走 deploymentFailed 时,
// 证书材料(仅内存)必须随 transitionJob 落库——否则任务回 downloaded 但材料
// 丢失,30s 补扫 hasCertMaterial=0 跳过,永久不可达只能重签烧 CA 配额。
func TestCertIssuer_deploymentFailed_persistsMaterial(t *testing.T) {
	// Given: downloaded 任务(材料未落库——首签发 persist 失败形态)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_dep_fail", false)
	res, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_dep_fail','example.test','downloaded')`)
	if err != nil {
		t.Fatal(err)
	}
	jobID64, _ := res.LastInsertId()
	jobID := int(jobID64)

	notAfter := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
	issuer := &CertIssuer{deploymentRetry: func(int, issuedCertificate, time.Duration) error { return nil }}

	// When: deploymentFailed 携带内存材料
	_ = issuer.deploymentFailed(jobID, issuedCertificate{
		ruleID: "lb_dep_fail", certPEM: "CERT_PEM", keyPEM: "KEY_PEM",
		notAfter: notAfter, providerID: 7,
	}, "persist failed", fmt.Errorf("simulated persist failure"))

	// Then: 材料已落库(补扫 hasCertMaterial=1 可达)+ downloaded + 退避窗口
	var certPEM, keyPEM, status, availableAfter string
	var providerID int
	var expiresAt string
	err = database.QueryRow(`SELECT COALESCE(cert_pem,''), COALESCE(key_pem,''), status,
		COALESCE(deployment_available_after,''), COALESCE(ca_provider_id,0), COALESCE(expires_at,'')
		FROM cert_jobs WHERE id=?`, jobID).Scan(&certPEM, &keyPEM, &status, &availableAfter, &providerID, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if certPEM != "CERT_PEM" || keyPEM != "KEY_PEM" {
		t.Fatalf("material not persisted: cert_pem=%q key_pem=%q", certPEM, keyPEM)
	}
	if status != "downloaded" {
		t.Fatalf("status=%s, want downloaded", status)
	}
	if availableAfter == "" {
		t.Fatal("deployment_available_after not set")
	}
	if providerID != 7 {
		t.Fatalf("ca_provider_id=%d, want 7", providerID)
	}
	if expiresAt == "" {
		t.Fatal("expires_at not persisted")
	}
}

// 续期扫描 Run 体不消费 rc.Ctx（SetRole 取消等价
// no-op），入口角色检查只做一次——demote 落在最长 6h 扫描/多任务候选窗口时，
// 循环会在队列停止前继续入队（已入队签发要跑完 ACME 才被角色检查拦下，白烧
// CA 配额）。逐任务入队前必须用同一 SQL 口径复核角色。
func TestRenewalScanRechecksRoleBeforeEachEnqueue(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	for _, ruleID := range []string{"lb_demote_a", "lb_demote_b"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	// ORDER BY expires_at ASC：A 先入队，B 在 demote 后被逐任务复核拦下。
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id) VALUES
		('lb_demote_a','lb_demote_a.example.com','issued',datetime('now','+1 day'),0,1),
		('lb_demote_b','lb_demote_b.example.com','issued',datetime('now','+2 day'),0,1)`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	logDir := filepath.Join(t.TempDir(), "tasks")
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldDir) })

	calls := 0
	oldHook := certRenewalRoleRecheckHook
	certRenewalRoleRecheckHook = func() {
		calls++
		if calls == 2 {
			// 第二个任务入队前 demote（模拟 SetRole 与长扫描的竞争窗口）。
			if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
				t.Errorf("demote: %v", err)
			}
		}
	}
	t.Cleanup(func() { certRenewalRoleRecheckHook = oldHook })

	resetCertificateServiceForTest(t)
	NewCertificateService().renewExpiringCertificates()

	if calls < 2 {
		t.Fatalf("逐任务角色复核未执行（hook 调用 %d 次）", calls)
	}
	var statusB string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE rule_id='lb_demote_b'`).Scan(&statusB); err != nil {
		t.Fatal(err)
	}
	if statusB != "issued" {
		t.Fatalf("demote 后第二个任务 status=%q, want issued（从节点不得继续入队）", statusB)
	}
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("read renewal task log: %v", err)
	}
	if !strings.Contains(string(data), "续期中止：扫描期间节点已切换为从节点，剩余 1 个任务本轮未入队") {
		t.Fatalf("demote 中止必须留痕: %q", string(data))
	}
}

// ---- 回归钉 ----

// 续期扫描把达上限 waiting_ca 转 failed 时，必须与
// markJobWaitingCA 上限分支同字段集清理冷却时间与 429 错误码。
func TestRenewalScan_capped_waiting_ca_failure_clears_cooldown_fields(t *testing.T) {
	_, database := newClusterTestService(t)
	resetCertificateServiceForTest(t)
	seedRuleWithCAProvider(t, "lb_capped_waiting", "capped.example.test", 0)
	maxAttempts := getCertRenewalAttempts()
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_available_after,last_error_code)
		VALUES ('lb_capped_waiting','capped.example.test','waiting_ca',datetime('now','+10 days'),?,datetime('now','-1 hour'),'429')`, maxAttempts); err != nil {
		t.Fatalf("seed waiting_ca job: %v", err)
	}

	// When
	NewCertificateService().renewExpiringCertificates()

	// Then
	var status string
	var availableAfter, lastErrorCode any
	if err := database.QueryRow(`SELECT status, ca_available_after, last_error_code FROM cert_jobs WHERE rule_id='lb_capped_waiting'`).Scan(&status, &availableAfter, &lastErrorCode); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed", status)
	}
	if availableAfter != nil {
		t.Fatalf("ca_available_after=%v, want NULL（终态不得残留冷却时间）", availableAfter)
	}
	if lastErrorCode != nil {
		t.Fatalf("last_error_code=%v, want NULL（终态不得残留 429）", lastErrorCode)
	}
}

// RestoreCertJobsForRule 是「整规则回滚 cert_jobs」，必须
// 与同规则的部署/文件回滚事务互斥（DeployLock），且对快照之后已落库的签发/部署
// 成果做行级 epoch 守卫——此前 + INSERT 会把补偿窗口内刚完成的续期/
// 部署回滚成旧快照行（PEM/状态丢失，磁盘/Caddy 与 DB 分叉）。
func TestRestoreCertJobs_deploy_lock_and_epoch_guard(t *testing.T) {
	_, database := newClusterTestService(t)
	const ruleID = "lb_restore_epoch"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'epoch', 'epoch.example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,ca_provider_id) VALUES (?, 'epoch.example.com', 'creating_order', '签发中', 7)`, ruleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// Given：快照之后并发签发完成（材料落库、状态推进到 downloaded），并且
	// 新增了一条带材料的新任务行（快照后新建的真实成果）
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "epoch.example.com")
	if _, err := database.Exec(`UPDATE cert_jobs SET status='downloaded', cert_pem=?, key_pem=?, expires_at=datetime('now','+90 days'), updated_at=datetime('now') WHERE id=?`, certPEM, keyPEM, jobID); err != nil {
		t.Fatalf("simulate concurrent issuance: %v", err)
	}
	newCertPEM, newKeyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "epoch-new.example.com")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES (?, 'epoch-new.example.com', 'downloaded', ?, ?)`, ruleID, newCertPEM, newKeyPEM); err != nil {
		t.Fatalf("seed post-snapshot row: %v", err)
	}

	// When：持有部署锁（模拟在途部署事务）时恢复必须等待
	unlock := DeployLock(ruleID)
	restoreDone := make(chan error, 1)
	go func() { restoreDone <- RestoreCertJobsForRule(snapshot) }()
	select {
	case restoreErr := <-restoreDone:
		unlock()
		t.Fatalf("restore err=%v 在部署锁释放前返回——恢复未与部署事务互斥", restoreErr)
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	if err := <-restoreDone; err != nil {
		t.Fatalf("restore err=%v, want nil", err)
	}

	// Then：快照后的签发成果不被回滚
	var status, restoredCert string
	var restoredKey sql.NullString
	if err := database.QueryRow("SELECT status, COALESCE(cert_pem,''), key_pem FROM cert_jobs WHERE id=?", jobID).Scan(&status, &restoredCert, &restoredKey); err != nil {
		t.Fatalf("read restored job: %v", err)
	}
	if status != "downloaded" || restoredCert != certPEM || !restoredKey.Valid {
		t.Fatalf("status=%q certMatch=%v keyValid=%v, want downloaded + 快照后签发材料保留（行级 epoch 守卫）", status, restoredCert == certPEM, restoredKey.Valid)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=? AND domain='epoch-new.example.com'", ruleID).Scan(&count); err != nil {
		t.Fatalf("count post-snapshot row: %v", err)
	}
	if count != 1 {
		t.Fatalf("post-snapshot row count=%d, want 1（带材料的新建任务属真实成果，不得清除）", count)
	}
}

// 材料快速路径（downloaded/cleanup_* + 材料）必须把
// deployment_available_after 推到当前时刻并落库。部署补扫
// （rescanDroppedDeploymentRetries）只收 status='downloaded' 且该列非空的行——
// 此前补偿保持/归一化到 downloaded 却不写该列（补偿 downloaded 快照常为 NULL），
// 队列未激活时两条补扫通道都不收，只能等重启恢复。断言同时消费补扫 SQL 谓词与
// 真实调度（stub deploymentRetry），避免只验字段形态。
func TestRequeueCertJobsSnapshot_material_fast_path_opens_deployment_window(t *testing.T) {
	for _, tc := range []struct{ name, seedStatus string }{
		{name: "downloaded with material stays downloaded", seedStatus: "downloaded"},
		{name: "cleanup_dns with material normalizes to downloaded", seedStatus: "cleanup_dns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "deploywindow.example.com")
			database, snapshot, manager, jobID, _ := seedRequeueMaterialFixture(t, "deploywindow.example.com", tc.seedStatus, certPEM, keyPEM)
			// 队列未激活：走 errCAQueueInactive 分支（不得谎称已入队/已转 queued）
			manager.mu.Lock()
			manager.active = false
			manager.mu.Unlock()

			// When
			err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

			// Then 1：按延后语义收敛（不把补偿拖入退避）
			if err != nil {
				t.Fatalf("requeue err=%v, want nil（队列未激活按延后语义收敛）", err)
			}
			var status, message string
			var availableAfter sql.NullString
			if err := database.QueryRow("SELECT status, COALESCE(message,''), deployment_available_after FROM cert_jobs WHERE id=?", jobID).
				Scan(&status, &message, &availableAfter); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if status != "downloaded" {
				t.Fatalf("status=%q, want downloaded（材料快速路径保持部署生命周期）", status)
			}
			if !availableAfter.Valid || availableAfter.String == "" {
				t.Fatalf("deployment_available_after=%v, want 非空（部署补扫谓词要求非 NULL）", availableAfter)
			}
			if strings.Contains(message, "queued") {
				t.Fatalf("message=%q, want 不宣称转 queued（日志/状态口径修正）", message)
			}

			// Then 2：补扫谓词实证——该行必须被 rescanDroppedDeploymentRetries 拾起并调度
			scheduled := make(chan int, 1)
			service := &CertificateService{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error { scheduled <- id; return nil }}
			service.rescanDroppedDeploymentRetries()
			select {
			case id := <-scheduled:
				if id != int(jobID) {
					t.Fatalf("scheduled job=%d, want %d", id, jobID)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("部署补扫未拾起材料快速路径任务（deployment_available_after 未落库或谓词不匹配）")
			}
		})
	}
}

// provider 不可用此前经 enqueueLocked 直接 failJob——对
// 「材料已落库、只差部署」的任务等于摘掉唯一自动恢复通道（部署重试链直接读库
// 材料，不解析 provider；部署补扫只收 downloaded/cleanup_*）。只差部署的任务必须
// 保持可部署态且部署窗口非空；签发生命周期任务维持既定 failJob 语义——负对照见
// TestCompensateRuleDeletion_provider_unavailable_fails_job_and_releases_lease。
func TestRequeueCertJobsSnapshot_provider_unavailable_keeps_deployment_only_job_deployable(t *testing.T) {
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "providergone-deploy.example.com")
	database, snapshot, manager, jobID, _ := seedRequeueMaterialFixture(t, "providergone-deploy.example.com", "downloaded", certPEM, keyPEM)
	// 全部 provider 禁用：loadCAProvider(7) 无行且无 enabled 回退
	if _, err := database.Exec(`UPDATE ca_providers SET enabled=0`); err != nil {
		t.Fatalf("disable providers: %v", err)
	}

	// When
	err := requeueCertJobsSnapshot(context.Background(), snapshot, manager)

	// Then 1：补偿照常收敛（不进入永久退避）
	if err != nil {
		t.Fatalf("requeue err=%v, want nil（provider 不可用按跳过语义收敛）", err)
	}
	// Then 2：任务未被 failJob，仍可部署
	var status string
	var availableAfter sql.NullString
	if err := database.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（只差部署的任务不得被 provider 不可用标 failed）", status)
	}
	if !availableAfter.Valid || availableAfter.String == "" {
		t.Fatalf("deployment_available_after=%v, want 非空（部署补扫接管）", availableAfter)
	}
	// Then 3：部署补扫确实能拾起该任务
	scheduled := make(chan int, 1)
	service := &CertificateService{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error { scheduled <- id; return nil }}
	service.rescanDroppedDeploymentRetries()
	select {
	case id := <-scheduled:
		if id != int(jobID) {
			t.Fatalf("scheduled job=%d, want %d", id, jobID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("provider 不可用后部署补扫未拾起只差部署的任务")
	}
}

// 联动：restore 的行级 epoch 守卫保留了快照后的签发成果（行已推进为
// downloaded 并携带新材料），补偿重排队必须按当前行判定——仍按快照状态会把刚签发
// 完成的任务转 'queued' 触发整轮重签（丢弃有效证书、白烧 CA 配额）。
func TestRequeueCertJobsSnapshot_uses_live_state_for_preserved_rows(t *testing.T) {
	_, database := newClusterTestService(t)
	const ruleID = "lb_requeue_live"
	const domain = "live-state.example.com"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?,?,'creating_order',7)`, ruleID, domain)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), domain)
	if _, err := database.Exec(`UPDATE cert_jobs SET status='downloaded', cert_pem=?, key_pem=?, expires_at=datetime('now','+90 days'), updated_at=datetime('now') WHERE id=?`, certPEM, keyPEM, jobID); err != nil {
		t.Fatalf("simulate concurrent issuance: %v", err)
	}
	if err := RestoreCertJobsForRule(snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// 队列未激活：只在库内落状态，不触网络
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: map[string]map[RuleBlockToken]struct{}{ruleID: {1: {}}},
	}

	// When
	if err := requeueCertJobsSnapshot(context.Background(), snapshot, manager); err != nil {
		t.Fatalf("requeue err=%v, want nil", err)
	}

	// Then：保持 downloaded + 部署窗口非空，不得被转回 queued
	var status string
	var availableAfter sql.NullString
	if err := database.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（按当前行判定，保留快照后签发成果）", status)
	}
	if !availableAfter.Valid || availableAfter.String == "" {
		t.Fatalf("deployment_available_after=%v, want 非空（部署补扫接管）", availableAfter)
	}
}

// 规则态纳入恢复 epoch：DisableRule 在补偿快照之后把任务置 disabled（并关闭规则），
// 后台补偿恢复若只看「行是否有新材料」会把该行回滚成快照状态（queued/waiting_ca），
// 让已禁用规则的任务重新可被周期扫描入队。规则已退出启用 ACME + 当前行 disabled
// 必须视为快照后的真实成果保留。
func TestCertJobsSnapshot_restore_preservesDisabledRowWhenRuleLeftACME(t *testing.T) {
	_, database := newClusterTestService(t)
	const ruleID = "lb_snapshot_disable"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'snapshot-disable', 'disable.example.com', 'http', 8443, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message) VALUES (?, 'disable.example.com', 'queued', '排队中')`, ruleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot jobs: %v", err)
	}

	// 快照之后：DisableRule 关闭规则并把任务置 disabled（无新材料）。
	if _, err := database.Exec(`UPDATE lb_rules SET enabled=0 WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("disable rule: %v", err)
	}
	if _, err := database.Exec(`UPDATE cert_jobs SET status='disabled', message='规则已禁用' WHERE id=?`, jobID); err != nil {
		t.Fatalf("disable job: %v", err)
	}

	if err := RestoreCertJobsForRule(snapshot); err != nil {
		t.Fatalf("restore jobs: %v", err)
	}

	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read restored job: %v", err)
	}
	if status != "disabled" {
		t.Fatalf("status=%q, want disabled（规则已退出启用 ACME，禁用终态不得被回滚）", status)
	}
	// 对照：规则仍启用 ACME 时同一形态必须照旧回滚（无材料的 UPSERT 覆写是
	// 恢复要修的形态，不得因本条守卫放行）。
	if _, err := database.Exec(`UPDATE lb_rules SET enabled=1 WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("re-enable rule: %v", err)
	}
	if err := RestoreCertJobsForRule(snapshot); err != nil {
		t.Fatalf("restore jobs (acme active): %v", err)
	}
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read restored job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（规则仍启用 ACME 时必须恢复快照态）", status)
	}
}

// 全量暂停的在途回调等待必须共享一个截止时间：逐项各自 cancelWaitTimeout 会让
// N 个挂起回调的最坏等待变成 N×timeout，配置导入的 PauseAndDrain（取
// caddyOpMu 之前）在该窗口内无界。三个永不退出的回调 + 80ms 截止：总耗时
// 必须落在「单倍截止 + 余量」内，而不是三倍。
func TestCertificateService_pauseDeploymentRetries_sharesSingleDeadline(t *testing.T) {
	service := NewCertificateService()
	service.cancelWaitTimeout = 80 * time.Millisecond
	service.deploymentTimers = make(map[int]*deploymentTimer)
	service.deploymentCallbacks = make(map[int]map[*deploymentTimer]struct{})
	for jobID := 1; jobID <= 3; jobID++ {
		callback := &deploymentTimer{done: make(chan struct{}), cancel: func() {}}
		service.deploymentCallbacks[jobID] = map[*deploymentTimer]struct{}{callback: {}}
	}

	start := time.Now()
	service.pauseDeploymentRetries()
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("暂停耗时 %v，want 单倍截止(~80ms)+余量（逐项等待会让 3 个回调叠加到 240ms）", elapsed)
	}
	if !service.timersPaused {
		t.Fatal("暂停后 timersPaused 必须为 true")
	}
}

// 导入/旧备份/带外改库可产生「waiting_ca + ca_available_after IS NULL」的行
// （正常运行期 markJobWaitingCA 恒写非空冷却时刻）。补扫轮此前要求非空冷却，这类
// 行在运行期没有任何周期通道（queued 滞留只收 queued、续期扫描只收有到期时间的
// 行、首发重试只收 failed），只能靠重启/Resume/手动重试收敛——任务列表长期显示
// 「等待 CA 频率限制冷却」而永不推进。补扫谓词因此容纳 NULL 冷却，并以 10 分钟
// 沉降阈值区分「带外静置行」与「刚被写侧写入的行」。
func TestCertificateService_requeueWaitingCAJobs_requeuesImportedNullCooldown(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)

	seedRuleWithCAProvider(t, "lb_null_cooldown", "null-cooldown.example.test", 1)
	seedRuleWithCAProvider(t, "lb_fresh_cooldown", "fresh-cooldown.example.test", 1)
	// 导入遗留：冷却时刻 NULL 且已静置 30 分钟（超过沉降阈值）。
	staleRes, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id,updated_at,created_at)
		VALUES ('lb_null_cooldown','null-cooldown.example.test','waiting_ca',NULL,1,datetime('now','-30 minutes'),datetime('now','-30 minutes'))`)
	if err != nil {
		t.Fatalf("seed imported waiting_ca row: %v", err)
	}
	staleID, _ := staleRes.LastInsertId()
	// 刚写入的行：沉降窗口内，本轮不得与写侧竞争。
	freshRes, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id,updated_at,created_at)
		VALUES ('lb_fresh_cooldown','fresh-cooldown.example.test','waiting_ca',NULL,1,datetime('now'),datetime('now'))`)
	if err != nil {
		t.Fatalf("seed fresh waiting_ca row: %v", err)
	}
	freshID, _ := freshRes.LastInsertId()

	requeued, disabled, err := NewCertificateService().requeueWaitingCAJobs()
	if err != nil {
		t.Fatalf("补扫不得因 NULL 冷却行失败: %v", err)
	}
	if requeued != 1 || disabled != 0 {
		t.Fatalf("requeued=%d disabled=%d, want 1/0（只有静置的 NULL 冷却行可重排）", requeued, disabled)
	}
	var staleStatus string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", staleID).Scan(&staleStatus); err != nil {
		t.Fatal(err)
	}
	if staleStatus == "waiting_ca" {
		t.Fatalf("静置的 NULL 冷却行未离开 waiting_ca（status=%q）", staleStatus)
	}
	var freshStatus string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", freshID).Scan(&freshStatus); err != nil {
		t.Fatal(err)
	}
	if freshStatus != "waiting_ca" {
		t.Fatalf("沉降窗口内的行被提前重排（status=%q）——刚由写侧写入的行不得与在途写竞争", freshStatus)
	}
}

// 锁粒度：s.mu 只保护「查询 → 读全量候选 → 关闭结果集」，逐任务 CAS 写库与
// 入队必须在锁外。waiting_ca 任务多/DB 慢时，补扫轮持锁会把 6h 节拍的续期扫描
// （CheckExpiration / checkFailedFirstIssuance 同取 s.mu）推迟到本轮之后。
// 并发安全不依赖该锁：写侧全程 CAS（transitionJob 的 from-status 白名单 +
// EnqueueIfActive 去重）。
func TestCertificateService_requeueWaitingCAJobs_doesNotHoldServiceLockDuringProcessing(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	manager := GetCAQueueManager()
	manager.Start()
	t.Cleanup(ResetCAQueueManagerForTest)

	seedRuleWithCAProvider(t, "lb_lock_scope", "lock-scope.example.test", 1)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id)
		VALUES ('lb_lock_scope','lock-scope.example.test','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatalf("seed waiting_ca job: %v", err)
	}
	service := NewCertificateService()
	probeRan := false
	manager.beforeActiveEnqueue = func() {
		probeRan = true
		if !service.mu.TryLock() {
			t.Error("逐任务处置期间 s.mu 仍被持有：补扫轮会把续期扫描（6h 节拍）推迟到本轮之后")
			return
		}
		service.mu.Unlock()
	}

	requeued, disabled, err := service.requeueWaitingCAJobs()
	if err != nil {
		t.Fatalf("补扫失败: %v", err)
	}
	if !probeRan {
		t.Fatalf("探测点未执行（requeued=%d disabled=%d）——判据未生效", requeued, disabled)
	}
	if requeued != 1 || disabled != 0 {
		t.Fatalf("requeued=%d disabled=%d, want 1/0", requeued, disabled)
	}
}
