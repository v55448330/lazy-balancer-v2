package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestCreateOrRequeueCertJob_returns_persisted_job_id(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
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
	if _, err := database.Exec(`INSERT INTO cert_jobs
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
	// 不能静默空转（R29 A-M1）
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs
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

func TestRequeueNonTerminalCertJobs_skips_downloaded_job_missing_cert_material_when_paused(t *testing.T) {
	// R46 A-F1 起恢复排队走 EnqueueIfActive：暂停的队列管理器在 transition 之前
	// 即拒绝（与 R45 PauseAndDrain 门控同语义），任务保持原状态等待下次恢复，
	// 不写库、不入队、不报错。
	// Given
	jobID, _ := seedCertificateJob(t, "cleanup_dns")
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().PauseAndDrain()
	t.Cleanup(ResetCAQueueManagerForTest)
	retried := make(chan int, 1)

	// When
	err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) {
		retried <- gotJobID
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

// R46 A-F1：requeueNonTerminalCertJobs 必须经 EnqueueIfActive 在途守卫——退役队列
// 中的滞行执行（zombie）仍持有 jobID 时，恢复流程不得 transition+Enqueue，否则
// 同 jobID 双执行（zombie 晚退 requeueCanceledJob 打回新执行状态，R44-2 同型）。
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
	err := requeueNonTerminalCertJobs(context.Background(), func(gotJobID int, _ issuedCertificate, _ time.Duration) {
		t.Errorf("deployment retry scheduled for non-downloaded job %d", gotJobID)
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

func TestCertificateService_deployment_retry_deduplicates_job_id(t *testing.T) {
	// Given
	service := NewCertificateService()
	calls := make(chan int, 2)
	service.retryDeployment = func(_ context.Context, jobID int) error {
		calls <- jobID
		return nil
	}
	service.scheduleDeploymentRetry(42, "lb_retry", time.Hour)

	// When
	service.scheduleDeploymentRetry(42, "lb_retry", 0)

	// Then
	if jobID := <-calls; jobID != 42 {
		t.Fatalf("retry job ID=%d, want 42", jobID)
	}
	service.pauseDeploymentRetries()
	select {
	case jobID := <-calls:
		t.Fatalf("duplicate retry ran for job %d", jobID)
	default:
	}
}

func TestCertificateService_scheduleDeploymentRetry_waits_for_inflight_callback_before_rescheduling(t *testing.T) {
	// R56 N-1(a)：重试回调 C1 在途（Caddy reload 挂起超 30s 暂停等待上限）时，
	// Resume/Unblock 补扫会对同 jobID 重新 schedule——去重只查 pending timer
	// （回调启动即自摘），不查在途回调，必然放行第二个并发回调部署同一证书。
	// 不变量：同 jobID 永不并发部署——补扫必须取消并等待 C1 退出后才创建新
	// timer（串行重试，而非并发重试）。
	// Given
	service := NewCertificateService()
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

	// When：C1 在途期间补扫重排
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

	// C1 退出后重排完成，新 timer 触发第二个回调（与 C1 串行）
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
	// R42 发现3：回调链条调到非 context-aware 的 caddyReloader，Caddy admin 异常
	// 挂起时 HTTP 调用方必须能在 cancelWaitTimeout 内返回，不能永久阻塞。
	service := NewCertificateService()
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

func TestCertificateService_periodic_scans_do_not_mutate_jobs_while_queue_paused(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
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

	// When
	service.renewExpiringCertificates()
	service.requeueWaitingCAJobs()

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
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
	for _, ruleID := range []string{"lb_first_retry", "lb_first_cooling", "lb_first_capped"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, ruleID, ruleID, ruleID+".example.com"); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
	}
	maxAttempts := GetCertRenewalAttempts()
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

func TestCertificateService_requeueWaitingCAJobs_disables_orphaned_waiting_job(t *testing.T) {
	// Given：waiting_ca 任务的规则已不存在（无 lb_rules 行），A-M1 守卫应按孤儿
	// 转 disabled 而不是重排签发（与 6h 孤儿 sweep 同口径）。
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	t.Cleanup(ResetCAQueueManagerForTest)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id) VALUES ('lb_gone','gone.example.com','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatalf("seed orphan waiting job: %v", err)
	}

	// When
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
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
	// R28 A-M1 起 requeue 守卫要求任务仍被启用中的 acme_dns TLS 规则引用，
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
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) {})

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
	jobs := NewCertificateService().CheckExpiration()

	// Then
	if len(jobs) != 1 || jobs[0].RuleID != "lb_current" {
		t.Fatalf("renewal jobs=%v, want only lb_current", jobs)
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
	jobs := NewCertificateService().CheckExpiration()

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
	jobs := NewCertificateService().CheckExpiration()

	// Then：冷却中的任务不得被续期扫描捕获（R35-5），冷却已过与无冷却的正常捕获
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
	// R48 A-F1：规则在补偿退避窗口内被并发删除时，restore 必须按补偿完成收尾
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
	// R48 A-F2：补偿退避窗口内同一 caddy_id 被重建为新域名（新化身）时，
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

// R48 A-F1 放弃语义的直接覆盖（R49 A-N3 + R50 S-4）：requeueCertJobsSnapshot 的
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
		// 补偿拖入永久退避循环且租约永不释放（R50 S-4）。
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

// N+8 B5-S1：补偿重排队路径必须在入队前把在途快照任务落库为 'queued'。快照保留
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
			drainQueue.failPendingProviderUnavailable([]queueItem{{jobID: int(jobID), ruleID: ruleID, domains: domain}}, "CA Provider 不可用：配置已禁用或删除（ID 7）")

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
	// 不得迁移 issued（I-D）。
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
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) {})

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

// I-D（第 14 轮审计发现）：'queued' 是用户显式触发的重签请求（RetryCertJob
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
	err := requeueNonTerminalCertJobs(context.Background(), func(int, issuedCertificate, time.Duration) {
		t.Error("deployment retry scheduled for non-downloaded job")
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
	var scheduled []int
	var delays []time.Duration
	service.deploymentRetry = func(jobID int, _ issuedCertificate, delay time.Duration) {
		scheduled = append(scheduled, jobID)
		delays = append(delays, delay)
	}
	service.pauseDeploymentRetries()

	// When
	service.resumeDeploymentRetries()

	// Then：材料齐全且规则适用的任务被重排——窗口已过的 A 以 delay=0 立即，
	// 窗口在未来的 B 以剩余等待 delay 重排（R59 A-2，与启动恢复同口径，
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

// N+9 C5-S1：N+8（2b68044a）为 requeueCertJobsSnapshot 引入「downloaded+材料保持
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

// N+9 C1-S2：部署生命周期（cleanup_dns/cleanup_warning）+ 材料在身的快照任务同样
// 只差部署——材料已落库、证书已签发（retryCertificateDeployment 从这些状态装载
// 材料即为证）。补偿重排队必须归一化为 'downloaded' 走 Issue 快速路径重部署，
// 不得转 'queued' 整轮重签（浪费 CA 配额并丢弃有效证书）。
// 'queued'+材料为负对照：I-D（第 14 轮审计）确立 queued 是显式重签请求
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

// N+9 C1-S1：referenced CA provider 不可用（禁用/删除且无 enabled 回退）时，
// enqueueCompensation→enqueueLocked 已同步 failJob（任务置 failed + job 日志 +
// 审计——现有 job-status/audit 通道即最终处置）。补偿不得把该错误上抛：否则
// StartRuleDeletionCompensation 的退避循环永久重试（每轮 restore 复活 failed 行
// 再重新失败 + CRITICAL 日志噪声），且规则租约（blockedRules）永不释放——该规则
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
	// R61-A2：restore 不得让 DATETIME 列漂移为驱动 `+00:00` 布局——
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
			t.Fatalf("%s drifted to non-canonical format %q: %v (R61-A2 regression)", col, raw.String, err)
		}
	}
}
