package services

import (
	"context"
	"errors"
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

func TestRequeueNonTerminalCertJobs_requeues_downloaded_job_missing_cert_material(t *testing.T) {
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

	// Then: 暂停的队列管理器只会在状态迁移之后拒绝入队
	if err == nil {
		t.Fatal("expected enqueue rejection from the paused queue manager")
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
	if status != "queued" {
		t.Fatalf("job status=%q, want queued", status)
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

func TestRequeueNonTerminalCertJobs_does_not_resurrect_failed_job(t *testing.T) {
	// Given：failed 任务虽持有之前签发的有效证书，也不得在启动恢复时被复活；
	// queued 任务持有有效证书则仍走"检测到已有有效证书"的恢复优化
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
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id) VALUES ('lb_recover_failed','failed.example.com','failed',datetime('now','+90 days'),?,?,1)`, failedCert, failedKey); err != nil {
		t.Fatalf("seed failed job: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id) VALUES ('lb_recover_queued','queued.example.com','queued',datetime('now','+90 days'),?,?,1)`, queuedCert, queuedKey); err != nil {
		t.Fatalf("seed queued job: %v", err)
	}

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
	if statuses["lb_recover_queued"] != "issued" {
		t.Fatalf("queued job status=%q, want issued", statuses["lb_recover_queued"])
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
	service.deploymentRetry = func(jobID int, _ issuedCertificate, _ time.Duration) {
		scheduled = append(scheduled, jobID)
	}
	service.pauseDeploymentRetries()

	// When
	service.resumeDeploymentRetries()

	// Then：只有窗口已过且材料齐全的任务被重排
	if len(scheduled) != 1 || scheduled[0] != 1 {
		t.Fatalf("scheduled=%v, want only job 1", scheduled)
	}
}
