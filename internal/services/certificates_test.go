package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestDisableCertJobsExceptDomain_disables_all_retired_jobs(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const ruleID = "lb_retire"
	for _, job := range []struct {
		domain string
		status string
	}{
		{domain: "keep.example.com", status: "queued"},
		{domain: "old.example.com", status: "downloaded"},
		{domain: "issued.example.com", status: "issued"},
		{domain: "failed.example.com", status: "failed"},
		{domain: "waiting.example.com", status: "waiting_ca"},
	} {
		if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,?)", ruleID, job.domain, job.status); err != nil {
			t.Fatalf("seed %s job: %v", job.domain, err)
		}
	}

	// When
	err := DisableCertJobsExceptDomain(ruleID, "keep.example.com")

	// Then
	if err != nil {
		t.Fatalf("disable retired jobs: %v", err)
	}
	want := map[string]string{
		"keep.example.com":    "queued",
		"old.example.com":     "disabled",
		"issued.example.com":  "disabled",
		"failed.example.com":  "disabled",
		"waiting.example.com": "disabled",
	}
	rows, err := database.Query("SELECT domain,status FROM cert_jobs WHERE rule_id=?", ruleID)
	if err != nil {
		t.Fatalf("query jobs: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var domain, status string
		if err := rows.Scan(&domain, &status); err != nil {
			t.Fatalf("scan job: %v", err)
		}
		if status != want[domain] {
			t.Fatalf("job %s status=%q, want %q", domain, status, want[domain])
		}
	}
}

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

func TestCertificateService_requeueWaitingCAJobs_pause_after_scan_start_leaves_job_waiting(t *testing.T) {
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
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
