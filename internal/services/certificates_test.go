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

func TestCreateOrRequeueCertJob_returns_job_id_when_enqueue_fails(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: false}

	// When
	jobID, err := CreateOrRequeueCertJob("lb_job_id", "example.com", 1, manager)

	// Then
	if err == nil || jobID <= 0 {
		t.Fatalf("create result jobID=%d err=%v, want persisted ID and enqueue error", jobID, err)
	}
	var storedID int
	if err := database.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_job_id'").Scan(&storedID); err != nil {
		t.Fatalf("read persisted job: %v", err)
	}
	if storedID != jobID {
		t.Fatalf("stored job ID=%d, returned %d", storedID, jobID)
	}
}

func TestRequeueNonTerminalCertJobs_schedules_downloaded_deployment(t *testing.T) {
	// Given
	jobID, _ := seedCertificateJob(t, "downloaded")
	service := NewCertificateService()
	retried := make(chan int, 1)
	service.retryDeployment = func(gotJobID int) error {
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
	service.retryDeployment = func(jobID int) error {
		calls <- jobID
		return nil
	}
	service.scheduleDeploymentRetry(42, time.Hour)

	// When
	service.scheduleDeploymentRetry(42, 0)

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
	service.retryDeployment = func(int) error {
		close(entered)
		<-release
		return errors.New("ignored test failure")
	}
	service.scheduleDeploymentRetry(42, 0)
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
	releaseCallback := make(chan struct{})
	service.retryDeployment = func(int) error {
		close(callbackEntered)
		<-releaseCallback
		return nil
	}
	go service.Start()
	service.scheduleDeploymentRetry(42, 0)
	<-callbackEntered
	stopDone := make(chan struct{})
	go func() {
		service.Stop()
		close(stopDone)
	}()

	// When
	select {
	case <-stopDone:
		t.Fatal("stop returned while deployment retry callback was running")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseCallback)

	// Then
	<-stopDone
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
