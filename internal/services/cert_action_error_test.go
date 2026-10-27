package services

import (
	"context"
	"strings"
	"testing"
)

func newCertActionErrorQueueManager() *CAQueueManager {
	return &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
		active:       true,
		reloader:     func() error { return nil },
	}
}

func useCertActionErrorQueueManager(t *testing.T) *CAQueueManager {
	t.Helper()
	previous := caQueueManager
	manager := newCertActionErrorQueueManager()
	caQueueManager = manager
	t.Cleanup(func() {
		manager.Stop()
		caQueueManager = previous
	})
	return manager
}

func TestBackfillMissingACMECertJobs_aggregatesPerRuleFailures(t *testing.T) {
	_, database := newClusterTestService(t)
	seedRuleWithCAProvider(t, "lb_backfill_fail", "backfill-fail.example.test", 1)
	seedRuleWithCAProvider(t, "lb_backfill_ok", "backfill-ok.example.test", 1)
	if _, err := database.Exec(`CREATE TRIGGER reject_backfill_write
		BEFORE INSERT ON cert_jobs WHEN NEW.rule_id='lb_backfill_fail'
		BEGIN SELECT RAISE(ABORT,'injected backfill write failure'); END`); err != nil {
		t.Fatal(err)
	}

	created, err := BackfillMissingACMECertJobs(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "lb_backfill_fail") {
		t.Fatalf("created=%d err=%v, want the failed rule identified", created, err)
	}
	if created != 1 {
		t.Fatalf("created=%d, want the unaffected rule to remain a partial success", created)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_backfill_ok'").Scan(&status); err != nil || status != "queued" {
		t.Fatalf("unaffected rule status=%q err=%v, want queued", status, err)
	}
}

func TestBackfillMissingACMECertJobs_reportsPostInsertEnqueueFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	seedRuleWithCAProvider(t, "lb_backfill_enqueue", "backfill-enqueue.example.test", 999)
	if _, err := database.Exec("UPDATE ca_providers SET enabled=0"); err != nil {
		t.Fatal(err)
	}
	manager := newCertActionErrorQueueManager()
	t.Cleanup(manager.Stop)

	created, err := BackfillMissingACMECertJobs(context.Background(), manager)
	if err == nil || !strings.Contains(err.Error(), "lb_backfill_enqueue") {
		t.Fatalf("created=%d err=%v, want post-insert enqueue failure", created, err)
	}
	if created != 1 {
		t.Fatalf("created=%d, want the inserted row retained as a partial result", created)
	}
}

func TestCertificateService_requeueWaitingCAJobs_reportsActionFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	useCertActionErrorQueueManager(t)
	seedRuleWithCAProvider(t, "lb_waiting_fail", "waiting-fail.example.test", 1)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id)
		VALUES ('lb_waiting_fail','waiting-fail.example.test','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_waiting_requeue
		BEFORE UPDATE ON cert_jobs WHEN OLD.rule_id='lb_waiting_fail'
		BEGIN SELECT RAISE(ABORT,'injected waiting requeue failure'); END`); err != nil {
		t.Fatal(err)
	}

	requeued, disabled, err := NewCertificateService().requeueWaitingCAJobs()
	if err == nil || !strings.Contains(err.Error(), "waiting-fail") && !strings.Contains(err.Error(), "lb_waiting_fail") {
		t.Fatalf("requeued=%d disabled=%d err=%v, want action failure", requeued, disabled, err)
	}
	if requeued != 0 || disabled != 0 {
		t.Fatalf("requeued=%d disabled=%d, want no successful action", requeued, disabled)
	}
}

func TestCertificateService_requeueWaitingCAJobs_reportsOrphanDisableFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	useCertActionErrorQueueManager(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,ca_provider_id)
		VALUES ('lb_waiting_orphan','waiting-orphan.example.test','waiting_ca',datetime('now','-1 minute'),1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_orphan_disable
		BEFORE UPDATE ON cert_jobs WHEN OLD.rule_id='lb_waiting_orphan'
		BEGIN SELECT RAISE(ABORT,'injected orphan disable failure'); END`); err != nil {
		t.Fatal(err)
	}

	requeued, disabled, err := NewCertificateService().requeueWaitingCAJobs()
	if err == nil {
		t.Fatalf("requeued=%d disabled=%d err=nil, want orphan disable failure", requeued, disabled)
	}
	if disabled != 0 {
		t.Fatalf("disabled=%d, want 0 after rejected update", disabled)
	}
}

func TestCAQueueManager_requeueStrandedQueuedJobs_reportsActionFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	manager := useCertActionErrorQueueManager(t)
	seedRuleWithCAProvider(t, "lb_stranded_fail", "stranded-fail.example.test", 1)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_stranded_fail','stranded-fail.example.test','queued',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_stranded_requeue
		BEFORE UPDATE ON cert_jobs WHEN OLD.rule_id='lb_stranded_fail'
		BEGIN SELECT RAISE(ABORT,'injected stranded requeue failure'); END`); err != nil {
		t.Fatal(err)
	}

	requeued, err := manager.requeueStrandedQueuedJobs()
	if err == nil || !strings.Contains(err.Error(), "lb_stranded_fail") {
		t.Fatalf("requeued=%d err=%v, want stranded action failure", requeued, err)
	}
	if requeued != 0 {
		t.Fatalf("requeued=%d, want 0 after rejected update", requeued)
	}
}

func TestCertificateService_renewExpiringCertificates_reportsActionFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	useCertActionErrorQueueManager(t)
	seedRuleWithCAProvider(t, "lb_renewal_fail", "renewal-fail.example.test", 1)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,renewal_attempts,ca_provider_id)
		VALUES ('lb_renewal_fail','renewal-fail.example.test','issued',datetime('now','+1 day'),0,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_renewal_requeue
		BEFORE UPDATE ON cert_jobs WHEN OLD.rule_id='lb_renewal_fail'
		BEGIN SELECT RAISE(ABORT,'injected renewal requeue failure'); END`); err != nil {
		t.Fatal(err)
	}
	resetCertificateServiceForTest(t)

	err := NewCertificateService().renewExpiringCertificates()
	if err == nil || !strings.Contains(err.Error(), "lb_renewal_fail") {
		t.Fatalf("renewal err=%v, want per-job enqueue failure", err)
	}
}
