package services

import (
	"context"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

func setupStrandedRequeueRoleFixture(t *testing.T) *CAQueueManager {
	t.Helper()
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())

	for _, rule := range []struct {
		id, domain string
	}{{"lb_stranded_role_one", "stranded-one.example.test"}, {"lb_stranded_role_two", "stranded-two.example.test"}} {
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, rule.id, rule.id, rule.domain); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
	}
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (11,'stranded CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	for _, job := range []struct {
		id             int
		ruleID, domain string
	}{{71, "lb_stranded_role_one", "stranded-one.example.test"}, {72, "lb_stranded_role_two", "stranded-two.example.test"}} {
		if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id,message,updated_at) VALUES (?, ?, ?, 'queued', 11, 'stranded-original', '2000-01-01 00:00:00')`, job.id, job.ruleID, job.domain); err != nil {
			t.Fatalf("seed stranded job: %v", err)
		}
	}

	oldManager := caQueueManager
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
		active:       true,
		reloader:     func() error { return nil },
	}
	caQueueManager = manager
	t.Cleanup(func() {
		manager.Stop()
		caQueueManager = oldManager
	})
	stubProviderQueueWithoutIssuance(t, manager, models.CAProvider{ID: 11, Name: "stranded CA", Provider: "letsencrypt"})
	return manager
}

func assertStrandedRequeueJobsUntouched(t *testing.T, manager *CAQueueManager) {
	t.Helper()
	for _, jobID := range []int{71, 72} {
		var status, message, updatedAt string
		if err := db.DB.QueryRow(`SELECT status, message, updated_at FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &message, &updatedAt); err != nil {
			t.Fatalf("read stranded job %d: %v", jobID, err)
		}
		if status != "queued" || message != "stranded-original" || updatedAt != "2000-01-01T00:00:00Z" {
			t.Fatalf("job %d changed after role gate closed: status=%q message=%q updated_at=%q", jobID, status, message, updatedAt)
		}
		if manager.IsJobActive(jobID) {
			t.Fatalf("job %d entered queue after role gate closed", jobID)
		}
	}
}

func TestCertWaitingCATickOnce_strandedRequeueStopsOnDemotion(t *testing.T) {
	manager := setupStrandedRequeueRoleFixture(t)
	calls := 0
	manager.beforeActiveEnqueue = func() {
		calls++
		if calls == 1 {
			if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
				t.Errorf("demote node: %v", err)
			}
		}
	}

	err := CertWaitingCATickOnce(context.Background())

	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped after demotion before first stranded enqueue", err)
	}
	if calls != 1 {
		t.Fatalf("enqueue attempts=%d, want 1 (demotion must stop subsequent jobs)", calls)
	}
	assertStrandedRequeueJobsUntouched(t, manager)
}

func TestCertWaitingCATickOnce_strandedRequeueFailsClosedOnUnknownRole(t *testing.T) {
	manager := setupStrandedRequeueRoleFixture(t)
	calls := 0
	manager.beforeActiveEnqueue = func() {
		calls++
		if calls == 1 {
			if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
				t.Errorf("remove node role: %v", err)
			}
		}
	}

	err := CertWaitingCATickOnce(context.Background())

	if err == nil || errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want role-read failure rather than success or voluntary skip", err)
	}
	if calls != 1 {
		t.Fatalf("enqueue attempts=%d, want 1 (unknown role must stop subsequent jobs)", calls)
	}
	assertStrandedRequeueJobsUntouched(t, manager)
}

func TestCertWaitingCATickOnce_strandedRequeueRunsOnMaster(t *testing.T) {
	manager := setupStrandedRequeueRoleFixture(t)
	calls := 0
	manager.beforeActiveEnqueue = func() { calls++ }

	if err := CertWaitingCATickOnce(context.Background()); err != nil {
		t.Fatalf("healthy master requeue failed: %v", err)
	}

	if calls != 2 {
		t.Fatalf("enqueue attempts=%d, want 2", calls)
	}
	for _, jobID := range []int{71, 72} {
		var message string
		if err := db.DB.QueryRow(`SELECT message FROM cert_jobs WHERE id=?`, jobID).Scan(&message); err != nil {
			t.Fatalf("read requeued job %d: %v", jobID, err)
		}
		if message != "周期巡检发现队列外滞留，重新排队" {
			t.Fatalf("job %d message=%q, want successful stranded requeue", jobID, message)
		}
	}
}
