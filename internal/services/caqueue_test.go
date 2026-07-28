package services

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestCAQueueManager_CancelJob_removes_pending_job(t *testing.T) {
	// Given
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_cancel", domains: "example.com"})
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	// When
	manager.CancelJob(42)

	// Then
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.pending) != 0 {
		t.Fatalf("pending jobs=%d, want 0", len(queue.pending))
	}
	if _, active := queue.active[42]; active {
		t.Fatal("cancelled pending job remains active")
	}
}

func TestCAQueue_prepareExecution_registers_cancel_atomically(t *testing.T) {
	// Given
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_dispatch", domains: "example.com"})

	// When
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(context.Background())
	queue.mu.Unlock()

	// Then
	if !ok {
		t.Fatal("pending job was not prepared")
	}
	defer execution.cancel()
	queue.mu.Lock()
	registered := queue.cancels[42] != nil
	queue.mu.Unlock()
	if !registered {
		t.Fatal("cancel function was not registered during dequeue")
	}
}

func TestIsTerminalJobStatus_returns_true_for_disabled_job(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_disabled', 'example.com', 'disabled')`)
	if err != nil {
		t.Fatalf("seed disabled job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job ID: %v", err)
	}

	// When / Then
	if !isTerminalJobStatus(int(jobID)) {
		t.Fatal("disabled job is not terminal")
	}
}

func TestCAQueue_tick_fails_pending_job_when_provider_disabled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name, provider, directory_url, enabled) VALUES ('temporary', 'letsencrypt', 'https://invalid.example/directory', 1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_queue_test', 'example.com', 'queued', ?)`, providerID)
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := jobResult.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	queue := newCAQueue(models.CAProvider{ID: int(providerID), MaxConcurrent: 1}, func() error { return nil })
	queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_queue_test", domains: "example.com"})
	if _, err := database.Exec("UPDATE ca_providers SET enabled=0 WHERE id=?", providerID); err != nil {
		t.Fatalf("disable CA provider: %v", err)
	}

	// When
	queue.tick()

	// Then
	queue.cancel()
	deadline := time.Now().Add(time.Second)
	for {
		queue.mu.Lock()
		running := queue.running
		queue.mu.Unlock()
		if running == 0 || time.Now().After(deadline) {
			break
		}
		runtime.Gosched()
	}
	var status, message string
	if err := database.QueryRow("SELECT status, COALESCE(message,'') FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message); err != nil {
		t.Fatalf("read certificate job: %v", err)
	}
	if status != "failed" || !strings.Contains(message, "CA Provider 不可用") {
		t.Fatalf("job status=%q message=%q, want provider-unavailable failure", status, message)
	}
}
