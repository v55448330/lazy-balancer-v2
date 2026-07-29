package services

import (
	"context"
	"errors"
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

func TestCAQueueManager_CancelJobsForRule_removes_pending_and_cancels_running(t *testing.T) {
	// Given
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 41, ruleID: "lb-target", domains: "one.example.com"})
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb-other", domains: "two.example.com"})
	runningCtx, cancel := context.WithCancel(context.Background())
	queue.mu.Lock()
	queue.active[43] = struct{}{}
	queue.cancels[43] = cancel
	queue.runningRules[43] = "lb-target"
	queue.mu.Unlock()
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	// When
	manager.CancelJobsForRule("lb-target")

	// Then
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.pending) != 1 || queue.pending[0].jobID != 42 {
		t.Fatalf("pending jobs=%v, want only job 42", queue.pending)
	}
	if _, active := queue.active[41]; active {
		t.Fatal("cancelled pending rule job remains active")
	}
	select {
	case <-runningCtx.Done():
	default:
		t.Fatal("running rule job was not cancelled")
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

func TestHandleQueueExecutionError_preserves_downloaded_deployment_failure(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_retry', 'example.com', 'downloaded')`)
	if err != nil {
		t.Fatalf("seed downloaded job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job ID: %v", err)
	}

	// When
	handleQueueExecutionError(int(jobID), &certificateDeploymentError{err: errors.New("reload failed")})

	// Then
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read deployment job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("deployment job status=%q, want downloaded", status)
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

func TestCAQueueManager_Stop_waits_for_in_progress_enqueue(t *testing.T) {
	// Given
	_, _ = newClusterTestService(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	manager := &CAQueueManager{
		queues: make(map[int]*caQueue),
		active: true,
		beforeEnqueue: func() {
			close(entered)
			<-release
		},
	}
	enqueueDone := make(chan error, 1)
	go func() {
		enqueueDone <- manager.Enqueue(1, 42, "lb_enqueue_stop", "example.com")
	}()
	<-entered
	stopDone := make(chan struct{})
	go func() {
		manager.Stop()
		close(stopDone)
	}()

	// When
	select {
	case <-stopDone:
		t.Fatal("Stop completed while Enqueue was inside its manager critical section")
	default:
	}
	close(release)

	// Then
	if err := <-enqueueDone; err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	<-stopDone
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active || len(manager.queues) != 0 {
		t.Fatalf("manager active=%v queues=%d, want stopped with no dead queues", manager.active, len(manager.queues))
	}
}

func TestCAQueueManager_Stop_waits_for_running_execution(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (id, rule_id, domain, status) VALUES (42, 'lb_stop', 'example.com', 'creating_order')`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	go queue.loop()
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error {
		close(started)
		<-release
		return nil
	}
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_stop", domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("pending execution was not prepared")
	}
	go queue.execute(execution)
	<-started
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}
	stopDone := make(chan struct{})
	go func() {
		manager.Stop()
		close(stopDone)
	}()

	// When
	select {
	case <-stopDone:
		t.Fatal("Stop returned before the running execution completed")
	default:
	}
	close(release)

	// Then
	<-stopDone
}

func TestCAQueue_execute_requeues_job_when_lifecycle_is_canceled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, renewal_attempts) VALUES ('lb_cancelled', 'example.com', 'creating_order', 2)`)
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	started := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	go queue.loop()
	queue.executeFn = func(ctx context.Context, _ queueItem, _ models.CAProvider) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_cancelled", domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("pending execution was not prepared")
	}
	go queue.execute(execution)
	<-started
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	// When
	manager.Stop()

	// Then
	var status string
	var attempts int
	if err := database.QueryRow("SELECT status, renewal_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read canceled certificate job: %v", err)
	}
	if status != "queued" || attempts != 2 {
		t.Fatalf("canceled job status=%q attempts=%d, want queued and 2", status, attempts)
	}
}
