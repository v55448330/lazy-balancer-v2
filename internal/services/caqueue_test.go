package services

import (
	"context"
	"errors"
	"lazy-balancer-v2/internal/db"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

func TestCAQueueManager_CancelJob_cancels_enqueue_admitted_during_cancel(t *testing.T) {
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
		enqueueDone <- manager.Enqueue(1, 42, "lb_cancel_race", "example.com")
	}()
	<-entered
	cancelDone := make(chan struct{})
	go func() {
		manager.CancelJob(42)
		close(cancelDone)
	}()
	select {
	case <-cancelDone:
		t.Fatal("cancel passed an enqueue inside the admission critical section")
	default:
	}
	close(release)
	if err := <-enqueueDone; err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	<-cancelDone

	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, queue := range manager.queues {
		queue.mu.Lock()
		_, active := queue.active[42]
		pending := len(queue.pending)
		queue.mu.Unlock()
		if active || pending != 0 {
			t.Fatalf("cancelled concurrent enqueue active=%v pending=%d", active, pending)
		}
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
	if err := manager.CancelJobsForRule(context.Background(), "lb-target"); err != nil {
		t.Fatalf("cancel rule jobs: %v", err)
	}

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

func TestCAQueue_prepareExecution_covers_issuer_worst_case_budget(t *testing.T) {
	// Given
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_timeout", domains: "example.com"})

	// When
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(context.Background())
	queue.mu.Unlock()

	// Then
	if !ok {
		t.Fatal("pending job was not prepared")
	}
	defer execution.cancel()
	deadline, hasDeadline := execution.ctx.Deadline()
	if !hasDeadline {
		t.Fatal("execution context has no deadline")
	}
	if remaining := time.Until(deadline); remaining < caExecutionTimeout-time.Minute || remaining > caExecutionTimeout {
		t.Fatalf("execution timeout=%v, want ~%v", remaining, caExecutionTimeout)
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

func TestWorkerWriteback_preserves_disabled_job(t *testing.T) {
	tests := []struct {
		name  string
		write func(int)
	}{
		{name: "rate limit", write: func(jobID int) { handleQueueExecutionError(jobID, &CAProviderRateLimitError{RetryAfter: time.Minute}) }},
		{name: "failure", write: func(jobID int) { failJob(jobID, "worker failed") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			result, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('lb_disabled', 'example.com', 'disabled')`)
			if err != nil {
				t.Fatalf("seed disabled job: %v", err)
			}
			jobID, err := result.LastInsertId()
			if err != nil {
				t.Fatalf("read job ID: %v", err)
			}

			tt.write(int(jobID))

			var status string
			var attempts int
			if err := database.QueryRow("SELECT status, COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
				t.Fatalf("read disabled job: %v", err)
			}
			if status != "disabled" || attempts != 0 {
				t.Fatalf("disabled job status=%q attempts=%d, want disabled/0", status, attempts)
			}
		})
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

func TestCAQueueManager_PauseAndDrain_cancels_pending_and_waits_for_running(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (id, rule_id, domain, status) VALUES (42, 'lb_all', 'example.com', 'creating_order')`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	started := make(chan struct{})
	finished := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	go queue.loop()
	queue.executeFn = func(ctx context.Context, _ queueItem, _ models.CAProvider) error {
		close(started)
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	}
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_all", domains: "example.com"})
	queue.enqueue(queueItem{jobID: 43, ruleID: "lb_pending", domains: "pending.example.com"})
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
	manager.PauseAndDrain()

	// Then
	<-finished
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(queue.pending) != 0 || queue.running != 0 || len(queue.active) != 0 {
		t.Fatalf("queue pending=%d running=%d active=%d", len(queue.pending), queue.running, len(queue.active))
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active || len(manager.queues) != 0 {
		t.Fatalf("manager active=%v queues=%d, want paused empty manager", manager.active, len(manager.queues))
	}
}

func TestCAQueueManager_PauseAndDrain_rejects_until_resume(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (id, rule_id, domain, status) VALUES (42, 'lb_pause', 'example.com', 'creating_order')`); err != nil {
		t.Fatalf("seed running job: %v", err)
	}
	started := make(chan struct{})
	finished := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	go queue.loop()
	queue.executeFn = func(ctx context.Context, _ queueItem, _ models.CAProvider) error {
		close(started)
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	}
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_pause", domains: "example.com"})
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
	manager.PauseAndDrain()

	// Then
	<-finished
	if err := manager.Enqueue(1, 43, "lb_paused", "paused.example.com"); err == nil {
		t.Fatal("enqueue succeeded while manager was paused")
	}
	manager.Resume()
	if err := manager.Enqueue(1, 43, "lb_paused", "paused.example.com"); err != nil {
		t.Fatalf("enqueue after resume: %v", err)
	}
	manager.Stop()
}

func TestCAQueueManager_Enqueue_has_no_database_side_effects_when_paused(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id, renewal_attempts) VALUES ('lb_paused_enqueue', 'example.com', 'queued', 999, 2)`)
	if err != nil {
		t.Fatalf("seed paused certificate job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read paused certificate job ID: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: false}

	// When
	err = manager.Enqueue(999, int(jobID), "lb_paused_enqueue", "example.com")

	// Then
	if err == nil {
		t.Fatal("enqueue succeeded while manager was paused")
	}
	var status string
	var providerID, attempts int
	if err := database.QueryRow("SELECT status, ca_provider_id, renewal_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &providerID, &attempts); err != nil {
		t.Fatalf("read paused certificate job: %v", err)
	}
	if status != "queued" || providerID != 999 || attempts != 2 {
		t.Fatalf("paused job status=%q provider=%d attempts=%d, want unchanged", status, providerID, attempts)
	}
}

func TestCAQueueManager_CancelJobsForRule_cancels_and_waits_for_deployment_callback(t *testing.T) {
	// Given
	service := NewCertificateService()
	callbackEntered := make(chan struct{})
	cancellationObserved := make(chan struct{})
	releaseCallback := make(chan struct{})
	wroteFiles := make(chan struct{}, 1)
	service.retryDeployment = func(ctx context.Context, _ int) error {
		close(callbackEntered)
		<-ctx.Done()
		close(cancellationObserved)
		<-releaseCallback
		if ctx.Err() == nil {
			wroteFiles <- struct{}{}
		}
		return ctx.Err()
	}
	service.scheduleDeploymentRetry(42, "lb_deleted", 0)
	<-callbackEntered
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	cancelDone := make(chan struct{})
	go func() {
		if err := manager.CancelJobsForRule(context.Background(), "lb_deleted"); err != nil {
			t.Errorf("cancel rule jobs: %v", err)
		}
		close(cancelDone)
	}()
	<-cancellationObserved

	// When
	select {
	case <-cancelDone:
		t.Fatal("rule cancellation returned while deployment callback was running")
	default:
	}
	close(releaseCallback)

	// Then
	<-cancelDone
	select {
	case <-wroteFiles:
		t.Fatal("deployment callback wrote files after rule cancellation")
	default:
	}
}

func TestCAQueueManager_CancelJobsForRule_blocks_retry_created_during_worker_exit(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (42,'lb_deleted','example.com','downloaded')`); err != nil {
		t.Fatalf("seed deployment job: %v", err)
	}
	service := NewCertificateService()
	newClusterTestService(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (42,'lb_deleted','example.com','creating_order',0)`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	retryRan := make(chan struct{}, 1)
	service.retryDeployment = func(context.Context, int) error {
		retryRan <- struct{}{}
		return nil
	}
	workerStarted := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.executeFn = func(ctx context.Context, item queueItem, _ models.CAProvider) error {
		close(workerStarted)
		<-ctx.Done()
		scheduleCertificateDeploymentRetry(item.jobID, issuedCertificate{ruleID: item.ruleID}, 0)
		return ctx.Err()
	}
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_deleted", domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("worker execution was not prepared")
	}
	go queue.loop()
	go queue.execute(execution)
	<-workerStarted
	ResetCAQueueManagerForTest()
	InitCAQueueManager(nil)
	t.Cleanup(ResetCAQueueManagerForTest)
	manager := GetCAQueueManager()
	manager.mu.Lock()
	manager.queues[1] = queue
	manager.mu.Unlock()
	manager.BlockJobsForRule("lb_deleted")

	// When
	if err := manager.CancelJobsForRule(context.Background(), "lb_deleted"); err != nil {
		t.Fatalf("cancel rule jobs: %v", err)
	}
	manager.UnblockJobsForRule("lb_deleted")

	// Then
	select {
	case <-retryRan:
		t.Fatal("deployment retry revived after rule cancellation")
	case <-time.After(50 * time.Millisecond):
	}
	service.pauseDeploymentRetries()
}

func TestCAQueueManager_CancelJobsForRule_returns_context_error_for_stuck_worker(t *testing.T) {
	// Given
	newClusterTestService(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (42,'lb_stuck','example.com','creating_order',0)`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	workerStarted := make(chan struct{})
	releaseWorker := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error {
		close(workerStarted)
		<-releaseWorker
		return nil
	}
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_stuck", domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("worker execution was not prepared")
	}
	go queue.execute(execution)
	<-workerStarted
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// When
	err := manager.CancelJobsForRule(ctx, "lb_stuck")

	// Then
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel error=%v, want deadline exceeded", err)
	}
	close(releaseWorker)
	if err := manager.CancelJobsForRule(context.Background(), "lb_stuck"); err != nil {
		t.Fatalf("drain released worker: %v", err)
	}
}

func TestCAQueue_enqueue_notifies_worker_loop(t *testing.T) {
	// Given
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)

	// When
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_wake", domains: "example.com"})

	// Then
	select {
	case <-queue.wakeCh:
	default:
		t.Fatal("enqueue did not signal the worker loop")
	}
}

func TestCAQueueManager_PauseAndDrain_waits_for_deployment_retry_callback(t *testing.T) {
	// Given
	service := NewCertificateService()
	callbackEntered := make(chan struct{})
	cancellationObserved := make(chan struct{})
	releaseCallback := make(chan struct{})
	resumedRetry := make(chan struct{}, 1)
	service.retryDeployment = func(ctx context.Context, jobID int) error {
		if jobID == 42 {
			close(callbackEntered)
			<-ctx.Done()
			close(cancellationObserved)
			<-releaseCallback
			return ctx.Err()
		}
		resumedRetry <- struct{}{}
		return nil
	}
	service.scheduleDeploymentRetry(42, "lb_pause", 0)
	<-callbackEntered
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	pauseDone := make(chan struct{})
	go func() {
		manager.PauseAndDrain()
		close(pauseDone)
	}()
	<-cancellationObserved

	// When
	select {
	case <-pauseDone:
		t.Fatal("pause returned while deployment retry callback was running")
	default:
	}
	close(releaseCallback)

	// Then
	<-pauseDone
	manager.Resume()
	service.scheduleDeploymentRetry(43, "lb_resumed", 0)
	<-resumedRetry
	manager.Stop()
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

// R30 F5：PauseAndDrain 会把在途签发置回 'queued'（requeueCanceledJob），
// Resume 必须把这些滞留任务显式重入队，否则只能等到进程重启或快照替换。
// R44-2：issuer 不响应 ctx 取消超过 caQueueDrainTimeout 时，PauseAndDrain 有界等待
// 返回后滞行执行仍在旧队列中运行；Resume 的 stranded 扫描必须经 retiredQueues 识别
// 该在途 job，不得重复入队造成同 jobID 双执行；滞行执行退出后任务可正常重入队。
func TestCAQueueManager_PauseAndDrain_timeout_straggler_not_double_executed(t *testing.T) {
	// Given：适用规则 + 提供商 + 'creating_order' 在途任务，执行体不响应取消（滞行）
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_straggler','lb_straggler','example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'straggler CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (42,'lb_straggler','example.com','creating_order',7)`); err != nil {
		t.Fatal(err)
	}
	oldTimeout := caQueueDrainTimeout
	caQueueDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { caQueueDrainTimeout = oldTimeout })

	started := make(chan struct{})
	var startedOnce sync.Once
	release := make(chan struct{})
	var executionCount atomic.Int32
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	go queue.loop()
	queue.executeFn = func(ctx context.Context, _ queueItem, _ models.CAProvider) error {
		executionCount.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release // 不响应 ctx 取消，模拟滞行执行
		return ctx.Err()
	}
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_straggler", domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("pending execution was not prepared")
	}
	go queue.execute(execution)
	<-started
	manager := &CAQueueManager{queues: map[int]*caQueue{7: queue}, active: true}

	// When：PauseAndDrain 超时返回（滞行执行未退出），随后 Resume
	manager.PauseAndDrain()

	// Then：滞行执行经 retiredQueues 仍视为在途，Resume 不得重入队
	if !manager.IsJobActive(42) {
		t.Fatal("straggler job invisible after drain timeout（retiredQueues 未登记）")
	}
	manager.Resume()
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=42").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "creating_order" {
		t.Fatalf("job status=%q after Resume, want creating_order（stranded 扫描应跳过在途任务）", status)
	}
	time.Sleep(300 * time.Millisecond) // 留给错误实现启动第二执行的调度窗口
	if got := executionCount.Load(); got != 1 {
		t.Fatalf("executions=%d, want 1（滞行期间不得双执行）", got)
	}

	// When：滞行执行最终退出（返回 ctx 错误 → requeueCanceledJob 落 'queued'）
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=42").Scan(&status); err == nil && status == "queued" && !manager.IsJobActive(42) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("straggler exit not settled: status=%q active=%v", status, manager.IsJobActive(42))
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Then：退役队列已排空被惰性摘除，任务可再次正常入队（不会永久滞留）
	manager.Resume()
	manager.mu.Lock()
	reenqueued := false
	for _, q := range manager.queues {
		q.mu.Lock()
		_, reenqueued = q.active[42]
		q.mu.Unlock()
	}
	manager.mu.Unlock()
	if !reenqueued {
		t.Fatal("job 42 was not re-enqueued after the straggler exited")
	}
	manager.Stop()
}

func TestCAQueueManager_Resume_requeuesLifecycleStrandedJobs(t *testing.T) {
	// Given：队列暂停后滞留的 'queued' 与 'creating_order' 任务（规则仍存在且
	// 适用）；'queued' 的孤儿任务（规则已删除）不重入队
	_, database := newClusterTestService(t)
	for _, rule := range []struct{ id, domain string }{
		{id: "lb_resume_stranded", domain: "example.com"},
		{id: "lb_resume_stranded2", domain: "www.example.com"},
	} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?,?,?,'http',8080,1,1,'acme_dns')`, rule.id, rule.id, rule.domain); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'resume CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	jobs := []struct {
		id                     int64
		status, ruleID, domain string
	}{
		{id: 51, status: "queued", ruleID: "lb_resume_stranded", domain: "example.com"},
		{id: 52, status: "creating_order", ruleID: "lb_resume_stranded2", domain: "www.example.com"},
		{id: 53, status: "queued", ruleID: "lb_deleted_rule", domain: "example.com"},
	}
	for _, job := range jobs {
		if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (?,?,?,?,7)`, job.id, job.ruleID, job.domain, job.status); err != nil {
			t.Fatal(err)
		}
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: false}
	manager.Resume()

	// Then：两个适用任务被重入队，孤儿任务保持滞留
	enqueued := make(map[int64]bool)
	for _, queue := range manager.queues {
		queue.mu.Lock()
		for jobID := range queue.active {
			enqueued[int64(jobID)] = true
		}
		queue.mu.Unlock()
	}
	for _, job := range jobs[:2] {
		if !enqueued[job.id] {
			t.Fatalf("stranded job %d (%s) was not re-enqueued after Resume", job.id, job.status)
		}
	}
	if enqueued[53] {
		t.Fatal("orphaned job 53 was re-enqueued for a deleted rule")
	}
	manager.Stop()
}

// R45 发现1：滞行执行退出后任务停在 'queued' 且无队列持有，Resume 之外的周期
// 巡检原先不覆盖纯 'queued'；requeueStrandedQueuedJobs 必须把适用滞留任务重新
// 入队（滞停窗口收敛到 30s），且只动 'queued'——'waiting_ca' 冷却任务与孤儿
// 任务均不得触碰。
func TestCAQueueManager_requeueStrandedQueuedJobs_reenqueues_queued_only(t *testing.T) {
	// Given：适用规则 + 提供商；一个 'queued' 滞留任务、一个同规则 'waiting_ca'
	// 任务、一个规则已删除的孤儿 'queued' 任务
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_periodic','lb_periodic','example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'periodic CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	for _, job := range []struct {
		id             int64
		status, ruleID string
		domain         string
	}{
		{id: 61, status: "queued", ruleID: "lb_periodic", domain: "example.com"},
		{id: 62, status: "waiting_ca", ruleID: "lb_periodic", domain: "www.example.com"},
		{id: 63, status: "queued", ruleID: "lb_gone_rule", domain: "example.com"},
	} {
		if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (?,?,?,?,7)`, job.id, job.ruleID, job.domain, job.status); err != nil {
			t.Fatal(err)
		}
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}

	// When
	manager.requeueStrandedQueuedJobs()

	// Then：'queued' 适用任务被重入队
	manager.mu.Lock()
	enqueued := false
	for _, q := range manager.queues {
		q.mu.Lock()
		_, enqueued = q.active[61]
		q.mu.Unlock()
	}
	manager.mu.Unlock()
	if !enqueued {
		t.Fatal("stranded 'queued' job 61 was not re-enqueued by the periodic scan")
	}
	// 'waiting_ca' 与孤儿任务保持原状态且未入队
	for id, want := range map[int64]string{62: "waiting_ca", 63: "queued"} {
		var status string
		if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != want {
			t.Fatalf("job %d status=%q, want %q（周期扫描不得触碰）", id, status, want)
		}
	}
	manager.mu.Lock()
	for _, q := range manager.queues {
		q.mu.Lock()
		_, waiting := q.active[62]
		_, orphan := q.active[63]
		q.mu.Unlock()
		if waiting || orphan {
			t.Fatal("waiting_ca/orphan job must not be enqueued by the periodic scan")
		}
	}
	manager.mu.Unlock()
	manager.Stop()
}

// R45 发现2：EnqueueIfActive 必须先查 IsJobActive——滞行悬挂（retiredQueues 中
// 的在途执行）期间手动重试/规则重建不得再次入队造成同 jobID 双执行；命中时返回
// changed=false（与 blocked 同语义走 !changed 分支），transition 不得执行。
func TestCAQueueManager_EnqueueIfActive_skips_when_job_still_active(t *testing.T) {
	// Given：一个带在途执行的退役队列（模拟 PauseAndDrain 超时后的滞行悬挂）
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.mu.Unlock()
	manager := &CAQueueManager{
		queues:        make(map[int]*caQueue),
		retiredQueues: []retiredCAQueue{{queue: queue, retiredAt: time.Now()}},
		active:        true,
	}

	// When：对在途 job 调用 EnqueueIfActive
	transitionRan := false
	_, changed, err := manager.EnqueueIfActive(7, 42, "lb_straggler", "example.com", func() (int, bool, error) {
		transitionRan = true
		return 42, true, nil
	})

	// Then：不入队、不执行 transition、无错误
	if err != nil {
		t.Fatalf("EnqueueIfActive err=%v, want nil", err)
	}
	if changed {
		t.Fatal("EnqueueIfActive changed=true, want false（在途任务不得重入队）")
	}
	if transitionRan {
		t.Fatal("transition must not run while the job is still active")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.queues) != 0 {
		t.Fatal("a new queue was created for an active job（双执行缺口）")
	}
}
