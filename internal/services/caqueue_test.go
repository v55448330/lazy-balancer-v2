package services

import (
	"context"
	"database/sql"
	"errors"
	"lazy-balancer-v2/internal/db"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// installCAQueueTestFixture 初始化临时库 + 任务日志目录（CA 队列用例只依赖
// 这两项）。本文件此前借用 autoban 域的夹具，连带劫持 autoban 时钟/角色缝并
// 重置其全局状态——跨域耦合让本域用例随无关域改动漂移。
func installCAQueueTestFixture(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
}

// 生命周期取消的重入队把部署生命周期全集（downloaded/cleanup_dns/
// cleanup_warning，含 cleanup_* 与材料在身）保留在原状态并推部署窗口：
// 打回 queued 会丢弃已签发证书并触发整轮重签（烧 CA 配额）。
func TestRequeueCanceledJobKeepsDeploymentLifecycleWithMaterial(t *testing.T) {
	installCAQueueTestFixture(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,cert_pem,key_pem) VALUES
		('lb_cleanup_dns','cleanup.example.com','cleanup_dns','清理 DNS 记录','CERT','KEY'),
		('lb_cleanup_warning','cleanupwarn.example.com','cleanup_warning','清理告警','CERT','KEY'),
		('lb_cleanup_nomaterial','cleanupnomaterial.example.com','cleanup_dns','清理 DNS 记录',NULL,NULL),
		('lb_downloaded','downloaded.example.com','downloaded','部署退避中','CERT','KEY')`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	ids := map[string]int{}
	rows, err := db.DB.Query(`SELECT rule_id, id FROM cert_jobs`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ruleID string
		var id int
		if err := rows.Scan(&ruleID, &id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		ids[ruleID] = id
	}
	rows.Close()

	// When
	for _, ruleID := range []string{"lb_cleanup_dns", "lb_cleanup_warning", "lb_cleanup_nomaterial", "lb_downloaded"} {
		requeueCanceledJob(ids[ruleID])
	}

	// Then：材料在身的部署生命周期任务保持原状态 + 窗口推到 now
	for ruleID, wantStatus := range map[string]string{
		"lb_cleanup_dns":     "cleanup_dns",
		"lb_cleanup_warning": "cleanup_warning",
		"lb_downloaded":      "downloaded",
	} {
		var status, message string
		var after sql.NullString
		if err := db.DB.QueryRow(`SELECT status, COALESCE(message,''), deployment_available_after FROM cert_jobs WHERE id=?`, ids[ruleID]).
			Scan(&status, &message, &after); err != nil {
			t.Fatalf("read %s: %v", ruleID, err)
		}
		if status != wantStatus {
			t.Fatalf("%s status=%q, want %q（部署生命周期任务不得被打回 queued 重签）", ruleID, status, wantStatus)
		}
		if !after.Valid || !strings.Contains(message, "等待恢复部署") {
			t.Fatalf("%s 部署窗口未推进: after=%v message=%q", ruleID, after.Valid, message)
		}
	}
	// 无材料的 cleanup_* 是历史脏行：回落重新签发
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, ids["lb_cleanup_nomaterial"]).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("无材料 cleanup_dns status=%q, want queued（回落重新签发）", status)
	}
}

// 两处部署窗口写（执行超时重排 / 生命周期取消重排）必须同口径推进
// updated_at：重试冷却门（certJobRetryBlocked）以 updated_at 为计时基准，
// 只推 deployment_available_after 而不推 updated_at 会让冷却门读到陈旧基准，
// 本轮重排对其不可见（可被连点绕过 + 行序失真）。
func TestDeploymentWindowWritesAdvanceUpdatedAt(t *testing.T) {
	installCAQueueTestFixture(t)
	const staleUpdatedAt = "2020-01-01 00:00:00"
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at) VALUES
		('lb_timeout','timeout.example.com','downloaded','CERT','KEY',?),
		('lb_cancel','cancel.example.com','cleanup_dns','CERT','KEY',?)`, staleUpdatedAt, staleUpdatedAt); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	ids := map[string]int{}
	rows, err := db.DB.Query(`SELECT rule_id, id FROM cert_jobs`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ruleID string
		var id int
		if err := rows.Scan(&ruleID, &id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		ids[ruleID] = id
	}
	rows.Close()

	// When
	handleExecutionTimeout(ids["lb_timeout"])
	requeueCanceledJob(ids["lb_cancel"])

	// Then：冷却门读值（updated_at）随写推进
	for ruleID, id := range ids {
		var updatedAt, after sql.NullString
		if err := db.DB.QueryRow(`SELECT updated_at, deployment_available_after FROM cert_jobs WHERE id=?`, id).Scan(&updatedAt, &after); err != nil {
			t.Fatalf("read %s: %v", ruleID, err)
		}
		if !updatedAt.Valid || updatedAt.String <= staleUpdatedAt {
			t.Fatalf("%s updated_at=%q, want 推进到当前时刻（冷却门基准）", ruleID, updatedAt.String)
		}
		if !after.Valid {
			t.Fatalf("%s deployment_available_after 未推进", ruleID)
		}
	}
}

// 执行超时且材料在身的任务走部署重试语义时，必须落 certjob-*.log 业务行
// （与 deploymentFailed/failJob 同族）——否则磁盘日志只剩签发阶段，
// 「超时后转重排」在排障视角完全无痕。
func TestHandleExecutionTimeout_materialBranchWritesCertJobLog(t *testing.T) {
	installCAQueueTestFixture(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_timeoutlog','timeoutlog.example.com','downloaded','CERT','KEY')`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}

	// When
	handleExecutionTimeout(1)

	// Then
	raw, err := os.ReadFile(CertJobLogPath("lb_timeoutlog"))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	if !strings.Contains(string(raw), "执行超时：证书材料已落库，等待重新部署") {
		t.Fatalf("certjob 日志缺少超时重排业务行:\n%s", raw)
	}
}

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
		enqueueDone <- manager.EnqueueForTest(1, 42, "lb_cancel_race", "example.com")
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

func TestCAQueueManager_CancelJobsForRule_waitsForRetiredExecution(t *testing.T) {
	// Given：PauseAndDrain 超时后的退役队列仍持有本规则执行。
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	executionDone := make(chan struct{})
	t.Cleanup(func() { close(executionDone) })
	executionCtx, cancelExecution := context.WithCancel(context.Background())
	var cancelOnce sync.Once
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.runningRules[42] = "lb_retired_drain"
	queue.executionDone[42] = executionDone
	queue.cancels[42] = func() { cancelOnce.Do(cancelExecution) }
	queue.mu.Unlock()
	manager := &CAQueueManager{
		queues:        make(map[int]*caQueue),
		retiredQueues: []retiredCAQueue{{queue: queue, retiredAt: time.Now()}},
	}

	// 回归：其他规则不等待、不取消本执行。
	if err := manager.CancelJobsForRule(context.Background(), "lb_other"); err != nil {
		t.Fatalf("cancel unrelated rule: %v", err)
	}
	select {
	case <-executionCtx.Done():
		t.Fatal("unrelated rule cancelled retired execution")
	default:
	}

	// When：本规则 drain 必须看到退役执行并在 ctx 到期时如实失败。
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := manager.CancelJobsForRule(ctx, "lb_retired_drain")

	// Then
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retired drain error=%v, want deadline exceeded instead of pseudo-success", err)
	}
	select {
	case <-executionCtx.Done():
	default:
		t.Fatal("retired execution was not cancelled")
	}
}

func TestCAQueueManager_HasRunningJobForRule_includesRetiredExecution(t *testing.T) {
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.runningRules[42] = "lb_retired_precheck"
	queue.mu.Unlock()
	manager := &CAQueueManager{retiredQueues: []retiredCAQueue{{queue: queue, retiredAt: time.Now()}}}

	if !manager.HasRunningJobForRule("lb_retired_precheck") {
		t.Fatal("retired execution is invisible to rule deletion precheck")
	}
	if manager.HasRunningJobForRule("lb_other") {
		t.Fatal("unrelated rule unexpectedly matched retired execution")
	}
}

func TestCAQueueManager_CancelJobsForRule_waitsForZombieExecution(t *testing.T) {
	for _, tc := range []struct {
		name string
		done chan struct{}
	}{
		{name: "completion signal", done: make(chan struct{})},
		{name: "missing completion signal", done: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &CAQueueManager{zombieJobs: map[int]zombieJob{42: {ruleID: "lb_zombie_drain", done: tc.done}}}
			if tc.done != nil {
				t.Cleanup(func() { close(tc.done) })
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := manager.CancelJobsForRule(ctx, "lb_zombie_drain"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("zombie drain error=%v, want deadline exceeded instead of pseudo-success", err)
			}
		})
	}
}

func TestCAQueueManager_agedOutZombieRetainsRuleDrainMetadata(t *testing.T) {
	// Given：超龄退役队列中的执行带 rule 元数据，迁移后仍须可被规则级 drain 看见。
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	done := make(chan struct{})
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.runningRules[42] = "lb_ageout_drain"
	queue.executionDone[42] = done
	queue.mu.Unlock()
	manager := &CAQueueManager{
		queues:        make(map[int]*caQueue),
		retiredQueues: []retiredCAQueue{{queue: queue, retiredAt: time.Now().Add(-(caExecutionTimeoutMax + 11*time.Minute))}},
	}
	if !manager.IsJobActive(42) {
		t.Fatal("aged-out execution lost activity protection")
	}
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			close(done)
		}
	})

	// Then：规则级预检与 drain 仍使用迁移后的 ruleID/完成信号。
	if !manager.HasRunningJobForRule("lb_ageout_drain") {
		t.Fatal("aged-out zombie lost its rule identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.CancelJobsForRule(ctx, "lb_ageout_drain"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("aged-out zombie drain error=%v, want deadline exceeded", err)
	}
}

func TestCAQueueManager_HasRunningJobForRule_includesZombieExecution(t *testing.T) {
	manager := &CAQueueManager{zombieJobs: map[int]zombieJob{42: {ruleID: "lb_zombie_precheck"}}}
	if !manager.HasRunningJobForRule("lb_zombie_precheck") {
		t.Fatal("zombie execution is invisible to rule deletion precheck")
	}
	if manager.HasRunningJobForRule("lb_other") {
		t.Fatal("unrelated rule unexpectedly matched zombie execution")
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
	manager := &CAQueueManager{queues: map[int]*caQueue{int(providerID): queue}, active: true}
	queue.manager = manager
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
		enqueueDone <- manager.EnqueueForTest(1, 42, "lb_enqueue_stop", "example.com")
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
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error {
		close(started)
		<-release
		return nil
	}
	// 先手工 prepare 再启动 loop——原顺序（loop 先行）存在竞态：loop 可能
	// 抢先消费 pending 使 prepareExecutionLocked 落空（断言 336 偶发失败，
	// 调度时序敏感）。prepare 已取走唯一 pending 项，loop 启动后无可消费。
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_stop", domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("pending execution was not prepared")
	}
	go queue.loop()
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
	// loop 必须在 prepare 之后启动：loop 先行会抢先消费 pending 首项，
	// 使上面的 prepare 落空（断言随机失败）；此时 running 已占满配额，
	// loop 只负责后续调度，不再抢走第二项。
	go queue.loop()
	go queue.execute(execution)
	<-started
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	// When
	// 执行体响应取消正常退出 → 必须报告完全排空（true）。
	if drained := manager.PauseAndDrain(); !drained {
		t.Fatal("PauseAndDrain drained=false, want true（执行体已响应取消退出）")
	}

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
	// 先 prepare 再启动 loop：loop 先行会抢走唯一 pending 项。
	go queue.loop()
	go queue.execute(execution)
	<-started
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}

	// When
	manager.PauseAndDrain()

	// Then
	<-finished
	if err := manager.EnqueueForTest(1, 43, "lb_paused", "paused.example.com"); err == nil {
		t.Fatal("enqueue succeeded while manager was paused")
	}
	manager.Resume()
	if err := manager.EnqueueForTest(1, 43, "lb_paused", "paused.example.com"); err != nil {
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
	err = manager.EnqueueForTest(999, int(jobID), "lb_paused_enqueue", "example.com")

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
	resetCertificateServiceForTest(t)
	callbackEntered := make(chan struct{})
	cancellationObserved := make(chan struct{})
	releaseCallback := make(chan struct{})
	wroteFiles := make(chan struct{}, 1)
	// close 幂等：取消/补扫路径可能对同一任务二次触发本闭包，
	// 裸 close 已关闭通道必 panic。
	var callbackOnce, cancellationOnce sync.Once
	service.retryDeployment = func(ctx context.Context, _ int) error {
		callbackOnce.Do(func() { close(callbackEntered) })
		<-ctx.Done()
		cancellationOnce.Do(func() { close(cancellationObserved) })
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
	// Given 单一夹具初始化：本用例只断言第二个库的行（同一 id 42 的
	// creating_order）——此前多一次 newClusterTestService + 一条随即被重建丢弃的
	// downloaded 种子行，属死种子，且让前一测试库句柄多存活到 t.Cleanup。
	newClusterTestService(t)
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
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
	GetCAQueueManager().Start()
	t.Cleanup(ResetCAQueueManagerForTest)
	manager := GetCAQueueManager()
	manager.mu.Lock()
	manager.queues[1] = queue
	manager.mu.Unlock()
	blockToken := manager.BlockJobsForRule("lb_deleted")

	// When
	if err := manager.CancelJobsForRule(context.Background(), "lb_deleted"); err != nil {
		t.Fatalf("cancel rule jobs: %v", err)
	}
	manager.UnblockJobsForRule("lb_deleted", blockToken)

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
	resetCertificateServiceForTest(t)
	callbackEntered := make(chan struct{})
	cancellationObserved := make(chan struct{})
	releaseCallback := make(chan struct{})
	resumedRetry := make(chan struct{}, 1)
	// close 幂等：同 TestCAQueueManager_CancelJobsForRule 闭包。
	var callbackOnce, cancellationOnce sync.Once
	service.retryDeployment = func(ctx context.Context, jobID int) error {
		if jobID == 42 {
			callbackOnce.Do(func() { close(callbackEntered) })
			<-ctx.Done()
			cancellationOnce.Do(func() { close(cancellationObserved) })
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
	// 先 prepare 再启动 loop：loop 先行会抢走唯一 pending 项。
	go queue.loop()
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

// PauseAndDrain 会把在途签发置回 'queued'（requeueCanceledJob），
// Resume 必须把这些滞留任务显式重入队，否则只能等到进程重启或快照替换。
// issuer 不响应 ctx 取消超过 caQueueDrainTimeout 时，PauseAndDrain 有界等待
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
	// 先 prepare 再启动 loop：loop 先行会抢走唯一 pending 项。
	go queue.loop()
	go queue.execute(execution)
	<-started
	manager := &CAQueueManager{queues: map[int]*caQueue{7: queue}, active: true}

	// When：PauseAndDrain 超时返回（滞行执行未退出），随后 Resume
	// 滞行执行不响应取消 → 必须报告未完全排空（false），
	// 调用方（配置导入）据此拒绝在证书任务仍在执行时继续。
	if drained := manager.PauseAndDrain(); drained {
		t.Fatal("PauseAndDrain drained=true, want false（issuer 未响应取消，滞行仍在执行）")
	}

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

// 发现1：滞行执行退出后任务停在 'queued' 且无队列持有，Resume 之外的周期
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

// 发现2：EnqueueIfActive 必须先查 IsJobActive——滞行悬挂（retiredQueues 中
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

// enqueueCompensation 必须先查 IsJobActive——补偿退避循环在角色翻转
// 退役旧队列后重跑时，drain 只扫 m.queues 看不到退役队列中的滞行执行，不经守卫
// 会二次入队同 jobID → 双执行。命中时跳过（返回 nil，不视为补偿失败）、不新建
// 队列、不写 DB。
func TestCAQueueManager_enqueueCompensation_skips_when_job_still_active(t *testing.T) {
	// Given：一个带在途执行的退役队列（模拟角色翻转退役后滞行悬挂），补偿租约
	// 仍在（blockedRules 非空），DB 中有对应 cert_jobs 行
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'comp CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (42,'lb_straggler','example.com','queued',7)`); err != nil {
		t.Fatal(err)
	}
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.mu.Unlock()
	manager := &CAQueueManager{
		queues:        make(map[int]*caQueue),
		retiredQueues: []retiredCAQueue{{queue: queue, retiredAt: time.Now()}},
		active:        true,
		blockedRules:  map[string]map[RuleBlockToken]struct{}{"lb_straggler": {1: {}}},
	}

	// When：补偿路径对仍在途的 job 重入队
	if err := manager.enqueueCompensation(7, 42, "lb_straggler", "example.com"); err != nil {
		t.Fatalf("enqueueCompensation err=%v, want nil（在途任务应跳过而非报错）", err)
	}

	// Then：不新建队列（无二次入队），DB 状态不变
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.queues) != 0 {
		t.Fatal("a new queue was created for an active job（同 jobID 双执行缺口）")
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=42").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("job 42 status=%q, want queued（补偿跳过不得触碰 DB 状态）", status)
	}
}

// 补偿循环必须在规则被并发删除后终止并释放租约。drain 成功后规则已
// 不存在（管理员重试 DeleteRule 或配置导入整树替换）时，没有可恢复对象——
// restore 不得写入幽灵 cert_jobs 行（无外键），requeue 的规则 SELECT 命中
// ErrNoRows 必须按成功语义收尾，否则补偿进入永久退避循环且 blockedRules 租约
// 永不释放（caddy_id 复用后新规则证书静默停发）。
func TestCAQueueManager_StartRuleDeletionCompensation_exits_when_rule_deleted_midflight(t *testing.T) {
	// Given：规则 + 证书任务快照，补偿 drain 首次执行时规则被另一路径并发删除
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'comp CA','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_vanish','vanish','example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (42,'lb_vanish','example.com','creating_order',7)`); err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotCertJobsForRule("lb_vanish")
	if err != nil {
		t.Fatalf("snapshot cert jobs: %v", err)
	}
	compensationCtx, compensationCancel := context.WithCancel(context.Background())
	manager := &CAQueueManager{
		queues:             make(map[int]*caQueue),
		active:             true,
		compensationCtx:    compensationCtx,
		compensationCancel: compensationCancel,
		compensationBackoff: func(int) time.Duration {
			return time.Millisecond
		},
	}
	t.Cleanup(func() {
		compensationCancel()
		manager.compensationWG.Wait()
	})
	token := manager.BlockJobsForRule("lb_vanish")
	var drainCalls atomic.Int32

	// When：启动补偿，drain 成功但规则已不在（模拟并发删除）
	if err := manager.StartRuleDeletionCompensation(RuleDeletionCompensation{
		RuleID: "lb_vanish", Token: token, Snapshot: snapshot,
		Drain: func(context.Context) error {
			drainCalls.Add(1)
			if _, err := database.Exec(`DELETE FROM cert_jobs WHERE rule_id='lb_vanish'`); err != nil {
				return err
			}
			if _, err := database.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_vanish'`); err != nil {
				return err
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("start compensation: %v", err)
	}

	// Then：补偿一次尝试内按成功收尾——租约释放、循环退出、无幽灵 cert_jobs 行
	deadline := time.Now().Add(2 * time.Second)
	for manager.IsRuleBlocked("lb_vanish") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if manager.IsRuleBlocked("lb_vanish") {
		t.Fatal("compensation lease never released（补偿未终止，永久退避循环）")
	}
	compensationCancel()
	manager.compensationWG.Wait()
	if calls := drainCalls.Load(); calls != 1 {
		t.Fatalf("drain calls=%d, want 1（补偿应在规则不存在时一次尝试内收尾）", calls)
	}
	var ghostJobs int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_vanish'`).Scan(&ghostJobs); err != nil {
		t.Fatal(err)
	}
	if ghostJobs != 0 {
		t.Fatalf("ghost cert_jobs=%d, want 0（规则已删除，restore 不得写入幽灵行）", ghostJobs)
	}
}

// Stop 弃置补偿（角色翻转/进程停止）后必须回收全部 blockedRules
// 租约——补偿 goroutine 已退出，其租约再无释放者；残留租约会让复用同
// caddy_id 的新规则被 EnqueueIfActive 永久拦截（证书静默停发）。
func TestCAQueueManager_Stop_releases_abandoned_rule_block_leases(t *testing.T) {
	// Given：持有一条规则删除屏障租约的队列管理器（模拟补偿被 Stop 取消后弃置）
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		active:       true,
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
	}
	token := manager.BlockJobsForRule("lb_abandoned")
	if !manager.IsRuleBlocked("lb_abandoned") {
		t.Fatal("lease not registered")
	}
	_ = token

	// When
	manager.Stop()

	// Then：租约被回收
	if manager.IsRuleBlocked("lb_abandoned") {
		t.Fatal("Stop must release abandoned blockedRules leases（角色翻转后 caddy_id 复用会被永久拦截）")
	}
}

// 退役条目 age-out 摘除不得遗忘在途 jobID——摘除后
// IsJobActive 必须继续返回 true（zombieJobs 迁移），直到滞行执行经 executionDone
// 信号退出；无 executionDone 的 jobID 永久保留保护（罕见，宁可永久保护不放双执行）。
func TestCAQueueManager_IsJobActive_agedOutRetiredEntry_migratesZombieProtection(t *testing.T) {
	// Given：超龄退役队列，job 42 带 executionDone 信号，job 43 无信号
	queue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	done := make(chan struct{})
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.executionDone[42] = done
	queue.active[43] = struct{}{}
	queue.mu.Unlock()
	manager := &CAQueueManager{
		queues: make(map[int]*caQueue),
		retiredQueues: []retiredCAQueue{{
			queue:     queue,
			retiredAt: time.Now().Add(-(caExecutionTimeoutMax + 11*time.Minute)),
		}},
		active: true,
	}

	// When：超龄条目在 IsJobActive 惰性检查中被摘除
	if !manager.IsJobActive(42) {
		t.Fatal("aged-out retired job lost protection（zombie 迁移未生效）")
	}

	// Then：条目已摘除，但在途保护经 zombieJobs 延续
	manager.mu.Lock()
	retired := len(manager.retiredQueues)
	zombies := len(manager.zombieJobs)
	manager.mu.Unlock()
	if retired != 0 {
		t.Fatalf("retiredQueues=%d, want 0（超龄条目应摘除）", retired)
	}
	if zombies != 2 {
		t.Fatalf("zombieJobs=%d, want 2（在途 jobID 应全部迁移）", zombies)
	}
	if !manager.IsJobActive(42) || !manager.IsJobActive(43) {
		t.Fatal("zombie protection must persist after age-out removal")
	}

	// When：滞行执行最终退出（executionDone 关闭）
	close(done)

	// Then：job 42 的保护被解除；job 43（无信号）永久保留
	deadline := time.Now().Add(5 * time.Second)
	for manager.IsJobActive(42) {
		if time.Now().After(deadline) {
			t.Fatal("zombie protection for job 42 not released after execution done")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !manager.IsJobActive(43) {
		t.Fatal("job without executionDone must keep permanent zombie protection")
	}
}

func TestCAQueue_prepareExecution_scales_budget_with_domain_count(t *testing.T) {
	// Given：双域名签发（authz + DNS 传播双倍串行叠加）
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_dual", domains: "example.com,www.example.com"})

	// When
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(context.Background())
	queue.mu.Unlock()

	// Then：预算按 40min 基础（caExecutionTimeout）+ 每增加一个域名 15min 缩放
	if !ok {
		t.Fatal("pending job was not prepared")
	}
	defer execution.cancel()
	deadline, hasDeadline := execution.ctx.Deadline()
	if !hasDeadline {
		t.Fatal("execution context has no deadline")
	}
	want := caExecutionTimeout + 15*time.Minute
	if remaining := time.Until(deadline); remaining < want-time.Minute || remaining > want {
		t.Fatalf("execution timeout=%v, want ~%v", remaining, want)
	}
}

func TestCAQueue_prepareExecution_budget_capped_at_max(t *testing.T) {
	// Given：五域名任务，缩放后预算必须封顶
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.enqueue(queueItem{jobID: 42, ruleID: "lb_many", domains: "a.example.com,b.example.com,c.example.com,d.example.com,e.example.com"})

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
	if remaining := time.Until(deadline); remaining < caExecutionTimeoutMax-time.Minute || remaining > caExecutionTimeoutMax {
		t.Fatalf("execution timeout=%v, want ~%v (cap)", remaining, caExecutionTimeoutMax)
	}
}

func TestCaExecutionTimeoutFor_counts_domains(t *testing.T) {
	// Given/When/Then（每域增量 10min→15min——单域内部分段
	// 最坏 ≈17min（传播 5m+递归 2m/域+验证 10m），15min 贴合最坏段和）
	testCases := []struct {
		domains string
		want    time.Duration
	}{
		{domains: "example.com", want: caExecutionTimeout},
		{domains: "example.com,www.example.com", want: caExecutionTimeout + 15*time.Minute},
		{domains: " example.com , www.example.com ", want: caExecutionTimeout + 15*time.Minute},
		{domains: "", want: caExecutionTimeout},
		{domains: "a.com,b.com,c.com", want: caExecutionTimeoutMax},
		{domains: "a.com,b.com,c.com,d.com", want: caExecutionTimeoutMax},
	}
	for _, testCase := range testCases {
		if got := caExecutionTimeoutFor(testCase.domains); got != testCase.want {
			t.Fatalf("caExecutionTimeoutFor(%q)=%v, want %v", testCase.domains, got, testCase.want)
		}
	}
}

func TestCAQueueManager_providerUnavailableFail_skipsCrossProviderTakeover(t *testing.T) {
	for _, running := range []bool{false, true} {
		name := "pending"
		if running {
			name = "active"
		}
		t.Run(name, func(t *testing.T) {
			// Given：旧 provider A 的 pending 已排空，同一任务已由 provider B 接管。
			installCAQueueTestFixture(t)
			if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES
				(7,'old CA','letsencrypt','https://old.example/directory',0),
				(8,'new CA','letsencrypt','https://new.example/directory',1)`); err != nil {
				t.Fatalf("seed CA providers: %v", err)
			}
			if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES
				(42,'lb_cross_provider','cross.example.com','queued',7)`); err != nil {
				t.Fatalf("seed certificate job: %v", err)
			}
			oldQueue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
			newQueue := newCAQueue(models.CAProvider{ID: 8, MaxConcurrent: 1}, nil)
			t.Cleanup(oldQueue.cancel)
			t.Cleanup(newQueue.cancel)
			item := queueItem{jobID: 42, ruleID: "lb_cross_provider", domains: "cross.example.com"}
			oldQueue.enqueue(item)
			oldQueue.mu.Lock()
			oldQueue.pending = nil
			delete(oldQueue.active, item.jobID)
			oldQueue.mu.Unlock()
			if running {
				newQueue.mu.Lock()
				newQueue.active[item.jobID] = struct{}{}
				newQueue.runningRules[item.jobID] = item.ruleID
				newQueue.running++
				newQueue.mu.Unlock()
			} else {
				newQueue.enqueue(item)
			}
			manager := &CAQueueManager{queues: map[int]*caQueue{7: oldQueue, 8: newQueue}, active: true}

			// When：旧 provider 的延迟失败处置在 B 接管之后到达。
			manager.failPendingProviderUnavailable([]queueItem{item}, "CA Provider 不可用：配置已禁用或删除（ID 7）")

			// Then：旧尝试不得覆盖新尝试的状态与重试计数。
			var status string
			var attempts int
			if err := db.DB.QueryRow("SELECT status, COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=42").Scan(&status, &attempts); err != nil {
				t.Fatalf("read certificate job: %v", err)
			}
			if status != "queued" || attempts != 0 {
				t.Fatalf("replacement job status=%q attempts=%d, want queued/0", status, attempts)
			}
		})
	}
}

func TestCAQueueManager_providerUnavailableFail_serializesLaterTakeover(t *testing.T) {
	// Given：旧 provider 已完成全局在途与 queued 复核，尚未写入 failed。
	installCAQueueTestFixture(t)
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES
		(7,'old CA','letsencrypt','https://old.example/directory',0),
		(8,'new CA','letsencrypt','https://new.example/directory',1)`); err != nil {
		t.Fatalf("seed CA providers: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES
		(42,'lb_after_recheck','after.example.com','queued',7)`); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	oldQueue := newCAQueue(models.CAProvider{ID: 7, MaxConcurrent: 1}, nil)
	newQueue := newCAQueue(models.CAProvider{ID: 8, MaxConcurrent: 1}, nil)
	t.Cleanup(oldQueue.cancel)
	t.Cleanup(newQueue.cancel)
	item := queueItem{jobID: 42, ruleID: "lb_after_recheck", domains: "after.example.com"}
	oldQueue.enqueue(item)
	oldQueue.mu.Lock()
	oldQueue.pending = nil
	delete(oldQueue.active, item.jobID)
	oldQueue.mu.Unlock()
	rechecked := make(chan struct{})
	releaseFailure := make(chan struct{})
	takeoverStarted := make(chan struct{})
	manager := &CAQueueManager{
		queues: map[int]*caQueue{7: oldQueue, 8: newQueue},
		active: true,
		beforeActiveEnqueue: func() {
			close(takeoverStarted)
		},
		beforeProviderUnavailableFail: func() {
			close(rechecked)
			<-releaseFailure
		},
	}
	drainDone := make(chan struct{})
	go func() {
		manager.failPendingProviderUnavailable([]queueItem{item}, "CA Provider 不可用：配置已禁用或删除（ID 7）")
		close(drainDone)
	}()
	<-rechecked

	// When：复核之后另一 provider 尝试接管；它必须与旧失败写库串行。
	type enqueueResult struct {
		changed bool
		err     error
	}
	enqueueDone := make(chan enqueueResult, 1)
	go func() {
		_, changed, err := manager.EnqueueIfActive(8, item.jobID, item.ruleID, item.domains, func() (int, bool, error) {
			// 只有旧失败先完成，这次 failed→queued 的新尝试才可能成功。
			err := transitionJob(db.DB, item.jobID, []string{"failed"}, "queued", map[string]any{
				"message":          "重新排队签发",
				"renewal_attempts": 0,
			})
			return item.jobID, err == nil, err
		})
		enqueueDone <- enqueueResult{changed: changed, err: err}
	}()
	<-takeoverStarted
	select {
	case result := <-enqueueDone:
		t.Fatalf("takeover crossed provider failure critical section: %+v", result)
	default:
	}
	close(releaseFailure)
	<-drainDone
	result := <-enqueueDone
	if result.err != nil || !result.changed {
		t.Fatalf("takeover changed=%v err=%v, want successful failed→queued transition", result.changed, result.err)
	}

	// Then：最终行属于 B 的新尝试，而非 A 的旧失败结果。
	var status string
	var attempts int
	if err := db.DB.QueryRow("SELECT status, COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=42").Scan(&status, &attempts); err != nil {
		t.Fatalf("read certificate job: %v", err)
	}
	if status != "queued" || attempts != 0 {
		t.Fatalf("final job status=%q attempts=%d, want queued/0", status, attempts)
	}
	newQueue.mu.Lock()
	_, active := newQueue.active[item.jobID]
	newQueue.mu.Unlock()
	if !active {
		t.Fatal("replacement job missing from new provider queue")
	}
}

func TestCAQueue_providerUnavailable_fail_skips_reenqueued_job(t *testing.T) {
	// Given：provider 失效，tick 已排空 pending（active 摘除）；窗口内并发
	// 手动重试按 RetryCertJob 的 CAS 语义把任务重置为新的一次尝试并重新入队。
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
	manager := &CAQueueManager{queues: map[int]*caQueue{int(providerID): queue}, active: true}
	queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_queue_test", domains: "example.com"})
	if _, err := database.Exec("UPDATE ca_providers SET enabled=0 WHERE id=?", providerID); err != nil {
		t.Fatalf("disable CA provider: %v", err)
	}

	// 复刻 tick drain 后的状态：pending 已排空、active 已摘除
	queue.mu.Lock()
	queue.pending = nil
	delete(queue.active, int(jobID))
	queue.mu.Unlock()

	// 并发重入队：CAS 重置 attempts + 重新占位队列
	if _, err := database.Exec(`UPDATE cert_jobs
		SET status='queued', message='重新排队签发', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now')
		WHERE id=? AND status='queued'`, jobID); err != nil {
		t.Fatalf("reenqueue job: %v", err)
	}
	queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_queue_test", domains: "example.com"})

	// When：旧的 provider 失效处置路径
	manager.failPendingProviderUnavailable([]queueItem{{jobID: int(jobID), ruleID: "lb_queue_test", domains: "example.com"}}, "CA Provider 不可用：配置已禁用或删除（ID 1）")

	// Then：新尝试未被误标 failed（attempts 不 +1、状态保持 queued）
	var status string
	var attempts int
	if err := database.QueryRow("SELECT status, COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read certificate job: %v", err)
	}
	if status != "queued" || attempts != 0 {
		t.Fatalf("reenqueued job status=%q attempts=%d, want queued/0", status, attempts)
	}
	queue.cancel()
}

func TestCAQueue_providerUnavailable_fail_skips_deleted_or_disabled_job(t *testing.T) {
	// Given：drain 后窗口内任务被并发删除 / 禁用
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name, provider, directory_url, enabled) VALUES ('temporary', 'letsencrypt', 'https://invalid.example/directory', 0)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	deletedResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_deleted', 'example.com', 'queued', ?)`, providerID)
	if err != nil {
		t.Fatalf("seed deleted job: %v", err)
	}
	deletedJobID, err := deletedResult.LastInsertId()
	if err != nil {
		t.Fatalf("read deleted job ID: %v", err)
	}
	disabledResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_disabled', 'example.com', 'queued', ?)`, providerID)
	if err != nil {
		t.Fatalf("seed disabled job: %v", err)
	}
	disabledJobID, err := disabledResult.LastInsertId()
	if err != nil {
		t.Fatalf("read disabled job ID: %v", err)
	}
	queue := newCAQueue(models.CAProvider{ID: int(providerID), MaxConcurrent: 1}, func() error { return nil })
	manager := &CAQueueManager{queues: map[int]*caQueue{int(providerID): queue}, active: true}

	if _, err := database.Exec("DELETE FROM cert_jobs WHERE id=?", deletedJobID); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	if _, err := database.Exec("UPDATE cert_jobs SET status='disabled' WHERE id=?", disabledJobID); err != nil {
		t.Fatalf("disable job: %v", err)
	}

	// When
	manager.failPendingProviderUnavailable([]queueItem{
		{jobID: int(deletedJobID), ruleID: "lb_deleted", domains: "example.com"},
		{jobID: int(disabledJobID), ruleID: "lb_disabled", domains: "example.com"},
	}, "CA Provider 不可用：配置已禁用或删除（ID 1）")

	// Then：已删行不复活、已禁用行不被改写为 failed
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE id=?", deletedJobID).Scan(&count); err != nil {
		t.Fatalf("count deleted job: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted job resurrected: count=%d", count)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", disabledJobID).Scan(&status); err != nil {
		t.Fatalf("read disabled job: %v", err)
	}
	if status != "disabled" {
		t.Fatalf("disabled job status=%q, want disabled", status)
	}
	queue.cancel()
}

// 并发/间隔闸门只需缓存 provider 与内存态即可判定，必须先于
// loadCAProvider——否则积压窗口内每 100ms tick 都打 1-2 次 provider 查询
// （~10 次/秒）。可观测判据：provider 已在 DB 禁用（无 enabled 回退），闸门
// 关闭时 tick 不得触发 provider 加载——一旦加载必然走 drain→failJob 路径。
func TestCAQueue_tick_memory_gates_skip_provider_load(t *testing.T) {
	seedGatedQueue := func(t *testing.T) (*caQueue, int64) {
		t.Helper()
		_, database := newClusterTestService(t)
		result, err := database.Exec(`INSERT INTO ca_providers (name, provider, directory_url, enabled, max_concurrent, min_interval_ms) VALUES ('gated', 'letsencrypt', 'https://invalid.example/directory', 1, 1, 60000)`)
		if err != nil {
			t.Fatalf("seed CA provider: %v", err)
		}
		providerID, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read CA provider ID: %v", err)
		}
		jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_gated', 'example.com', 'queued', ?)`, providerID)
		if err != nil {
			t.Fatalf("seed certificate job: %v", err)
		}
		jobID, err := jobResult.LastInsertId()
		if err != nil {
			t.Fatalf("read certificate job ID: %v", err)
		}
		queue := newCAQueue(models.CAProvider{ID: int(providerID), MaxConcurrent: 1, MinIntervalMS: 60000}, func() error { return nil })
		queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_gated", domains: "example.com"})
		if _, err := database.Exec("UPDATE ca_providers SET enabled=0 WHERE id=?", providerID); err != nil {
			t.Fatalf("disable CA provider: %v", err)
		}
		t.Cleanup(queue.cancel)
		return queue, jobID
	}

	assertNotDrained := func(t *testing.T, queue *caQueue, jobID int64) {
		t.Helper()
		queue.mu.Lock()
		pending := len(queue.pending)
		_, active := queue.active[int(jobID)]
		queue.mu.Unlock()
		if pending != 1 || !active {
			t.Fatalf("pending=%d active=%v, want 1/true（闸门关闭时不得加载 provider 并排空队列）", pending, active)
		}
		var status string
		if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
			t.Fatalf("read certificate job: %v", err)
		}
		if status != "queued" {
			t.Fatalf("job status=%q, want queued（未派发不得改写任务状态）", status)
		}
	}

	t.Run("min interval not elapsed", func(t *testing.T) {
		// Given：刚派发过一次（lastOrder=now），60s 间隔闸门关闭
		queue, jobID := seedGatedQueue(t)
		queue.mu.Lock()
		queue.lastOrder = time.Now()
		queue.mu.Unlock()

		// When
		queue.tick()

		// Then
		assertNotDrained(t, queue, jobID)
	})

	t.Run("max concurrent reached", func(t *testing.T) {
		// Given：并发已满（running=1 = MaxConcurrent）
		queue, jobID := seedGatedQueue(t)
		queue.mu.Lock()
		queue.running = 1
		queue.mu.Unlock()

		// When
		queue.tick()

		// Then
		assertNotDrained(t, queue, jobID)
	})
}

// 闸门按缓存放行后，加载到的新配置若收紧必须复核拦截——派发决策始终按最新
// provider 配置评估，不弱于原先"每次 tick 都用新加载值评估"的语义。
func TestCAQueue_tick_rechecks_gates_with_refreshed_provider(t *testing.T) {
	// Given：缓存 MaxConcurrent=2，DB 已收紧为 1，running=1（缓存闸门放行）
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name, provider, directory_url, enabled, max_concurrent) VALUES ('tightened', 'letsencrypt', 'https://invalid.example/directory', 1, 2)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_tightened', 'example.com', 'queued', ?)`, providerID)
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := jobResult.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	if _, err := database.Exec("UPDATE ca_providers SET max_concurrent=1 WHERE id=?", providerID); err != nil {
		t.Fatalf("tighten CA provider: %v", err)
	}
	queue := newCAQueue(models.CAProvider{ID: int(providerID), MaxConcurrent: 2}, func() error { return nil })
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error {
		return errors.New("unexpected dispatch")
	}
	queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_tightened", domains: "example.com"})
	queue.mu.Lock()
	queue.running = 1
	queue.mu.Unlock()
	t.Cleanup(queue.cancel)

	// When
	queue.tick()

	// Then：新值复核拦截，无派发、pending 保留
	queue.mu.Lock()
	pending := len(queue.pending)
	running := queue.running
	queue.mu.Unlock()
	if pending != 1 || running != 1 {
		t.Fatalf("pending=%d running=%d, want 1/1（收紧后的并发上限必须拦截派发）", pending, running)
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read certificate job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("job status=%q, want queued", status)
	}
}

// 闸门全开时 provider 刷新仅发生在真正派发时，且派发用的是 DB 新鲜配置。
func TestCAQueue_tick_dispatches_with_refreshed_provider(t *testing.T) {
	// Given：缓存 MaxConcurrent=1，DB 为 3；闸门全开
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name, provider, directory_url, enabled, max_concurrent) VALUES ('dispatch', 'letsencrypt', 'https://invalid.example/directory', 1, 3)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_dispatch', 'example.com', 'queued', ?)`, providerID)
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := jobResult.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	queue := newCAQueue(models.CAProvider{ID: int(providerID), MaxConcurrent: 1}, func() error { return nil })
	gotProvider := make(chan models.CAProvider, 1)
	queue.executeFn = func(_ context.Context, _ queueItem, provider models.CAProvider) error {
		gotProvider <- provider
		return nil
	}
	queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_dispatch", domains: "example.com"})
	t.Cleanup(queue.cancel)

	// When
	queue.tick()

	// Then：派发用的 provider 来自 DB 刷新（MaxConcurrent=3），而非缓存值 1
	select {
	case provider := <-gotProvider:
		if provider.MaxConcurrent != 3 {
			t.Fatalf("dispatched provider MaxConcurrent=%d, want 3（派发必须用 DB 新鲜配置）", provider.MaxConcurrent)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not start with all gates open")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		queue.mu.Lock()
		settled := len(queue.pending) == 0 && queue.running == 0
		queue.mu.Unlock()
		if settled || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	queue.mu.Lock()
	settled := len(queue.pending) == 0 && queue.running == 0
	queue.mu.Unlock()
	if !settled {
		t.Fatal("dispatch did not settle after completion")
	}
}

// requeueStrandedJobs 迭代健壮性——Scan 失败补
// warn 留痕（曾静默 continue 零信号），循环后补 rows.Err() 检查（曾迭代
// 中途出错时部分任务集被当全量处理）。
func TestCAQueue_requeueStrandedJobsLogsScanFailure(t *testing.T) {
	// Given 类型漂移行：ca_provider_id 存非数值文本（INTEGER 亲和列透传），
	// COALESCE 读出 TEXT → Scan 入 int 必败
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_scan_drift', 'scan-drift.test', 'queued', 'abc')`); err != nil {
		t.Fatalf("seed drift row: %v", err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	oldWriter := log.Writer()
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When
	manager.requeueStrandedJobs(`j.status='queued'`, "周期巡检发现队列外滞留，重新排队", "test-scan")

	// Then Scan 失败有 warn 留痕（含 logPrefix——此前静默 continue 零信号）
	if !strings.Contains(buf.String(), "test-scan") {
		t.Fatalf("Scan 失败应留 warn（含 logPrefix），日志=%q", buf.String())
	}
}

// provider 配置提交后必须发布失效事件——缓存闸门（性能
// 优化）此前先于 loadCAProvider 判定，max_concurrent/min_interval 修改在积压窗口
// 内不生效（缓存=1+running=1 时抬到 3 仍不派发；间隔下调同理）。版本号脏标记
// 让队列在下一 tick 先按新值复核。
func TestCAQueue_tick_appliesProviderConfigUpdateWhileQueued(t *testing.T) {
	type seed struct {
		queue      *caQueue
		jobID      int
		providerID int
	}
	seedQueue := func(t *testing.T, cachedMaxConcurrent, cachedMinInterval, dbMaxConcurrent, dbMinInterval int) seed {
		t.Helper()
		_, database := newClusterTestService(t)
		result, err := database.Exec(`INSERT INTO ca_providers (name, provider, directory_url, enabled, max_concurrent, min_interval_ms) VALUES ('refresh', 'letsencrypt', 'https://invalid.example/directory', 1, ?, ?)`, dbMaxConcurrent, dbMinInterval)
		if err != nil {
			t.Fatalf("seed CA provider: %v", err)
		}
		providerID, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read CA provider ID: %v", err)
		}
		jobResult, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_provider_id) VALUES ('lb_refresh', 'example.com', 'queued', ?)`, providerID)
		if err != nil {
			t.Fatalf("seed certificate job: %v", err)
		}
		jobID, err := jobResult.LastInsertId()
		if err != nil {
			t.Fatalf("read certificate job ID: %v", err)
		}
		queue := newCAQueue(models.CAProvider{ID: int(providerID), MaxConcurrent: cachedMaxConcurrent, MinIntervalMS: cachedMinInterval}, func() error { return nil })
		dispatched := make(chan struct{}, 1)
		release := make(chan struct{})
		queue.executeFn = func(context.Context, queueItem, models.CAProvider) error {
			dispatched <- struct{}{}
			<-release
			return nil
		}
		queue.enqueue(queueItem{jobID: int(jobID), ruleID: "lb_refresh", domains: "example.com"})
		t.Cleanup(func() {
			close(release)
			queue.cancel()
		})
		return seed{queue: queue, jobID: int(jobID), providerID: int(providerID)}
	}

	t.Run("max concurrent raised", func(t *testing.T) {
		// Given：缓存 MaxConcurrent=1 且 running=1（闸门关闭），DB 改为 3
		s := seedQueue(t, 1, 1, 1, 1)
		s.queue.mu.Lock()
		s.queue.running = 1
		s.queue.mu.Unlock()
		three := 3
		service := NewCAProviderService()
		if _, err := service.UpdateCAProvider(s.providerID, models.UpdateCAProviderRequest{MaxConcurrent: &three}); err != nil {
			t.Fatalf("update provider: %v", err)
		}

		// When
		s.queue.tick()

		// Then：按新值复核后派发（running=2, pending 清空）
		s.queue.mu.Lock()
		pending := len(s.queue.pending)
		running := s.queue.running
		s.queue.mu.Unlock()
		if pending != 0 || running != 2 {
			t.Fatalf("pending=%d running=%d, want 0/2（配置提交后必须按新上限复核）", pending, running)
		}
	})

	t.Run("min interval lowered", func(t *testing.T) {
		// Given：缓存间隔 60s 且刚派发过（闸门关闭），DB 下调为 1ms
		s := seedQueue(t, 1, 60000, 1, 60000)
		s.queue.mu.Lock()
		s.queue.lastOrder = time.Now()
		s.queue.mu.Unlock()
		one := 1
		service := NewCAProviderService()
		if _, err := service.UpdateCAProvider(s.providerID, models.UpdateCAProviderRequest{MinIntervalMS: &one}); err != nil {
			t.Fatalf("update provider: %v", err)
		}

		// When：更新与 tick 之间留出 >1ms 墙钟余量（新间隔=1ms；否则 time.Since
		// 可能仍在亚毫秒内，测试会与实现速度耦合）
		time.Sleep(5 * time.Millisecond)
		s.queue.tick()
		s.queue.mu.Lock()
		pending := len(s.queue.pending)
		running := s.queue.running
		s.queue.mu.Unlock()
		if pending != 0 || running != 1 {
			t.Fatalf("pending=%d running=%d, want 0/1（间隔下调后必须按新值放行）", pending, running)
		}
	})
}

// 生命周期取消的重入队 from 集合此前含终态
// issued/failed——并发部署回调的终态落定可被无条件拉回 queued（issued→整轮
// 重签烧配额 / failed→终态复活）。终态必须不被改写；downloaded 保持部署语义；
// 中间态照常重排。
func TestRequeueCanceledJobDoesNotResurrectTerminalStates(t *testing.T) {
	installCAQueueTestFixture(t) // 通用临时库 + 任务日志目录
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,cert_pem,key_pem) VALUES
		('lb_issued','issued.example.com','issued','签发成功','CERT','KEY'),
		('lb_failed','failed.example.com','failed','CA 签发失败: boom',NULL,NULL),
		('lb_downloaded','downloaded.example.com','downloaded','部署退避中','CERT2','KEY2'),
		('lb_mid','mid.example.com','creating_account','开始申请证书',NULL,NULL)`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	ids := map[string]int{}
	rows, err := db.DB.Query(`SELECT rule_id, id FROM cert_jobs`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ruleID string
		var id int
		if err := rows.Scan(&ruleID, &id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		ids[ruleID] = id
	}
	rows.Close()

	for _, ruleID := range []string{"lb_issued", "lb_failed", "lb_downloaded", "lb_mid"} {
		requeueCanceledJob(ids[ruleID])
	}

	read := func(ruleID string) (status, message string, deploymentAfter bool) {
		t.Helper()
		var after any
		if err := db.DB.QueryRow(`SELECT status, COALESCE(message,''), deployment_available_after FROM cert_jobs WHERE id=?`, ids[ruleID]).
			Scan(&status, &message, &after); err != nil {
			t.Fatalf("read %s: %v", ruleID, err)
		}
		return status, message, after != nil
	}

	if status, _, _ := read("lb_issued"); status != "issued" {
		t.Fatalf("issued 被拉回 %q（终态复活 = 整轮重签烧配额）", status)
	}
	if status, _, _ := read("lb_failed"); status != "failed" {
		t.Fatalf("failed 被拉回 %q（终态不复活契约被绕过）", status)
	}
	if status, message, after := read("lb_downloaded"); status != "downloaded" || !after || !strings.Contains(message, "等待恢复部署") {
		t.Fatalf("downloaded 必须保持部署语义: status=%q after=%v message=%q", status, after, message)
	}
	if status, _, _ := read("lb_mid"); status != "queued" {
		t.Fatalf("中间态 creating_account 应重排为 queued，得到 %q", status)
	}
}

// ---- 回归钉 ----

// seedRuleWithCAProvider 落一条启用中的 ACME 规则并固定其 CA 提供商。
func seedRuleWithCAProvider(t *testing.T, ruleID, domain string, providerID int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,ca_provider_id)
		VALUES (?,?,?,'http',8080,1,1,'acme_dns',?)`, ruleID, ruleID, domain, providerID); err != nil {
		t.Fatalf("seed rule %s: %v", ruleID, err)
	}
}

func seedQueuedCertJob(t *testing.T, ruleID, domain string, providerID int) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?,?,'queued',?)`, ruleID, domain, providerID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return id
}

// 显式选择的 CA 提供商「存在但已禁用」时不得静默改派到其它
// 启用提供商（改派会消耗另一 CA 配额并持久化改写 cert_jobs.ca_provider_id），
// 必须以可见失败落定任务；已删除 ID 仍保留回退（任务延续）。
func TestCAQueue_loadCAProvider_disabled_explicit_id_fails_instead_of_silent_switch(t *testing.T) {
	// Given：两个启用提供商，其中一个被禁用（守卫只拦截启用中规则引用，
	// 禁用规则/历史任务仍可能持有该 ID）。
	_, database := newClusterTestService(t)
	rows, err := database.Query(`SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id`)
	if err != nil {
		t.Fatalf("read providers: %v", err)
	}
	var enabledIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan provider: %v", err)
		}
		enabledIDs = append(enabledIDs, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate providers: %v", err)
	}
	rows.Close()
	if len(enabledIDs) < 2 {
		t.Fatalf("seeded providers=%d, want >= 2（回退可用性前置）", len(enabledIDs))
	}
	disabledID := enabledIDs[1]
	if _, err := database.Exec(`UPDATE ca_providers SET enabled=0 WHERE id=?`, disabledID); err != nil {
		t.Fatalf("disable provider: %v", err)
	}
	seedRuleWithCAProvider(t, "lb_disabled_ca", "disabled-ca.example.test", disabledID)
	jobID := seedQueuedCertJob(t, "lb_disabled_ca", "disabled-ca.example.test", disabledID)

	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		active:       true,
		blockedRules: map[string]map[RuleBlockToken]struct{}{},
	}

	// When
	manager.mu.Lock()
	enqueueErr := manager.enqueueLocked(disabledID, int(jobID), "lb_disabled_ca", "disabled-ca.example.test")
	queues := len(manager.queues)
	manager.mu.Unlock()

	// Then：可见失败（errCAProviderUnavailable），且未回退/未创建其它 CA 队列
	if !errors.Is(enqueueErr, errCAProviderUnavailable) {
		t.Fatalf("enqueue err=%v, want errCAProviderUnavailable", enqueueErr)
	}
	if !strings.Contains(enqueueErr.Error(), "已禁用") {
		t.Fatalf("enqueue err=%q, want 点明「已禁用」", enqueueErr.Error())
	}
	if queues != 0 {
		t.Fatalf("queues=%d, want 0（禁用提供商不得回退建队列）", queues)
	}
	var status, message string
	var persistedProvider int
	if err := database.QueryRow("SELECT status, COALESCE(message,''), COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message, &persistedProvider); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || !strings.Contains(message, "已禁用") {
		t.Fatalf("job status=%q message=%q, want failed + 已禁用", status, message)
	}
	if persistedProvider != disabledID {
		t.Fatalf("job provider=%d, want 保留原 ID %d（不得静默改派并持久化）", persistedProvider, disabledID)
	}
}

func TestCAQueue_loadCAProvider_deleted_explicit_id_still_falls_back(t *testing.T) {
	// Given：任务指向已删除的提供商（历史/导入残留），仍有启用提供商可延续
	_, database := newClusterTestService(t)
	var firstEnabled int
	if err := database.QueryRow(`SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1`).Scan(&firstEnabled); err != nil {
		t.Fatalf("read enabled provider: %v", err)
	}
	// 规则显式选择了一个已不存在于 ca_providers 的 ID（历史/导入残留）——
	// 「跟随默认」（0）不适用：0 语义是每次按当前默认解析，不做回退固化。
	seedRuleWithCAProvider(t, "lb_deleted_ca", "deleted-ca.example.test", 4242)
	jobID := seedQueuedCertJob(t, "lb_deleted_ca", "deleted-ca.example.test", 9999)
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		active:       true,
		blockedRules: map[string]map[RuleBlockToken]struct{}{},
		reloader:     func() error { return nil },
	}

	// When
	manager.mu.Lock()
	enqueueErr := manager.enqueueLocked(9999, int(jobID), "lb_deleted_ca", "deleted-ca.example.test")
	queues := len(manager.queues)
	manager.mu.Unlock()

	// Then：回退到首个启用提供商并持久化该 ID（用户裁定方案 A）
	if enqueueErr != nil {
		t.Fatalf("enqueue err=%v, want nil（已删除 ID 保留历史回退）", enqueueErr)
	}
	if queues != 1 {
		t.Fatalf("queues=%d, want 1（按回退提供商建队列）", queues)
	}
	var persistedProvider int
	if err := database.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id=?", jobID).Scan(&persistedProvider); err != nil {
		t.Fatalf("read job provider: %v", err)
	}
	if persistedProvider != firstEnabled {
		t.Fatalf("job provider=%d, want 回退 ID %d", persistedProvider, firstEnabled)
	}
	manager.Stop()
}

// CancelJob 必须与按规则取消同口径覆盖退役队列与僵尸任务
// ——此前只扫 m.queues，退役/僵尸形态仅靠 ctx 已取消「碰巧安全」。
func TestCancelJob_waits_for_retired_and_zombie_executions(t *testing.T) {
	newClusterTestService(t)
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		active:       true,
		zombieJobs:   make(map[int]zombieJob),
		blockedRules: map[string]map[RuleBlockToken]struct{}{},
	}
	// 退役队列形态：MarkRetiredJobRunningForTest 登记 active+runningRules+cancels+done
	done := manager.MarkRetiredJobRunningForTest("lb_retired_job", 42)

	returned := make(chan struct{})
	go func() {
		manager.CancelJob(42)
		close(returned)
	}()
	// Then 1：在途执行未退出前 CancelJob 不得返回
	select {
	case <-returned:
		t.Fatal("CancelJob returned before retired execution finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(done)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("CancelJob did not return after retired execution finished")
	}

	// Given 2：僵尸形态（age-out 摘除退役条目后迁入 zombieJobs，执行仍悬挂）
	zombieDone := make(chan struct{})
	manager.mu.Lock()
	manager.zombieJobs[43] = zombieJob{ruleID: "lb_zombie_job", done: zombieDone}
	manager.mu.Unlock()
	zombieReturned := make(chan struct{})
	go func() {
		manager.CancelJob(43)
		close(zombieReturned)
	}()
	select {
	case <-zombieReturned:
		t.Fatal("CancelJob returned before zombie execution finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(zombieDone)
	select {
	case <-zombieReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("CancelJob did not return after zombie execution finished")
	}
}

// PauseAndDrain 的 drained 判据必须并入既有
// retiredQueues / zombieJobs——否则前一次排空超时退役的滞行执行仍存活时，
// 第二次调用会谎报 drained=true，配置导入据此放行整树替换（同 jobID 写入
// 与导入快照竞争）。
func TestCAQueueManager_PauseAndDrain_secondCallSeesPriorRetiredStragglers(t *testing.T) {
	// Given：一个「旧队列」仍持有在途执行（模拟上一次 PauseAndDrain 超时退役）
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	go queue.loop()
	t.Cleanup(queue.stop)
	queue.mu.Lock()
	queue.active[42] = struct{}{}
	queue.mu.Unlock()
	manager := &CAQueueManager{
		queues:        map[int]*caQueue{},
		retiredQueues: []retiredCAQueue{{queue: queue, retiredAt: time.Now()}},
		active:        true,
	}

	// When：第二次调用（本次没有新队列可停）
	drained := manager.PauseAndDrain()

	// Then：旧退役队列仍有在途 active → 必须
	if drained {
		t.Fatal("PauseAndDrain drained=true, want false（既有退役队列仍有在途执行）")
	}

	// 回归形状：在途执行清空后同一调用报告已排空
	queue.mu.Lock()
	delete(queue.active, 42)
	queue.mu.Unlock()
	manager.mu.Lock()
	manager.zombieJobs = nil
	manager.mu.Unlock()
	if drained := manager.PauseAndDrain(); !drained {
		t.Fatal("PauseAndDrain drained=false, want true（退役队列已无在途执行）")
	}
}

// 畸形形态：zombieJobs 非空（退役队列已但 jobID 仍受保护）
// 同样视为未排空。
func TestCAQueueManager_PauseAndDrain_zombieJobsBlockDrain(t *testing.T) {
	manager := &CAQueueManager{
		queues:     map[int]*caQueue{},
		zombieJobs: map[int]zombieJob{42: {}},
		active:     true,
	}
	if drained := manager.PauseAndDrain(); drained {
		t.Fatal("PauseAndDrain drained=true, want false（zombieJobs 非空代表仍有未知在途签发）")
	}
}

// 屏障期入队拒绝必须携带 ErrCertRuleBusy 哨兵（瞬时冲突语义）——
// CreateOrRequeueCertJobVerified 对「队列激活 + 任务不在途 + 规则被
// BlockJobsForRule 租约屏障」的归因此前是裸错「was not queued」，
// handler 侧折成 500；哨兵使 handler 映射 409。
func TestCreateOrRequeueCertJobVerified_blockedRuleReturnsBusySentinel(t *testing.T) {
	_, database := newClusterTestService(t)
	manager := &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
		active:       true,
	}
	t.Cleanup(manager.Stop)
	token := manager.BlockJobsForRule("lb_busy_rule")
	defer manager.UnblockJobsForRule("lb_busy_rule", token)

	_, _, err := CreateOrRequeueCertJobVerified("lb_busy_rule", "busy.example.test", 0, manager)
	if !errors.Is(err, ErrCertRuleBusy) {
		t.Fatalf("err=%v, want ErrCertRuleBusy（屏障期哨兵）", err)
	}
	// 行未落库（屏障期不得创建任务行）
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_busy_rule'").Scan(&count); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if count != 0 {
		t.Fatalf("cert_jobs count=%d, want 0（屏障期不得落行）", count)
	}
}

// Given 配置导入窗口（粘性 hold）内常驻 cert-issuance 重启触发
// CAQueueManager.Start。
// When 调用 Start。
// Then 队列保持 inactive（不恢复部署重试），意图延迟到 EndConfigImportHold
// 兑现——旧形态 Start 直接置 active=true 并恢复部署重试，绕开导入排空屏障。
func TestCAQueueManager_StartDeferredDuringImportHold(t *testing.T) {
	installCAQueueTestFixture(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(ResetCAQueueManagerForTest)
	manager := GetCAQueueManager()
	manager.PauseAndDrain()
	if manager.IsActive() {
		t.Fatal("前置态错误：队列应为 inactive")
	}

	BeginConfigImportHold()
	manager.Start()
	if manager.IsActive() {
		t.Fatal("导入屏障窗口内 Start 打开了 CA 队列（排空隔离被绕过）")
	}
	EndConfigImportHold()
	if !manager.IsActive() {
		t.Fatal("导入屏障解除后未兑现延迟的启动意图（证书签发永久停摆）")
	}
}

// 材料在身的部署生命周期任务（downloaded/cleanup_*）不得被 failJob 打成终态：
// 终态会把新证书从全部自动恢复通道摘除（部署补扫只收 downloaded/cleanup_*、
// 续期扫描看新证不在窗口、对账只重建 issued/downloaded）→ 材料搁浅且规则无
// TLS。与执行超时/生命周期取消同口径：保持可部署态并立即重排部署。
func TestFailJob_materialBearingDeploymentJobStaysDeployable(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES
		(81,'lb_fail_material','fail-material.example.test','downloaded','CERT','KEY'),
		(82,'lb_fail_material','requeue.example.test','queued','OLD-CERT','OLD-KEY')`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}

	failJob(81, "部署回调 CAS 冲突")
	failJob(82, "重签请求失败")

	var status, message string
	var window sql.NullString
	if err := database.QueryRow("SELECT status, COALESCE(message,''), deployment_available_after FROM cert_jobs WHERE id=81").Scan(&status, &message, &window); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（材料在身不得终态化）", status)
	}
	if !window.Valid {
		t.Fatal("部署窗口未推进（30s 补扫无法接管）")
	}
	if !strings.Contains(message, "等待重新部署") {
		t.Fatalf("message=%q, want 说明材料已落库/等待重新部署", message)
	}
	// 对照：queued（显式重签请求）材料是上轮残留，失败必须是真实失败。
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=82").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("queued job status=%q, want failed（重签失败不得被降级为部署重试）", status)
	}
}

// Given 规则删除补偿的重试次数（含 0/负数这类「未尝试」形态）。
// When 计算下一次补偿延迟。
// Then 从 1 分钟指数翻倍并在 10 分钟封顶——不封顶会让第 6 次起延迟到 32/64
// 分钟，补偿队列在规则已删除后的等待期远超人工介入窗口；attempt<=1 恒为
// 1 分钟。
func TestRuleDeletionCompensationBackoff_exponentialWithTenMinuteCap(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: -3, want: time.Minute},
		{attempt: 0, want: time.Minute},
		{attempt: 1, want: time.Minute},
		{attempt: 2, want: 2 * time.Minute},
		{attempt: 3, want: 4 * time.Minute},
		{attempt: 4, want: 8 * time.Minute},
		{attempt: 5, want: 10 * time.Minute},
		{attempt: 6, want: 10 * time.Minute},
		{attempt: 99, want: 10 * time.Minute},
	} {
		if got := ruleDeletionCompensationBackoff(tc.attempt); got != tc.want {
			t.Fatalf("attempt=%d backoff=%s, want %s", tc.attempt, got, tc.want)
		}
	}
}

// Given 续签失败的原始消息与尝试上限；另一形态是消息里已含上限标记。
// When 追加终态说明。
// Then 首次追加「已达到最大重试次数 N」并保留原消息；已含标记时逐字返回
// （幂等——重复追加会把同一句话叠成两段，且第二次的 N 会覆盖首次数值）。
func TestMaxRenewalAttemptsMessage_appendsLimitOnceAndIsIdempotent(t *testing.T) {
	const base = "ACME 签发失败：连接超时"
	want := base + "（已达到最大重试次数 5，停止自动重试，可手动重试）"
	got := maxRenewalAttemptsMessage(base, 5)
	if got != want {
		t.Fatalf("message=%q, want %q", got, want)
	}
	if again := maxRenewalAttemptsMessage(got, 5); again != got {
		t.Fatalf("已含上限标记时二次调用=%q, want 原样 %q", again, got)
	}
	if again := maxRenewalAttemptsMessage(got, 9); again != got {
		t.Fatalf("已含上限标记时改用另一上限=%q, want 原样 %q（不得覆盖首次数值）", again, got)
	}
	if empty := maxRenewalAttemptsMessage("", 3); !strings.Contains(empty, "已达到最大重试次数 3") {
		t.Fatalf("空消息也必须带上限说明: %q", empty)
	}
}
