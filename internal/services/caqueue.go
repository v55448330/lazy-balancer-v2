package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CAQueueManager schedules ACME issuance jobs per CA provider.
type CAQueueManager struct {
	mu                  sync.Mutex
	queues              map[int]*caQueue
	reloader            func() error
	active              bool
	beforeEnqueue       func()
	beforeActiveEnqueue func()
}

var (
	caQueueManager     *CAQueueManager
	caQueueManagerOnce sync.Once
)

// InitCAQueueManager initializes the singleton queue manager with the given
// Caddy reloader. It must be called once during application startup before
// GetCAQueueManager is used.
func InitCAQueueManager(reloader func() error) {
	caQueueManagerOnce.Do(func() {
		caQueueManager = &CAQueueManager{
			queues:   make(map[int]*caQueue),
			reloader: reloader,
			active:   true,
		}
	})
}

// GetCAQueueManager returns the singleton queue manager. InitCAQueueManager
// must have been called first.
func GetCAQueueManager() *CAQueueManager {
	return caQueueManager
}

// ResetCAQueueManagerForTest 停止并清空单例，仅供测试隔离使用
func ResetCAQueueManagerForTest() {
	if caQueueManager != nil {
		caQueueManager.Stop()
	}
	caQueueManager = nil
	caQueueManagerOnce = sync.Once{}
}

// CancelJob aborts an in-flight issuance for the given job across all
// provider queues; deletion handlers call this before removing the row so a
// worker cannot keep issuing and deploying after the job is gone.
func (m *CAQueueManager) CancelJob(jobID int) {
	cancelCertificateDeploymentRetry(jobID)
	m.mu.Lock()
	var done []<-chan struct{}
	var cancels []context.CancelFunc
	for _, q := range m.queues {
		q.mu.Lock()
		pending := q.pending[:0]
		for _, item := range q.pending {
			if item.jobID == jobID {
				delete(q.active, jobID)
				continue
			}
			pending = append(pending, item)
		}
		q.pending = pending
		cancel, ok := q.cancels[jobID]
		if ok {
			cancels = append(cancels, cancel)
		}
		if executionDone := q.executionDone[jobID]; executionDone != nil {
			done = append(done, executionDone)
		}
		q.mu.Unlock()
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, executionDone := range done {
		<-executionDone
	}
}

func (m *CAQueueManager) CancelJobsForRule(ruleID string) {
	cancelCertificateDeploymentRetriesForRule(ruleID)
	m.mu.Lock()
	var done []<-chan struct{}
	var cancels []context.CancelFunc
	for _, q := range m.queues {
		q.mu.Lock()
		pending := q.pending[:0]
		for _, item := range q.pending {
			if item.ruleID == ruleID {
				delete(q.active, item.jobID)
				continue
			}
			pending = append(pending, item)
		}
		q.pending = pending
		for jobID, runningRuleID := range q.runningRules {
			if runningRuleID == ruleID {
				if cancel := q.cancels[jobID]; cancel != nil {
					cancels = append(cancels, cancel)
				}
				if executionDone := q.executionDone[jobID]; executionDone != nil {
					done = append(done, executionDone)
				}
			}
		}
		q.mu.Unlock()
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, executionDone := range done {
		<-executionDone
	}
}

// PauseAndDrain prevents new work, cancels every queue, and waits for all
// workers to exit before returning.
func (m *CAQueueManager) PauseAndDrain() {
	m.mu.Lock()
	m.active = false
	queues := m.stopQueuesLocked()
	m.mu.Unlock()
	pauseCertificateDeploymentRetries()

	for _, q := range queues {
		q.wait()
	}
}

func (m *CAQueueManager) stopQueuesLocked() []*caQueue {
	queues := make([]*caQueue, 0, len(m.queues))
	for _, q := range m.queues {
		q.mu.Lock()
		for _, item := range q.pending {
			delete(q.active, item.jobID)
		}
		q.pending = nil
		q.mu.Unlock()
		q.stop()
		queues = append(queues, q)
	}
	m.queues = make(map[int]*caQueue)
	return queues
}

func (m *CAQueueManager) Resume() {
	m.mu.Lock()
	m.active = true
	m.mu.Unlock()
	resumeCertificateDeploymentRetries()
}

func (m *CAQueueManager) IsPaused() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.active
}

// IsJobActive reports whether the job is currently queued or running.
func (m *CAQueueManager) IsJobActive(jobID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, queue := range m.queues {
		queue.mu.Lock()
		_, active := queue.active[jobID]
		queue.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

// Enqueue adds or re-enqueues a cert job.
func (m *CAQueueManager) Enqueue(providerID int, jobID int, ruleID, domains string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return errors.New("从节点不运行证书签发队列")
	}
	return m.enqueueLocked(providerID, jobID, ruleID, domains)
}

func (m *CAQueueManager) EnqueueIfActive(providerID int, jobID int, ruleID, domains string, transition func() (bool, error)) (bool, error) {
	if m.beforeActiveEnqueue != nil {
		m.beforeActiveEnqueue()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return false, nil
	}
	changed, err := transition()
	if err != nil || !changed {
		return changed, err
	}
	return true, m.enqueueLocked(providerID, jobID, ruleID, domains)
}

func (m *CAQueueManager) enqueueLocked(providerID int, jobID int, ruleID, domains string) error {
	provider, err := loadCAProvider(providerID)
	if err != nil {
		failJob(jobID, fmt.Sprintf("CA Provider 不可用: %v", err))
		return err
	}
	log.Printf("CA queue Enqueue job=%d providerID=%d resolved=%s (%s)", jobID, providerID, provider.Name, provider.Provider)

	// Persist the resolved provider ID so renewals use the same provider unless
	// the admin intentionally changes the default and triggers a new job.
	if providerID != provider.ID {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET ca_provider_id=? WHERE id=?", provider.ID, jobID); err != nil {
			log.Printf("CA queue: failed to update resolved provider for job %d: %v", jobID, err)
		}
	}

	q, ok := m.queues[provider.ID]
	if !ok {
		q = newCAQueue(provider, m.reloader)
		m.queues[provider.ID] = q
		go q.loop()
	} else {
		// 队列缓存的 provider 快照可能早于用户修改的凭证/配置，每次入队刷新
		q.mu.Lock()
		q.provider = provider
		q.mu.Unlock()
	}
	if m.beforeEnqueue != nil {
		m.beforeEnqueue()
	}
	q.enqueue(queueItem{
		jobID:   jobID,
		ruleID:  ruleID,
		domains: domains,
	})
	return nil
}

func (m *CAQueueManager) Start() {
	m.Resume()
}

func (m *CAQueueManager) Stop() {
	m.PauseAndDrain()
}

type queueItem struct {
	jobID   int
	ruleID  string
	domains string
}

type caQueue struct {
	provider      models.CAProvider
	pending       []queueItem
	running       int
	active        map[int]struct{} // jobIDs currently pending or running
	cancels       map[int]context.CancelFunc
	executionDone map[int]chan struct{}
	runningRules  map[int]string
	lastOrder     time.Time
	reloader      func() error
	mu            sync.Mutex
	stopCh        chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	loopDone      chan struct{}
	executions    sync.WaitGroup
	stopping      bool
	executeFn     func(context.Context, queueItem, models.CAProvider) error
}

type queueExecution struct {
	item     queueItem
	provider models.CAProvider
	ctx      context.Context
	cancel   context.CancelFunc
}

func newCAQueue(provider models.CAProvider, reloader func() error) *caQueue {
	if provider.MaxConcurrent <= 0 {
		provider.MaxConcurrent = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &caQueue{
		provider:      provider,
		reloader:      reloader,
		active:        make(map[int]struct{}),
		cancels:       make(map[int]context.CancelFunc),
		executionDone: make(map[int]chan struct{}),
		runningRules:  make(map[int]string),
		stopCh:        make(chan struct{}),
		loopDone:      make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
	}
	q.executeFn = func(ctx context.Context, item queueItem, provider models.CAProvider) error {
		return NewCertIssuer(q.reloader).Issue(ctx, item.jobID, item.ruleID, item.domains, provider)
	}
	return q
}

func (q *caQueue) enqueue(item queueItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.active[item.jobID]; ok {
		return
	}
	q.pending = append(q.pending, item)
	q.active[item.jobID] = struct{}{}
}

func (q *caQueue) loop() {
	defer close(q.loopDone)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			q.tick()
		}
	}
}

func (q *caQueue) tick() {
	q.mu.Lock()
	if q.stopping {
		q.mu.Unlock()
		return
	}
	if len(q.pending) == 0 {
		q.mu.Unlock()
		return
	}

	providerID := q.provider.ID
	provider, err := loadCAProvider(providerID)
	if err != nil || provider.ID != providerID {
		pending := q.pending
		q.pending = nil
		for _, item := range pending {
			delete(q.active, item.jobID)
		}
		q.mu.Unlock()
		message := fmt.Sprintf("CA Provider 不可用：配置已禁用或删除（ID %d）", providerID)
		for _, item := range pending {
			failJob(item.jobID, message)
		}
		return
	}
	if provider.MaxConcurrent <= 0 {
		provider.MaxConcurrent = 1
	}
	q.provider = provider
	if q.running >= provider.MaxConcurrent {
		q.mu.Unlock()
		return
	}
	interval := time.Duration(provider.MinIntervalMS) * time.Millisecond
	if time.Since(q.lastOrder) < interval {
		q.mu.Unlock()
		return
	}

	execution, ok := q.prepareExecutionLocked(q.ctx)
	if !ok {
		q.mu.Unlock()
		return
	}
	q.lastOrder = time.Now()
	q.mu.Unlock()

	go q.execute(execution)
}

func (q *caQueue) prepareExecutionLocked(parent context.Context) (queueExecution, bool) {
	if len(q.pending) == 0 {
		return queueExecution{}, false
	}
	item := q.pending[0]
	q.pending = q.pending[1:]
	q.running++
	q.executions.Add(1)
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	q.cancels[item.jobID] = cancel
	done := make(chan struct{})
	q.executionDone[item.jobID] = done
	q.runningRules[item.jobID] = item.ruleID
	return queueExecution{item: item, provider: q.provider, ctx: ctx, cancel: cancel}, true
}

func (q *caQueue) execute(execution queueExecution) {
	item := execution.item
	defer q.executions.Done()
	defer execution.cancel()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CA queue panic for job %d: %v", item.jobID, r)
			failJob(item.jobID, fmt.Sprintf("调度器异常: %v", r))
		}
		q.mu.Lock()
		q.running--
		delete(q.active, item.jobID)
		delete(q.cancels, item.jobID)
		close(q.executionDone[item.jobID])
		delete(q.executionDone, item.jobID)
		delete(q.runningRules, item.jobID)
		q.mu.Unlock()
	}()

	if err := execution.ctx.Err(); err != nil {
		return
	}

	// If the rule/job was deleted while the item was queued, skip it silently.
	if !jobExists(item.jobID) {
		log.Printf("CA queue: job %d no longer exists, skipping", item.jobID)
		return
	}

	if err := q.executeFn(execution.ctx, item, execution.provider); err != nil {
		log.Printf("CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
		if execution.ctx.Err() != nil {
			requeueCanceledJob(item.jobID)
			return
		}
		handleQueueExecutionError(item.jobID, err)
	}
}

func (q *caQueue) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopping {
		return
	}
	q.stopping = true
	q.cancel()
	close(q.stopCh)
}

func (q *caQueue) wait() {
	<-q.loopDone
	q.executions.Wait()
}

func requeueCanceledJob(jobID int) {
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET status='queued', message='节点生命周期切换，等待恢复签发', updated_at=datetime('now') WHERE id=? AND status!='disabled'`, jobID); err != nil {
		log.Printf("CA queue: failed to requeue canceled job %d: %v", jobID, err)
	}
}

func handleQueueExecutionError(jobID int, err error) {
	var deploymentErr *certificateDeploymentError
	if errors.As(err, &deploymentErr) {
		return
	}
	var rateLimitErr *CAProviderRateLimitError
	if errors.As(err, &rateLimitErr) {
		markJobWaitingCA(jobID, rateLimitErr.RetryAfter)
		return
	}
	failJob(jobID, fmt.Sprintf("CA 签发失败: %v", err))
}

// jobExists returns true if a cert_jobs row with the given id still exists.
func jobExists(jobID int) bool {
	var exists bool
	err := db.DB.QueryRow("SELECT 1 FROM cert_jobs WHERE id=?", jobID).Scan(&exists)
	return err == nil
}

func loadCAProvider(id int) (models.CAProvider, error) {
	var p models.CAProvider
	if id == 0 {
		// Use system default.
		var err error
		id, err = GetDefaultCAProvider()
		if err != nil {
			log.Printf("CA queue: failed to load default CA provider: %v", err)
			id = 0
		}
	}

	err := scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
	if err != nil {
		// If the requested/default provider is disabled or missing, fall back to the first enabled provider.
		var fallbackID int
		if fallbackErr := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&fallbackID); fallbackErr == nil {
			id = fallbackID
			err = scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
		}
	}
	if err != nil {
		return p, fmt.Errorf("load CA provider %d: %w", id, err)
	}
	return p, nil
}

func markJobWaitingCA(jobID int, retryAfter time.Duration) {
	maxAttempts := GetCertRenewalAttempts()

	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&attempts); err != nil {
		log.Printf("CA queue: failed to read attempts for job %d: %v", jobID, err)
	}
	attempts++

	cooling := computeBackoff(attempts, retryAfter)
	available := time.Now().Add(cooling).UTC()
	loc := time.FixedZone("CST", 8*3600)
	display := available.In(loc)

	if attempts >= maxAttempts {
		result, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, renewal_attempts=?, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=? AND status NOT IN ('issued','failed','disabled')", fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts), attempts, jobID)
		if err != nil {
			log.Printf("CA queue: failed to mark job %d as failed at max attempts: %v", jobID, err)
			return
		}
		updated, err := result.RowsAffected()
		if err != nil {
			log.Printf("CA queue: failed to read max-attempt result for job %d: %v", jobID, err)
			return
		}
		if updated == 1 {
			WriteCertJobLog(jobID, "ERROR", "failed", fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts))
			RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("max_attempts")), "")
		}
		return
	}

	result, err := db.DB.Exec(
		"UPDATE cert_jobs SET status='waiting_ca', message='等待 CA 频率限制冷却', ca_available_after=?, last_error_code='429', renewal_attempts=?, updated_at=datetime('now') WHERE id=? AND status NOT IN ('issued','failed','disabled')",
		available.UTC().Format("2006-01-02 15:04:05"), attempts, jobID,
	)
	if err != nil {
		log.Printf("CA queue: failed to mark job %d as waiting_ca: %v", jobID, err)
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		log.Printf("CA queue: failed to read waiting_ca result for job %d: %v", jobID, err)
		return
	}
	if updated == 1 {
		WriteCertJobLog(jobID, "WARN", "waiting_ca", fmt.Sprintf("CA 频率限制，第 %d 次，将在 %s 后重试", attempts, display.Format("2006-01-02 15:04:05 -07:00")))
		RecordAuditLog("system", "CA限流", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), fmt.Sprintf("第 %d 次限流", attempts), fmt.Sprintf("恢复时间：%s", display.Format("2006-01-02 15:04:05"))), "")
	}
}
func failJob(jobID int, message string) {
	result, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, renewal_attempts=COALESCE(renewal_attempts,0)+1, updated_at=datetime('now') WHERE id=? AND status NOT IN ('issued','failed','disabled')", message, jobID)
	if err != nil {
		log.Printf("CA queue: failed to mark job %d as failed: %v", jobID, err)
		return
	}
	updated, err := result.RowsAffected()
	if err != nil {
		log.Printf("CA queue: failed to read fail result for job %d: %v", jobID, err)
		return
	}
	if updated == 1 {
		WriteCertJobLog(jobID, "ERROR", "failed", message)
		RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("failed")), "")
	}
}
