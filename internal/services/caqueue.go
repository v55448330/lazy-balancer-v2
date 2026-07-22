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
	mu       sync.Mutex
	queues   map[int]*caQueue
	reloader func() error
	active   bool
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

// CancelJob aborts an in-flight issuance for the given job across all
// provider queues; deletion handlers call this before removing the row so a
// worker cannot keep issuing and deploying after the job is gone.
func (m *CAQueueManager) CancelJob(jobID int) {
	m.mu.Lock()
	queues := make([]*caQueue, 0, len(m.queues))
	for _, q := range m.queues {
		queues = append(queues, q)
	}
	m.mu.Unlock()
	for _, q := range queues {
		q.mu.Lock()
		cancel, ok := q.cancels[jobID]
		q.mu.Unlock()
		if ok {
			cancel()
		}
	}
}

// Enqueue adds or re-enqueues a cert job.
func (m *CAQueueManager) Enqueue(providerID int, jobID int, ruleID, domains string) error {
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

	// The active check and queue get/create must share one lock: a concurrent
	// Stop would otherwise leave a fresh live queue running on a demoted node.
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return errors.New("从节点不运行证书签发队列")
	}
	q, ok := m.queues[provider.ID]
	if !ok {
		q = newCAQueue(provider, m.reloader)
		m.queues[provider.ID] = q
		go q.loop()
	}
	m.mu.Unlock()

	q.enqueue(queueItem{
		jobID:   jobID,
		ruleID:  ruleID,
		domains: domains,
	})
	return nil
}

func (m *CAQueueManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = true
}

func (m *CAQueueManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return
	}
	m.active = false
	for _, queue := range m.queues {
		queue.cancel()
		close(queue.stopCh)
	}
	m.queues = make(map[int]*caQueue)
}

type queueItem struct {
	jobID   int
	ruleID  string
	domains string
}

type caQueue struct {
	provider  models.CAProvider
	pending   []queueItem
	running   int
	active    map[int]struct{} // jobIDs currently pending or running
	cancels   map[int]context.CancelFunc
	lastOrder time.Time
	reloader  func() error
	mu        sync.Mutex
	stopCh    chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
}

func newCAQueue(provider models.CAProvider, reloader func() error) *caQueue {
	if provider.MaxConcurrent <= 0 {
		provider.MaxConcurrent = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &caQueue{
		provider: provider,
		reloader: reloader,
		active:   make(map[int]struct{}),
		cancels:  make(map[int]context.CancelFunc),
		stopCh:   make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}
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
	if q.running >= q.provider.MaxConcurrent || len(q.pending) == 0 {
		q.mu.Unlock()
		return
	}
	interval := time.Duration(q.provider.MinIntervalMS) * time.Millisecond
	if time.Since(q.lastOrder) < interval {
		q.mu.Unlock()
		return
	}

	item := q.pending[0]
	q.pending = q.pending[1:]
	q.running++
	q.lastOrder = time.Now()
	q.mu.Unlock()

	go q.execute(item)
}

func (q *caQueue) execute(item queueItem) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CA queue panic for job %d: %v", item.jobID, r)
			failJob(item.jobID, fmt.Sprintf("调度器异常: %v", r))
		}
		q.mu.Lock()
		q.running--
		delete(q.active, item.jobID)
		delete(q.cancels, item.jobID)
		q.mu.Unlock()
	}()

	// If the rule/job was deleted while the item was queued, skip it silently.
	if !jobExists(item.jobID) {
		log.Printf("CA queue: job %d no longer exists, skipping", item.jobID)
		return
	}

	issuer := NewCertIssuer(q.reloader)
	ctx, cancel := context.WithTimeout(q.ctx, 15*time.Minute)
	defer cancel()
	q.mu.Lock()
	q.cancels[item.jobID] = cancel
	q.mu.Unlock()

	if err := issuer.Issue(ctx, item.jobID, item.ruleID, item.domains, q.provider); err != nil {
		log.Printf("CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
		if !isTerminalJobStatus(item.jobID) {
			var raErr *CAProviderRateLimitError
			if errors.As(err, &raErr) {
				markJobWaitingCA(item.jobID, raErr.RetryAfter)
			} else {
				failJob(item.jobID, fmt.Sprintf("CA 签发失败: %v", err))
			}
		}
	}
}

func isTerminalJobStatus(jobID int) bool {
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		return false
	}
	return status == "issued" || status == "failed"
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

	err := db.DB.QueryRow(`
		SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled
		FROM ca_providers WHERE id=? AND enabled=1
	`, id).Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled)
	if err != nil {
		// If the requested/default provider is disabled or missing, fall back to the first enabled provider.
		var fallbackID int
		if fallbackErr := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&fallbackID); fallbackErr == nil {
			id = fallbackID
			err = db.DB.QueryRow(`
				SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled
				FROM ca_providers WHERE id=? AND enabled=1
			`, id).Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled)
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
		WriteCertJobLog(jobID, "ERROR", "failed", fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts))
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, renewal_attempts=?, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?", fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts), attempts, jobID); err != nil {
			log.Printf("CA queue: failed to mark job %d as failed at max attempts: %v", jobID, err)
		} else {
			RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("max_attempts")), "")
		}
		return
	}

	WriteCertJobLog(jobID, "WARN", "waiting_ca", fmt.Sprintf("CA 频率限制，第 %d 次，将在 %s 后重试", attempts, display.Format("2006-01-02 15:04:05 -07:00")))
	if _, err := db.DB.Exec(
		"UPDATE cert_jobs SET status='waiting_ca', message='等待 CA 频率限制冷却', ca_available_after=?, last_error_code='429', renewal_attempts=?, updated_at=datetime('now') WHERE id=?",
		available.UTC().Format("2006-01-02 15:04:05"), attempts, jobID,
	); err != nil {
		log.Printf("CA queue: failed to mark job %d as waiting_ca: %v", jobID, err)
	} else {
		RecordAuditLog("system", "CA限流", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), fmt.Sprintf("第 %d 次限流", attempts), fmt.Sprintf("恢复时间：%s", display.Format("2006-01-02 15:04:05"))), "")
	}
}
func failJob(jobID int, message string) {
	if !jobExists(jobID) {
		log.Printf("CA queue: cannot fail missing job %d: %s", jobID, message)
		return
	}
	WriteCertJobLog(jobID, "ERROR", "failed", message)
	if _, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, renewal_attempts=COALESCE(renewal_attempts,0)+1, updated_at=datetime('now') WHERE id=?", message, jobID); err != nil {
		log.Printf("CA queue: failed to mark job %d as failed: %v", jobID, err)
	} else {
		RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("failed")), "")
	}
}
