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
		}
	})
}

// GetCAQueueManager returns the singleton queue manager. InitCAQueueManager
// must have been called first.
func GetCAQueueManager() *CAQueueManager {
	return caQueueManager
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

	m.mu.Lock()
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
	lastOrder time.Time
	reloader  func() error
	mu        sync.Mutex
	stopCh    chan struct{}
}

func newCAQueue(provider models.CAProvider, reloader func() error) *caQueue {
	if provider.MaxConcurrent <= 0 {
		provider.MaxConcurrent = 1
	}
	return &caQueue{
		provider: provider,
		reloader: reloader,
		active:   make(map[int]struct{}),
		stopCh:   make(chan struct{}),
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
		q.mu.Unlock()
	}()

	// If the rule/job was deleted while the item was queued, skip it silently.
	if !jobExists(item.jobID) {
		log.Printf("CA queue: job %d no longer exists, skipping", item.jobID)
		return
	}

	issuer := NewCertIssuer(q.reloader)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

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
		if _, err := db.DB.Exec("INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'error', ?)", jobID, fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts)); err != nil {
			log.Printf("CA queue: failed to insert max-attempts log for job %d: %v", jobID, err)
		}
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, renewal_attempts=?, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?", fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts), attempts, jobID); err != nil {
			log.Printf("CA queue: failed to mark job %d as failed at max attempts: %v", jobID, err)
		}
		return
	}

	if _, err := db.DB.Exec(
		"INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'warning', ?)",
		jobID, fmt.Sprintf("CA 频率限制，第 %d 次，将在 %s 后重试", attempts, display.Format("2006-01-02 15:04:05 -07:00")),
	); err != nil {
		log.Printf("CA queue: failed to insert waiting log for job %d: %v", jobID, err)
	}
	if _, err := db.DB.Exec(
		"UPDATE cert_jobs SET status='waiting_ca', message='等待 CA 频率限制冷却', ca_available_after=?, last_error_code='429', renewal_attempts=?, updated_at=datetime('now') WHERE id=?",
		available.UTC().Format("2006-01-02 15:04:05"), attempts, jobID,
	); err != nil {
		log.Printf("CA queue: failed to mark job %d as waiting_ca: %v", jobID, err)
	}
}
func failJob(jobID int, message string) {
	if !jobExists(jobID) {
		log.Printf("CA queue: cannot fail missing job %d: %s", jobID, message)
		return
	}
	if _, err := db.DB.Exec("INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'error', ?)", jobID, message); err != nil {
		log.Printf("CA queue: failed to insert error log for job %d: %v", jobID, err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, renewal_attempts=COALESCE(renewal_attempts,0)+1, updated_at=datetime('now') WHERE id=?", message, jobID); err != nil {
		log.Printf("CA queue: failed to mark job %d as failed: %v", jobID, err)
	}
}


