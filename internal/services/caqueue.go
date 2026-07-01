package services

import (
	"context"
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

// GetCAQueueManager returns the singleton queue manager.
func GetCAQueueManager(reloader func() error) *CAQueueManager {
	caQueueManagerOnce.Do(func() {
		caQueueManager = &CAQueueManager{
			queues:   make(map[int]*caQueue),
			reloader: reloader,
		}
	})
	return caQueueManager
}

// SetCAReloader updates the reloader used by existing and new issuers.
func (m *CAQueueManager) SetCAReloader(reloader func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloader = reloader
	for _, q := range m.queues {
		q.mu.Lock()
		q.reloader = reloader
		q.mu.Unlock()
	}
}

// Enqueue adds or re-enqueues a cert job.
func (m *CAQueueManager) Enqueue(providerID int, jobID int, ruleID, domains string) error {
	provider, err := loadCAProvider(providerID)
	if err != nil {
		failJob(jobID, fmt.Sprintf("CA Provider 不可用: %v", err))
		return err
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := issuer.Issue(ctx, item.jobID, item.ruleID, item.domains, q.provider); err != nil {
		log.Printf("CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
		if !isTerminalJobStatus(item.jobID) {
			failJob(item.jobID, fmt.Sprintf("CA 签发失败: %v", err))
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
		}
	}

	err := db.DB.QueryRow(`
		SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled
		FROM ca_providers WHERE id=? AND enabled=1
	`, id).Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled)
	if err != nil {
		// If the requested/default provider is disabled or missing, fall back to the first enabled provider.
		if id != 0 {
			var fallbackID int
			if fallbackErr := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&fallbackID); fallbackErr == nil {
				id = fallbackID
				err = db.DB.QueryRow(`
					SELECT id, name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled
					FROM ca_providers WHERE id=? AND enabled=1
				`, id).Scan(&p.ID, &p.Name, &p.Provider, &p.DirectoryURL, &p.Credentials, &p.MaxConcurrent, &p.MinIntervalMS, &p.Enabled)
			}
		}
	}
	if err != nil {
		return p, fmt.Errorf("load CA provider %d: %w", id, err)
	}
	return p, nil
}

// failJob marks a job as failed and writes an error log.
func failJob(jobID int, message string) {
	if !jobExists(jobID) {
		log.Printf("CA queue: cannot fail missing job %d: %s", jobID, message)
		return
	}
	if _, err := db.DB.Exec("INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'error', ?)", jobID, message); err != nil {
		log.Printf("CA queue: failed to insert error log for job %d: %v", jobID, err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET status='failed', message=?, updated_at=datetime('now') WHERE id=?", message, jobID); err != nil {
		log.Printf("CA queue: failed to mark job %d as failed: %v", jobID, err)
	}
}

// RequeueNonTerminalJobs scans cert_jobs and re-enqueues jobs that are not in a terminal state.
// Jobs whose associated rule or CA provider no longer exists or is disabled are marked as failed.
func RequeueNonTerminalJobs(qm *CAQueueManager) {
	rows, err := db.DB.Query(`
		SELECT id, rule_id, domain, ca_provider_id FROM cert_jobs
		WHERE status IN ('pending','processing','queued')
	`)
	if err != nil {
		log.Printf("Failed to requeue non-terminal jobs: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var jobID, caProviderID int
		var ruleID, domain string
		if err := rows.Scan(&jobID, &ruleID, &domain, &caProviderID); err != nil {
			log.Printf("Failed to scan cert job for requeue: %v", err)
			continue
		}

		// Verify the associated rule still exists and is enabled.
		var ruleEnabled bool
		err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&ruleEnabled)
		if err != nil || !ruleEnabled {
			failJob(jobID, "关联规则不存在或已禁用")
			continue
		}

		// Verify the CA provider exists and is enabled (providerID 0 resolves to the default).
		provider, err := loadCAProvider(caProviderID)
		if err != nil {
			failJob(jobID, fmt.Sprintf("CA Provider 不存在或已禁用: %v", err))
			continue
		}

		// Mark queued and enqueue; deduplication inside CAQueueManager prevents duplicates.
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='queued', message='等待排队签发', updated_at=datetime('now') WHERE id=?", jobID); err != nil {
			log.Printf("Failed to update cert job %d status to queued: %v", jobID, err)
			continue
		}
		if err := qm.Enqueue(provider.ID, jobID, ruleID, domain); err != nil {
			log.Printf("Failed to requeue job %d: %v", jobID, err)
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating cert jobs for requeue: %v", err)
	}
}
