package services

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type CertificateService struct {
	mu                  sync.Mutex
	ctx                 context.Context
	cancel              context.CancelFunc
	done                chan struct{}
	recoverJobs         func(context.Context)
	deploymentRetry     func(int, issuedCertificate, time.Duration)
	timerMu             sync.Mutex
	deploymentTimers    map[int]*deploymentTimer
	deploymentCallbacks map[int]map[*deploymentTimer]struct{}
	timersPaused        bool
	stopping            bool
	retryDeployment     func(context.Context, int) error
}

type deploymentTimer struct {
	timer    *time.Timer
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	ruleID   string
	canceled bool
}

var (
	certificateServiceMu sync.Mutex
	certificateService   *CertificateService
)

type certJobSnapshot struct {
	id                       int
	ruleID                   string
	domain                   string
	status                   string
	message                  sql.NullString
	expiresAt                sql.NullTime
	certPEM                  sql.NullString
	keyPEM                   sql.NullString
	caProviderID             int
	renewalAttempts          int
	caAvailableAfter         sql.NullTime
	lastErrorCode            sql.NullString
	deploymentAttempts       int
	deploymentAvailableAfter sql.NullTime
	createdAt                sql.NullTime
	updatedAt                sql.NullTime
}

// CertJobsSnapshot is an opaque cert_jobs restore point used to compensate a
// failed UpdateRule ACME enqueue after an UPSERT may have replaced old state.
type CertJobsSnapshot struct {
	ruleID string
	jobs   []certJobSnapshot
}

// DisableCertJobsExceptDomain retires non-terminal jobs that no longer match
// the rule's current ACME domain.
func DisableCertJobsExceptDomain(ruleID, keepDomain string) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin certificate job retirement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT id FROM cert_jobs WHERE rule_id=? AND domain<>? AND status<>'disabled'`, ruleID, keepDomain)
	if err != nil {
		return fmt.Errorf("query retired certificate jobs: %w", err)
	}
	var jobIDs []int
	for rows.Next() {
		var jobID int
		if err := rows.Scan(&jobID); err != nil {
			rows.Close()
			return fmt.Errorf("scan retired certificate job: %w", err)
		}
		jobIDs = append(jobIDs, jobID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate retired certificate jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close retired certificate jobs: %w", err)
	}

	result, err := tx.Exec(`UPDATE cert_jobs SET status='disabled', message='规则域名已变更，任务已退役', updated_at=datetime('now')
		WHERE rule_id=? AND domain<>? AND status<>'disabled'`, ruleID, keepDomain)
	if err != nil {
		return fmt.Errorf("disable retired certificate jobs: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read retired certificate job count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit certificate job retirement: %w", err)
	}

	if manager := GetCAQueueManager(); manager != nil {
		for _, jobID := range jobIDs {
			manager.CancelJob(jobID)
		}
	} else {
		for _, jobID := range jobIDs {
			cancelCertificateDeploymentRetry(jobID)
		}
	}
	if updated > 0 {
		WriteCertJobLogByRule(ruleID, "WARN", "cancelled", "规则域名已变更，旧证书签发任务已退役")
		RecordAuditLog("system", "禁用", "证书签发任务", FormatAuditDetail(AuditRulePart(ruleID), fmt.Sprintf("退役任务：%d 个", updated)), "")
	}
	return nil
}

// SnapshotCertJobsForRule captures all cert_jobs rows for UpdateRule ACME
// enqueue compensation.
func SnapshotCertJobsForRule(ruleID string) (CertJobsSnapshot, error) {
	snapshot := CertJobsSnapshot{ruleID: ruleID}
	rows, err := db.DB.Query(`SELECT id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,
		renewal_attempts,ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at
		FROM cert_jobs WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return CertJobsSnapshot{}, fmt.Errorf("query certificate job snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var job certJobSnapshot
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.message, &job.expiresAt,
			&job.certPEM, &job.keyPEM, &job.caProviderID, &job.renewalAttempts, &job.caAvailableAfter,
			&job.lastErrorCode, &job.deploymentAttempts, &job.deploymentAvailableAfter, &job.createdAt, &job.updatedAt); err != nil {
			return CertJobsSnapshot{}, fmt.Errorf("scan certificate job snapshot: %w", err)
		}
		snapshot.jobs = append(snapshot.jobs, job)
	}
	if err := rows.Err(); err != nil {
		return CertJobsSnapshot{}, fmt.Errorf("iterate certificate job snapshot: %w", err)
	}
	return snapshot, nil
}

// RestoreCertJobsForRule restores UPSERT-overwritten rows and removes jobs
// created after SnapshotCertJobsForRule captured the rule state.
func RestoreCertJobsForRule(snapshot CertJobsSnapshot) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin certificate job restore: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id=?", snapshot.ruleID); err != nil {
		return fmt.Errorf("clear certificate jobs for restore: %w", err)
	}
	for _, job := range snapshot.jobs {
		if _, err := tx.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,
			renewal_attempts,ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, job.id, job.ruleID, job.domain, job.status, job.message,
			job.expiresAt, job.certPEM, job.keyPEM, job.caProviderID, job.renewalAttempts, job.caAvailableAfter,
			job.lastErrorCode, job.deploymentAttempts, job.deploymentAvailableAfter, job.createdAt, job.updatedAt); err != nil {
			return fmt.Errorf("restore certificate job %d: %w", job.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit certificate job restore: %w", err)
	}
	return nil
}

func NewCertificateService() *CertificateService {
	ctx, cancel := context.WithCancel(context.Background())
	service := &CertificateService{
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		deploymentRetry:     scheduleCertificateDeploymentRetry,
		deploymentTimers:    make(map[int]*deploymentTimer),
		deploymentCallbacks: make(map[int]map[*deploymentTimer]struct{}),
	}
	service.retryDeployment = func(ctx context.Context, jobID int) error {
		manager := GetCAQueueManager()
		if manager == nil {
			return fmt.Errorf("Caddy reloader is not initialized")
		}
		manager.mu.Lock()
		reloader := manager.reloader
		manager.mu.Unlock()
		return retryCertificateDeployment(ctx, jobID, reloader)
	}
	service.recoverJobs = service.recoverCertJobs
	certificateServiceMu.Lock()
	certificateService = service
	certificateServiceMu.Unlock()
	return service
}

func (s *CertificateService) scheduleDeploymentRetry(jobID int, ruleID string, delay time.Duration) {
	for {
		s.timerMu.Lock()
		if s.stopping || s.timersPaused {
			s.timerMu.Unlock()
			return
		}
		if previous := s.deploymentTimers[jobID]; previous != nil {
			previous.canceled = true
			previous.cancel()
			stopped := previous.timer.Stop()
			delete(s.deploymentTimers, jobID)
			s.timerMu.Unlock()
			if stopped {
				close(previous.done)
			} else {
				<-previous.done
			}
			continue
		}
		entry := &deploymentTimer{done: make(chan struct{}), ruleID: ruleID}
		entry.ctx, entry.cancel = context.WithCancel(s.ctx)
		entry.timer = time.AfterFunc(delay, func() {
			s.timerMu.Lock()
			if s.deploymentTimers[jobID] == entry {
				delete(s.deploymentTimers, jobID)
			}
			callbacks := s.deploymentCallbacks[jobID]
			if callbacks == nil {
				callbacks = make(map[*deploymentTimer]struct{})
				s.deploymentCallbacks[jobID] = callbacks
			}
			callbacks[entry] = struct{}{}
			stopping := entry.canceled || s.stopping || s.timersPaused
			s.timerMu.Unlock()
			defer func() {
				s.timerMu.Lock()
				delete(s.deploymentCallbacks[jobID], entry)
				if len(s.deploymentCallbacks[jobID]) == 0 {
					delete(s.deploymentCallbacks, jobID)
				}
				s.timerMu.Unlock()
				close(entry.done)
			}()
			if stopping {
				return
			}
			if err := s.retryDeployment(entry.ctx, jobID); err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.Canceled) {
				log.Printf("certificate deployment retry failed for job %d: %v", jobID, err)
			}
		})
		s.deploymentTimers[jobID] = entry
		s.timerMu.Unlock()
		return
	}
}

func (s *CertificateService) cancelDeploymentRetry(jobID int) {
	s.timerMu.Lock()
	entry := s.deploymentTimers[jobID]
	var pendingDone <-chan struct{}
	if entry != nil {
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			delete(s.deploymentTimers, jobID)
			close(entry.done)
		} else {
			pendingDone = entry.done
		}
	}
	runningDone := make([]<-chan struct{}, 0, len(s.deploymentCallbacks[jobID]))
	for callback := range s.deploymentCallbacks[jobID] {
		callback.canceled = true
		callback.cancel()
		runningDone = append(runningDone, callback.done)
	}
	s.timerMu.Unlock()
	if pendingDone != nil {
		<-pendingDone
	}
	for _, done := range runningDone {
		<-done
	}
}

func (s *CertificateService) cancelDeploymentRetriesForRule(ruleID string) {
	s.timerMu.Lock()
	waitFor := make(map[*deploymentTimer]struct{})
	for jobID, entry := range s.deploymentTimers {
		if entry.ruleID != ruleID {
			continue
		}
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			delete(s.deploymentTimers, jobID)
			close(entry.done)
		} else {
			waitFor[entry] = struct{}{}
		}
	}
	for _, callbacks := range s.deploymentCallbacks {
		for callback := range callbacks {
			if callback.ruleID == ruleID {
				callback.canceled = true
				callback.cancel()
				waitFor[callback] = struct{}{}
			}
		}
	}
	s.timerMu.Unlock()
	for entry := range waitFor {
		<-entry.done
	}
}

func (s *CertificateService) pauseDeploymentRetries() {
	s.timerMu.Lock()
	s.timersPaused = true
	var waitFor []<-chan struct{}
	for jobID, entry := range s.deploymentTimers {
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			close(entry.done)
		} else {
			waitFor = append(waitFor, entry.done)
		}
		delete(s.deploymentTimers, jobID)
	}
	for _, callbacks := range s.deploymentCallbacks {
		for callback := range callbacks {
			callback.canceled = true
			callback.cancel()
			waitFor = append(waitFor, callback.done)
		}
	}
	s.timerMu.Unlock()
	for _, done := range waitFor {
		<-done
	}
}

func (s *CertificateService) resumeDeploymentRetries() {
	s.timerMu.Lock()
	if !s.stopping {
		s.timersPaused = false
	}
	s.timerMu.Unlock()
}

func (s *CertificateService) Start() {
	defer close(s.done)
	// Recover any jobs left in non-terminal states from a previous run.
	s.recoverJobs(s.ctx)

	// Run renewal check shortly after startup, then every 6 hours.
	initialRenewal := time.NewTimer(30 * time.Second)
	renewalTicker := time.NewTicker(6 * time.Hour)
	manualTicker := time.NewTicker(10 * time.Minute)
	waitingCATicker := time.NewTicker(30 * time.Second)
	defer initialRenewal.Stop()
	defer renewalTicker.Stop()
	defer manualTicker.Stop()
	defer waitingCATicker.Stop()
	for {
		select {
		case <-initialRenewal.C:
			s.renewExpiringCertificates()
		case <-renewalTicker.C:
			s.renewExpiringCertificates()
		case <-manualTicker.C:
			s.checkManualCertExpiration()
		case <-waitingCATicker.C:
			s.requeueWaitingCAJobs()
		case <-s.ctx.Done():
			return
		}
	}
}

// requeueWaitingCAJobs re-enqueues cert jobs parked in 'waiting_ca' once
// their CA cooling period has elapsed. This covers first-time issuance jobs
// (expires_at IS NULL) that renewExpiringCertificates cannot see.
func (s *CertificateService) requeueWaitingCAJobs() {
	qm := GetCAQueueManager()
	if qm == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := db.DB.Query(`
		SELECT id, rule_id, domain, ca_provider_id
		FROM cert_jobs
		WHERE status = 'waiting_ca'
		  AND ca_available_after IS NOT NULL
		  AND datetime(ca_available_after) <= datetime('now')
	`)
	if err != nil {
		log.Printf("waiting_ca scan: query failed: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var jobID, caProviderID int
		var ruleID, domain string
		if err := rows.Scan(&jobID, &ruleID, &domain, &caProviderID); err != nil {
			continue
		}
		changed, err := qm.EnqueueIfActive(caProviderID, jobID, ruleID, domain, func() (bool, error) {
			res, err := db.DB.Exec(
				"UPDATE cert_jobs SET status='queued', message='冷却结束，重新排队签发', updated_at=datetime('now') WHERE id=? AND status='waiting_ca' AND (ca_available_after IS NULL OR datetime(ca_available_after) <= datetime('now'))",
				jobID,
			)
			if err != nil {
				return false, err
			}
			rows, err := res.RowsAffected()
			return rows != 0, err
		})
		if err != nil {
			log.Printf("waiting_ca scan: failed to requeue job %d: %v", jobID, err)
			continue
		}
		if !changed {
			continue
		}
		RecordAuditLog("system", "重新排队", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(ruleID), AuditSourcePart("ca_cooldown")), "")
	}
}

// recoverCertJobs re-enqueues cert jobs that were not in a terminal state when
// the process last exited. Jobs whose rule or CA provider no longer exist are
// marked as failed.
func (s *CertificateService) recoverCertJobs(ctx context.Context) {
	if err := requeueNonTerminalCertJobs(ctx, s.deploymentRetry); err != nil {
		log.Printf("Failed to recover non-terminal cert jobs: %v", err)
	}
}

func RequeueNonTerminalCertJobs() error {
	return requeueNonTerminalCertJobs(context.Background(), scheduleCertificateDeploymentRetry)
}

func requeueNonTerminalCertJobs(ctx context.Context, deploymentRetry func(int, issuedCertificate, time.Duration)) error {
	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.domain, j.status, j.ca_provider_id, COALESCE(j.deployment_attempts,0), j.deployment_available_after,
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' AND r.domain=j.domain THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status NOT IN ('issued','failed','disabled')
		  AND (j.status != 'waiting_ca' OR j.ca_available_after IS NULL OR datetime(j.ca_available_after) <= datetime('now'))
	`)
	if err != nil {
		return fmt.Errorf("query non-terminal certificate jobs: %w", err)
	}
	type recoveryJob struct {
		id, providerID, deploymentAttempts int
		ruleID, domain, status             string
		deploymentAvailableAfter           sql.NullTime
		applicable                         bool
	}
	var jobs []recoveryJob
	for rows.Next() {
		var job recoveryJob
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.providerID, &job.deploymentAttempts, &job.deploymentAvailableAfter, &job.applicable); err != nil {
			rows.Close()
			return fmt.Errorf("scan non-terminal certificate job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate non-terminal certificate jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close non-terminal certificate jobs: %w", err)
	}

	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !job.applicable {
			if _, err := db.DB.ExecContext(ctx, "UPDATE cert_jobs SET status='disabled', message='关联规则已不再使用当前 ACME 证书任务', updated_at=datetime('now') WHERE id=? AND status NOT IN ('issued','failed','disabled')", job.id); err != nil {
				return fmt.Errorf("disable ineligible recovered certificate job %d: %w", job.id, err)
			}
			continue
		}
		if job.status == "downloaded" {
			delay := time.Duration(0)
			if job.deploymentAvailableAfter.Valid {
				delay = time.Until(job.deploymentAvailableAfter.Time)
				if delay < 0 {
					delay = 0
				}
			}
			deploymentRetry(job.id, issuedCertificate{ruleID: job.ruleID, providerID: job.providerID, deploymentAttempt: job.deploymentAttempts}, delay)
			continue
		}

		if _, err := db.DB.ExecContext(ctx,
			"UPDATE cert_jobs SET status='queued', message='等待排队签发', updated_at=datetime('now') WHERE id=?",
			job.id,
		); err != nil {
			return fmt.Errorf("queue recovered certificate job %d: %w", job.id, err)
		}
		RecordAuditLog("system", "恢复排队", "证书签发任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("startup_recovery")), "")
		qm := GetCAQueueManager()
		if qm == nil {
			return fmt.Errorf("CA queue manager not initialized")
		}
		if err := qm.Enqueue(job.providerID, job.id, job.ruleID, job.domain); err != nil {
			return fmt.Errorf("enqueue recovered certificate job %d: %w", job.id, err)
		}
	}
	return nil
}

func (s *CertificateService) Stop() {
	s.timerMu.Lock()
	s.stopping = true
	s.timerMu.Unlock()
	s.pauseDeploymentRetries()
	s.cancel()
	<-s.done
}

// CreateOrRequeueCertJob creates a queued cert job for the rule and enqueues it.
// Uses an atomic INSERT ... ON CONFLICT to avoid races between concurrent callers.
func CreateOrRequeueCertJob(ruleID, domains string, caProviderID int, qm *CAQueueManager) (int, error) {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return 0, fmt.Errorf("invalid ACME domains: %s", domains)
	}
	joined := strings.Join(list, ",")

	// Defensive: if no explicit CA provider was supplied, use the rule's own
	// setting rather than falling back to the global default.
	if caProviderID == 0 {
		var ruleCA int
		if err := db.DB.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&ruleCA); err == nil && ruleCA != 0 {
			caProviderID = ruleCA
		}
	}
	log.Printf("CreateOrRequeueCertJob rule=%s domain=%s ca_provider_id=%d", ruleID, joined, caProviderID)

	var jobID int
	err := db.DB.QueryRow(`
		INSERT INTO cert_jobs (rule_id, domain, status, message, ca_provider_id)
		VALUES (?, ?, 'queued', '等待排队签发', ?)
		ON CONFLICT(rule_id, domain) DO UPDATE SET
			status = CASE
				WHEN cert_jobs.status = 'creating_account' AND cert_jobs.updated_at > datetime('now','-2 minutes') THEN cert_jobs.status
				ELSE 'queued'
			END,
			message = CASE
				WHEN cert_jobs.status = 'creating_account' AND cert_jobs.updated_at > datetime('now','-2 minutes') THEN cert_jobs.message
				ELSE '重新排队签发'
			END,
			ca_provider_id = excluded.ca_provider_id,
			updated_at = datetime('now')
		RETURNING id
	`, ruleID, joined, caProviderID).Scan(&jobID)
	if err != nil {
		return 0, fmt.Errorf("upsert cert job: %w", err)
	}

	return jobID, qm.Enqueue(caProviderID, jobID, ruleID, joined)
}

// HasCertJob reports whether any certificate job row exists for the given
// rule and domain, regardless of status. It is used to avoid re-creating
// jobs when one already exists (in any state); the existing ON CONFLICT
// and queue/renewal logic handle the rest.
func HasCertJob(ruleID, domains string) bool {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return false
	}
	joined := strings.Join(list, ",")

	var exists bool
	err := db.DB.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM cert_jobs
			WHERE rule_id = ? AND domain = ?
		)
	`, ruleID, joined).Scan(&exists)
	if err != nil {
		log.Printf("HasCertJob query failed for rule %s: %v", ruleID, err)
		return false
	}
	return exists
}

func (s *CertificateService) renewExpiringCertificates() {
	qm := GetCAQueueManager()

	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}

	// CheckExpiration locks s.mu internally; the loop below only touches the
	// DB and the queue, so holding s.mu here would deadlock the renewal.
	maxAttempts := GetCertRenewalAttempts()
	jobs := s.CheckExpiration()
	if len(jobs) == 0 {
		return
	}

	for _, j := range jobs {
		if j.RenewalAttempts >= maxAttempts {
			if j.Status == "waiting_ca" {
				if _, err := db.DB.Exec(
					"UPDATE cert_jobs SET status='failed', message='已达到最大重试次数，请检查 CA 配置后手动重签', updated_at=datetime('now') WHERE id=?",
					j.ID,
				); err != nil {
					log.Printf("Renewal: failed to convert waiting_ca job %d to failed: %v", j.ID, err)
				} else {
					RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(j.ID), AuditRulePart(j.RuleID), AuditResultPart("max_attempts")), "")
				}
			}
			continue
		}

		if qm == nil {
			log.Printf("Renewal: CA queue manager not initialized")
			return
		}
		changed, err := qm.EnqueueIfActive(j.CAProviderID, j.ID, j.RuleID, j.Domain, func() (bool, error) {
			res, err := db.DB.Exec(
				"UPDATE cert_jobs SET status='queued', message='等待排队续期', updated_at=datetime('now') WHERE id=? AND status IN ('issued','failed','waiting_ca') AND (ca_available_after IS NULL OR datetime(ca_available_after) <= datetime('now'))",
				j.ID,
			)
			if err != nil {
				return false, err
			}
			rows, err := res.RowsAffected()
			return rows != 0, err
		})
		if err != nil {
			log.Printf("Renewal: failed to update job %d status: %v", j.ID, err)
			continue
		}
		if !changed {
			continue
		}
		RecordAuditLog("system", "续签排队", "证书签发任务", FormatAuditDetail(AuditJobPart(j.ID), AuditRulePart(j.RuleID), AuditSourcePart("renewal")), "")
	}
}

func (s *CertificateService) checkManualCertExpiration() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-read all manual certificates into memory, then close cursor before parsing
	rows, err := db.DB.Query(`
		SELECT caddy_id, name, domain, tls_cert 
		FROM lb_rules 
		WHERE enable_tls = 1 AND COALESCE(tls_source,'manual') = 'manual' AND tls_cert != ''
	`)
	if err != nil {
		log.Printf("Failed to query TLS certificates for expiration check: %v", err)
		return
	}
	type certInfo struct {
		caddyID string
		name    string
		domain  string
		certPEM string
	}
	var certs []certInfo
	for rows.Next() {
		var c certInfo
		if err := rows.Scan(&c.caddyID, &c.name, &c.domain, &c.certPEM); err != nil {
			continue
		}
		certs = append(certs, c)
	}
	rows.Close()

	now := time.Now()
	var expiredCount, expiringSoonCount int

	warnDays := 30
	_ = db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&warnDays)
	for _, c := range certs {
		block, _ := pem.Decode([]byte(c.certPEM))
		if block == nil {
			log.Printf("Warning: Invalid certificate PEM for rule %s (%s)", c.caddyID, c.name)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Warning: Failed to parse certificate for rule %s (%s): %v", c.caddyID, c.name, err)
			continue
		}

		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

		if now.After(cert.NotAfter) {
			log.Printf("⚠️ CRITICAL: TLS certificate expired for rule '%s' (domain: %s, caddy_id: %s). Expired on %s",
				c.name, c.domain, c.caddyID, cert.NotAfter.Format("2006-01-02"))
			expiredCount++
		} else if daysUntilExpiry <= warnDays {
			log.Printf("⚠️ WARNING: TLS certificate expiring soon for rule '%s' (domain: %s, caddy_id: %s). Expires in %d days (%s)",
				c.name, c.domain, c.caddyID, daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
			expiringSoonCount++
		}
	}

	if expiredCount > 0 || expiringSoonCount > 0 {
		log.Printf("TLS Certificate Check: %d expired, %d expiring within %d days", expiredCount, expiringSoonCount, warnDays)
	}
}

func (s *CertificateService) CheckExpiration() []models.CertJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&days)
	if err != nil {
		days = 30
	}
	if days <= 0 {
		days = 30
	}

	rows, err := db.DB.Query(`
		SELECT j.id, j.rule_id, j.domain, j.status, j.expires_at, j.ca_provider_id, COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,'')
		FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.expires_at IS NOT NULL
		  AND j.expires_at <= datetime('now', '+' || ? || ' days')
		  AND j.status IN ('issued', 'failed', 'waiting_ca')
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' AND r.domain=j.domain
		ORDER BY j.expires_at ASC
	`, days)
	if err != nil {
		log.Printf("Failed to query expiring certificates: %v", err)
		return nil
	}
	defer rows.Close()

	var jobs []models.CertJob
	for rows.Next() {
		var j models.CertJob
		if err := rows.Scan(
			&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt, &j.CAProviderID, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode,
		); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	return jobs
}
