package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type CertificateService struct {
	adminURL      string
	client        *http.Client
	mu            sync.Mutex
	stopCh        chan struct{}
	caddyReloader func() error
}

func NewCertificateService(adminURL string, reloader func() error) *CertificateService {
	return &CertificateService{
		adminURL:      adminURL,
		client:        &http.Client{Timeout: 10 * time.Second},
		stopCh:        make(chan struct{}),
		caddyReloader: reloader,
	}
}

func (s *CertificateService) Start() {
	// Recover any jobs left in non-terminal states from a previous run.
	s.recoverCertJobs()

	// Run renewal check shortly after startup, then every 6 hours.
	time.AfterFunc(30*time.Second, s.renewExpiringCertificates)
	renewalTicker := time.NewTicker(6 * time.Hour)
	manualTicker := time.NewTicker(10 * time.Minute)
	waitingCATicker := time.NewTicker(30 * time.Second)
	defer renewalTicker.Stop()
	defer manualTicker.Stop()
	defer waitingCATicker.Stop()
	for {
		select {
		case <-renewalTicker.C:
			s.renewExpiringCertificates()
		case <-manualTicker.C:
			s.checkManualCertExpiration()
		case <-waitingCATicker.C:
			s.requeueWaitingCAJobs()
		case <-s.stopCh:
			return
		}
	}
}

// requeueWaitingCAJobs re-enqueues cert jobs parked in 'waiting_ca' once
// their CA cooling period has elapsed. This covers first-time issuance jobs
// (expires_at IS NULL) that renewExpiringCertificates cannot see.
func (s *CertificateService) requeueWaitingCAJobs() {
	s.mu.Lock()
	defer s.mu.Unlock()

	qm := GetCAQueueManager()
	if qm == nil {
		return
	}

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
		res, err := db.DB.Exec(
			"UPDATE cert_jobs SET status='queued', message='冷却结束，重新排队签发', updated_at=datetime('now') WHERE id=? AND status='waiting_ca' AND (ca_available_after IS NULL OR datetime(ca_available_after) <= datetime('now'))",
			jobID,
		)
		if err != nil {
			log.Printf("waiting_ca scan: failed to requeue job %d: %v", jobID, err)
			continue
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			continue
		}
		RecordAuditLog("system", "重新排队", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(ruleID), AuditSourcePart("ca_cooldown")), "")
		if err := qm.Enqueue(caProviderID, jobID, ruleID, domain); err != nil {
			log.Printf("waiting_ca scan: failed to enqueue job %d: %v", jobID, err)
		}
	}
}

// recoverCertJobs re-enqueues cert jobs that were not in a terminal state when
// the process last exited. Jobs whose rule or CA provider no longer exist are
// marked as failed.
func (s *CertificateService) recoverCertJobs() {
	rows, err := db.DB.Query(`
		SELECT id, rule_id, domain, ca_provider_id FROM cert_jobs
		WHERE status NOT IN ('issued','failed')
		  AND (status != 'waiting_ca' OR ca_available_after IS NULL OR datetime(ca_available_after) <= datetime('now'))
	`)
	if err != nil {
		log.Printf("Failed to recover non-terminal cert jobs: %v", err)
		return
	}
	defer rows.Close()

	qm := GetCAQueueManager()
	if qm == nil {
		log.Printf("Recovery: CA queue manager not initialized")
		return
	}

	for rows.Next() {
		var jobID, caProviderID int
		var ruleID, domain string
		if err := rows.Scan(&jobID, &ruleID, &domain, &caProviderID); err != nil {
			log.Printf("Failed to scan cert job for recovery: %v", err)
			continue
		}

		var ruleExists bool
		if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1)", ruleID).Scan(&ruleExists); err != nil {
			log.Printf("Failed to check rule existence for job %d: %v", jobID, err)
			continue
		}
		if !ruleExists {
			failJob(jobID, "关联规则不存在或已禁用")
			continue
		}

		if _, err := db.DB.Exec(
			"UPDATE cert_jobs SET status='queued', message='等待排队签发', updated_at=datetime('now') WHERE id=?",
			jobID,
		); err != nil {
			log.Printf("Failed to update cert job %d status to queued: %v", jobID, err)
			continue
		}
		RecordAuditLog("system", "恢复排队", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(ruleID), AuditSourcePart("startup_recovery")), "")
		if err := qm.Enqueue(caProviderID, jobID, ruleID, domain); err != nil {
			log.Printf("Failed to enqueue recovered job %d: %v", jobID, err)
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating cert jobs for recovery: %v", err)
	}
}

func (s *CertificateService) Stop() { close(s.stopCh) }

// CreateOrRequeueCertJob creates a queued cert job for the rule and enqueues it.
// Uses an atomic INSERT ... ON CONFLICT to avoid races between concurrent callers.
func CreateOrRequeueCertJob(ruleID, domains string, caProviderID int, qm *CAQueueManager) error {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return fmt.Errorf("invalid ACME domains: %s", domains)
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
		return fmt.Errorf("upsert cert job: %w", err)
	}

	return qm.Enqueue(caProviderID, jobID, ruleID, joined)
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
	s.mu.Lock()
	defer s.mu.Unlock()

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

		res, err := db.DB.Exec(
			"UPDATE cert_jobs SET status='queued', message='等待排队续期', updated_at=datetime('now') WHERE id=? AND status IN ('issued','failed','waiting_ca') AND (ca_available_after IS NULL OR datetime(ca_available_after) <= datetime('now'))",
			j.ID,
		)
		if err != nil {
			log.Printf("Renewal: failed to update job %d status: %v", j.ID, err)
			continue
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			continue
		}
		RecordAuditLog("system", "续签排队", "证书签发任务", FormatAuditDetail(AuditJobPart(j.ID), AuditRulePart(j.RuleID), AuditSourcePart("renewal")), "")
		qm := GetCAQueueManager()
		if qm == nil {
			log.Printf("Renewal: CA queue manager not initialized")
			continue
		}
		if err := qm.Enqueue(j.CAProviderID, j.ID, j.RuleID, j.Domain); err != nil {
			log.Printf("Renewal: failed to enqueue job %d: %v", j.ID, err)
		}
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
		} else if daysUntilExpiry <= 30 {
			log.Printf("⚠️ WARNING: TLS certificate expiring soon for rule '%s' (domain: %s, caddy_id: %s). Expires in %d days (%s)",
				c.name, c.domain, c.caddyID, daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
			expiringSoonCount++
		}
	}

	if expiredCount > 0 || expiringSoonCount > 0 {
		log.Printf("TLS Certificate Check: %d expired, %d expiring within 30 days", expiredCount, expiringSoonCount)
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
		SELECT id, rule_id, domain, status, expires_at, ca_provider_id, COALESCE(renewal_attempts,0) as renewal_attempts, ca_available_after, last_error_code
		FROM cert_jobs
		WHERE expires_at IS NOT NULL
		  AND expires_at <= datetime('now', '+' || ? || ' days')
		  AND status IN ('issued', 'failed', 'waiting_ca')
		ORDER BY expires_at ASC
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
