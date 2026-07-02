package services

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
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
	// Run renewal check shortly after startup, then every 6 hours.
	time.AfterFunc(30*time.Second, s.renewExpiringCertificates)
	renewalTicker := time.NewTicker(6 * time.Hour)
	manualTicker := time.NewTicker(10 * time.Minute)
	defer renewalTicker.Stop()
	defer manualTicker.Stop()
	for {
		select {
		case <-renewalTicker.C:
			s.renewExpiringCertificates()
		case <-manualTicker.C:
			s.checkManualCertExpiration()
		case <-s.stopCh:
			return
		}
	}
}

func (s *CertificateService) Stop() { close(s.stopCh) }

// CreateOrRequeueCertJob creates a queued cert job for the rule and enqueues it.
func CreateOrRequeueCertJob(ruleID, domains string, caProviderID int, qm *CAQueueManager) error {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return fmt.Errorf("invalid ACME domains: %s", domains)
	}
	joined := strings.Join(list, ",")

	var jobID int
	err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id=? AND domain=?", ruleID, joined).Scan(&jobID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("lookup cert job: %w", err)
		}
		res, err := db.DB.Exec(
			"INSERT INTO cert_jobs (rule_id, domain, status, message, ca_provider_id) VALUES (?, ?, 'queued', '等待排队签发', ?)",
			ruleID, joined, caProviderID,
		)
		if err != nil {
			return fmt.Errorf("create cert job: %w", err)
		}
		id64, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("get last insert id: %w", err)
		}
		jobID = int(id64)
	} else {
		if _, err := db.DB.Exec(
			"UPDATE cert_jobs SET status='queued', message='重新排队签发', updated_at=datetime('now'), ca_provider_id=? WHERE id=?",
			caProviderID, jobID,
		); err != nil {
			return fmt.Errorf("update cert job: %w", err)
		}
	}
	return qm.Enqueue(caProviderID, jobID, ruleID, joined)
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
				}
			}
			continue
		}

		res, err := db.DB.Exec(
			"UPDATE cert_jobs SET status='queued', message='等待排队续期', updated_at=datetime('now') WHERE id=? AND status IN ('issued','failed','waiting_ca') AND (ca_available_after IS NULL OR ca_available_after <= datetime('now'))",
			j.ID,
		)
		if err != nil {
			log.Printf("Renewal: failed to update job %d status: %v", j.ID, err)
			continue
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			continue
		}
		qm := GetCAQueueManager(s.caddyReloader)
		if err := qm.Enqueue(0, j.ID, j.RuleID, j.Domain); err != nil {
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
