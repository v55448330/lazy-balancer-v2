package services

import (
	"context"
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

func (s *CertificateService) CreateJobsForRule(ruleID string, domains string) error {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return nil
	}
	primary := list[0]
	joinedDomains := strings.Join(list, ",")

	var existing int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id = ? AND domain = ?", ruleID, primary).Scan(&existing)
	if err != nil {
		log.Printf("Create cert job failed: %v", err)
		return nil
	}
	if existing > 0 {
		return nil
	}

	_, err = db.DB.Exec(`
		INSERT INTO cert_jobs (rule_id, domain, status, message)
		VALUES (?, ?, 'pending', '等待签发')
	`, ruleID, joinedDomains)
	if err != nil {
		log.Printf("Create cert job failed: %v", err)
	}
	return nil
}

func (s *CertificateService) renewExpiringCertificates() {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobs := s.CheckExpiration()
	if len(jobs) == 0 {
		return
	}

	for _, j := range jobs {
		// Avoid concurrent renewals: skip if the job is already in a non-terminal state.
		var currentStatus string
		err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", j.ID).Scan(&currentStatus)
		if err != nil {
			log.Printf("Renewal: failed to read job %d status: %v", j.ID, err)
			continue
		}
		if isCertJobActive(currentStatus) {
			continue
		}

		log.Printf("Renewal: re-issuing certificate for rule %s domain %s (expires %s)", j.RuleID, j.Domain, j.ExpiresAt.Time.Format("2006-01-02"))
		go func(job models.CertJob) {
			issuer := NewCertIssuer(s.caddyReloader)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			provider, err := loadCAProvider(job.CAProviderID)
			if err != nil {
				log.Printf("Renewal: failed to load CA provider for job %d: %v", job.ID, err)
				failJob(job.ID, fmt.Sprintf("CA Provider 不可用: %v", err))
				return
			}
			if err := issuer.Issue(ctx, job.ID, job.RuleID, job.Domain, provider); err != nil {
				log.Printf("Renewal: failed to re-issue certificate for %s: %v", job.Domain, err)
			}
		}(j)
	}
}

func isCertJobActive(status string) bool {
	return status != "issued" && status != "failed"
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
	err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1").Scan(&days)
	if err != nil {
		days = 30
	}

	rows, err := db.DB.Query(`
		SELECT id, rule_id, domain, status, expires_at, ca_provider_id
		FROM cert_jobs
		WHERE status = 'issued'
		  AND expires_at IS NOT NULL
		  AND expires_at <= datetime('now', '+' || ? || ' days')
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
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt, &j.CAProviderID); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	return jobs
}
