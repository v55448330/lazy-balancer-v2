package services

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type CertificateService struct {
	adminURL string
	client   *http.Client
	mu       sync.Mutex
	stopCh   chan struct{}
}

func NewCertificateService(adminURL string) *CertificateService {
	return &CertificateService{
		adminURL: adminURL,
		client:   &http.Client{Timeout: 10 * time.Second},
		stopCh:   make(chan struct{}),
	}
}

func (s *CertificateService) Start() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.poll()
			s.checkManualCertExpiration()
		case <-s.stopCh:
			return
		}
	}
}

func (s *CertificateService) Stop() { close(s.stopCh) }

func (s *CertificateService) CreateJobsForRule(ruleID string, domains string) error {
	for _, d := range strings.Split(domains, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}

		var existing int
		err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id = ? AND domain = ?", ruleID, d).Scan(&existing)
		if err != nil {
			log.Printf("Create cert job failed: %v", err)
			continue
		}
		if existing > 0 {
			continue
		}

		_, err = db.DB.Exec(`
			INSERT INTO cert_jobs (rule_id, domain, status, message)
			VALUES (?, ?, 'issuing', '等待 Caddy 签发')
		`, ruleID, d)
		if err != nil {
			log.Printf("Create cert job failed: %v", err)
		}
	}
	return nil
}

func (s *CertificateService) poll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Skip polling if there are no pending/issuing/failed cert jobs to avoid unnecessary DB/Caddy load
	var pendingCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE status IN ('pending','issuing','failed')").Scan(&pendingCount); err != nil {
		log.Printf("Failed to count pending cert jobs: %v", err)
		return
	}
	if pendingCount == 0 {
		return
	}

	// Pre-read all jobs into memory, then close cursor before writing
	rows, err := db.DB.Query("SELECT id, domain, status FROM cert_jobs WHERE status IN ('pending','issuing','failed')")
	if err != nil {
		log.Printf("Failed to query cert jobs: %v", err)
		return
	}
	type job struct {
		id     int
		domain string
		status string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.domain, &j.status); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	rows.Close()

	// Read cert_pem from cert_jobs if available, otherwise fall back to the
	// Caddy local CA endpoint (which only exposes the local CA root, not
	// ACME-issued certificates).
	for _, j := range jobs {
		var certPEM string
		err := db.DB.QueryRow("SELECT COALESCE(cert_pem, '') FROM cert_jobs WHERE id=?", j.id).Scan(&certPEM)
		if err != nil {
			log.Printf("Failed to read cert_pem for job %d: %v", j.id, err)
			continue
		}

		var notAfter time.Time
		if certPEM != "" {
			block, _ := pem.Decode([]byte(certPEM))
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					notAfter = cert.NotAfter
				}
			}
		}

		// Fallback: try to locate the certificate in Caddy storage by scanning
		// the certificates directory.
		if notAfter.IsZero() {
			notAfter = s.findCertExpiryInStorage(j.domain)
		}

		if !notAfter.IsZero() {
			_, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='签发成功', expires_at=? WHERE id=?", notAfter, j.id)
			if err != nil {
				log.Printf("Failed to update issued cert job: %v", err)
			}
			continue
		}

		// Still not found: if the job is failed, reset it to issuing so a retry
		// (e.g. from the UI) can be tracked. If it has been issuing for too long,
		// mark it failed.
		if j.status == "failed" {
			_, err := db.DB.Exec("UPDATE cert_jobs SET status='issuing', message='重新签发' WHERE id=?", j.id)
			if err != nil {
				log.Printf("Failed to reset failed cert job to issuing: %v", err)
			}
		} else if j.status == "issuing" {
			_, err := db.DB.Exec(`
				UPDATE cert_jobs SET status='failed', message='签发超时，请检查 DNS 配置和域名解析'
				WHERE id=? AND datetime(created_at, '+10 minutes') < datetime('now')
			`, j.id)
			if err != nil {
				log.Printf("Failed to update failed cert job: %v", err)
			}
		}
	}
}

func (s *CertificateService) findCertExpiryInStorage(domain string) time.Time {
	// Try the well-known Caddy storage layout for ACME certificates.
	baseDir := "/root/.local/share/caddy/certificates"
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return time.Time{}
	}
	for _, issuerDir := range entries {
		if !issuerDir.IsDir() {
			continue
		}
		certFile := filepath.Join(baseDir, issuerDir.Name(), domain, domain+".crt")
		data, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if cert.Subject.CommonName == domain || containsDomain(cert.DNSNames, domain) {
			return cert.NotAfter
		}
	}
	return time.Time{}
}

func containsDomain(names []string, domain string) bool {
	for _, n := range names {
		if n == domain {
			return true
		}
	}
	return false
}

func (s *CertificateService) checkManualCertExpiration() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-read all manual certificates into memory, then close cursor before parsing
	rows, err := db.DB.Query(`
		SELECT caddy_id, name, domain, tls_cert 
		FROM lb_rules 
		WHERE enable_tls = 1 AND tls_auto_cert = 0 AND tls_cert != ''
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
		SELECT id, rule_id, domain, status, expires_at
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
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	return jobs
}
