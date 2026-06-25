package services

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
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

	resp, err := s.client.Get(s.adminURL + "/pki/ca/local")
	if err != nil {
		log.Printf("Failed to get Caddy certificates: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Caddy certificates endpoint returned %d", resp.StatusCode)
		return
	}

	var data struct {
		Roots []struct {
			Subject  string    `json:"subject"`
			NotAfter time.Time `json:"not_after"`
		} `json:"roots"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("Failed to decode Caddy certificates response: %v", err)
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

	for _, j := range jobs {
		found := false
		var notAfter time.Time
		for _, r := range data.Roots {
			if strings.Contains(r.Subject, j.domain) {
				found = true
				notAfter = r.NotAfter
				break
			}
		}

		if found {
			_, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='签发成功', expires_at=? WHERE id=?", notAfter, j.id)
			if err != nil {
				log.Printf("Failed to update issued cert job: %v", err)
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
