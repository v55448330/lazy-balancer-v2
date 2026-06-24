package services

import (
	"encoding/json"
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

	rows, err := db.DB.Query("SELECT id, domain, status FROM cert_jobs WHERE status IN ('pending','issuing','failed')")
	if err != nil {
		log.Printf("Failed to query cert jobs: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var domain, status string
		if err := rows.Scan(&id, &domain, &status); err != nil {
			continue
		}

		found := false
		var notAfter time.Time
		for _, r := range data.Roots {
			if strings.Contains(r.Subject, domain) {
				found = true
				notAfter = r.NotAfter
				break
			}
		}

		if found {
			_, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='签发成功', expires_at=? WHERE id=?", notAfter, id)
			if err != nil {
				log.Printf("Failed to update issued cert job: %v", err)
			}
		} else if status == "issuing" {
			_, err := db.DB.Exec(`
				UPDATE cert_jobs SET status='failed', message='签发超时，请检查 DNS 配置和域名解析'
				WHERE id=? AND datetime(created_at, '+10 minutes') < datetime('now')
			`, id)
			if err != nil {
				log.Printf("Failed to update failed cert job: %v", err)
			}
		}
	}
}

func (s *CertificateService) CheckExpiration() []models.CertJob {
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
