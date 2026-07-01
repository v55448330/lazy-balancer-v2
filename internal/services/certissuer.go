package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider"
)

// CertIssuer coordinates ACME certificate issuance: creates/updates cert_jobs,
// runs the ACME flow, persists cert+key to DB, and triggers Caddy reload.
type CertIssuer struct {
	caddyReloader func() error
}

// NewCertIssuer creates a new CertIssuer. The reloader is called after a
// certificate is successfully issued so Caddy picks up the new cert.
func NewCertIssuer(reloader func() error) *CertIssuer {
	return &CertIssuer{caddyReloader: reloader}
}

// jobLogger writes issuance progress to cert_job_logs and updates cert_jobs.status.
type jobLogger struct {
	jobID int
}

func (l *jobLogger) Log(stage, message string) {
	_, _ = db.DB.Exec("INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, ?, ?)",
		l.jobID, "info", fmt.Sprintf("[%s] %s", stage, message))
	_, _ = db.DB.Exec("UPDATE cert_jobs SET status=?, message=?, updated_at=datetime('now') WHERE id=?",
		stage, message, l.jobID)
}

// Issue obtains a certificate for the given rule and domains.
// It validates domains, creates/updates a cert_jobs row, runs ACME, and
// persists the cert+key on success.
func (s *CertIssuer) Issue(ctx context.Context, ruleID, domains string) error {
	domainList := normalizeAndValidateDomains(domains)
	if domainList == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}
	primaryDomain := domainList[0]

	// Create or reset the cert job (unique per rule_id+domain).
	var jobID int
	err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id=? AND domain=?", ruleID, primaryDomain).Scan(&jobID)
	if err != nil {
		// Insert new job
		res, err := db.DB.Exec(
			"INSERT INTO cert_jobs (rule_id, domain, status, message) VALUES (?, ?, 'creating_account', '开始申请证书')",
			ruleID, primaryDomain,
		)
		if err != nil {
			return fmt.Errorf("create cert job: %w", err)
		}
		id64, _ := res.LastInsertId()
		jobID = int(id64)
	} else {
		// Reset existing job
		_, _ = db.DB.Exec(
			"UPDATE cert_jobs SET status='creating_account', message='重新申请证书', updated_at=datetime('now') WHERE id=?",
			jobID,
		)
	}

	// Resolve ACME config for the rule.
	var acmeConfigID int
	var acmeEmail string
	err = db.DB.QueryRow("SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&acmeConfigID)
	if err != nil {
		s.failJob(jobID, "读取规则 ACME 配置失败")
		return fmt.Errorf("read rule acme config: %w", err)
	}

	var dnsCredentialsJSON string
	if acmeConfigID > 0 {
		err = db.DB.QueryRow("SELECT COALESCE(dns_credentials,''), COALESCE(acme_email,'') FROM certificate_configs WHERE id=?", acmeConfigID).Scan(&dnsCredentialsJSON, &acmeEmail)
		if err != nil {
			s.failJob(jobID, "读取 DNS 凭证配置失败")
			return fmt.Errorf("read certificate config: %w", err)
		}
	}
	if strings.TrimSpace(acmeEmail) == "" {
		db.DB.QueryRow("SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail)
	}
	if strings.TrimSpace(acmeEmail) == "" {
		db.DB.QueryRow("SELECT COALESCE(letsencrypt_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail)
	}
	if dnsCredentialsJSON == "" {
		// Fallback to legacy global_config
		err = db.DB.QueryRow("SELECT COALESCE(dns_credentials,'') FROM global_config WHERE id=1").Scan(&dnsCredentialsJSON)
		if err != nil {
			s.failJob(jobID, "读取 DNS 凭证失败")
			return fmt.Errorf("read global dns credentials: %w", err)
		}
	}
	if dnsCredentialsJSON == "" {
		s.failJob(jobID, "ACME DNS 凭证未配置")
		return fmt.Errorf("ACME DNS credentials not configured")
	}

	provider, err := dnsprovider.NewProviderFromCredentials(dnsCredentialsJSON)
	if err != nil {
		s.failJob(jobID, err.Error())
		return err
	}

	// Create ACME client
	if strings.TrimSpace(acmeEmail) == "" {
		s.failJob(jobID, "ACME 邮箱未配置，请在「系统设置 / 免费证书」中填写邮箱")
		return fmt.Errorf("ACME 邮箱未配置")
	}
	client, err := acme.NewClient("https://acme-v02.api.letsencrypt.org/directory", acmeEmail)
	if err != nil {
		s.failJob(jobID, err.Error())
		return err
	}

	logger := &jobLogger{jobID: jobID}
	issuer := &acme.Issuer{
		Client:   client,
		Provider: provider,
		Logger:   logger,
	}

	// Run the ACME issuance flow
	certPEM, keyPEM, err := issuer.Issue(ctx, domainList)
	if err != nil {
		s.failJob(jobID, err.Error())
		return err
	}

	// Parse certificate expiry
	notAfter, err := parseCertNotAfter(certPEM)
	if err != nil {
		s.failJob(jobID, err.Error())
		return err
	}

	// Persist cert+key to database
	_, err = db.DB.Exec(
		"UPDATE cert_jobs SET status='issued', message='签发成功', cert_pem=?, key_pem=?, expires_at=?, updated_at=datetime('now') WHERE id=?",
		certPEM, keyPEM, notAfter, jobID,
	)
	if err != nil {
		return fmt.Errorf("update cert job: %w", err)
	}

	// Reload Caddy to pick up the new certificate
	if s.caddyReloader != nil {
		if err := s.caddyReloader(); err != nil {
			log.Printf("Cert issued but Caddy reload failed: %v", err)
		}
	}

	return nil
}

func (s *CertIssuer) failJob(jobID int, message string) {
	_, _ = db.DB.Exec(
		"UPDATE cert_jobs SET status='failed', message=?, updated_at=datetime('now') WHERE id=?",
		message, jobID,
	)
	_, _ = db.DB.Exec(
		"INSERT INTO cert_job_logs (job_id, level, message) VALUES (?, 'error', ?)",
		jobID, message,
	)
}

// IsACMECertIssued returns true if cert_jobs has an issued certificate for the
// given rule (by caddy_id) and domain.
func IsACMECertIssued(caddyID, domain string) bool {
	return isACMECertIssued(caddyID, domain)
}

// ValidateACMEDomains returns an error if the domains string is not a valid
// ACME certificate request (single domain or root+www).
func ValidateACMEDomains(domains string) error {
	if normalizeAndValidateDomains(domains) == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}
	return nil
}

// normalizeAndValidateDomains returns a cleaned domain list if it is either
// a single domain or a root domain plus its www subdomain. Otherwise nil.
func normalizeAndValidateDomains(domains string) []string {
	parts := strings.Split(domains, ",")
	var list []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		d := strings.TrimSpace(strings.ToLower(p))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		list = append(list, d)
	}
	if len(list) == 0 || len(list) > 2 {
		return nil
	}
	if len(list) == 1 {
		return list
	}
	// Must be root + www.root (either ordering)
	a, b := list[0], list[1]
	if b == "www."+a || a == "www."+b {
		return list
	}
	return nil
}

// parseCertNotAfter extracts the NotAfter time from a PEM certificate chain.
func parseCertNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}