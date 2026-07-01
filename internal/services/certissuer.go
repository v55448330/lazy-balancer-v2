package services

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider"
	"lazy-balancer-v2/internal/models"
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

// Issue obtains a certificate for the given rule and domains using the
// provided CA provider. The caller (queue manager) must pass a valid jobID.
func (s *CertIssuer) Issue(ctx context.Context, jobID int, ruleID, domains string, provider models.CAProvider) error {
	if jobID <= 0 {
		return fmt.Errorf("invalid job ID: %d", jobID)
	}

	domainList := normalizeAndValidateDomains(domains)
	if domainList == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}

	// Reset the existing job row (queue manager already created/reused it).
	res, err := db.DB.Exec(
		"UPDATE cert_jobs SET status='creating_account', message='开始申请证书', updated_at=datetime('now') WHERE id=?",
		jobID,
	)
	if err != nil {
		return fmt.Errorf("update cert job status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		failJob(jobID, "证书任务不存在")
		return fmt.Errorf("cert job %d not found", jobID)
	}

	logger := &jobLogger{jobID: jobID}

	// Resolve ACME config for the rule.
	var acmeConfigID int
	err = db.DB.QueryRow("SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&acmeConfigID)
	if err != nil {
		failJob(jobID, "读取规则 ACME 配置失败")
		return fmt.Errorf("read rule acme config: %w", err)
	}

	// Load ACME email from global config (single source of truth).
	var acmeEmail string
	if err := db.DB.QueryRow("SELECT COALESCE(acme_email,'') FROM global_config WHERE id=1").Scan(&acmeEmail); err != nil {
		failJob(jobID, "读取 ACME 邮箱失败")
		return fmt.Errorf("read global acme email: %w", err)
	}

	// Load DNS credentials from the rule's selected provider.
	var dnsCredentialsJSON string
	if acmeConfigID > 0 {
		err = db.DB.QueryRow("SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=? AND enabled=1", acmeConfigID).Scan(&dnsCredentialsJSON)
		if err != nil && err != sql.ErrNoRows {
			failJob(jobID, "读取 DNS 凭证配置失败")
			return fmt.Errorf("read certificate config: %w", err)
		}
	}
	if dnsCredentialsJSON == "" {
		failJob(jobID, "未选择可用的 DNS 提供商，请先在规则中选择 DNS 凭证")
		return fmt.Errorf("no enabled DNS provider selected for rule")
	}

	dnsProvider, err := dnsprovider.NewProviderFromCredentials(dnsCredentialsJSON)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	// Create ACME client for the selected provider
	if strings.TrimSpace(acmeEmail) == "" {
		failJob(jobID, "ACME 邮箱未配置，请在「系统设置 / 免费证书」中填写邮箱")
		return fmt.Errorf("ACME 邮箱未配置")
	}
	client, err := acme.NewClientForProvider(provider, acmeEmail)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	issuer := &acme.Issuer{
		Client:   client,
		Provider: dnsProvider,
		Logger:   logger,
	}

	// Run the ACME issuance flow
	certPEM, keyPEM, err := issuer.Issue(ctx, domainList)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	// Parse certificate expiry
	notAfter, err := parseCertNotAfter(certPEM)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	// Persist cert+key to database
	_, err = db.DB.Exec(
		"UPDATE cert_jobs SET status='issued', message='签发成功', cert_pem=?, key_pem=?, expires_at=?, ca_provider_id=?, updated_at=datetime('now') WHERE id=?",
		certPEM, keyPEM, notAfter, provider.ID, jobID,
	)
	if err != nil {
		failJob(jobID, fmt.Sprintf("证书保存失败: %v", err))
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

// NewACMEClientForProvider exposes the ACME client factory for handlers.
func NewACMEClientForProvider(provider models.CAProvider, email string) (*acme.Client, error) {
	return acme.NewClientForProvider(provider, email)
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
