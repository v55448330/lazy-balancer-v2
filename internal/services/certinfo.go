package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type CertInfoCandidate = CertificateCandidate

func SelectRuleCertificate(candidates []CertInfoCandidate, ruleDomains string, now time.Time) (string, bool) {
	selection, selected := SelectCertificate(candidates, ruleDomains, now)
	if selected {
		return selection.Candidate.CertPEM, true
	}
	return "", false
}

// GetCertExpiryThreshold returns the configured cert expiry warning threshold in days.
func GetCertExpiryThreshold() int {
	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days, 30) FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		Logf("error", "GetCertExpiryThreshold: failed to read global_config, using default 30: %v", err)
		return 30
	}
	if days <= 0 {
		return 30
	}
	return days
}

// GetCertRenewalAttempts returns the configured max renewal attempts.
func GetCertRenewalAttempts() int {
	var attempts int
	err := db.DB.QueryRow("SELECT COALESCE(cert_renewal_attempts, 5) FROM global_config WHERE id = 1").Scan(&attempts)
	if err != nil {
		Logf("error", "GetCertRenewalAttempts: failed to read global_config, using default 5: %v", err)
		return 5
	}
	if attempts <= 0 {
		return 5
	}
	return attempts
}

// ParseCertInfo parses a PEM certificate and returns structured display info.
func ParseCertInfo(certPEM, source, ruleDomains string) *models.RuleCertInfo {
	info := &models.RuleCertInfo{
		Source:  source,
		Domains: ruleDomains,
		Status:  "unknown",
	}

	if strings.TrimSpace(certPEM) == "" {
		info.Error = "证书不存在"
		return info
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		info.Error = "证书格式无效"
		return info
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.Error = fmt.Sprintf("证书解析失败: %v", err)
		return info
	}

	// Domains: prefer certificate DNSNames, fallback to CommonName, fallback to rule domain
	domainSet := make(map[string]struct{})
	var parsedDomains []string
	for _, name := range cert.DNSNames {
		if name != "" {
			if _, exists := domainSet[name]; !exists {
				domainSet[name] = struct{}{}
				parsedDomains = append(parsedDomains, name)
			}
		}
	}
	if cert.Subject.CommonName != "" {
		if _, exists := domainSet[cert.Subject.CommonName]; !exists {
			domainSet[cert.Subject.CommonName] = struct{}{}
			parsedDomains = append(parsedDomains, cert.Subject.CommonName)
		}
	}
	if len(parsedDomains) > 0 {
		info.Domains = strings.Join(parsedDomains, ", ")
	}

	// Issuer: prefer Organization, fallback to CommonName
	issuer := cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		issuer = cert.Issuer.Organization[0]
		if cert.Issuer.CommonName != "" {
			issuer = fmt.Sprintf("%s (%s)", issuer, cert.Issuer.CommonName)
		}
	}
	info.Issuer = issuer
	if info.Issuer == "" {
		info.Issuer = "-"
	}

	const timeFmt = "2006-01-02 15:04:05"
	info.NotBefore = cert.NotBefore.Format(timeFmt)
	info.NotAfter = cert.NotAfter.Format(timeFmt)

	now := time.Now()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
	info.DaysRemaining = daysRemaining

	if !now.Before(cert.NotAfter) {
		info.Status = "expired"
	} else if daysRemaining <= GetCertExpiryThreshold() {
		info.Status = "expiring"
	} else {
		info.Status = "valid"
	}

	return info
}

// GetRuleCertInfo returns parsed certificate info for a single rule.
func GetRuleCertInfo(caddyID string) *models.RuleCertInfo {
	var enableTLS bool
	var tlsSource, ruleDomain, tlsCert string
	err := db.DB.QueryRow(`
		SELECT COALESCE(enable_tls, 0), COALESCE(tls_source, 'manual'), COALESCE(domain, ''), COALESCE(tls_cert, '')
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&enableTLS, &tlsSource, &ruleDomain, &tlsCert)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read rule %s: %v", caddyID, err)
		return nil
	}

	if !enableTLS {
		return nil
	}

	switch tlsSource {
	case "manual":
		info := ParseCertInfo(tlsCert, "manual", ruleDomain)
		info.CaddyID = caddyID
		return info
	case "acme_dns":
		return getACMECertInfo(caddyID, ruleDomain)
	default:
		// Fallback to manual cert if source is unrecognized but tls_cert exists
		info := ParseCertInfo(tlsCert, tlsSource, ruleDomain)
		info.CaddyID = caddyID
		return info
	}
}

// getACMECertInfo returns parsed certificate info for an ACME-issued rule.
// It reads the issued certificate from cert_jobs.cert_pem.
func getACMECertInfo(caddyID, ruleDomain string) *models.RuleCertInfo {
	rows, err := db.DB.Query(`
		SELECT id, status, COALESCE(cert_pem, ''), COALESCE(key_pem, ''),
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
		FROM cert_jobs
		WHERE rule_id = ? AND COALESCE(cert_pem, '') != '' AND COALESCE(key_pem, '') != ''
		ORDER BY updated_at DESC, id DESC`, caddyID)
	if err != nil {
		Logf("error", "GetRuleCertInfo: failed to read ACME certificates for %s: %v", caddyID, err)
		return missingACMECertInfo(caddyID, ruleDomain)
	}
	defer rows.Close()
	candidates := make([]CertInfoCandidate, 0)
	for rows.Next() {
		var candidate CertInfoCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); err != nil {
			Logf("error", "GetRuleCertInfo: failed to scan ACME certificate for %s: %v", caddyID, err)
			return missingACMECertInfo(caddyID, ruleDomain)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		Logf("error", "GetRuleCertInfo: failed to iterate ACME certificates for %s: %v", caddyID, err)
		return missingACMECertInfo(caddyID, ruleDomain)
	}
	if certPEM, selected := SelectRuleCertificate(candidates, ruleDomain, time.Now()); selected {
		info := ParseCertInfo(certPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		return info
	}
	// CERT40-1:选中失败区分「已过期」与「尚未签发」。
	if info := ExpiredACMECertInfoFallback(candidates, caddyID, ruleDomain); info != nil {
		return info
	}
	return missingACMECertInfo(caddyID, ruleDomain)
}

// ExpiredACMECertInfoFallback(CERT40-1/CERT42-1 共享):候选集 PEM 非空但
// SelectRuleCertificate 无一可选中时,逐个解析——首个非 disabled 且 PEM 非空
// 的已过期候选按 expired 呈现(Error=「ACME 证书已过期」),不再误报「尚未
// 签发或不存在」;无已过期候选(解析失败/未过期)返回 nil,调用方维持原口径。
// 单规则(GetRuleCertInfo)与批量(handlers GetRulesCertInfo)两路径同用。
func ExpiredACMECertInfoFallback(candidates []CertInfoCandidate, caddyID, ruleDomain string) *models.RuleCertInfo {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.CertPEM) == "" || candidate.Status == "disabled" {
			continue
		}
		info := ParseCertInfo(candidate.CertPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		if info.Status == "expired" {
			info.Error = "ACME 证书已过期"
			return info
		}
	}
	return nil
}

func missingACMECertInfo(caddyID, ruleDomain string) *models.RuleCertInfo {
	return &models.RuleCertInfo{
		CaddyID: caddyID,
		Source:  "acme_dns",
		Domains: ruleDomain,
		Status:  "unknown",
		Error:   "ACME 证书尚未签发或不存在",
	}
}
