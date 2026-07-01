package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// GetCertExpiryThreshold returns the configured cert expiry warning threshold in days.
func GetCertExpiryThreshold() int {
	var days int
	err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days, 30) FROM global_config WHERE id = 1").Scan(&days)
	if err != nil {
		log.Printf("GetCertExpiryThreshold: failed to read global_config, using default 30: %v", err)
		return 30
	}
	if days <= 0 {
		return 30
	}
	return days
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

	if now.After(cert.NotAfter) {
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
		log.Printf("GetRuleCertInfo: failed to read rule %s: %v", caddyID, err)
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
	var certPEM string
	err := db.DB.QueryRow(`
		SELECT COALESCE(cert_pem, '') FROM cert_jobs
		WHERE rule_id = ? AND status = 'issued' AND cert_pem IS NOT NULL AND cert_pem != ''
		ORDER BY updated_at DESC LIMIT 1`, caddyID).Scan(&certPEM)
	if err == nil && certPEM != "" {
		info := ParseCertInfo(certPEM, "acme_dns", ruleDomain)
		info.CaddyID = caddyID
		return info
	}

	info := &models.RuleCertInfo{
		CaddyID: caddyID,
		Source:  "acme_dns",
		Domains: ruleDomain,
		Status:  "unknown",
		Error:   "ACME 证书尚未签发或不存在",
	}
	return info
}

// GetRulesCertInfo returns parsed certificate info for multiple rules.
func GetRulesCertInfo(caddyIDs []string) map[string]*models.RuleCertInfo {
	result := make(map[string]*models.RuleCertInfo, len(caddyIDs))
	for _, id := range caddyIDs {
		result[id] = GetRuleCertInfo(id)
	}
	return result
}
