package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

type batchRuleCertInput struct {
	id, certPEM, source, ruleDomains string
	expiryDays                       int
	now                              time.Time
}

// GetRuleCertInfo returns parsed certificate information for a single rule.
func (h *Handlers) GetRuleCertInfo(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	info := services.GetRuleCertInfo(caddyID)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

// GetRulesCertInfo returns parsed certificate information for multiple rules in one call.
func (h *Handlers) GetRulesCertInfo(c *gin.Context) {
	var req models.CertInfoBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}

	if len(req.CaddyIDs) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]*models.RuleCertInfo{}})
		return
	}

	// Limit batch size to prevent abuse
	if len(req.CaddyIDs) > 200 {
		req.CaddyIDs = req.CaddyIDs[:200]
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(req.CaddyIDs)), ",")
	args := make([]any, len(req.CaddyIDs))
	for index, id := range req.CaddyIDs {
		args[index] = id
	}
	rows, err := db.DB.QueryContext(c.Request.Context(), fmt.Sprintf(`
		SELECT caddy_id, COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(domain,''), COALESCE(tls_cert,''),
			(SELECT COALESCE(cert_expiry_days,30) FROM global_config WHERE id=1)
		FROM lb_rules WHERE caddy_id IN (%s)`, placeholders), args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取规则证书配置失败"})
		return
	}
	defer rows.Close()
	type ruleCertificate struct {
		id, source, domains, certPEM string
		enabled                      bool
		expiryDays                   int
	}
	rules := make(map[string]ruleCertificate, len(req.CaddyIDs))
	for rows.Next() {
		var rule ruleCertificate
		if err := rows.Scan(&rule.id, &rule.enabled, &rule.source, &rule.domains, &rule.certPEM, &rule.expiryDays); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取规则证书配置失败"})
			return
		}
		rules[rule.id] = rule
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取规则证书配置失败"})
		return
	}

	jobRows, err := db.DB.QueryContext(c.Request.Context(), fmt.Sprintf(`
		SELECT rule_id, id, status, COALESCE(cert_pem,''), COALESCE(key_pem,''),
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
		FROM cert_jobs
		WHERE rule_id IN (%s) AND COALESCE(cert_pem,'')<>'' AND COALESCE(key_pem,'')<>''
		ORDER BY rule_id, updated_at DESC, id DESC`, placeholders), args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取签发证书失败"})
		return
	}
	defer jobRows.Close()
	candidates := make(map[string][]services.CertInfoCandidate, len(rules))
	now := time.Now()
	for jobRows.Next() {
		var id string
		var candidate services.CertInfoCandidate
		if err := jobRows.Scan(&id, &candidate.ID, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取签发证书失败"})
			return
		}
		candidates[id] = append(candidates[id], candidate)
	}
	if err := jobRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取签发证书失败"})
		return
	}

	result := make(map[string]*models.RuleCertInfo, len(req.CaddyIDs))
	for _, id := range req.CaddyIDs {
		rule, exists := rules[id]
		if !exists || !rule.enabled {
			result[id] = nil
			continue
		}
		certPEM := rule.certPEM
		if rule.source == "acme_dns" {
			certPEM, _ = services.SelectRuleCertificate(candidates[id], rule.domains, now)
		}
		result[id] = parseBatchRuleCertInfo(batchRuleCertInput{
			id: id, certPEM: certPEM, source: rule.source, ruleDomains: rule.domains,
			expiryDays: rule.expiryDays, now: now,
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func parseBatchRuleCertInfo(input batchRuleCertInput) *models.RuleCertInfo {
	info := &models.RuleCertInfo{CaddyID: input.id, Source: input.source, Domains: input.ruleDomains, Status: "unknown"}
	if strings.TrimSpace(input.certPEM) == "" {
		if input.source == "acme_dns" {
			info.Error = "ACME 证书尚未签发或不存在"
		} else {
			info.Error = "证书不存在"
		}
		return info
	}
	block, _ := pem.Decode([]byte(input.certPEM))
	if block == nil {
		info.Error = "证书格式无效"
		return info
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.Error = "证书解析失败: " + err.Error()
		return info
	}
	domainSet := make(map[string]struct{}, len(cert.DNSNames)+1)
	domains := make([]string, 0, len(cert.DNSNames)+1)
	for _, domain := range append(cert.DNSNames, cert.Subject.CommonName) {
		if domain != "" {
			if _, exists := domainSet[domain]; !exists {
				domainSet[domain] = struct{}{}
				domains = append(domains, domain)
			}
		}
	}
	if len(domains) > 0 {
		info.Domains = strings.Join(domains, ", ")
	}
	info.Issuer = cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		info.Issuer = cert.Issuer.Organization[0]
		if cert.Issuer.CommonName != "" {
			info.Issuer += " (" + cert.Issuer.CommonName + ")"
		}
	}
	if info.Issuer == "" {
		info.Issuer = "-"
	}
	info.NotBefore = cert.NotBefore.Format("2006-01-02 15:04:05")
	info.NotAfter = cert.NotAfter.Format("2006-01-02 15:04:05")
	info.DaysRemaining = int(cert.NotAfter.Sub(input.now).Hours() / 24)
	if !input.now.Before(cert.NotAfter) {
		info.Status = "expired"
	} else if info.DaysRemaining <= input.expiryDays {
		info.Status = "expiring"
	} else {
		info.Status = "valid"
	}
	return info
}
