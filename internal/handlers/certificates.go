package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/services/dnsproviders"
)

func (h *Handlers) ListCertificateConfigs(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, dns_provider, dns_credentials, enabled, created_at, updated_at FROM certificate_configs ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query configs"})
		return
	}
	defer rows.Close()

	var configs []models.CertificateConfig
	for rows.Next() {
		var cfg models.CertificateConfig
		if err := rows.Scan(&cfg.ID, &cfg.Name, &cfg.DNSProvider, &cfg.DNSCredentials, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
			continue
		}
		configs = append(configs, cfg)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configs})
}

func (h *Handlers) CreateCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot create configs on slave node"})
		return
	}

	var req models.CreateCertificateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.DNSProvider == "" {
		req.DNSProvider = "dnspod"
	}

	provider, ok := dnsproviders.Get(req.DNSProvider)
	if !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown DNS provider"})
		return
	}

	if _, err := provider.BuildCredentialsJSON(req.DNSCredentials); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	credsJSON, _ := json.Marshal(req.DNSCredentials)
	result, err := db.DB.Exec(`
		INSERT INTO certificate_configs (name, dns_provider, dns_credentials, enabled)
		VALUES (?, ?, ?, ?)
	`, req.Name, req.DNSProvider, string(credsJSON), req.Enabled)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create config"})
		return
	}

	id, _ := result.LastInsertId()
	recordAudit(c, "创建", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), req.Name, req.DNSProvider, fmt.Sprintf("启用：%t", req.Enabled)))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Config created", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot update configs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))

	var req models.UpdateCertificateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.DNSProvider != "" {
		provider, ok := dnsproviders.Get(req.DNSProvider)
		if !ok {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown DNS provider"})
			return
		}
		if req.DNSCredentials != nil {
			if _, err := provider.BuildCredentialsJSON(req.DNSCredentials); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
		}
	}

	var oldName, oldProvider, oldCredentials string
	var oldEnabled bool
	if err := db.DB.QueryRow("SELECT name, dns_provider, COALESCE(dns_credentials,''), COALESCE(enabled,1) FROM certificate_configs WHERE id=?", id).Scan(&oldName, &oldProvider, &oldCredentials, &oldEnabled); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Config not found"})
		return
	}

	changed := []string{}
	query := "UPDATE certificate_configs SET "
	var args []interface{}

	if req.Name != "" && req.Name != oldName {
		query += "name = ?, "
		args = append(args, req.Name)
		changed = append(changed, "名称")
	}
	if req.DNSProvider != "" && req.DNSProvider != oldProvider {
		query += "dns_provider = ?, "
		args = append(args, req.DNSProvider)
		changed = append(changed, "DNS提供商")
	}
	if req.DNSCredentials != nil {
		credsJSON, _ := json.Marshal(req.DNSCredentials)
		if string(credsJSON) != oldCredentials {
			query += "dns_credentials = ?, "
			args = append(args, string(credsJSON))
			changed = append(changed, "凭证")
		}
	}
	if req.Enabled != nil && *req.Enabled != oldEnabled {
		query += "enabled = ?, "
		args = append(args, *req.Enabled)
		changed = append(changed, "启用状态")
	}

	if len(changed) == 0 {
		recordAudit(c, "更新", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), "无修改"))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config unchanged"})
		return
	}

	query += "updated_at = datetime('now') WHERE id = ?"
	args = append(args, id)

	if _, err := db.DB.Exec(query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update config"})
		return
	}
	recordAudit(c, "更新", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}

func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete configs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))
	var name, provider string
	if err := db.DB.QueryRow("SELECT name, dns_provider FROM certificate_configs WHERE id = ?", id).Scan(&name, &provider); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Config not found"})
		return
	}
	if _, err := db.DB.Exec("DELETE FROM certificate_configs WHERE id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete config"})
		return
	}
	recordAudit(c, "删除", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), name, provider))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config deleted"})
}

func (h *Handlers) ListDNSProviders(c *gin.Context) {
	providers := dnsproviders.List()
	var result []gin.H
	for _, p := range providers {
		fields := p.CredentialFields()
		var fieldList []gin.H
		for _, f := range fields {
			fieldList = append(fieldList, gin.H{
				"name":        f.Name,
				"label":       f.Label,
				"type":        f.Type,
				"required":    f.Required,
				"placeholder": f.Placeholder,
				"options":     p.CredentialFieldOptions(f.Name),
			})
		}
		result = append(result, gin.H{
			"code":              p.Code(),
			"name":              p.Name(),
			"credential_fields": fieldList,
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func (h *Handlers) TestCertificateConfig(c *gin.Context) {
	var provider, credentials string
	var creds map[string]string

	var req struct {
		Domain         string            `json:"domain"`
		DNSProvider    string            `json:"dns_provider"`
		DNSCredentials map[string]string `json:"dns_credentials"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	id, idErr := strconv.Atoi(c.Param("id"))
	var configName string
	if idErr == nil && id > 0 {
		err := db.DB.QueryRow("SELECT name, dns_provider, dns_credentials FROM certificate_configs WHERE id=?", id).Scan(&configName, &provider, &credentials)
		if err != nil {
			recordAudit(c, "测试失败", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), services.AuditResultPart("not_found")))
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Config not found"})
			return
		}
		json.Unmarshal([]byte(credentials), &creds)
	} else {
		provider = req.DNSProvider
		creds = req.DNSCredentials
	}

	if req.Domain == "" {
		recordAudit(c, "测试失败", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, services.AuditResultPart("missing_domain")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请输入用于测试的域名"})
		return
	}

	p, ok := dnsproviders.Get(provider)
	if !ok {
		recordAudit(c, "测试失败", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, services.AuditResultPart("unknown_provider")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown provider"})
		return
	}
	if err := p.Validate(creds, req.Domain); err != nil {
		recordAudit(c, "测试失败", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, req.Domain, services.AuditResultPart("credentials_invalid")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	recordAudit(c, "测试成功", "DNS提供商配置", services.FormatAuditDetail(fmt.Sprintf("配置 %d", id), configName, provider, req.Domain, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "凭证有效"})
}

func (h *Handlers) ListCertificates(c *gin.Context) {
	resp, err := http.Get(h.cfg.CaddyAdminURL + "/pki/ca/local")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get certificates"})
		return
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

func (h *Handlers) IssueCertificate(c *gin.Context) {
	recordAudit(c, "触发签发", "证书", services.FormatAuditDetail("范围：所有已启用的 ACME 规则", services.AuditResultPart("requested")))
	h.applyCaddyConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Certificate issuance triggered"})
}

func (h *Handlers) ParseCertificate(c *gin.Context) {
	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	info, err := parseTLSCertificate(req.CertPEM, req.KeyPEM)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}
