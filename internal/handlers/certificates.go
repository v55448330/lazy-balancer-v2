package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services/dnsproviders"
)

func (h *Handlers) ListCertificateConfigs(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, dns_provider, enabled, created_at, updated_at FROM certificate_configs ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query configs"})
		return
	}
	defer rows.Close()

	var configs []models.CertificateConfig
	for rows.Next() {
		var cfg models.CertificateConfig
		if err := rows.Scan(&cfg.ID, &cfg.Name, &cfg.DNSProvider, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt,
		); err != nil {
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

	query := "UPDATE certificate_configs SET "
	var args []interface{}

	if req.Name != "" {
		query += "name = ?, "
		args = append(args, req.Name)
	}
	if req.DNSProvider != "" {
		query += "dns_provider = ?, "
		args = append(args, req.DNSProvider)
	}
	if req.DNSCredentials != nil {
		credsJSON, _ := json.Marshal(req.DNSCredentials)
		query += "dns_credentials = ?, "
		args = append(args, string(credsJSON))
	}
	if req.Enabled != nil {
		query += "enabled = ?, "
		args = append(args, *req.Enabled)
	}

	query += "updated_at = datetime('now') WHERE id = ?"
	args = append(args, id)

	if _, err := db.DB.Exec(query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update config"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}

func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete configs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM certificate_configs WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config deleted"})
}

func (h *Handlers) ListDNSProviders(c *gin.Context) {
	providers := dnsproviders.List()
	var result []gin.H
	for _, p := range providers {
		result = append(result, gin.H{
			"code":              p.Code(),
			"name":              p.Name(),
			"credential_fields": p.CredentialFields(),
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func (h *Handlers) TestCertificateConfig(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var name, provider, credentials string
	err := db.DB.QueryRow("SELECT name, dns_provider, dns_credentials FROM certificate_configs WHERE id=?", id).Scan(&name, &provider, &credentials)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Config not found"})
		return
	}
	p, ok := dnsproviders.Get(provider)
	if !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Unknown provider"})
		return
	}
	var creds map[string]string
	json.Unmarshal([]byte(credentials), &creds)
	if err := p.Validate(creds); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
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
