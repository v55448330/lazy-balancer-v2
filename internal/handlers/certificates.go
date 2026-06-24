package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) ListCertificateConfigs(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, domain, cert_pem, key_pem, issuer, acme_email, expires_at, created_at, updated_at FROM tls_certificates ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query configs"})
		return
	}
	defer rows.Close()

	var configs []models.CertificateConfig
	for rows.Next() {
		var cfg models.CertificateConfig
		rows.Scan(&cfg.ID, &cfg.Name, &cfg.ACMEEmail, &cfg.DNSProvider, &cfg.DNSID, &cfg.DNSKey, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt)
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

	result, err := db.DB.Exec(`
		INSERT INTO certificate_configs (name, acme_email, dns_provider, dns_id, dns_key, enabled)
		VALUES (?, ?, ?, ?, ?, ?)
	`, req.Name, req.ACMEEmail, req.DNSProvider, req.DNSID, req.DNSKey, req.Enabled)

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

	query := "UPDATE certificate_configs SET "
	var args []interface{}

	if req.Name != "" {
		query += "name = ?, "
		args = append(args, req.Name)
	}
	if req.ACMEEmail != "" {
		query += "acme_email = ?, "
		args = append(args, req.ACMEEmail)
	}
	if req.DNSProvider != "" {
		query += "dns_provider = ?, "
		args = append(args, req.DNSProvider)
	}
	if req.DNSID != "" || req.DNSKey != "" {
		if req.DNSID != "" {
			query += "dns_id = ?, "
			args = append(args, req.DNSID)
		}
		if req.DNSKey != "" {
			query += "dns_key = ?, "
			args = append(args, req.DNSKey)
		}
	}
	if req.Enabled != nil {
		query += "enabled = ?, "
		args = append(args, *req.Enabled)
	}

	query += "updated_at = datetime('now') WHERE id = ?"
	args = append(args, id)

	db.DB.Exec(query, args...)
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


func (h *Handlers) ListCertificates(c *gin.Context) {
	// Call Caddy to get certificates
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

