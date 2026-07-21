package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GetAdminTLS(c *gin.Context) {
	cfg := services.LoadAdminTLSConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"enabled":       cfg.Enabled,
		"mode":          cfg.Mode,
		"port":          cfg.Port,
		"acme_rule_id":  cfg.ACMERuleID,
		"has_uploaded":  cfg.Cert != "" && cfg.Key != "",
		"restart_hint":  true,
	}})
}

func (h *Handlers) UpdateAdminTLS(c *gin.Context) {
	var req struct {
		Enabled    *bool   `json:"enabled"`
		Mode       string  `json:"mode"`
		Cert       string  `json:"cert"`
		Key        string  `json:"key"`
		ACMERuleID string  `json:"acme_rule_id"`
		Port       *int    `json:"port"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的请求"})
		return
	}

	current := services.LoadAdminTLSConfig()
	enabled := current.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	mode := current.Mode
	if req.Mode != "" {
		mode = req.Mode
	}
	cert, key, ruleID := current.Cert, current.Key, current.ACMERuleID
	if req.Cert != "" {
		cert = req.Cert
	}
	if req.Key != "" {
		key = req.Key
	}
	if req.ACMERuleID != "" {
		ruleID = req.ACMERuleID
	}
	port := current.Port
	if req.Port != nil {
		if *req.Port < 1 || *req.Port > 65535 || *req.Port == 8000 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口无效或与 HTTP 端口冲突"})
			return
		}
		port = *req.Port
	}

	if enabled {
		if mode != "selfsigned" && mode != "upload" && mode != "acme" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的证书来源"})
			return
		}
		probe := services.AdminTLSConfig{Enabled: true, Mode: mode, Cert: cert, Key: key, ACMERuleID: ruleID, Port: port}
		if _, err := probe.ResolveCertificate(h.cfg.DataDir); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书不可用: " + err.Error()})
			return
		}
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=?, admin_tls_mode=?, admin_tls_cert=?, admin_tls_key=?, admin_tls_acme_rule_id=?, admin_tls_port=?, updated_at=datetime('now') WHERE id=1`,
		enabled, mode, cert, key, ruleID, port); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 HTTPS 配置失败: " + err.Error()})
		return
	}

	recordAudit(c, "更新", "HTTPS 访问", services.FormatAuditDetail(
		map[bool]string{true: "启用", false: "禁用"}[enabled],
		"证书来源："+mode,
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已保存，请在系统信息中重启服务生效"})
}
