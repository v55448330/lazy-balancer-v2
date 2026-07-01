package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GetConfig(c *gin.Context) {
	var cfg models.GlobalConfig
	err := db.DB.QueryRow(`
		SELECT id, caddy_config, dns_provider, COALESCE(dns_credentials,'') as dns_credentials,
		       COALESCE(acme_email,'') as acme_email, COALESCE(cert_expiry_days,30) as cert_expiry_days,
		       COALESCE(default_ca_provider_id,0) as default_ca_provider_id,
		       log_level, access_log_enabled,
		       COALESCE(caddy_log_path,'/app/logs/caddy.log') as caddy_log_path,
		       COALESCE(caddy_log_level,'info') as caddy_log_level,
		       COALESCE(caddy_log_size_mb,100) as caddy_log_size_mb,
		       is_master, COALESCE(master_url, '') as master_url, sync_interval,
		       last_sync, updated_at
		FROM global_config WHERE id = 1
	`).Scan(&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider, &cfg.DNSCredentials,
		&cfg.ACMEEmail, &cfg.CertExpiryDays, &cfg.DefaultCAProviderID,
		&cfg.LogLevel, &cfg.AccessLogEnabled,
		&cfg.CaddyLogPath, &cfg.CaddyLogLevel, &cfg.CaddyLogSizeMB,
		&cfg.IsMaster, &cfg.MasterURL, &cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get config: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}


func (h *Handlers) GetUpstreamHealth(c *gin.Context) {
	healthStatus, err := h.caddyService.GetUpstreamHealthDetailed()
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]map[string]interface{}{}})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: healthStatus})
}


func (h *Handlers) UpdateConfig(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot update config on slave node"})
		return
	}

	var req models.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.CaddyLogPath != "" {
		if !filepath.IsAbs(req.CaddyLogPath) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy log path must be absolute"})
			return
		}
		if err := os.MkdirAll(filepath.Dir(req.CaddyLogPath), 0755); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create log directory: " + err.Error()})
			return
		}
	}

	if req.CaddyLogLevel != "" {
		switch strings.ToLower(req.CaddyLogLevel) {
		case "debug", "info", "warn", "error":
		default:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid Caddy log level"})
			return
		}
	}

	if req.CaddyLogSizeMB != nil && *req.CaddyLogSizeMB <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy log size must be greater than 0"})
		return
	}

	if req.DefaultCAProviderID != nil {
		if err := services.ValidateDefaultCAProvider(*req.DefaultCAProviderID); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Update DNS credentials in environment if provided
	if req.DNSCredentials != "" {
		parts := strings.Split(req.DNSCredentials, ",")
		if len(parts) >= 2 {
			os.Setenv("DNSPOD_ID", parts[0])
			os.Setenv("DNSPOD_TOKEN", parts[1])
		}
	}

	db.DB.Exec(`
		UPDATE global_config SET
			dns_provider = COALESCE(?, dns_provider),
			dns_credentials = COALESCE(?, dns_credentials),
			acme_email = COALESCE(?, acme_email),
			cert_expiry_days = COALESCE(?, cert_expiry_days),
			default_ca_provider_id = COALESCE(?, default_ca_provider_id),
			log_level = COALESCE(?, log_level),
			access_log_enabled = COALESCE(?, access_log_enabled),
			caddy_log_path = COALESCE(?, caddy_log_path),
			caddy_log_level = COALESCE(?, caddy_log_level),
			caddy_log_size_mb = COALESCE(?, caddy_log_size_mb),
			is_master = COALESCE(?, is_master),
			master_url = COALESCE(?, master_url),
			sync_interval = COALESCE(?, sync_interval),
			updated_at = datetime('now')
		WHERE id = 1
	`, req.DNSProvider, req.DNSCredentials, req.ACMEEmail, req.CertExpiryDays, req.DefaultCAProviderID, req.LogLevel, req.AccessLogEnabled,
		req.CaddyLogPath, req.CaddyLogLevel, req.CaddyLogSizeMB,
		req.IsMaster, req.MasterURL, req.SyncInterval)

	// Update node mode in memory
	if req.IsMaster != nil && *req.IsMaster {
		h.nodeService.SetMode("master")
	} else if req.IsMaster != nil && !*req.IsMaster {
		h.nodeService.SetMode("slave")
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}


func (h *Handlers) ValidateConfig(c *gin.Context) {
	var configData map[string]interface{}
	c.ShouldBindJSON(&configData)

	// Call Caddy validate endpoint
	resp, err := http.Post(h.cfg.CaddyAdminURL+"/adapt", "application/json", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to validate config"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Config validation failed", Data: string(body)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config is valid"})
}


func (h *Handlers) ReloadCaddy(c *gin.Context) {
	h.applyCaddyConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy config reloaded"})
}


func (h *Handlers) GetCaddyStatus(c *gin.Context) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:2019/config/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"status": "running"}})
			return
		}
	}
	cmd := exec.Command("sh", "-c", "pgrep -x caddy 2>/dev/null | head -1 | xargs -I{} ps -o state= -p {} 2>/dev/null | grep -E '^[RSD]' && echo running || echo stopped")
	output, _ := cmd.Output()
	if strings.Contains(string(output), "running") {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"status": "running"}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"status": "stopped"}})
}


func (h *Handlers) GetCaddyConfig(c *gin.Context) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:2019/config/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to connect to Caddy: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy returned error status"})
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read Caddy config: " + err.Error()})
		return
	}
	var configData interface{}
	if err := json.Unmarshal(body, &configData); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to parse Caddy config: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configData})
}


func (h *Handlers) PutCaddyConfig(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var configData interface{}
	if err := json.Unmarshal([]byte(req.Content), &configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid JSON config"})
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	body, err := json.Marshal(configData)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to marshal config"})
		return
	}

	resp, err := client.Post("http://localhost:2019/config/", "application/json", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to connect to Caddy: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy rejected config: " + string(respBody)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config saved"})
}


func (h *Handlers) StartCaddy(c *gin.Context) {
	cmd := exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	time.Sleep(2 * time.Second)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy started"})
}


func (h *Handlers) StopCaddy(c *gin.Context) {
	exec.Command("sh", "-c", "kill -9 $(pgrep -x caddy) 2>/dev/null || killall -9 caddy 2>/dev/null || pkill -9 -x caddy 2>/dev/null || true").Run()
	time.Sleep(1 * time.Second)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy stopped"})
}


func (h *Handlers) RestartCaddy(c *gin.Context) {
	exec.Command("sh", "-c", "kill -9 $(pgrep -x caddy) 2>/dev/null || killall -9 caddy 2>/dev/null || pkill -9 -x caddy 2>/dev/null || true").Run()
	time.Sleep(1 * time.Second)
	cmd := exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	time.Sleep(2 * time.Second)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy restarted"})
}

