package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
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
		       COALESCE(cert_renewal_days,30) as cert_renewal_days,
		       COALESCE(cert_renewal_attempts,5) as cert_renewal_attempts,
		       COALESCE(default_ca_provider_id,0) as default_ca_provider_id,
		       log_level,
		       COALESCE(caddy_log_path,'/app/logs/caddy.log') as caddy_log_path,
		       COALESCE(caddy_log_level,'info') as caddy_log_level,
		       COALESCE(caddy_log_size_mb,100) as caddy_log_size_mb,
		       COALESCE(request_body_max_size_mb,0) as request_body_max_size_mb,
		       COALESCE(http_read_timeout,0) as http_read_timeout,
		       COALESCE(http_write_timeout,0) as http_write_timeout,
		       COALESCE(http_idle_timeout,0) as http_idle_timeout,
		       COALESCE(upstream_keepalive_timeout,0) as upstream_keepalive_timeout,
		       COALESCE(proxy_dial_timeout,0) as proxy_dial_timeout,
		       COALESCE(proxy_response_header_timeout,0) as proxy_response_header_timeout,
		       COALESCE(proxy_read_timeout,0) as proxy_read_timeout,
		       COALESCE(proxy_write_timeout,0) as proxy_write_timeout,
		       COALESCE(proxy_stream_timeout,0) as proxy_stream_timeout,
		       COALESCE(server_tokens_hidden,FALSE) as server_tokens_hidden,
		       COALESCE(cert_job_log_size_mb,10) as cert_job_log_size_mb,
		       COALESCE(runtime_log_size_mb,100) as runtime_log_size_mb,
		       COALESCE(access_log_json,TRUE) as access_log_json,
		       COALESCE(access_log_format,'') as access_log_format,
		       COALESCE(audit_retention_months,3) as audit_retention_months,
		       COALESCE(jwt_expire_minutes,20) as jwt_expire_minutes,
		       COALESCE(timezone,'Asia/Shanghai') as timezone,
		       is_master, COALESCE(master_url, '') as master_url, sync_interval,
		       last_sync, updated_at
		FROM global_config WHERE id = 1
	`).Scan(
		&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider, &cfg.DNSCredentials,
		&cfg.ACMEEmail, &cfg.CertExpiryDays, &cfg.CertRenewalDays, &cfg.CertRenewalAttempts, &cfg.DefaultCAProviderID,
		&cfg.LogLevel,
		&cfg.CaddyLogPath, &cfg.CaddyLogLevel, &cfg.CaddyLogSizeMB,
		&cfg.RequestBodyMaxSizeMB, &cfg.HTTPReadTimeout, &cfg.HTTPWriteTimeout, &cfg.HTTPIdleTimeout,
		&cfg.UpstreamKeepaliveTimeout, &cfg.ProxyDialTimeout, &cfg.ProxyResponseHeaderTimeout, &cfg.ProxyReadTimeout, &cfg.ProxyWriteTimeout, &cfg.ProxyStreamTimeout,
		&cfg.ServerTokensHidden, &cfg.CertJobLogSizeMB, &cfg.RuntimeLogSizeMB, &cfg.AccessLogJSON, &cfg.AccessLogFormat, &cfg.AuditRetentionMonths, &cfg.JWTExpireMinutes, &cfg.Timezone,
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

func (h *Handlers) PreviewConfigUpdate(c *gin.Context) {
	var req models.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}
	req.CaddyLogPath = nil

	old, err := loadConfigSnapshot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read current config"})
		return
	}
	plan := planConfigChanges(req, old)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: plan})
}

func (h *Handlers) UpdateConfig(c *gin.Context) {

	var req models.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// 与规则写路径同一锁序：先 caddyOpMu，DB 写入与 Caddy 应用全程持锁
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	// Log path is managed by the system and cannot be changed through the UI/API.
	req.CaddyLogPath = nil

	if req.CaddyLogLevel != nil {
		switch strings.ToLower(*req.CaddyLogLevel) {
		case "debug", "info", "warn", "error":
		default:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid Caddy log level"})
			return
		}
	}

	if req.CaddyLogSizeMB != nil && *req.CaddyLogSizeMB < 100 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 日志大小不能小于 100MB"})
		return
	}

	if req.DNSProvider != nil {
		switch *req.DNSProvider {
		case "dnspod":
		default:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid DNS provider"})
			return
		}
	}

	if req.CertRenewalDays != nil && (*req.CertRenewalDays < 0 || *req.CertRenewalDays > 90) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "cert_renewal_days must be between 0 and 90"})
		return
	}

	if req.CertRenewalAttempts != nil && (*req.CertRenewalAttempts < 1 || *req.CertRenewalAttempts > 10) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "cert_renewal_attempts must be between 1 and 10"})
		return
	}

	if req.DefaultCAProviderID != nil {
		if err := services.ValidateDefaultCAProvider(*req.DefaultCAProviderID); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	if req.RequestBodyMaxSizeMB != nil && *req.RequestBodyMaxSizeMB < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "request_body_max_size_mb must be >= 0"})
		return
	}
	if (req.HTTPReadTimeout != nil && *req.HTTPReadTimeout < 0) || (req.HTTPWriteTimeout != nil && *req.HTTPWriteTimeout < 0) || (req.HTTPIdleTimeout != nil && *req.HTTPIdleTimeout < 0) || (req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "timeouts must be >= 0"})
		return
	}
	if (req.ProxyDialTimeout != nil && *req.ProxyDialTimeout < 0) ||
		(req.ProxyResponseHeaderTimeout != nil && *req.ProxyResponseHeaderTimeout < 0) ||
		(req.ProxyReadTimeout != nil && *req.ProxyReadTimeout < 0) ||
		(req.ProxyWriteTimeout != nil && *req.ProxyWriteTimeout < 0) ||
		(req.ProxyStreamTimeout != nil && *req.ProxyStreamTimeout < 0) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "代理超时时间不能为负数"})
		return
	}

	if req.CertJobLogSizeMB != nil && *req.CertJobLogSizeMB <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "证书日志大小必须大于 0"})
		return
	}
	if req.RuntimeLogSizeMB != nil && *req.RuntimeLogSizeMB <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "运行日志大小必须大于 0"})
		return
	}

	old, err := loadConfigSnapshot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read current config"})
		return
	}
	plan := planConfigChanges(req, old)
	if !plan.Changed {
		recordAudit(c, "更新", plan.Section, "无修改")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config unchanged", Data: plan})
		return
	}

	if req.AccessLogFormat != nil {
		if err := validateAccessLogFormat(*req.AccessLogFormat); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Generate config with requested overrides — DB is NOT touched yet
	testConfig := services.GenerateCaddyConfig(h.cfg, &req)
	if err := h.caddyService.ValidateConfig(testConfig, "global_config_validation"); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败: " + err.Error()})
		return
	}

	// Validation passed — write in a transaction; Caddy applies the uncommitted
	// state and the transaction only commits after a successful apply, so a
	// failed apply leaves DB and env unchanged.
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启配置事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.Exec(`
			UPDATE global_config SET
				dns_provider = COALESCE(?, dns_provider),
				dns_credentials = COALESCE(?, dns_credentials),
				acme_email = COALESCE(?, acme_email),
				cert_expiry_days = COALESCE(?, cert_expiry_days),
				cert_renewal_days = COALESCE(?, cert_renewal_days),
				cert_renewal_attempts = COALESCE(?, cert_renewal_attempts),
				default_ca_provider_id = COALESCE(?, default_ca_provider_id),
				log_level = COALESCE(?, log_level),
								caddy_log_path = COALESCE(?, caddy_log_path),
				caddy_log_level = COALESCE(?, caddy_log_level),
				caddy_log_size_mb = COALESCE(?, caddy_log_size_mb),
				request_body_max_size_mb = COALESCE(?, request_body_max_size_mb),
				http_read_timeout = COALESCE(?, http_read_timeout),
				http_write_timeout = COALESCE(?, http_write_timeout),
				http_idle_timeout = COALESCE(?, http_idle_timeout),
				upstream_keepalive_timeout = COALESCE(?, upstream_keepalive_timeout),
				proxy_dial_timeout = COALESCE(?, proxy_dial_timeout),
				proxy_response_header_timeout = COALESCE(?, proxy_response_header_timeout),
				proxy_read_timeout = COALESCE(?, proxy_read_timeout),
				proxy_write_timeout = COALESCE(?, proxy_write_timeout),
				proxy_stream_timeout = COALESCE(?, proxy_stream_timeout),
				server_tokens_hidden = COALESCE(?, server_tokens_hidden),
				cert_job_log_size_mb = COALESCE(?, cert_job_log_size_mb),
				runtime_log_size_mb = COALESCE(?, runtime_log_size_mb),
				access_log_json = COALESCE(?, access_log_json),
				access_log_format = COALESCE(?, access_log_format),
				audit_retention_months = COALESCE(?, audit_retention_months),
				jwt_expire_minutes = COALESCE(?, jwt_expire_minutes),
				timezone = COALESCE(?, timezone),
				updated_at = datetime('now')
			WHERE id = 1
		`, req.DNSProvider, req.DNSCredentials, req.ACMEEmail, req.CertExpiryDays, req.CertRenewalDays, req.CertRenewalAttempts, req.DefaultCAProviderID, req.LogLevel,
		req.CaddyLogPath, req.CaddyLogLevel, req.CaddyLogSizeMB,
		req.RequestBodyMaxSizeMB, req.HTTPReadTimeout, req.HTTPWriteTimeout, req.HTTPIdleTimeout,
		req.UpstreamKeepaliveTimeout, req.ProxyDialTimeout, req.ProxyResponseHeaderTimeout, req.ProxyReadTimeout, req.ProxyWriteTimeout, req.ProxyStreamTimeout,
		req.ServerTokensHidden, req.CertJobLogSizeMB, req.RuntimeLogSizeMB, req.AccessLogJSON, req.AccessLogFormat, req.AuditRetentionMonths, req.JWTExpireMinutes, req.Timezone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败: " + err.Error()})
		return
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败: 未找到配置记录"})
		return
	}

	// Update DNS credentials in environment if provided
	oldDNSPodID, hadDNSPodID := os.LookupEnv("DNSPOD_ID")
	oldDNSPodToken, hadDNSPodToken := os.LookupEnv("DNSPOD_TOKEN")
	envChanged := false
	if req.DNSCredentials != nil {
		parts := strings.Split(*req.DNSCredentials, ",")
		if len(parts) >= 2 {
			os.Setenv("DNSPOD_ID", parts[0])
			os.Setenv("DNSPOD_TOKEN", parts[1])
			envChanged = true
		}
	}

	if err := h.caddyService.ApplyConfigFromTx(h.cfg, tx); err != nil {
		if envChanged {
			restoreEnv := func(key, value string, existed bool) {
				if existed {
					os.Setenv(key, value)
				} else {
					os.Unsetenv(key)
				}
			}
			restoreEnv("DNSPOD_ID", oldDNSPodID, hadDNSPodID)
			restoreEnv("DNSPOD_TOKEN", oldDNSPodToken, hadDNSPodToken)
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，配置未保存: " + err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交配置失败: " + err.Error()})
		return
	}
	committed = true
	services.ApplyLogLevel()

	if len(plan.SectionChanges) > 0 {
		for section, fields := range plan.SectionChanges {
			recordAudit(c, "更新", section, fmt.Sprintf("修改了: %s", strings.Join(fields, ", ")))
		}
	}

	recordAudit(c, "重载", "Caddy配置", "保存配置后自动重载")

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated and applied", Data: plan})
}

func (h *Handlers) ValidateConfig(c *gin.Context) {
	var configData map[string]interface{}
	if err := c.ShouldBindJSON(&configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid config JSON"})
		return
	}
	if err := h.caddyService.ValidateConfig(configData, ""); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Config validation failed", Data: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config is valid"})
}

func (h *Handlers) ReloadCaddy(c *gin.Context) {
	if err := h.applyCaddyConfigE(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置重载失败: " + err.Error()})
		return
	}
	recordAudit(c, "重载", "Caddy配置", "手动重载 Caddy 配置")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 配置已重载"})
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

func (h *Handlers) GetCaddyLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "runtime")
	pathMap := map[string]string{
		"runtime": "/app/logs/caddy.log",
		"tls":     "/app/logs/caddy-tls.log",
		"server":  "/app/logs/caddy-server.log",
		"proxy":   "/app/logs/caddy-proxy.log",
	}
	logPath, ok := pathMap[logType]
	if !ok {
		logPath = pathMap["runtime"]
	}

	const maxBytes = 128 * 1024
	const maxLines = 500

	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Log file not accessible: " + err.Error()})
		return
	}

	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}

	f, err := os.Open(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to open log file: " + err.Error()})
		return
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read log file: " + err.Error()})
		return
	}

	data, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read log file: " + err.Error()})
		return
	}

	if startOffset > 0 {
		if idx := bytes.Index(data, []byte("\n")); idx != -1 {
			data = data[idx+1:]
		}
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	content := convertLogTimezone(strings.Join(lines, "\n"))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

var logTimeRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)`)

func convertLogTimezone(content string) string {
	var tzStr string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tzStr); err != nil {
		return content
	}
	loc, err := time.LoadLocation(tzStr)
	if err != nil || loc.String() == "UTC" {
		return content
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := logTimeRe.FindString(line)
		if m == "" {
			continue
		}
		t, err := time.ParseInLocation("2006/01/02 15:04:05.000", m, time.UTC)
		if err != nil {
			continue
		}
		lines[i] = t.In(loc).Format("2006/01/02 15:04:05.000") + line[len(m):]
	}
	return strings.Join(lines, "\n")
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
	if _, err := db.DB.ExecContext(c.Request.Context(), "UPDATE global_config SET caddy_config=?, updated_at=datetime('now') WHERE id=1", req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败"})
		return
	}

	recordAudit(c, "更新", "Caddy配置", "保存 Caddy 全局配置")
	recordAudit(c, "重载", "Caddy配置", "保存配置后自动重载")
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

// validateAccessLogFormat enforces the fields the log stats feature relies
// on: a client IP and a request URI must survive the format (present natively
// or renamed, never deleted).
func validateAccessLogFormat(format string) error {
	if strings.TrimSpace(format) == "" {
		return nil
	}
	type rule struct {
		path   string
		action string
	}
	var rules []rule
	for _, line := range strings.Split(format, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "->", 2)
		if len(parts) != 2 {
			continue
		}
		rules = append(rules, rule{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
	}
	fieldKept := func(paths ...string) bool {
		for _, p := range paths {
			for _, r := range rules {
				if r.path == p && r.action == "delete" {
					return false
				}
			}
		}
		return true
	}
	if !fieldKept("request>remote_ip", "request>client_ip") {
		return fmt.Errorf("日志格式不能删除客户端 IP 字段（request>remote_ip / request>client_ip），日志统计依赖该字段")
	}
	if !fieldKept("request>uri") {
		return fmt.Errorf("日志格式不能删除 URI 字段（request>uri），日志统计依赖该字段")
	}
	if !fieldKept("request>headers") {
		return fmt.Errorf("日志格式不能删除请求头（request>headers），UA 统计依赖该字段")
	}
	renameAlias := func(paths []string, allowed []string) error {
		for _, p := range paths {
			for _, r := range rules {
				if r.path == p && r.action != "delete" && r.action != "" {
					ok := false
					for _, a := range allowed {
						if r.action == a {
							ok = true
							break
						}
					}
					if !ok {
						return fmt.Errorf("字段 %s 重命名为 %s 后统计将无法识别，仅支持：%s", p, r.action, strings.Join(allowed, " / "))
					}
				}
			}
		}
		return nil
	}
	if err := renameAlias([]string{"request>remote_ip", "request>client_ip"}, []string{"src", "src_ip"}); err != nil {
		return err
	}
	if err := renameAlias([]string{"request>uri"}, []string{"uri_path"}); err != nil {
		return err
	}
	return nil
}
