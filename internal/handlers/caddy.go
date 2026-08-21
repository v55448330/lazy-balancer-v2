package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var caddyRunCommand = func() *exec.Cmd {
	return exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
}

var caddyStopCommand = func(adminURL string) *exec.Cmd {
	address := adminURL
	if parsed, err := url.Parse(adminURL); err == nil && parsed.Host != "" {
		address = parsed.Host
	}
	return exec.Command("caddy", "stop", "--address", address)
}

var caddyProcessCommand = func() *exec.Cmd { return exec.Command("pgrep", "-x", "caddy") }

func caddyProcessRunning() bool {
	return caddyProcessCommand().Run() == nil
}

func caddyAdminReady(adminURL string) bool {
	client := &http.Client{Timeout: 250 * time.Millisecond}
	response, err := client.Get(strings.TrimRight(adminURL, "/") + "/config/")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode < http.StatusInternalServerError
}

func startCaddy(adminURL string) error {
	cmd := caddyRunCommand()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			if err == nil {
				err = errors.New("Caddy exited before Admin API became ready")
			}
			return err
		case <-ticker.C:
			if caddyAdminReady(adminURL) {
				return nil
			}
		case <-deadline.C:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				<-exited
			}
			return errors.New("Caddy Admin API did not become ready")
		}
	}
}

func stopCaddy(adminURL string) error {
	if err := caddyStopCommand(adminURL).Run(); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !caddyAdminReady(adminURL) && !caddyProcessRunning() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("Caddy Admin API is still reachable after stop")
}

func (h *Handlers) GetConfig(c *gin.Context) {
	var cfg models.GlobalConfig
	err := db.DB.QueryRow(`
		SELECT id, caddy_config, dns_provider, COALESCE(dns_credentials,'') as dns_credentials,
		       COALESCE(acme_email,'') as acme_email, COALESCE(cert_expiry_days,30) as cert_expiry_days,
		       COALESCE(cert_renewal_days,30) as cert_renewal_days,
		       COALESCE(cert_renewal_attempts,5) as cert_renewal_attempts,
		       COALESCE(default_ca_provider_id,0) as default_ca_provider_id,
		       log_level,

		       COALESCE(caddy_log_level,'info') as caddy_log_level,
		       COALESCE(caddy_log_size_mb,100) as caddy_log_size_mb,
		       COALESCE(request_body_max_size_mb,0) as request_body_max_size_mb,
		       COALESCE(http_read_timeout,60) as http_read_timeout,
		       COALESCE(http_write_timeout,60) as http_write_timeout,
		       COALESCE(http_idle_timeout,120) as http_idle_timeout,
		       COALESCE(upstream_keepalive_timeout,60) as upstream_keepalive_timeout,
		       COALESCE(proxy_dial_timeout,0) as proxy_dial_timeout,
		       COALESCE(proxy_response_header_timeout,0) as proxy_response_header_timeout,
		       COALESCE(proxy_read_timeout,0) as proxy_read_timeout,
		       COALESCE(proxy_write_timeout,0) as proxy_write_timeout,
		       COALESCE(proxy_stream_timeout,0) as proxy_stream_timeout,
		       COALESCE(proxy_flush_interval,0) as proxy_flush_interval,
		       COALESCE(proxy_stream_close_delay,0) as proxy_stream_close_delay,
		       COALESCE(server_tokens_hidden,FALSE) as server_tokens_hidden,
		       COALESCE(cert_job_log_size_mb,10) as cert_job_log_size_mb,
		       COALESCE(audit_log_size_mb,10) as audit_log_size_mb,
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
		&cfg.CaddyLogLevel, &cfg.CaddyLogSizeMB,
		&cfg.RequestBodyMaxSizeMB, &cfg.HTTPReadTimeout, &cfg.HTTPWriteTimeout, &cfg.HTTPIdleTimeout,
		&cfg.UpstreamKeepaliveTimeout, &cfg.ProxyDialTimeout, &cfg.ProxyResponseHeaderTimeout, &cfg.ProxyReadTimeout, &cfg.ProxyWriteTimeout, &cfg.ProxyStreamTimeout, &cfg.ProxyFlushInterval, &cfg.ProxyStreamCloseDelay,
		&cfg.ServerTokensHidden, &cfg.CertJobLogSizeMB, &cfg.AuditLogSizeMB, &cfg.RuntimeLogSizeMB, &cfg.AccessLogJSON, &cfg.AccessLogFormat, &cfg.AuditRetentionMonths, &cfg.JWTExpireMinutes, &cfg.Timezone,
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
		log.Printf("collect upstream health: %v", err)
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: "Failed to collect upstream health"})
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
	old, err := loadConfigSnapshot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read current config"})
		return
	}
	plan := planConfigChanges(req, old)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: plan})
}

// isPureConfigValidationError 展开 errors.Join 树，判定全部叶子均为
// *configValidationError（含 fmt.Errorf %w 包装的配置错误）。
func isPureConfigValidationError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !isPureConfigValidationError(child) {
				return false
			}
		}
		return true
	}
	var validationErr *configValidationError
	return errors.As(err, &validationErr)
}

// writeConfigValidationFailure 映射聚合预校验错误。R54 新发现4：纯配置错误
// 保持 400 且展示全部规则问题（Round 30 F-4）；一旦混入非配置类错误（DB 故障
// 等），改映射 500 通用文案并记日志——否则 400 消息携带底层 DB 错误文本，
// 客户端会把服务端故障误判为配置问题。
func writeConfigValidationFailure(c *gin.Context, err error) {
	var validationErr *configValidationError
	if !errors.As(err, &validationErr) {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败: " + err.Error()})
		return
	}
	if !isPureConfigValidationError(err) {
		services.Logf("error", "更新全局配置的规则预校验混入非配置类错误：%v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败"})
		return
	}
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
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

	if req.LogLevel != nil {
		level := strings.ToLower(strings.TrimSpace(*req.LogLevel))
		switch level {
		case "debug", "info", "warn", "error":
			*req.LogLevel = level
		default:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid application log level"})
			return
		}
	}

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

	// R57 C-7：上限 4096MB——无上限时天文数字在渲染侧 int64 乘法（MB→字节）
	// 回绕可正可负：负/零让 Caddy requestbody 处理器不生效（限制静默取消）。
	if req.RequestBodyMaxSizeMB != nil && (*req.RequestBodyMaxSizeMB < 0 || *req.RequestBodyMaxSizeMB > 4096) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "request_body_max_size_mb must be in [0, 4096] MB"})
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
	if req.ProxyFlushInterval != nil && *req.ProxyFlushInterval < -1 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "代理刷新间隔不能小于 -1"})
		return
	}
	if req.ProxyStreamCloseDelay != nil && *req.ProxyStreamCloseDelay < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "代理流关闭延迟不能为负数"})
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
	// Round 33 N-5: 审计日志轮转大小上限 512MB（主节点侧校验；从节点经集群
	// 同步照单全收，配置源始终为主节点）。
	if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "审计日志轮转大小必须大于 0"})
		return
	}
	if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB > 512 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "审计日志轮转大小上限 512MB"})
		return
	}
	if req.JWTExpireMinutes != nil && (*req.JWTExpireMinutes <= 0 || *req.JWTExpireMinutes > 1440) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "jwt_expire_minutes must be between 1 and 1440"})
		return
	}
	// R55 F3：audit_retention_months 服务端范围校验（UI 口径 1-12）——超大值使
	// 年龄裁剪的 datetime('now', '-N days') 越出 SQLite 年份范围返回 NULL，
	// 年龄 DELETE 恒假静默失效（仅剩条数兜底）。
	if req.AuditRetentionMonths != nil && (*req.AuditRetentionMonths < 1 || *req.AuditRetentionMonths > 12) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "日志保留月数必须在 1-12 之间"})
		return
	}
	if req.Timezone != nil {
		if _, err := time.LoadLocation(*req.Timezone); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的时区: " + err.Error()})
			return
		}
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
	if err := validateEnabledStoredRuleConfigs(c.Request.Context()); err != nil {
		writeConfigValidationFailure(c, err)
		return
	}

	// Generate config with requested overrides — DB is NOT touched yet
	testConfig := services.GenerateCaddyConfig(&req)
	if err := h.caddyService.ValidateConfig(testConfig); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败: " + err.Error()})
		return
	}
	oldRuntimeConfig, err := h.caddyService.GetConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前 Caddy 配置失败: " + err.Error()})
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
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("UpdateConfig rollback failed: %v", rollbackErr)
			}
		}
	}()
	// 可空列（dns_credentials/acme_email/access_log_format/default_ca_provider_id）需支持
	// 清空：传空值即置 NULL（COALESCE 无法区分“未传”与“清空”）。其余列保留 COALESCE 语义
	// —— 未传(nil) 保持原值。CASE WHEN ? IS NULL 用于区分 nil 与空字符串。
	res, err := tx.Exec(`
			UPDATE global_config SET
				dns_provider = COALESCE(?, dns_provider),
				dns_credentials = CASE WHEN ? IS NULL THEN dns_credentials ELSE NULLIF(?, '') END,
				acme_email = CASE WHEN ? IS NULL THEN acme_email ELSE NULLIF(?, '') END,
				cert_expiry_days = COALESCE(?, cert_expiry_days),
				cert_renewal_days = COALESCE(?, cert_renewal_days),
				cert_renewal_attempts = COALESCE(?, cert_renewal_attempts),
				default_ca_provider_id = CASE WHEN ? IS NULL THEN default_ca_provider_id ELSE NULLIF(?, 0) END,
				log_level = COALESCE(?, log_level),
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
				proxy_flush_interval = COALESCE(?, proxy_flush_interval),
				proxy_stream_close_delay = COALESCE(?, proxy_stream_close_delay),
				server_tokens_hidden = COALESCE(?, server_tokens_hidden),
				cert_job_log_size_mb = COALESCE(?, cert_job_log_size_mb),
				audit_log_size_mb = COALESCE(?, audit_log_size_mb),
				runtime_log_size_mb = COALESCE(?, runtime_log_size_mb),
				access_log_json = COALESCE(?, access_log_json),
				access_log_format = CASE WHEN ? IS NULL THEN access_log_format ELSE NULLIF(?, '') END,
			audit_retention_months = COALESCE(?, audit_retention_months),
			jwt_expire_minutes = COALESCE(?, jwt_expire_minutes),
				timezone = COALESCE(?, timezone),
				updated_at = datetime('now')
			WHERE id = 1
		`, req.DNSProvider, req.DNSCredentials, req.DNSCredentials, req.ACMEEmail, req.ACMEEmail, req.CertExpiryDays, req.CertRenewalDays, req.CertRenewalAttempts, req.DefaultCAProviderID, req.DefaultCAProviderID, req.LogLevel,
		req.CaddyLogLevel, req.CaddyLogSizeMB,
		req.RequestBodyMaxSizeMB, req.HTTPReadTimeout, req.HTTPWriteTimeout, req.HTTPIdleTimeout,
		req.UpstreamKeepaliveTimeout, req.ProxyDialTimeout, req.ProxyResponseHeaderTimeout, req.ProxyReadTimeout, req.ProxyWriteTimeout, req.ProxyStreamTimeout, req.ProxyFlushInterval, req.ProxyStreamCloseDelay,
		req.ServerTokensHidden, req.CertJobLogSizeMB, req.AuditLogSizeMB, req.RuntimeLogSizeMB, req.AccessLogJSON, req.AccessLogFormat, req.AccessLogFormat, req.AuditRetentionMonths, req.JWTExpireMinutes, req.Timezone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败: " + err.Error()})
		return
	}
	rows, err := res.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败: " + err.Error()})
		return
	}
	if rows != 1 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("配置写入数据库失败: 影响记录数为 %d", rows)})
		return
	}

	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.caddyService.ApplyConfig(oldRuntimeConfig)
		err = errors.Join(err, restoreErr)
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置验证失败: " + validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，配置未保存: " + err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		rollbackErr := tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		restoreErr := h.caddyService.ApplyConfig(oldRuntimeConfig)
		err = errors.Join(err, rollbackErr, restoreErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交配置失败: " + err.Error()})
		return
	}
	committed = true
	services.ApplyLogLevel()
	if req.Timezone != nil {
		if _, err := services.ConfigureLocation(*req.Timezone); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "应用时区失败: " + err.Error()})
			return
		}
	}

	if len(plan.SectionChanges) > 0 {
		for section, fields := range plan.SectionChanges {
			recordAudit(c, "更新", section, fmt.Sprintf("修改了: %s", strings.Join(fields, ", ")))
		}
	}

	recordAudit(c, "重载", "Caddy服务", "保存配置后自动重载")

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated and applied", Data: plan})
}

func (h *Handlers) ValidateConfig(c *gin.Context) {
	var configData map[string]interface{}
	if err := c.ShouldBindJSON(&configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid config JSON"})
		return
	}
	if err := h.caddyService.ValidateConfig(configData); err != nil {
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
	recordAudit(c, "重载", "Caddy服务", "手动重载 Caddy 配置")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 配置已重载"})
}

func (h *Handlers) GetCaddyStatus(c *gin.Context) {
	applyError := ""
	if db.DB != nil {
		db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&applyError)
	}
	drift := services.CurrentConfigDrift()
	statusData := func(state string) map[string]string {
		return map[string]string{
			"status":            state,
			"apply_error":       applyError,
			"config_consistent": strconv.FormatBool(drift.Consistent),
			"config_drift":      driftBannerText(drift),
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:2019/config/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
			return
		}
	}
	cmd := exec.Command("sh", "-c", "pgrep -x caddy 2>/dev/null | head -1 | xargs -I{} ps -o state= -p {} 2>/dev/null | grep -E '^[RSD]' && echo running || echo stopped")
	output, _ := cmd.Output()
	if strings.Contains(string(output), "running") {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("stopped")})
}

// driftBannerText 生成前端全局横幅的展示文案（一致时为空串）。
func driftBannerText(drift services.ConfigDriftStatus) string {
	if drift.Consistent {
		return ""
	}
	return formatDriftBanner(drift.Missing, drift.Extra, drift.Since)
}

func formatDriftBanner(missing, extra []string, since string) string {
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, "缺失规则路由: "+strings.Join(missing, "、"))
	}
	if len(extra) > 0 {
		parts = append(parts, "多余规则路由: "+strings.Join(extra, "、"))
	}
	return strings.Join(parts, "；") + "（检测于 " + since + " UTC）"
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
	// R39 C-5: 限制请求体大小防止超大 JSON 全量缓冲（与 CreateRule
	// maxCreateRuleBodyBytes 同口径）。
	const maxPutCaddyConfigBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxPutCaddyConfigBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPutCaddyConfigBytes)

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// R40 F-2: MaxBytesReader 超限（chunked/未知 ContentLength）映射 413，与导入路径口径一致
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var configData map[string]interface{}
	if err := json.Unmarshal([]byte(req.Content), &configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid JSON config"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime(nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前 Caddy 配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启 Caddy 配置事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("PutCaddyConfig rollback failed: %v", rollbackErr)
			}
		}
	}()
	result, err := tx.ExecContext(c.Request.Context(), "UPDATE global_config SET caddy_config=?, updated_at=datetime('now') WHERE id=1", req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败: " + err.Error()})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败"})
		return
	}
	if err := h.caddyService.ApplyConfig(configData); err != nil {
		rollbackErr := tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		err = errors.Join(err, rollbackErr, restoreErr)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy rejected config: " + err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		rollbackErr := tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		err = errors.Join(err, rollbackErr, restoreErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交 Caddy 配置失败: " + err.Error()})
		return
	}
	committed = true

	recordAudit(c, "更新", "Caddy配置", "保存 Caddy 全局配置")
	recordAudit(c, "重载", "Caddy服务", "保存配置后自动重载")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config saved"})
}

func (h *Handlers) StartCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// `caddy run` boots with the bare Caddyfile (welcome page); re-apply the
	// database-generated config so every rule survives a Caddy restart.
	// caddyApplyNoteLocked: caller already holds caddyOpMu (applyCaddyConfigE
	// would re-lock the non-reentrant mutex and deadlock).
	if note := h.caddyApplyNoteLocked(); note != "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy started but config apply failed: " + note})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy started"})
}

func (h *Handlers) StopCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy stopped"})
}

func (h *Handlers) RestartCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// Same as StartCaddy: caller holds caddyOpMu, use the locked variant.
	if note := h.caddyApplyNoteLocked(); note != "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy restarted but config apply failed: " + note})
		return
	}
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
				if r.action != "delete" {
					continue
				}
				// R57 C-3：祖先路径同样致命——删除 request 整树会连带抹掉
				// remote_ip/uri/headers 全部统计字段；精确相等或 r.path 是
				// 受保护路径的祖先前缀（request 是 request>remote_ip 的前缀）
				// 均视为删除。
				if r.path == p || strings.HasPrefix(p, r.path+">") {
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
	if !fieldKept("request>headers>User-Agent") {
		return fmt.Errorf("日志格式不能删除 User-Agent 字段（request>headers>User-Agent），UA 统计依赖该字段")
	}
	renameAlias := func(paths []string, allowed []string) error {
		for _, p := range paths {
			for _, r := range rules {
				if r.action == "delete" || r.action == "" {
					continue
				}
				// R57 C-3：父级改名同样移走子树（request>headers 改名会把
				// User-Agent 一并带走）——祖先前缀视为命中。
				if r.path != p && !strings.HasPrefix(p, r.path+">") {
					continue
				}
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
		return nil
	}
	if err := renameAlias([]string{"request>remote_ip", "request>client_ip"}, []string{"src", "src_ip"}); err != nil {
		return err
	}
	if err := renameAlias([]string{"request>uri"}, []string{"uri_path"}); err != nil {
		return err
	}
	for _, r := range rules {
		if r.path == "request>headers>User-Agent" && r.action != "" && r.action != "delete" {
			return fmt.Errorf("User-Agent 字段不能重命名（request>headers>User-Agent），UA 统计依赖固定字段名")
		}
	}
	return nil
}
