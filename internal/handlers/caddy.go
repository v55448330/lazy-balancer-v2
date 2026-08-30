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
	"path/filepath"
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

// caddyProcRoot 是进程状态读取的根目录（生产=/proc；测试指向临时伪 /proc 目录）。
var caddyProcRoot = "/proc"

// caddyProcessRunning 纯 /proc 实现：遍历 /proc/*/stat，存在任一 comm=caddy 且
// 状态非 Z（僵尸）的进程即为运行中。Z=僵尸——entrypoint 孵化、父进程未回收的
// caddy 子进程死后会永久滞留（Go 不回收非 exec 子进程），其 comm 仍为 caddy、
// 进程仍在，但已 dead 不能服务，必须排除在「运行中」之外（否则 stop/restart 的
// 完成判定在该僵尸存在期间永远失败——2026-08-28 生产复现）。不用 ps：busybox ps
// 不支持 -p 选项（alpine 容器内 GNU 语法的 ps -o stat= -p 直接报
// "unrecognized option"），/proc 是唯一可靠来源。
func caddyProcessRunning() bool {
	return caddyLivePID() > 0
}

// caddyLivePID 返回首个存活（非 Z 状态）caddy 进程的 pid，无存活进程时返回 0。
// 与 caddyProcessRunning 共用同一 /proc 遍历（仪表盘「运行中（pid）」展示）。
func caddyLivePID() int {
	entries, err := os.ReadDir(caddyProcRoot)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(caddyProcRoot, entry.Name(), "stat"))
		if err != nil {
			continue // 进程可能刚退出，stat 已消失——视为非运行候选，跳过
		}
		line := string(content)
		// stat 格式：pid (comm) state ...；comm 可含空格与右括号，取最后一个 ')'
		// 之后的单字符状态（R/S/D/T/Z…）。
		open := strings.Index(line, "(")
		close := strings.LastIndex(line, ")")
		if open < 0 || close <= open || close+2 >= len(line) {
			continue
		}
		if line[open+1:close] != "caddy" {
			continue
		}
		if line[close+2] != 'Z' {
			if pid, err := strconv.Atoi(entry.Name()); err == nil {
				return pid
			}
		}
	}
	return 0
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
				err = errors.New("Caddy 在 Admin API 就绪前退出")
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
			return errors.New("Caddy Admin API 未就绪")
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
	return errors.New("停止后 Caddy Admin API 仍可达")
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
		       COALESCE(upstream_keepalive_timeout,0) as upstream_keepalive_timeout,
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
	       COALESCE(github_proxy_url,'https://v4.gh-proxy.org/') as github_proxy_url,
		       COALESCE(mfa_write_guard,0) as mfa_write_guard,
		       COALESCE(mfa_lockout_enabled,0) as mfa_lockout_enabled,
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
		&cfg.ServerTokensHidden, &cfg.CertJobLogSizeMB, &cfg.AuditLogSizeMB, &cfg.RuntimeLogSizeMB, &cfg.AccessLogJSON, &cfg.AccessLogFormat, &cfg.AuditRetentionMonths, &cfg.JWTExpireMinutes, &cfg.Timezone, &cfg.GitHubProxyURL, &cfg.MFAWriteGuard, &cfg.MFALockoutEnabled,
		&cfg.IsMaster, &cfg.MasterURL, &cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取全局配置失败: " + err.Error()})
		return
	}
	// R72 二十六次 D4：DNS 凭证最小可见性——非 admin 响应以掩码占位。
	// UpdateConfig 侧对掩码值按「未提交」处理（保持原值），回传保存不破坏凭证。
	if role, _ := c.Get("role"); role != "admin" && cfg.DNSCredentials != "" {
		cfg.DNSCredentials = maskedDNSCredentialsSentinel
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}

func (h *Handlers) GetUpstreamHealth(c *gin.Context) {
	healthStatus, err := h.caddyService.GetUpstreamHealthDetailed()
	if err != nil {
		log.Printf("collect upstream health: %v", err)
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: "收集上游健康状态失败"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: healthStatus})
}

func (h *Handlers) PreviewConfigUpdate(c *gin.Context) {
	var req models.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	old, err := loadConfigSnapshot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前配置失败"})
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	// R72 二十六次 D4：非 admin 的 GET /config 已把凭证替换为掩码——前端原样
	// 回传时按「未提交」处理，避免掩码串覆盖真实凭证。
	if req.DNSCredentials != nil && *req.DNSCredentials == maskedDNSCredentialsSentinel {
		req.DNSCredentials = nil
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
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的应用日志级别"})
			return
		}
	}

	if req.CaddyLogLevel != nil {
		switch strings.ToLower(*req.CaddyLogLevel) {
		case "debug", "info", "warn", "error":
		default:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 Caddy 日志级别"})
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
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 DNS 提供商"})
			return
		}
	}

	if req.CertRenewalDays != nil && (*req.CertRenewalDays < 0 || *req.CertRenewalDays > 90) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "cert_renewal_days 必须在 0-90 之间"})
		return
	}

	if req.CertRenewalAttempts != nil && (*req.CertRenewalAttempts < 1 || *req.CertRenewalAttempts > 10) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "cert_renewal_attempts 必须在 1-10 之间"})
		return
	}

	// R58 C-N5：cert_expiry_days 与另两个续签数值同边界（导入侧已按
	// [1,365] 钳制）——写侧缺校验会让 0/负值落库，续期窗口计算漂移。
	if req.CertExpiryDays != nil && (*req.CertExpiryDays < 1 || *req.CertExpiryDays > 365) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "cert_expiry_days 必须在 1-365 之间"})
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "request_body_max_size_mb 必须在 0-4096 MB 之间"})
		return
	}
	if (req.HTTPReadTimeout != nil && *req.HTTPReadTimeout < 0) || (req.HTTPWriteTimeout != nil && *req.HTTPWriteTimeout < 0) || (req.HTTPIdleTimeout != nil && *req.HTTPIdleTimeout < 0) || (req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "超时时间不能为负数"})
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "jwt_expire_minutes 必须在 1-1440 之间"})
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

	// GitHub 加速代理仅允许内置选项（防 SSRF），CRS/IP2Region 下载共用。
	if req.GitHubProxyURL != nil {
		if err := services.ValidateGitHubProxyURL(*req.GitHubProxyURL); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	old, err := loadConfigSnapshot()
	if err != nil {
		// I-K（第 14 轮审计）：保存端点服务端失败分支留痕（操作者归因 + 错误详情），
		// 此前仅成功路径写审计；动作复用既有 danger 词条「更新失败」。
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("读取当前配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前配置失败"})
		return
	}
	plan := planConfigChanges(req, old)
	if !plan.Changed {
		recordAudit(c, "更新", plan.Section, "无修改")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置无变化", Data: plan})
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
	// R69 C-N3-c：旧运行配置先于 validate 摄取——ValidateConfig 经 /load 真实
	// apply 候选配置，后摄的 oldRuntimeConfig 是候选而非变更前状态，保存失败
	// 时会把未提交配置恢复回去（DB/Caddy 反向分叉）。
	oldRuntimeConfig, err := h.caddyService.GetConfig()
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("获取当前 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取当前 Caddy 配置失败"})
		return
	}
	if err := h.caddyService.ValidateConfig(testConfig); err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("Caddy 配置验证失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败: " + err.Error()})
		return
	}

	// Validation passed — write in a transaction; Caddy applies the uncommitted
	// state and the transaction only commits after a successful apply, so a
	// failed apply leaves DB and env unchanged.
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("开启配置事务失败", err.Error(), services.AuditResultPart("failure")))
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
				github_proxy_url = COALESCE(?, github_proxy_url),
				mfa_write_guard = COALESCE(?, mfa_write_guard),
				mfa_lockout_enabled = COALESCE(?, mfa_lockout_enabled),
				updated_at = datetime('now')
			WHERE id = 1
		`, req.DNSProvider, req.DNSCredentials, req.DNSCredentials, req.ACMEEmail, req.ACMEEmail, req.CertExpiryDays, req.CertRenewalDays, req.CertRenewalAttempts, req.DefaultCAProviderID, req.DefaultCAProviderID, req.LogLevel,
		req.CaddyLogLevel, req.CaddyLogSizeMB,
		req.RequestBodyMaxSizeMB, req.HTTPReadTimeout, req.HTTPWriteTimeout, req.HTTPIdleTimeout,
		req.UpstreamKeepaliveTimeout, req.ProxyDialTimeout, req.ProxyResponseHeaderTimeout, req.ProxyReadTimeout, req.ProxyWriteTimeout, req.ProxyStreamTimeout, req.ProxyFlushInterval, req.ProxyStreamCloseDelay,
		req.ServerTokensHidden, req.CertJobLogSizeMB, req.AuditLogSizeMB, req.RuntimeLogSizeMB, req.AccessLogJSON, req.AccessLogFormat, req.AccessLogFormat, req.AuditRetentionMonths, req.JWTExpireMinutes, req.Timezone, req.GitHubProxyURL, req.MFAWriteGuard, req.MFALockoutEnabled)
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败: " + err.Error()})
		return
	}
	rows, err := res.RowsAffected()
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败: " + err.Error()})
		return
	}
	if rows != 1 {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", fmt.Sprintf("影响记录数为 %d", rows), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("配置写入数据库失败: 影响记录数为 %d", rows)})
		return
	}

	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.caddyService.ApplyConfig(oldRuntimeConfig)
		err = errors.Join(err, restoreErr)
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("Caddy 配置应用失败", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置验证失败: " + validationErr.Error()})
			return
		}
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("Caddy 配置应用失败", err.Error(), services.AuditResultPart("failure")))
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
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("提交配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交配置失败: " + err.Error()})
		return
	}
	committed = true
	services.ApplyLogLevel()
	if req.Timezone != nil {
		if _, err := services.ConfigureLocation(*req.Timezone); err != nil {
			recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("应用时区失败", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "应用时区失败: " + err.Error()})
			return
		}
	}

	if len(plan.SectionChanges) > 0 {
		for section, fields := range plan.SectionChanges {
			recordAudit(c, "更新", section, fmt.Sprintf("修改了: %s", strings.Join(fields, ", ")))
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置已更新并应用", Data: plan})
}

func (h *Handlers) ValidateConfig(c *gin.Context) {
	// R72 二十六次 W1-8：本端点执行两次真实 /load（校验载荷 + 权威回弹），
	// 必须与其他写端点共享 caddyOpMu——与 UpdateConfig 并发时，用户配置可能
	// 被捕获进其 oldRuntimeConfig 快照，后续失败恢复会把用户配置重新应用
	// （运行时与 DB 分叉）。rare×rare 且自愈，但违反「写端点持锁」不变量。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	var configData map[string]interface{}
	if err := c.ShouldBindJSON(&configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的配置 JSON"})
		return
	}
	// R69 C-N3-c：Caddy /load 无 validate-only 语义——校验成功即用户配置已被
	// 加载为运行配置。此处立即回弹 DB 生成的权威全量配置，把「校验」窗口收敛
	// 到单个 admin 往返；回弹失败属严重分叉（运行配置停留为用户 JSON），审计
	// 留痕供人工恢复（下次任意 apply 也会重新收敛）。校验失败时 /load 原子
	// 拒绝、运行配置不变。
	if err := h.caddyService.ValidateConfig(configData); err != nil {
		recordAudit(c, "校验失败", "Caddy配置", services.FormatAuditDetail("配置校验", services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败", Data: err.Error()})
		return
	}
	if restoreErr := h.caddyService.ApplyConfig(services.GenerateCaddyConfig()); restoreErr != nil {
		recordAudit(c, "校验成功", "Caddy配置", services.FormatAuditDetail("配置校验通过，但回弹权威配置失败，运行配置可能停留为校验载荷", services.AuditResultPart("partial")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置校验通过，但恢复运行配置失败: " + restoreErr.Error()})
		return
	}

	recordAudit(c, "校验成功", "Caddy配置", services.FormatAuditDetail("配置校验", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置有效"})
}

func (h *Handlers) ReloadCaddy(c *gin.Context) {
	if err := h.applyCaddyConfigE(); err != nil {
		// I-K（第 14 轮审计）：手动重载恰是最需要留痕的操作——失败分支记录
		// 操作者归因 + 错误详情（recordCaddyApplyResult 的系统级「应用失败」
		// 不带用户身份，不能替代本条）。
		recordAudit(c, "重载失败", "Caddy服务", services.FormatAuditDetail("手动重载 Caddy 配置", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置重载失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 配置已重载"})
}

func (h *Handlers) GetCaddyStatus(c *gin.Context) {
	applyError := ""
	if db.DB != nil {
		db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&applyError)
	}
	drift := services.CurrentConfigDrift()
	pid := caddyLivePID()
	statusData := func(state string) map[string]string {
		return map[string]string{
			"status":            state,
			"pid":               strconv.Itoa(pid),
			"apply_error":       applyError,
			"config_consistent": strconv.FormatBool(drift.Consistent),
			"config_drift":      driftBannerText(drift),
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/config/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
			return
		}
	}
	// /config/ 不可达时按 /proc 判定进程存活（替换 GNU ps 管线：busybox ps 不支持 -p，
	// 原实现 'ps -o state= -p' 在容器内恒判 stopped）。
	if caddyProcessRunning() {
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
	// D5-S3：与 GetCaddyStatus 同源取 cfg.CaddyAdminURL——此前硬编码
	// localhost:2019，自定义 admin 地址的部署读到的是错误端点。
	resp, err := client.Get(strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/config/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "连接 Caddy 失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 返回错误状态"})
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 Caddy 配置失败: " + err.Error()})
		return
	}
	var configData interface{}
	if err := json.Unmarshal(body, &configData); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 Caddy 配置失败: " + err.Error()})
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "日志文件不可访问: " + err.Error()})
		return
	}

	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}

	f, err := os.Open(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "打开日志文件失败: " + err.Error()})
		return
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志文件失败: " + err.Error()})
		return
	}

	data, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志文件失败: " + err.Error()})
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}

	var configData map[string]interface{}
	if err := json.Unmarshal([]byte(req.Content), &configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 JSON 配置"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime(nil)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("备份当前 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前 Caddy 配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("开启 Caddy 配置事务失败", err.Error(), services.AuditResultPart("failure")))
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
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("保存 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败: " + err.Error()})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("保存 Caddy 配置失败", fmt.Sprintf("影响记录数为 %d", rowsAffected), services.AuditResultPart("failure")))
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
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("Caddy 配置应用失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 拒绝配置: " + err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		rollbackErr := tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		err = errors.Join(err, rollbackErr, restoreErr)
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("提交 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交 Caddy 配置失败: " + err.Error()})
		return
	}
	committed = true

	recordAudit(c, "更新", "Caddy配置", "保存 Caddy 全局配置")
	// R72 二十六次 D3（裁决：保留逃生口 + 明示后果）：自定义 Caddy 配置是
	// 一次性逃生口，数据库生成器从不消费 caddy_config 列——任何后续规则/
	// 配置变更或集群同步都会以权威生成配置覆盖它。保存成功即明示。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置已保存（注意：自定义配置为一次性逃生口，任何后续规则/配置变更或集群同步都会以数据库生成的权威配置覆盖它）"})
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 已启动但配置应用失败: " + note})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已启动"})
}

func (h *Handlers) StopCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已停止"})
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 已重启但配置应用失败: " + note})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已重启"})
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
