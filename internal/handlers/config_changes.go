package handlers

import (
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type configSnapshot struct {
	ACMEEmail                  string
	DNSProvider                string
	DNSCredentials             string
	CertExpiryDays             int
	CertRenewalDays            int
	CertRenewalAttempts        int
	DefaultCAProviderID        int
	LogLevel                   string
	Timezone                   string
	CaddyLogLevel              string
	CaddyLogSizeMB             int
	RequestBodyMaxSizeMB       int
	HTTPReadTimeout            int
	HTTPWriteTimeout           int
	HTTPIdleTimeout            int
	UpstreamKeepaliveTimeout   int
	ProxyDialTimeout           int
	ProxyResponseHeaderTimeout int
	ProxyReadTimeout           int
	ProxyWriteTimeout          int
	ProxyStreamTimeout         int
	ServerTokensHidden         bool
	AccessLogJSON              bool
	AccessLogFormat            string
	CertJobLogSizeMB           int
	RuntimeLogSizeMB           int
	AuditRetentionMonths       int
	JWTExpireMinutes           int
}

type configChangePlan struct {
	Changed        bool                `json:"changed"`
	Section        string              `json:"section"`
	Changes        []string            `json:"changes"`
	SectionChanges map[string][]string `json:"-"`
}

func loadConfigSnapshot() (configSnapshot, error) {
	var old configSnapshot
	err := db.DB.QueryRow(`SELECT COALESCE(acme_email,''), COALESCE(dns_provider,'dnspod'), COALESCE(dns_credentials,''),
		COALESCE(cert_expiry_days,30), COALESCE(cert_renewal_days,30), COALESCE(cert_renewal_attempts,5),
		COALESCE(default_ca_provider_id,0), COALESCE(log_level,'info'),
		COALESCE(timezone,'Asia/Shanghai'),
		COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100), COALESCE(request_body_max_size_mb,0),
		COALESCE(http_read_timeout,60), COALESCE(http_write_timeout,60), COALESCE(http_idle_timeout,120),
		COALESCE(upstream_keepalive_timeout,60),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
		COALESCE(server_tokens_hidden,FALSE),
		COALESCE(access_log_json,TRUE), COALESCE(access_log_format,''),
		COALESCE(cert_job_log_size_mb,10), COALESCE(runtime_log_size_mb,100), COALESCE(audit_retention_months,3), COALESCE(jwt_expire_minutes,20)
		FROM global_config WHERE id=1`).Scan(
		&old.ACMEEmail, &old.DNSProvider, &old.DNSCredentials,
		&old.CertExpiryDays, &old.CertRenewalDays, &old.CertRenewalAttempts,
		&old.DefaultCAProviderID, &old.LogLevel,
		&old.Timezone,
		&old.CaddyLogLevel, &old.CaddyLogSizeMB, &old.RequestBodyMaxSizeMB,
		&old.HTTPReadTimeout, &old.HTTPWriteTimeout, &old.HTTPIdleTimeout,
		&old.UpstreamKeepaliveTimeout, &old.ProxyDialTimeout, &old.ProxyResponseHeaderTimeout, &old.ProxyReadTimeout, &old.ProxyWriteTimeout, &old.ProxyStreamTimeout,
		&old.ServerTokensHidden,
		&old.AccessLogJSON, &old.AccessLogFormat,
		&old.CertJobLogSizeMB, &old.RuntimeLogSizeMB, &old.AuditRetentionMonths, &old.JWTExpireMinutes)
	return old, err
}

func planConfigChanges(req models.UpdateConfigRequest, old configSnapshot) configChangePlan {
	plan := configChangePlan{
		Section:        services.GetConfigSourceSection(req.Source),
		Changes:        []string{},
		SectionChanges: map[string][]string{},
	}
	add := func(field, label string, changed bool) {
		if !changed {
			return
		}
		plan.Changed = true
		plan.Changes = append(plan.Changes, label)
		section := services.GetConfigSection(field)
		plan.SectionChanges[section] = append(plan.SectionChanges[section], label)
	}

	add("acme_email", "ACME邮箱", req.ACMEEmail != nil && *req.ACMEEmail != old.ACMEEmail)
	add("dns_provider", "DNS提供商", req.DNSProvider != nil && *req.DNSProvider != old.DNSProvider)
	add("dns_credentials", "DNS凭证", req.DNSCredentials != nil && *req.DNSCredentials != old.DNSCredentials)
	add("cert_expiry_days", "过期提醒天数", req.CertExpiryDays != nil && *req.CertExpiryDays != old.CertExpiryDays)
	add("default_ca_provider_id", "CA提供商", req.DefaultCAProviderID != nil && *req.DefaultCAProviderID != old.DefaultCAProviderID)
	add("cert_renewal_days", "续签天数", req.CertRenewalDays != nil && *req.CertRenewalDays != old.CertRenewalDays)
	add("cert_renewal_attempts", "重试次数", req.CertRenewalAttempts != nil && *req.CertRenewalAttempts != old.CertRenewalAttempts)
	add("log_level", "系统日志级别", req.LogLevel != nil && *req.LogLevel != old.LogLevel)
	add("timezone", "时区", req.Timezone != nil && *req.Timezone != old.Timezone)
	add("audit_retention_months", "日志保留", req.AuditRetentionMonths != nil && *req.AuditRetentionMonths != old.AuditRetentionMonths)
	add("jwt_expire_minutes", "登录过期时间", req.JWTExpireMinutes != nil && *req.JWTExpireMinutes != old.JWTExpireMinutes)
	add("cert_job_log_size_mb", "证书日志大小", req.CertJobLogSizeMB != nil && *req.CertJobLogSizeMB != old.CertJobLogSizeMB)
	add("runtime_log_size_mb", "运行日志大小", req.RuntimeLogSizeMB != nil && *req.RuntimeLogSizeMB != old.RuntimeLogSizeMB)
	add("caddy_log_level", "Caddy日志级别", req.CaddyLogLevel != nil && *req.CaddyLogLevel != old.CaddyLogLevel)
	add("caddy_log_size_mb", "日志大小", req.CaddyLogSizeMB != nil && *req.CaddyLogSizeMB != old.CaddyLogSizeMB)
	add("request_body_max_size_mb", "请求体大小", req.RequestBodyMaxSizeMB != nil && *req.RequestBodyMaxSizeMB != old.RequestBodyMaxSizeMB)
	add("http_read_timeout", "读取超时", req.HTTPReadTimeout != nil && *req.HTTPReadTimeout != old.HTTPReadTimeout)
	add("http_write_timeout", "写入超时", req.HTTPWriteTimeout != nil && *req.HTTPWriteTimeout != old.HTTPWriteTimeout)
	add("http_idle_timeout", "空闲超时", req.HTTPIdleTimeout != nil && *req.HTTPIdleTimeout != old.HTTPIdleTimeout)
	add("upstream_keepalive_timeout", "Keepalive超时", req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout != old.UpstreamKeepaliveTimeout)
	add("proxy_dial_timeout", "代理连接超时", req.ProxyDialTimeout != nil && *req.ProxyDialTimeout != old.ProxyDialTimeout)
	add("proxy_response_header_timeout", "代理响应头超时", req.ProxyResponseHeaderTimeout != nil && *req.ProxyResponseHeaderTimeout != old.ProxyResponseHeaderTimeout)
	add("proxy_read_timeout", "代理读取超时", req.ProxyReadTimeout != nil && *req.ProxyReadTimeout != old.ProxyReadTimeout)
	add("proxy_write_timeout", "代理写入超时", req.ProxyWriteTimeout != nil && *req.ProxyWriteTimeout != old.ProxyWriteTimeout)
	add("proxy_stream_timeout", "代理流超时", req.ProxyStreamTimeout != nil && *req.ProxyStreamTimeout != old.ProxyStreamTimeout)
	add("server_tokens_hidden", "Server Tokens", req.ServerTokensHidden != nil && *req.ServerTokensHidden != old.ServerTokensHidden)
	add("access_log_json", "访问日志 JSON 开关", req.AccessLogJSON != nil && *req.AccessLogJSON != old.AccessLogJSON)
	add("access_log_format", "日志格式模板", req.AccessLogFormat != nil && *req.AccessLogFormat != old.AccessLogFormat)
	return plan
}
