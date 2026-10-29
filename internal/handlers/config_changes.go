package handlers

import (
	"context"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type configSnapshot struct {
	ACMEEmail                  string
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
	ProxyFlushInterval         int
	ProxyStreamCloseDelay      int
	ServerTokensHidden         bool
	AccessLogJSON              bool
	AccessLogFormat            string
	TaskLogSizeMB              int
	AuditLogSizeMB             int
	RuntimeLogSizeMB           int
	AuditRetentionMonths       int
	JWTExpireMinutes           int
	GitHubProxyURL             string
	GitHubToken                string
	// D-新3：v2.1.8 两个 MFA 全局开关——预览变更清单与字段级审计需要
	//（此前缺位：安全开关可无确认直存且变更零审计留痕）。
	MFAWriteGuard     bool
	MFALockoutEnabled bool
	// v2.3.x 受信代理（CDN 真实 IP）：预览变更清单与字段级审计。
	TrustedProxyEnabled   bool
	TrustedProxyRanges    string
	TrustedProxyRangeRefs string
	TrustedProxyHeaders   string
	TrustedProxyStrict    bool
	// 威胁大屏本站坐标（v3，node-local）：预览变更清单与字段级审计。
	ServerMapLat                float64
	ServerMapLon                float64
	ThreatScreenMode            string
	ThreatTrafficSampleN        int
	SecurityEventsRetentionDays int
	SecurityEventsRowCap        int
}

type configChangePlan struct {
	Changed        bool                `json:"changed"`
	Section        string              `json:"section"`
	Changes        []string            `json:"changes"`
	SectionChanges map[string][]string `json:"-"`
	// AffectsCaddy 表示本次变更字段是否进入 Caddy 配置渲染。为 false 时
	// 保存端点不渲染、不校验、不 /load——仅写库（面板设置、保留策略等
	// 不参与 Caddy 的字段被 Caddy 可用性绑架是错误耦合）。
	AffectsCaddy bool `json:"affects_caddy"`
}

// fieldAffectsCaddy 枚举渲染侧真实消费的 global_config 字段（单一真相：
// services 渲染读列清单 + trusted_proxy_* 的 server 级字段）。新增字段
// 若被渲染函数读取，必须同步登记，否则保存只写库不重载。
func fieldAffectsCaddy(field string) bool {
	switch field {
	case "caddy_log_level", "caddy_log_size_mb",
		"request_body_max_size_mb",
		"http_read_timeout", "http_write_timeout", "http_idle_timeout",
		"upstream_keepalive_timeout",
		"proxy_dial_timeout", "proxy_response_header_timeout",
		"proxy_read_timeout", "proxy_write_timeout", "proxy_stream_timeout",
		"proxy_flush_interval", "proxy_stream_close_delay",
		"server_tokens_hidden",
		"access_log_json", "access_log_format",
		"trusted_proxy_enabled", "trusted_proxy_ranges", "trusted_proxy_range_refs",
		"trusted_proxy_headers", "trusted_proxy_strict":
		return true
	}
	return false
}

func loadConfigSnapshot(ctx context.Context) (configSnapshot, error) {
	// 库值唯一真相（批 1+2）：类型①值型列（caddy_log_size_mb/request_body/
	// http 三超时）直读——变更预览展示库值原样，不再 COALESCE 数值默认掩盖
	//（NOT NULL DEFAULT+每启动回填报证不可达；upstream_keepalive_timeout 为
	// 类型②省略型保留 COALESCE 0）。
	var old configSnapshot
	// 证书到期/续签天数/重试次数三列兜底统一绑定 db.Default*（caddy.go 与
	// 集群快照同口径）；缺行仍整体报错（预览面拒绝「以零值快照误报全字段变更」）。
	err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(acme_email,''),
		COALESCE(cert_expiry_days,?), COALESCE(cert_renewal_days,?), COALESCE(cert_renewal_attempts,?),
		COALESCE(default_ca_provider_id,0), COALESCE(log_level,'info'),
		COALESCE(timezone,?),
		COALESCE(caddy_log_level,'info'), caddy_log_size_mb, request_body_max_size_mb,
		http_read_timeout, http_write_timeout, http_idle_timeout,
		COALESCE(upstream_keepalive_timeout,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(server_tokens_hidden,FALSE),
		COALESCE(access_log_json,TRUE), COALESCE(access_log_format,''),
		COALESCE(task_log_size_mb,?), COALESCE(audit_log_size_mb,?), COALESCE(runtime_log_size_mb,?), COALESCE(audit_retention_months,?),
		COALESCE(jwt_expire_minutes,?),
		COALESCE(github_proxy_url,'https://v4.gh-proxy.org/'),
		COALESCE(github_token,''),
		COALESCE(mfa_write_guard,0),
		COALESCE(mfa_lockout_enabled,0),
		COALESCE(trusted_proxy_enabled,0), COALESCE(trusted_proxy_ranges,'[]'), COALESCE(trusted_proxy_range_refs,'[]'), COALESCE(trusted_proxy_headers,'[]'), COALESCE(trusted_proxy_strict,1),
		COALESCE(server_map_lat,0), COALESCE(server_map_lon,0), COALESCE(threat_screen_mode,?), COALESCE(threat_traffic_sample_n,?), COALESCE(security_events_retention_days,?), COALESCE(security_events_row_cap,?)
		FROM global_config WHERE id=1`, db.DefaultCertExpiryDays, db.DefaultCertRenewalDays, db.DefaultCertRenewalAttempts, db.DefaultTimezone,
		db.DefaultTaskLogSizeMB, db.DefaultAuditLogSizeMB, db.DefaultRuntimeLogSizeMB, db.DefaultAuditRetentionMonths, db.DefaultJWTExpireMinutes,
		db.DefaultThreatScreenMode, db.DefaultThreatTrafficSampleN, db.DefaultSecurityEventsRetentionDays, db.DefaultSecurityEventsRowCap).Scan(
		&old.ACMEEmail,
		&old.CertExpiryDays, &old.CertRenewalDays, &old.CertRenewalAttempts,
		&old.DefaultCAProviderID, &old.LogLevel,
		&old.Timezone,
		&old.CaddyLogLevel, &old.CaddyLogSizeMB, &old.RequestBodyMaxSizeMB,
		&old.HTTPReadTimeout, &old.HTTPWriteTimeout, &old.HTTPIdleTimeout,
		&old.UpstreamKeepaliveTimeout, &old.ProxyDialTimeout, &old.ProxyResponseHeaderTimeout, &old.ProxyReadTimeout, &old.ProxyWriteTimeout, &old.ProxyStreamTimeout, &old.ProxyFlushInterval, &old.ProxyStreamCloseDelay,
		&old.ServerTokensHidden,
		&old.AccessLogJSON, &old.AccessLogFormat,
		&old.TaskLogSizeMB, &old.AuditLogSizeMB, &old.RuntimeLogSizeMB, &old.AuditRetentionMonths, &old.JWTExpireMinutes,
		&old.GitHubProxyURL,
		&old.GitHubToken,
		&old.MFAWriteGuard, &old.MFALockoutEnabled,
		&old.TrustedProxyEnabled, &old.TrustedProxyRanges, &old.TrustedProxyRangeRefs, &old.TrustedProxyHeaders, &old.TrustedProxyStrict,
		&old.ServerMapLat, &old.ServerMapLon, &old.ThreatScreenMode, &old.ThreatTrafficSampleN, &old.SecurityEventsRetentionDays, &old.SecurityEventsRowCap)
	return old, err
}

// appendConfigChange 追加一条字段级变更：去重键是 (section,label)——同段内
// 多字段共用 label（大屏本站坐标 lat/lon）只列一次；跨段复用同一 label（如
// 两处「日志大小」）必须各自保留归因，否则第二个字段的变更会从清单消失且
// 字段级审计指向错误卡片。
func appendConfigChange(plan *configChangePlan, seen map[string]bool, field, label string) {
	section := services.GetConfigSection(field)
	key := section + "\x00" + label
	if seen[key] {
		return
	}
	seen[key] = true
	plan.Changes = append(plan.Changes, label)
	plan.SectionChanges[section] = append(plan.SectionChanges[section], label)
}

func planConfigChanges(req models.UpdateConfigRequest, old configSnapshot) configChangePlan {
	plan := configChangePlan{
		Section:        services.GetConfigSourceSection(req.Source),
		Changes:        []string{},
		SectionChanges: map[string][]string{},
	}
	seen := map[string]bool{}
	add := func(field, label string, changed bool) {
		if !changed {
			return
		}
		plan.Changed = true
		if fieldAffectsCaddy(field) {
			plan.AffectsCaddy = true
		}
		appendConfigChange(&plan, seen, field, label)
	}

	add("acme_email", "ACME邮箱", req.ACMEEmail != nil && *req.ACMEEmail != old.ACMEEmail)
	// global_config.dns_credentials 为遗留列：读路径不回显、写路径已移除，
	// 不再参与变更清单/字段级审计归因（签发凭证的唯一来源是
	// certificate_configs.dns_credentials）。
	add("cert_expiry_days", "过期提醒天数", req.CertExpiryDays != nil && *req.CertExpiryDays != old.CertExpiryDays)
	add("default_ca_provider_id", "CA提供商", req.DefaultCAProviderID != nil && *req.DefaultCAProviderID != old.DefaultCAProviderID)
	add("cert_renewal_days", "续签天数", req.CertRenewalDays != nil && *req.CertRenewalDays != old.CertRenewalDays)
	add("cert_renewal_attempts", "重试次数", req.CertRenewalAttempts != nil && *req.CertRenewalAttempts != old.CertRenewalAttempts)
	add("log_level", "系统日志级别", req.LogLevel != nil && *req.LogLevel != old.LogLevel)
	add("timezone", "时区", req.Timezone != nil && *req.Timezone != old.Timezone)
	add("github_proxy_url", "GitHub加速代理", req.GitHubProxyURL != nil && *req.GitHubProxyURL != old.GitHubProxyURL)
	// 令牌变更只记字段名（不落值）——config_changes 预览面无敏感信息；
	// nil=保持、空串=清除（用户裁定：显式空串须计入变更，
	// 否则「空串清除」请求整包落入「配置无变化」短路，撤销永不到达 UPDATE）。
	add("github_token", "GitHub 令牌", req.GitHubToken != nil && *req.GitHubToken != old.GitHubToken)
	add("audit_retention_months", "日志保留", req.AuditRetentionMonths != nil && *req.AuditRetentionMonths != old.AuditRetentionMonths)
	add("server_map_lat", "大屏本站坐标", req.ServerMapLat != nil && *req.ServerMapLat != old.ServerMapLat)
	add("server_map_lon", "大屏本站坐标", req.ServerMapLon != nil && *req.ServerMapLon != old.ServerMapLon)
	add("threat_screen_mode", "大屏视觉模式", req.ThreatScreenMode != nil && *req.ThreatScreenMode != old.ThreatScreenMode)
	add("threat_traffic_sample_n", "大屏流量采样", req.ThreatTrafficSampleN != nil && *req.ThreatTrafficSampleN != old.ThreatTrafficSampleN)
	add("security_events_retention_days", "安全事件保留天数", req.SecurityEventsRetentionDays != nil && *req.SecurityEventsRetentionDays != old.SecurityEventsRetentionDays)
	add("security_events_row_cap", "安全事件行数上限", req.SecurityEventsRowCap != nil && *req.SecurityEventsRowCap != old.SecurityEventsRowCap)
	add("jwt_expire_minutes", "登录过期时间", req.JWTExpireMinutes != nil && *req.JWTExpireMinutes != old.JWTExpireMinutes)
	add("mfa_write_guard", "MFA 写操作验证", req.MFAWriteGuard != nil && *req.MFAWriteGuard != old.MFAWriteGuard)
	add("mfa_lockout_enabled", "登录失败锁定", req.MFALockoutEnabled != nil && *req.MFALockoutEnabled != old.MFALockoutEnabled)
	add("trusted_proxy_enabled", "受信代理开关", req.TrustedProxyEnabled != nil && *req.TrustedProxyEnabled != old.TrustedProxyEnabled)
	add("trusted_proxy_ranges", "受信代理网段", req.TrustedProxyRanges != nil && *req.TrustedProxyRanges != old.TrustedProxyRanges)
	add("trusted_proxy_range_refs", "受信代理引用列表", req.TrustedProxyRangeRefs != nil && *req.TrustedProxyRangeRefs != old.TrustedProxyRangeRefs)
	add("trusted_proxy_headers", "受信代理请求头", req.TrustedProxyHeaders != nil && *req.TrustedProxyHeaders != old.TrustedProxyHeaders)
	add("trusted_proxy_strict", "受信代理严格模式", req.TrustedProxyStrict != nil && *req.TrustedProxyStrict != old.TrustedProxyStrict)
	add("task_log_size_mb", "任务日志大小", req.TaskLogSizeMB != nil && *req.TaskLogSizeMB != old.TaskLogSizeMB)
	add("audit_log_size_mb", "审计日志大小", req.AuditLogSizeMB != nil && *req.AuditLogSizeMB != old.AuditLogSizeMB)
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
	add("proxy_flush_interval", "代理刷新间隔", req.ProxyFlushInterval != nil && *req.ProxyFlushInterval != old.ProxyFlushInterval)
	add("proxy_stream_close_delay", "代理流关闭延迟", req.ProxyStreamCloseDelay != nil && *req.ProxyStreamCloseDelay != old.ProxyStreamCloseDelay)
	add("server_tokens_hidden", "Server Tokens", req.ServerTokensHidden != nil && *req.ServerTokensHidden != old.ServerTokensHidden)
	add("access_log_json", "访问日志 JSON 开关", req.AccessLogJSON != nil && *req.AccessLogJSON != old.AccessLogJSON)
	add("access_log_format", "日志格式模板", req.AccessLogFormat != nil && *req.AccessLogFormat != old.AccessLogFormat)
	return plan
}
