package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"lazy-balancer-v2/internal/models"
)

func (s *ClusterService) Snapshot(ctx context.Context, sinceVersion int, clientFingerprint string) (models.ClusterSnapshot, bool, error) {
	snapshot, err := s.buildSnapshot(ctx)
	if err != nil {
		return models.ClusterSnapshot{}, false, err
	}
	canonical := snapshot
	canonical.Fingerprint = ""
	canonical.Version = 0
	content, err := json.Marshal(canonical)
	if err != nil {
		return models.ClusterSnapshot{}, false, fmt.Errorf("序列化集群快照: %w", err)
	}
	hash := sha256.Sum256(content)
	snapshot.Fingerprint = hex.EncodeToString(hash[:])
	if sinceVersion >= snapshot.Version && clientFingerprint != "" && clientFingerprint == snapshot.Fingerprint {
		return snapshot, false, nil
	}
	return snapshot, true, nil
}

func (s *ClusterService) buildSnapshot(ctx context.Context) (models.ClusterSnapshot, error) {
	var snapshot models.ClusterSnapshot
	var syncCaddy bool
	var caddyConfig string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(cluster_version,0), COALESCE(sync_caddy_config,0), COALESCE(caddy_config,'{}'),
		COALESCE(log_level,'info'), COALESCE(access_log_json,1), COALESCE(access_log_format,''),
		COALESCE(cert_job_log_size_mb,10), COALESCE(runtime_log_size_mb,100), COALESCE(audit_retention_months,3), COALESCE(jwt_expire_minutes,20), COALESCE(timezone,'Asia/Shanghai'),
		COALESCE(acme_email,''), COALESCE(cert_expiry_days,30), COALESCE(cert_renewal_days,30), COALESCE(cert_renewal_attempts,5),
		COALESCE(default_ca_provider_id,0), COALESCE(dns_provider,''), COALESCE(dns_credentials,''), COALESCE(sync_interval,60)
		FROM global_config WHERE id=1`).Scan(&snapshot.Version, &syncCaddy, &caddyConfig,
		&snapshot.BasicSettings.LogLevel, &snapshot.BasicSettings.AccessLogJSON, &snapshot.BasicSettings.AccessLogFormat,
		&snapshot.BasicSettings.CertJobLogSizeMB, &snapshot.BasicSettings.RuntimeLogSizeMB, &snapshot.BasicSettings.AuditRetentionMonths, &snapshot.BasicSettings.JWTExpireMinutes, &snapshot.BasicSettings.Timezone,
		&snapshot.BasicSettings.ACMEEmail, &snapshot.BasicSettings.CertExpiryDays, &snapshot.BasicSettings.CertRenewalDays, &snapshot.BasicSettings.CertRenewalAttempts,
		&snapshot.BasicSettings.DefaultCAProviderID, &snapshot.BasicSettings.DNSProvider, &snapshot.BasicSettings.DNSCredentials, &snapshot.BasicSettings.SyncInterval)
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("读取集群基础设置: %w", err)
	}
	if syncCaddy {
		snapshot.CaddyConfig = &caddyConfig
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(caddy_log_path,'/app/logs/caddy.log'), COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
			COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,0), COALESCE(http_write_timeout,0), COALESCE(http_idle_timeout,0),
			COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0)
			FROM global_config WHERE id=1`).Scan(
			&snapshot.BasicSettings.CaddyLogPath, &snapshot.BasicSettings.CaddyLogLevel, &snapshot.BasicSettings.CaddyLogSizeMB,
			&snapshot.BasicSettings.RequestBodyMaxSizeMB, &snapshot.BasicSettings.HTTPReadTimeout, &snapshot.BasicSettings.HTTPWriteTimeout, &snapshot.BasicSettings.HTTPIdleTimeout,
			&snapshot.BasicSettings.UpstreamKeepaliveTimeout, &snapshot.BasicSettings.ServerTokensHidden); err != nil {
			return models.ClusterSnapshot{}, fmt.Errorf("读取 Caddy 全局设置: %w", err)
		}
	}
	if snapshot.Rules, err = s.snapshotRules(ctx); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Users, err = s.snapshotUsers(ctx); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.APIKeys, err = s.snapshotAPIKeys(ctx); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Certs, err = s.snapshotCertificates(ctx); err != nil {
		return models.ClusterSnapshot{}, err
	}
	return snapshot, nil
}

func (s *ClusterService) snapshotRules(ctx context.Context) ([]models.LbRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port,
		COALESCE(strategy,'weighted_round_robin'), COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(host_header,''),
		COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), COALESCE(enabled,1), COALESCE(log_enabled,0), COALESCE(created_by,0), COALESCE(updated_by,0)
		FROM lb_rules ORDER BY caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照规则: %w", err)
	}
	defer rows.Close()
	rules := make([]models.LbRule, 0)
	for rows.Next() {
		var rule models.LbRule
		if err := rows.Scan(&rule.CaddyID, &rule.Name, &rule.Description, &rule.Protocol, &rule.Domain, &rule.ListenPort,
			&rule.Strategy, &rule.DynamicDNS, &rule.EnableDnsServer, &rule.DnsServer, &rule.DnsFamily,
			&rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout, &rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
			&rule.EnableActiveHealthCheck, &rule.TCPHealthCheckPort, &rule.TCPTryDuration, &rule.TCPTryInterval,
			&rule.RequestBodyMaxSizeMB, &rule.UpstreamKeepaliveTimeout, &rule.ServerTokensHidden, &rule.HostHeader,
			&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.CAProviderID, &rule.TLSCert, &rule.TLSKey,
			&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.LogEnabled, &rule.CreatedBy, &rule.UpdatedBy); err != nil {
			return nil, fmt.Errorf("扫描快照规则: %w", err)
		}
		upstreams, upstreamErr := s.snapshotUpstreams(ctx, rule.CaddyID)
		if upstreamErr != nil {
			return nil, upstreamErr
		}
		rule.Upstreams = upstreams
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照规则: %w", err)
	}
	return rules, nil
}

func (s *ClusterService) snapshotUpstreams(ctx context.Context, ruleID string) ([]models.Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), COALESCE(enabled,1), COALESCE(protocol,'http'), COALESCE(dns_server,''), COALESCE(max_connections,0), COALESCE(proxy_protocol,'') FROM upstreams WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("读取规则上游 %s: %w", ruleID, err)
	}
	defer rows.Close()
	upstreams := make([]models.Upstream, 0)
	for rows.Next() {
		var upstream models.Upstream
		if err := rows.Scan(&upstream.ID, &upstream.RuleID, &upstream.Host, &upstream.Port, &upstream.Weight, &upstream.Domain, &upstream.DynamicDNS, &upstream.Enabled, &upstream.Protocol, &upstream.DnsServer, &upstream.MaxConnections, &upstream.ProxyProtocol); err != nil {
			return nil, fmt.Errorf("扫描规则上游 %s: %w", ruleID, err)
		}
		upstreams = append(upstreams, upstream)
	}
	return upstreams, rows.Err()
}

func (s *ClusterService) snapshotUsers(ctx context.Context) ([]models.ClusterUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, password_hash, role, COALESCE(display_name,''), COALESCE(is_enabled,1) FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("读取快照用户: %w", err)
	}
	defer rows.Close()
	users := make([]models.ClusterUser, 0)
	for rows.Next() {
		var user models.ClusterUser
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.DisplayName, &user.IsEnabled); err != nil {
			return nil, fmt.Errorf("扫描快照用户: %w", err)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *ClusterService) snapshotAPIKeys(ctx context.Context) ([]models.ClusterAPIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, key_hash, key_prefix, created_by, COALESCE(expires_at,''), COALESCE(is_enabled,1) FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照密钥: %w", err)
	}
	defer rows.Close()
	keys := make([]models.ClusterAPIKey, 0)
	for rows.Next() {
		var key models.ClusterAPIKey
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyHash, &key.KeyPrefix, &key.CreatedBy, &key.ExpiresAt, &key.IsEnabled); err != nil {
			return nil, fmt.Errorf("扫描快照密钥: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *ClusterService) snapshotCertificates(ctx context.Context) ([]models.ClusterCertificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT caddy_id, tls_cert, tls_key, '' FROM lb_rules WHERE enable_tls=1 AND tls_source='manual' AND COALESCE(tls_cert,'')<>'' AND COALESCE(tls_key,'')<>''
		UNION ALL SELECT rule_id, cert_pem, key_pem, COALESCE(expires_at,'') FROM cert_jobs WHERE status='issued' AND COALESCE(cert_pem,'')<>'' AND COALESCE(key_pem,'')<>'' ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("读取快照证书: %w", err)
	}
	defer rows.Close()
	certs := make([]models.ClusterCertificate, 0)
	for rows.Next() {
		var cert models.ClusterCertificate
		if err := rows.Scan(&cert.RuleID, &cert.CertPEM, &cert.KeyPEM, &cert.ExpiresAt); err != nil {
			return nil, fmt.Errorf("扫描快照证书: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}
